// LinkMesh - 可以在多个操作系统上运行的内网穿透工具
// Copyright (C) 2026 Linux-System-0(Github) / 一架在Linux上起飞的A320(Bilibili) <ls0_1@qq.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! 内核态虚拟网卡（Linux TUN / Windows 内置 Wintun）与隧道数据帧。
//!
//! 隧道帧格式（加密前的明文结构）：
//!
//! ```text
//! 0     pkt_type   (1B)  TUNNEL_HELLO / TUNNEL_DATA / TUNNEL_ACK / TUNNEL_REKEY
//! 1-4   epoch      (4B, BE) 数据面密钥轮换代数（防重放/防旧密钥）
//! 5-12  seq        (8B, BE) 本方向发送序号（单调递增，防重放；兼作 AEAD nonce 成分）
//! 13..  payload
//! ```
//!
//! - `TUNNEL_DATA`：载荷为完整 IP 包，用对端会话密钥（含 rk 临时成分，见 peer.rs）加密，
//!   接收端校验 `epoch == 当前` 且 `seq > 上次接收`，否则视为重放/乱序丢弃；收到后会
//!   回 `TUNNEL_ACK` 累计确认，发送端据此从可靠发送窗口移除已确认包；
//! - `TUNNEL_ACK`：可靠传输累计确认，载荷 = `ack(8B, BE)`（对端已连续收到的最大 seq），
//!   用当前会话密钥加密，帧头 `seq` 恒为 0（类型在解密后的明文头部，不存在 nonce 冲突，
//!   因为 HELLO/REKEY 用随机 nonce、DATA 用确定性 nonce，ACK 用随机 nonce）；
//! - `TUNNEL_HELLO`：握手/保活，载荷 = `rk_pub(32B) ‖ salt(12B) ‖ 本机虚拟 IP`，
//!   用当前密钥（握手前为静态 ECDH 密钥，握手后为对端会话密钥）加密；
//! - `TUNNEL_REKEY`：路由密钥轮换，载荷 = `new_rk_pub(32B) ‖ new_salt(12B)`，
//!   用**旧**会话密钥加密，收方据此派生新密钥并推进 epoch。
//!
//! 密码学细节见 `docs/身份认证与密钥管理体系设计.md` §5.1 / §7.1。

use crate::config::VmNicConfig;

pub const TUNNEL_HELLO: u8 = 0x01;
pub const TUNNEL_DATA: u8 = 0x02;
pub const TUNNEL_REKEY: u8 = 0x03;
pub const TUNNEL_ACK: u8 = 0x04;

pub const EPOCH_LEN: usize = 4;
pub const SEQ_LEN: usize = 8;
pub const FRAME_HEADER_LEN: usize = 1 + EPOCH_LEN + SEQ_LEN; // 13
pub const HANDSHAKE_EXTRA: usize = 32 + 12; // rk_pub + salt（HELLO/REKEY 载荷前缀）

/// 由 (epoch, seq) 构成 12 字节确定性 AEAD nonce（与帧头一致，杜绝复用）。
pub fn data_nonce(epoch: u32, seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&epoch.to_be_bytes());
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// 组装隧道数据帧（在会话密钥加密之前的明文结构）。
pub fn frame_tunnel_packet(pkt_type: u8, epoch: u32, seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.push(pkt_type);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 解析隧道数据帧，返回 (类型, epoch, seq, 载荷)。
pub fn parse_tunnel_packet(pkt: &[u8]) -> Option<(u8, u32, u64, &[u8])> {
    if pkt.len() < FRAME_HEADER_LEN {
        return None;
    }
    let typ = pkt[0];
    let epoch = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
    let seq = u64::from_be_bytes([
        pkt[5], pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11], pkt[12],
    ]);
    Some((typ, epoch, seq, &pkt[FRAME_HEADER_LEN..]))
}

/// 组装 ACK 载荷：累计确认序号 `ack(8B, BE)`。
pub fn ack_payload(ack: u64) -> Vec<u8> {
    ack.to_be_bytes().to_vec()
}

/// 解析 ACK 载荷，返回累计确认序号。
pub fn parse_ack_payload(payload: &[u8]) -> Option<u64> {
    if payload.len() < 8 {
        return None;
    }
    let mut ack = [0u8; 8];
    ack.copy_from_slice(&payload[..8]);
    Some(u64::from_be_bytes(ack))
}

/// 组装 HELLO 载荷：`rk_pub(32B) ‖ salt(12B) ‖ 本机虚拟 IP`。
pub fn frame_hello_payload(rk_pub: &[u8; 32], salt: &[u8; 12], ip: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDSHAKE_EXTRA + ip.len());
    out.extend_from_slice(rk_pub);
    out.extend_from_slice(salt);
    out.extend_from_slice(ip);
    out
}

/// 组装 REKEY 载荷：`new_rk_pub(32B) ‖ new_salt(12B)`。
pub fn frame_rekey_payload(new_rk_pub: &[u8; 32], new_salt: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDSHAKE_EXTRA);
    out.extend_from_slice(new_rk_pub);
    out.extend_from_slice(new_salt);
    out
}

/// 解析 IP 包的目的地址（IPv4 为第 16-20 字节，IPv6 为第 24-40 字节）。
pub fn extract_dst_ip(pkt: &[u8]) -> Option<std::net::IpAddr> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                pkt[16], pkt[17], pkt[18], pkt[19],
            )))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[24..40]);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// 虚拟网卡封装。
pub struct TunDevice {
    dev: tun::AsyncDevice,
}

impl TunDevice {
    pub fn create(nic: &VmNicConfig) -> Result<Self, String> {
        ensure_wintun_dll();
        let mut config = tun::Configuration::default();
        config
            .tun_name(&nic.name)
            .address(&nic.ip)
            .netmask(&nic.netmask)
            .mtu(nic.mtu as u16)
            .up();
        let dev = tun::create_as_async(&config).map_err(|e| format!("tun 创建失败: {e}"))?;
        Ok(TunDevice { dev })
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, String> {
        self.dev.recv(buf).await.map_err(|e| e.to_string())
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize, String> {
        self.dev.send(buf).await.map_err(|e| e.to_string())
    }
}

#[cfg(target_os = "windows")]
fn ensure_wintun_dll() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    if let Some(dir) = exe_dir {
        let target = dir.join("wintun.dll");
        if !target.exists() {
            if let Err(e) = std::fs::write(&target, WINTUN_DLL) {
                eprintln!("警告: 写出 wintun.dll 失败: {e}");
            }
        }
    } else {
        eprintln!("警告: 无法定位可执行文件目录，wintun.dll 需手工放置");
    }
}

#[cfg(not(target_os = "windows"))]
fn ensure_wintun_dll() {}

// Windows 上内嵌的 wintun.dll 字节（由 build.rs 生成）
#[cfg(target_os = "windows")]
include!(concat!(env!("OUT_DIR"), "/wintun_embedded.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = frame_tunnel_packet(TUNNEL_DATA, 3, 42, b"ip-packet");
        let (t, e, s, p) = parse_tunnel_packet(&f).unwrap();
        assert_eq!((t, e, s), (TUNNEL_DATA, 3, 42));
        assert_eq!(p, b"ip-packet");
    }

    #[test]
    fn frame_too_short_rejected() {
        assert!(parse_tunnel_packet(&[]).is_none());
        assert!(parse_tunnel_packet(&[TUNNEL_DATA, 0, 0, 0]).is_none());
    }

    #[test]
    fn data_nonce_layout() {
        let n = data_nonce(1, 7);
        assert_eq!(&n[..4], &1u32.to_be_bytes());
        assert_eq!(&n[4..], &7u64.to_be_bytes());
        assert_ne!(data_nonce(1, 7), data_nonce(2, 7));
        assert_ne!(data_nonce(1, 7), data_nonce(1, 8));
    }

    #[test]
    fn hello_payload_layout() {
        let rk = [9u8; 32];
        let salt = [1u8; 12];
        let ip = b"10.13.13.2";
        let p = frame_hello_payload(&rk, &salt, ip);
        assert_eq!(&p[..32], &rk);
        assert_eq!(&p[32..44], &salt);
        assert_eq!(&p[44..], ip);
    }
}
