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

//! 信令 / 中继 UDP 封包协议。
//!
//! 所有封包均以 2 字节魔数 `LM` 开头，便于区分业务包。
//!
//! ## 信令封包（客户端 ↔ 服务端，密文是 AEAD 加密后的二进制定长负载）
//!
//! ```text
//! 0-1   magic              = "LM"
//! 2     version            = 2
//! 3     msg_type
//! 4-35  sender_public_key  (32B, 明文)
//! 36..  ciphertext         (nonce(12B) + ChaCha20-Poly1305 密文)
//! ```
//!
//! 发送方公钥以明文携带，接收方用它计算共享密钥后才能解密，私钥不参与传输。
//!
//! ## 中继封包（客户端 → 服务端，服务端仅按目标转发，不解密业务数据）
//!
//! ```text
//! 0-1   magic              = "LM"
//! 2     version            = 2
//! 3     msg_type           = RELAY
//! 4-35  dest_public_key    (32B, 明文目标)
//! 36-67 src_public_key     (32B, 明文来源)
//! 68..  ciphertext         (业务数据，双方共享密钥加密)
//! ```
//!
//! ## 批量中继封包（服务端 → 客户端，服务端把短时间内到达的多个小中继帧聚合成一个大 UDP 载荷）
//!
//! ```text
//! 0-1   magic              = "LM"
//! 2     version            = 2
//! 3     msg_type           = RELAY_BATCH
//! 4-35  dest_public_key    (32B, 明文公共目标)
//! 36..  多个子帧，每个子帧 = [len(u16 BE)] [src_public_key(32B)] [ciphertext len 字节]
//! ```
//!
//! 接收端按 `len` 长度头依次拆分每个子帧，子帧内的 src_public_key 用于定位对端会话。
//!
//! ## 负载编码（v2，替代旧版 JSON）
//!
//! 自 v2 起，AEAD 密文内的信令负载从 `serde_json` 改为固定布局的二进制结构体
//! （zerocopy v0.8 `#[repr(C)]` + `FromBytes/IntoBytes/Unaligned`），见 [`crate::wire`]。
//! 所有字段固定大小：文本字段定长、密钥/签名用原始字节。该层在 `wire` 模块实现；
//! 本模块只保留面向业务的「域类型」（字符串形式）与帧头编解码。

use crate::crypto::RawKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub use crate::wire::{
    decode_auth, decode_auth_resp, decode_join, decode_notify, decode_query, decode_register,
    decode_response, decode_server_info_body, encode_auth, encode_auth_resp, encode_join,
    encode_notify, encode_query, encode_register, encode_response, encode_server_info_body,
};

pub const MAGIC: [u8; 2] = *b"LM";
pub const VERSION: u8 = 2;

pub const HEADER_LEN: usize = 36;
pub const RELAY_HEADER_LEN: usize = 68;

pub const MSG_REGISTER: u8 = 0x01;
pub const MSG_QUERY: u8 = 0x02;
pub const MSG_RESPONSE: u8 = 0x03;
pub const MSG_NOTIFY: u8 = 0x04;
pub const MSG_BYE: u8 = 0x05;
pub const MSG_RELAY: u8 = 0x06;
pub const MSG_HEARTBEAT: u8 = 0x07;
/// 首次接触：客户端向服务端索取 root 签名的 ServerInfo（网格根指纹 TOFU）。
pub const MSG_KEYQUERY: u8 = 0x08;
/// 批量中继：一个 UDP 载荷内拼接多个中继子帧。
pub const MSG_RELAY_BATCH: u8 = 0x0A;
// ---------- 认证 / 密钥轮换 / 吊销（协议能力版本 2，见 ServerInfo.protocol_ver） ----------
/// 签名 ServerInfo（KEYQUERY 的响应，root 签名，见 cert::ServerInfo）。
pub const MSG_SERVERINFO: u8 = 0x0B;
/// 加入请求：加入码 + 设备双公钥（onboarding）。
pub const MSG_JOIN: u8 = 0x0C;
/// 会话认证：设备证书 + 新鲜临时公钥。
pub const MSG_AUTH: u8 = 0x0D;
/// 会话认证响应：服务端临时公钥 + CRL + ServerInfo + 分配 IP。
pub const MSG_AUTH_RESP: u8 = 0x0E;
/// 会话/路由密钥轮换（双向）。
pub const MSG_REKEY: u8 = 0x0F;
/// 设备长期密钥轮换声明（旧 ik_s 签名 + root 签名）。
pub const MSG_ROTATE: u8 = 0x10;
/// 拉取/下发吊销列表。
pub const MSG_CRL: u8 = 0x11;
/// CRL 更新推送（在线成员即时同步）。
pub const MSG_CRL_NOTIFY: u8 = 0x12;
/// 会话被吊销/强制下线。
pub const MSG_KICK: u8 = 0x13;
/// rk 头部中继（P1-7）：目标/来源均为短期路由密钥 rk，代替长期身份密钥 ik_x，
/// 消除线上长期身份关联；密文含 epoch+seq 前缀（数据面防重放）。
pub const MSG_RELAY_RK: u8 = 0x14;

/// 协议能力版本：2 = 强制认证（mesh root + 设备证书 + 会话握手）。
///
/// 帧头 `VERSION` 恒为 2；能力版本由 ServerInfo 声明。
pub const PROTOCOL_VER: u32 = 2;

/// 端点：`ip:port` 字符串。
pub type Endpoint = String;

/// 信令封包头部。
#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub version: u8,
    pub msg_type: u8,
    pub sender_public_key: RawKey,
}

/// 定长帧头（信令）：`LM` + version + msg_type + 32B 发送方公钥。
#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct SignalHeader {
    magic: [u8; 2],
    version: u8,
    msg_type: u8,
    sender_public_key: [u8; 32],
}

/// 定长帧头（中继）：`LM` + version + msg_type + 32B 目标 + 32B 来源。
#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct RelayHeader {
    magic: [u8; 2],
    version: u8,
    msg_type: u8,
    dest_public_key: [u8; 32],
    src_public_key: [u8; 32],
}

/// 组装信令封包：明文头 + 密文负载。
pub fn frame_signaling(msg_type: u8, sender_public_key: &RawKey, ciphertext: &[u8]) -> Vec<u8> {
    let hdr = SignalHeader {
        magic: MAGIC,
        version: VERSION,
        msg_type,
        sender_public_key: *sender_public_key,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// 解析信令封包头，返回版本、消息类型与发送方公钥。
pub fn parse_header(packet: &[u8]) -> Result<PacketHeader, String> {
    if packet.len() < HEADER_LEN {
        return Err("封包过短".into());
    }
    let (hdr, _) = SignalHeader::ref_from_prefix(packet)
        .map_err(|_| "封包过短".to_string())?;
    if &hdr.magic != &MAGIC {
        return Err("魔数不匹配，不是 LinkMesh 封包".into());
    }
    Ok(PacketHeader {
        version: hdr.version,
        msg_type: hdr.msg_type,
        sender_public_key: hdr.sender_public_key,
    })
}

/// 组装中继封包：明文目标/来源公钥头 + 密文负载。
pub fn frame_relay(
    dest_public_key: &RawKey,
    src_public_key: &RawKey,
    ciphertext: &[u8],
) -> Vec<u8> {
    let hdr = RelayHeader {
        magic: MAGIC,
        version: VERSION,
        msg_type: MSG_RELAY,
        dest_public_key: *dest_public_key,
        src_public_key: *src_public_key,
    };
    let mut out = Vec::with_capacity(RELAY_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// 解析中继封包头部，返回目标公钥、来源公钥与密文偏移。
pub fn parse_relay(packet: &[u8]) -> Result<(RawKey, RawKey, &[u8]), String> {
    if packet.len() < RELAY_HEADER_LEN {
        return Err("中继封包过短".into());
    }
    let (hdr, rest) = RelayHeader::ref_from_prefix(packet)
        .map_err(|_| "中继封包过短".to_string())?;
    if &hdr.magic != &MAGIC {
        return Err("魔数不匹配".into());
    }
    Ok((hdr.dest_public_key, hdr.src_public_key, rest))
}

/// 组装 rk 中继封包（P1-7）：目标/来源为短期路由密钥 rk，代替长期身份密钥 ik_x。
pub fn frame_relay_rk(dest_rk: &RawKey, src_rk: &RawKey, ciphertext: &[u8]) -> Vec<u8> {
    let hdr = RelayHeader {
        magic: MAGIC,
        version: VERSION,
        msg_type: MSG_RELAY_RK,
        dest_public_key: *dest_rk,
        src_public_key: *src_rk,
    };
    let mut out = Vec::with_capacity(RELAY_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// 组装批量中继封包：明文公共目标公钥头 + 一组长度前缀的子帧。
/// 每个子帧 = `src_public_key(32B) + ciphertext`，整体用 `len(u16 BE)` 前缀定界。
pub fn frame_relay_batch(dest_public_key: &RawKey, subframes: &[&[u8]]) -> Vec<u8> {
    let total: usize = subframes.iter().map(|s| 2 + s.len()).sum();
    let hdr = SignalHeader {
        magic: MAGIC,
        version: VERSION,
        msg_type: MSG_RELAY_BATCH,
        sender_public_key: *dest_public_key,
    };
    let mut out = Vec::with_capacity(HEADER_LEN + total);
    out.extend_from_slice(hdr.as_bytes());
    for sf in subframes {
        let len = u16::try_from(sf.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(sf);
    }
    out
}

/// 解析批量中继封包，返回公共目标公钥与所有子帧切片（子帧内部为 `src + ciphertext`）。
pub fn parse_relay_batch(packet: &[u8]) -> Result<(RawKey, Vec<&[u8]>), String> {
    if packet.len() < HEADER_LEN {
        return Err("批量中继封包过短".into());
    }
    let (hdr, rest) = SignalHeader::ref_from_prefix(packet)
        .map_err(|_| "批量中继封包过短".to_string())?;
    if &hdr.magic != &MAGIC {
        return Err("魔数不匹配".into());
    }
    let mut subframes = Vec::new();
    let mut cur = rest;
    // 子帧数上限：单帧 UDP（≤~65KB）即便全是最小长度头，子帧数也应远小于此。
    // 防止攻击者用大量空/超小子帧放大 CPU（每子帧触发接收端会话表查询+解密尝试，安全审计 F1）。
    const MAX_SUBFRAMES: usize = 1024;
    while !cur.is_empty() {
        if subframes.len() >= MAX_SUBFRAMES {
            return Err("批量中继子帧数超限".into());
        }
        if cur.len() < 2 {
            return Err("批量中继子帧长度头不足".into());
        }
        let len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
        cur = &cur[2..];
        if cur.len() < len {
            return Err("批量中继子帧长度越界".into());
        }
        subframes.push(&cur[..len]);
        cur = &cur[len..];
    }
    Ok((hdr.sender_public_key, subframes))
}

// ---------- 信令负载（AEAD 加密后传输的二进制定长负载，域类型字符串形式） ----------

/// 注册 / 心跳。客户端登记自己的虚拟 IP，服务端据此建立 ip→公钥→Endpoint 映射。
#[derive(Debug, Clone)]
pub struct RegisterBody {
    pub ip: String,
    /// 本机中继路由密钥（X25519 公钥，base64，P1-7）。
    pub relay_rk: Option<String>,
    /// 房间令牌。
    pub token: Option<String>,
    /// 设备自报别名。
    pub alias: Option<String>,
}

/// 查询对端坐标：按虚拟 IP（`ip`）或按别名（`name`）查询，二者填一。
#[derive(Debug, Clone)]
pub struct QueryBody {
    pub ip: String,
    pub name: Option<String>,
}

/// 对端坐标信息（域类型，非线格式）。
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub public_key: String,
    pub endpoint: Endpoint,
    pub relay_rk: Option<String>,
    pub alias: Option<String>,
    pub ip: Option<String>,
}

/// 服务端主动通知客户端「某对端已上线/已查询你」。
#[derive(Debug, Clone)]
pub struct NotifyBody {
    pub peer: PeerInfo,
}

/// 响应负载的类型化数据（替代旧版 `serde_json::Value` 的动态 data）。
#[derive(Debug, Clone)]
pub enum ResponseData {
    /// 仅成功确认，无数据。
    None,
    /// 查询命中：目标坐标（`req` 为查询键回显，客户端据此匹配待处理查询）。
    QueryHit {
        req: String,
        ip: String,
        public_key: String,
        endpoint: String,
        relay_rk: Option<String>,
        alias: String,
    },
    /// 查询未命中：回显 `req`（查询键）与错误信息。
    QueryMiss { req: String, error: String },
    /// 加入成功：设备 ID、分配 IP、证书、ServerInfo 与 CRL。
    Join {
        device_id: String,
        allocated_ip: String,
        cert: crate::cert::DeviceCert,
        server_info: crate::cert::ServerInfo,
        crl: crate::cert::Crl,
    },
}

/// 统一响应体（类型化，替代旧版 JSON `ok/data/error` 结构）。
#[derive(Debug, Clone)]
pub struct ResponseBody {
    pub ok: bool,
    pub data: ResponseData,
    pub error: Option<String>,
}

impl ResponseBody {
    pub fn ok() -> Self {
        ResponseBody {
            ok: true,
            data: ResponseData::None,
            error: None,
        }
    }

    pub fn ok_with_data(data: ResponseData) -> Self {
        ResponseBody {
            ok: true,
            data,
            error: None,
        }
    }

    pub fn err(err: impl Into<String>) -> Self {
        ResponseBody {
            ok: false,
            data: ResponseData::None,
            error: Some(err.into()),
        }
    }
}

/// 加入请求（onboarding）。密钥字段为 base64。
#[derive(Debug, Clone)]
pub struct JoinBody {
    /// 一次性加入码。
    pub code: String,
    pub device_id: String,
    pub ik_x: String,
    pub ik_s_pub: String,
    pub requested_ip: Option<String>,
    /// 房间令牌。
    pub token: Option<String>,
    /// 设备自报别名。
    pub alias: Option<String>,
}

/// 会话认证请求（`MSG_AUTH`）：携带设备证书与新鲜临时公钥。
#[derive(Debug, Clone)]
pub struct AuthBody {
    pub device_id: String,
    pub cert: crate::cert::DeviceCert,
    /// 客户端临时公钥（base64）。
    pub ek_c: String,
    /// Unix 时间戳（秒）。
    pub timestamp: u64,
    /// 随机 12 字节（base64）。
    pub nonce: String,
    /// 房间令牌。
    pub token: Option<String>,
}

/// 会话认证响应（`MSG_AUTH_RESP`）。
#[derive(Debug, Clone)]
pub struct AuthRespBody {
    pub ek_s: String,
    /// 随机会话 ID（base64，16 字节）。
    pub session_id: String,
    pub crl: crate::cert::Crl,
    pub server_info: crate::cert::ServerInfo,
    pub allocated_ip: String,
}

/// 服务器信息响应（`MSG_SERVERINFO`，root 签名，见 cert::ServerInfo）。
#[derive(Debug, Clone)]
pub struct ServerInfoBody {
    pub server_info: crate::cert::ServerInfo,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signaling_frame_roundtrip() {
        let key = [7u8; 32];
        let pkt = frame_signaling(MSG_QUERY, &key, b"ciphertext");
        let h = parse_header(&pkt).unwrap();
        assert_eq!(h.version, VERSION);
        assert_eq!(h.msg_type, MSG_QUERY);
        assert_eq!(h.sender_public_key, key);
        assert_eq!(&pkt[HEADER_LEN..], b"ciphertext");
    }

    #[test]
    fn relay_frame_roundtrip() {
        let dest = [1u8; 32];
        let src = [2u8; 32];
        let pkt = frame_relay(&dest, &src, b"payload");
        let (d, s, body) = parse_relay(&pkt).unwrap();
        assert_eq!(d, dest);
        assert_eq!(s, src);
        assert_eq!(body, b"payload");
    }

    #[test]
    fn reject_garbage() {
        assert!(parse_header(&[0u8; 10]).is_err());
        assert!(parse_header(&[0xff; 40]).is_err());
    }

    #[test]
    fn relay_batch_roundtrip() {
        let dest = [1u8; 32];
        let sf1: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&[2u8; 32]);
            v.extend_from_slice(b"payload-a");
            v
        };
        let sf2: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&[3u8; 32]);
            v.extend_from_slice(b"payload-bb");
            v
        };
        let pkt = frame_relay_batch(&dest, &[&sf1, &sf2]);
        assert_eq!(pkt[3], MSG_RELAY_BATCH);
        let (d, subs) = parse_relay_batch(&pkt).unwrap();
        assert_eq!(d, dest);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0], sf1.as_slice());
        assert_eq!(subs[1], sf2.as_slice());
    }

    #[test]
    fn relay_batch_truncated_length_fails() {
        let dest = [1u8; 32];
        let sf: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&[2u8; 32]);
            v.extend_from_slice(b"payload-a");
            v
        };
        let pkt = frame_relay_batch(&dest, &[&sf]);
        let broken = &pkt[..pkt.len() - 2];
        assert!(parse_relay_batch(broken).is_err());
    }
}
