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

//! 对端会话：记录对端公钥、虚拟 IP、坐标、传输方式，以及数据面会话密钥（PFS）。
//!
//! 数据面安全模型（P0 修复，见 `docs/身份认证与密钥管理体系设计.md` §5.1）：
//! - 握手期用静态 ECDH 密钥（`handshake_key`）交换双方路由密钥 rk 与盐；
//! - 握手完成后数据面用 `peer_key = HKDF(DH(ik)‖DH(rk), "linkmesh/peer/v1")` 加密，
//!   rk 为每次连接/轮换生成的临时密钥（Drop 清零）——静态密钥泄露无法恢复历史数据；
//! - 帧内携带 `epoch(4B)+seq(8B)`，接收端拒绝过期 epoch 与乱序 seq（防重放）；
//! - 按包数/时间自动轮换 rk（`TUNNEL_REKEY`），旧 rk 清零。

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use linkmesh_shared::crypto::{RawKey, SessionKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// 正在尝试 UDP 打洞。
    Punching,
    /// UDP 打洞成功，直连。
    Direct,
    /// 打洞失败，走中继。
    Relay,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Punching => "打洞中",
            Transport::Direct => "直连",
            Transport::Relay => "中继",
        }
    }
}

/// 一个对端的会话状态。
pub struct PeerSession {
    pub public_key: RawKey,
    /// 对端虚拟 IP（从 Hello 或查询获得）。
    pub ip: String,
    pub endpoint: Option<SocketAddr>,
    pub transport: Transport,
    pub attempts: u32,
    pub error_count: u32,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_seen: Instant,

    // ---------- 数据面安全状态 ----------
    /// 握手期密钥 = ECDH(静态 ik_x 双方)，仅用于初始 HELLO 交换；握手完成后仍保留用于回放旧帧。
    pub handshake_key: RawKey,
    /// 对端会话密钥（含 rk 临时成分），握手完成后 Some，Drop 清零。
    pub peer_key: Option<SessionKey>,
    /// 本机路由密钥（每次连接/轮换生成，Drop 清零）。
    pub rk_priv: Option<SessionKey>,
    /// 本机 rk 公钥。
    pub rk_pub: Option<RawKey>,
    /// 对端 rk 公钥（握手/轮换后更新）。
    pub peer_rk_pub: Option<RawKey>,
    /// 对端中继路由密钥（P1-7，从查询响应获得）：中继头部用它寻址，代替长期 ik_x。
    pub peer_relay_rk: Option<RawKey>,
    /// 本机握手盐。
    pub my_salt: Option<[u8; 12]>,
    /// 对端握手盐。
    pub peer_salt: Option<[u8; 12]>,
    /// 当前密钥代数（rekey 递增，防旧密钥帧）。
    pub epoch: u32,
    /// 本方向发送序号（跨 rekey 单调递增，兼作 AEAD nonce 成分）。
    pub send_seq: u64,
    /// 已接收序号（连续高水位，拒绝重放；跨 rekey 不重置，可靠传输据此累计确认）。
    pub recv_seq: u64,
    /// 可靠发送窗口：seq → (首次发送时刻, 已重传次数, IP 包明文)。未收到对端 ACK 前保留，
    /// 超时重传（重传次数达上限后暂停，等待重连恢复时重置）；收到累计 ACK 后移除 ≤ack 的项。
    /// 保证「丢了就重传直至确认」。
    pub send_unacked: BTreeMap<u64, (Instant, u32, Vec<u8>)>,
    /// 接收侧乱序缓冲：seq → IP 包明文。仅缓存 `recv_seq` 之后的乱序包，
    /// 收到缺失包后按序冲刷交付并推进高水位（配合 ACK 实现可靠按序投递）。
    pub recv_buf: BTreeMap<u64, Vec<u8>>,
    /// 是否已发送过初始 HELLO。
    pub hello_sent: bool,
    /// 握手完成前的数据缓冲（握手完成后按序发送）。
    pub pending: VecDeque<Vec<u8>>,
    /// 已发送数据包计数（触发按包数自动 rekey）。
    pub sent_pkts: u64,
    /// 上次 rekey 时间（触发按时间自动 rekey）。
    pub last_rekey: Instant,
    /// 上次重新查询对端坐标的时间（静默检测用）。
    pub last_requery: Option<Instant>,
    /// 上次直连收到数据的时间（直连存活检测）。
    pub last_direct: Option<Instant>,
}

impl PeerSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        public_key: RawKey,
        ip: String,
        handshake_key: RawKey,
        endpoint: Option<SocketAddr>,
        rk_priv: SessionKey,
        rk_pub: RawKey,
        my_salt: [u8; 12],
    ) -> Self {
        PeerSession {
            public_key,
            ip,
            endpoint,
            transport: Transport::Punching,
            attempts: 0,
            error_count: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            last_seen: Instant::now(),
            handshake_key,
            peer_key: None,
            rk_priv: Some(rk_priv),
            rk_pub: Some(rk_pub),
            peer_rk_pub: None,
            peer_relay_rk: None,
            my_salt: Some(my_salt),
            peer_salt: None,
            epoch: 0,
            send_seq: 0,
            recv_seq: 0,
            send_unacked: BTreeMap::new(),
            recv_buf: BTreeMap::new(),
            hello_sent: false,
            pending: VecDeque::new(),
            sent_pkts: 0,
            last_rekey: Instant::now(),
            last_requery: None,
            last_direct: None,
        }
    }

    /// 当前用于加解密的数据面密钥：握手完成后用对端会话密钥，否则回退握手期静态密钥。
    pub fn current_key(&self) -> &[u8; 32] {
        match &self.peer_key {
            Some(k) => k.as_raw(),
            None => &self.handshake_key,
        }
    }

    /// 会话是否已建立（收到对端 HELLO 并派生会话密钥）。
    pub fn established(&self) -> bool {
        self.peer_key.is_some()
    }

    /// 取本机 rk 私钥（无则生成并缓存）。
    pub fn ensure_rk(&mut self) -> (SessionKey, RawKey) {
        if let (Some(priv_sk), Some(pubk)) = (&self.rk_priv, &self.rk_pub) {
            return (SessionKey::new(*priv_sk.as_raw()), *pubk);
        }
        let kp = linkmesh_shared::crypto::generate_keypair();
        let rk_priv = SessionKey::new(kp.private);
        let rk_pub = kp.public;
        self.rk_priv = Some(SessionKey::new(kp.private));
        self.rk_pub = Some(rk_pub);
        (rk_priv, rk_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linkmesh_shared::crypto::generate_keypair;

    #[test]
    fn session_establishment_flow() {
        let a_ik = generate_keypair();
        let b_ik = generate_keypair();
        let a_rk = generate_keypair();
        let shared = linkmesh_shared::crypto::shared_secret(&a_ik.private, &b_ik.public);
        let mut s = PeerSession::new(
            b_ik.public,
            String::new(),
            shared,
            None,
            SessionKey::new(a_rk.private),
            a_rk.public,
            [1u8; 12],
        );
        assert!(!s.established());
        assert_eq!(s.current_key(), &s.handshake_key);
        let (rkp, rkq) = s.ensure_rk();
        assert_eq!(rkq, a_rk.public);
        assert_eq!(rkp.as_raw(), &a_rk.private);
    }
}
