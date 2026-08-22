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

//! 单条连接：注册 → 坐标查询 → UDP 打洞 → 打洞失败降级中继 → 数据面转发。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_shared::crypto::{self, RawKey, SessionKey};
use linkmesh_shared::protocol::{
    decode_auth_resp, decode_notify, decode_response, decode_server_info_body, encode_auth,
    encode_query, encode_register, frame_relay, frame_relay_rk, frame_signaling, parse_header,
    parse_relay, parse_relay_batch, AuthBody, AuthRespBody, HEADER_LEN, MSG_AUTH, MSG_AUTH_RESP,
    MSG_BYE, MSG_KEYQUERY, MSG_NOTIFY, MSG_QUERY, MSG_REGISTER, MSG_RELAY, MSG_RELAY_BATCH,
    MSG_RELAY_RK, MSG_RESPONSE, MSG_SERVERINFO, NotifyBody, PeerInfo, QueryBody, RegisterBody,
    ResponseBody, ResponseData, ServerInfoBody,
};
use rand::RngCore;
use serde::Serialize;
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::time::sleep;

use crate::config::{ClientConfig, ConnectionEntry, HolePunchConfig, ServerEntry, VmNicConfig};
use crate::dns::{DnsRegistry, NameResolver};
use crate::log::Logger;
use crate::peer::{PeerSession, Transport};
use crate::tunnel::{
    ack_payload, data_nonce, extract_dst_ip, frame_hello_payload, frame_rekey_payload,
    frame_tunnel_packet, parse_ack_payload, parse_tunnel_packet, TunDevice, TUNNEL_ACK,
    TUNNEL_DATA, TUNNEL_HELLO, TUNNEL_REKEY,
};

/// 直连路径判定失效的阈值：超过该时长未收到对端直连数据，发送侧自动切中继兜底。
const DIRECT_STALE_SECS: u64 = 5;
/// 对端「静默」阈值：超过该时长未收到对端任何来包，发送侧主动重新查询其坐标
/// （触发服务端 NOTIFY 让对方重建会话），修复对端重启后数据静默丢失的死锁。
/// 取值偏小以快速发现重启对端并学到其新 relay_rk；仅在向该对端发包时触发（需求驱动）。
const RE_QUERY_STALE_SECS: u64 = 1;
/// 重新查询的最小间隔：防止静默窗口内每次发包都触发查询/通知风暴。
const RE_QUERY_MIN_INTERVAL_SECS: u64 = 1;
/// 握手未完成时的数据缓冲上限（防止对端失联导致内存膨胀）。
const PENDING_CAP: usize = 256;
/// 可靠发送窗口上限：未确认（unacked）数据包数超过该值即拒绝接纳新包并告警，
/// 防止对端长期失联导致内存无限膨胀（健康链路上窗口会快速排空，不会触及上限）。
const RELIABLE_WINDOW: usize = 512;
/// 数据包重传间隔：入窗后超过该时长仍未被对端 ACK，即触发一次重传（毫秒）。
const RETRANSMIT_TIMEOUT_MS: u64 = 500;
/// 重传轮询周期：主循环每隔该时长扫描一次各对端的可靠发送窗口（毫秒）。
const RETRANSMIT_INTERVAL_MS: u64 = 250;
/// 单个数据包的重传次数上限：超过后视为对端断链/重启，交由「requery + ik_x 回退」恢复
/// 链路；恢复后数据仍保留在窗口内继续重传直至确认（数据不丢，仅延迟）。
const MAX_RETRIES: u32 = 20;

/// 会话握手盐：双方各发 12B 随机盐，最终盐 = XOR（与顺序无关，双方一致）。
fn xor_salt(a: [u8; 12], b: [u8; 12]) -> [u8; 12] {
    let mut out = [0u8; 12];
    for i in 0..12 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// 生成 12 字节随机盐。
fn random_salt() -> [u8; 12] {
    let mut salt = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// 供 `--status` 展示的对端摘要。
#[derive(Debug, Clone, Serialize)]
pub struct PeerState {
    pub ip: String,
    pub endpoint: String,
    pub transport: String,
}

/// 连接的可查询状态。
pub struct ConnectionState {
    pub server: String,
    pub vmnic: String,
    pub status: std::sync::Mutex<String>,
    pub error: std::sync::Mutex<Option<String>>,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

impl ConnectionState {
    pub fn new(server: String, vmnic: String) -> Self {
        ConnectionState {
            server,
            vmnic,
            status: std::sync::Mutex::new("连接中".to_string()),
            error: std::sync::Mutex::new(None),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }

    fn set_status(&self, s: &str) {
        *self.status.lock().unwrap() = s.to_string();
    }

    fn set_error(&self, e: String) {
        self.set_status("错误");
        *self.error.lock().unwrap() = Some(e);
    }
}

/// 控制台/测试可见的连接句柄。
pub struct ConnectionHandle {
    pub state: Arc<ConnectionState>,
    pub peers: Arc<Mutex<HashMap<RawKey, Arc<Mutex<PeerSession>>>>>,
}

impl ConnectionHandle {
    pub async fn snapshot(&self) -> serde_json::Value {
        let peers: Vec<PeerState> = {
            let mut v = Vec::new();
            let map = self.peers.lock().await;
            for s in map.values() {
                let s = s.lock().await;
                v.push(PeerState {
                    ip: s.ip.clone(),
                    endpoint: s.endpoint.map(|e| e.to_string()).unwrap_or_default(),
                    transport: s.transport.as_str().to_string(),
                });
            }
            v
        };
        json!({
            "server": self.state.server,
            "vmnic": self.state.vmnic,
            "status": *self.state.status.lock().unwrap(),
            "error": self.state.error.lock().unwrap().clone(),
            "tx_bytes": self.state.tx_bytes.load(Ordering::Relaxed),
            "rx_bytes": self.state.rx_bytes.load(Ordering::Relaxed),
            "peers": peers,
        })
    }
}

/// 等待对端查询结果的一次性通道。
pub type PendingQuery = oneshot::Sender<Result<PeerInfo, String>>;

/// 数据面共享状态。所有字段均可廉价 Clone，便于在异步任务中传递。
#[derive(Clone)]
struct Outbox {
    peers: Arc<Mutex<HashMap<RawKey, Arc<Mutex<PeerSession>>>>>,
    ip_index: Arc<Mutex<HashMap<String, RawKey>>>,
    addr_index: Arc<Mutex<HashMap<SocketAddr, RawKey>>>,
    /// rk → ik_x 反向索引（P1-7 中继来源解析，O(1)）：mesh 模式下每中继包都要把
    /// 帧头 rk 解析回对端 ik_x。在学到 `peer_relay_rk` 处同步维护，替代每包 O(n) 全表扫描。
    rk_index: Arc<Mutex<HashMap<RawKey, RawKey>>>,
    pending: Arc<Mutex<HashMap<String, PendingQuery>>>,
    inflight: Arc<Mutex<HashSet<String>>>,
    main_sock: Arc<UdpSocket>,
    server_addr: SocketAddr,
    relay_addr: SocketAddr,
    server_shared: RawKey,
    local_pub: RawKey,
    local_priv: RawKey,
    local_ip: String,
    hole_punch: HolePunchConfig,
    /// 数据面 rk 按发送包数自动轮换（0 = 仅按时间）。
    rekey_every_pkts: u64,
    /// 数据面 rk 按秒自动轮换（0 = 仅按包数）。
    rekey_every_secs: u64,
    /// 中继恢复回退阈值：对端超过该时长无任何来包（可能重启/断链）时，中继头部回退为
    /// 长期身份 ik_x（服务端按 ik_x 路由到对端当前入口），触发对端「陌生来源 → 回 HELLO」
    /// 重建会话并重新学到其新 rk。取值与 HELLO keepalive（heartbeat）同量级，确保正常
    /// 空闲/单向流量下 rk 中继头成为常态（P1-7 隐私），只在真正长时间失联时才让渡。
    relay_recover_stale: Duration,
    state: Arc<ConnectionState>,
    /// mesh 模式：会话期信令用 3-DH 会话密钥 SK + 计数器 nonce 加密（P0-2）。
    session_sk: Arc<Mutex<Option<SessionKey>>>,
    /// 会话期帧头 sender = ek_c（session_pub）。
    session_pub: Arc<Mutex<Option<RawKey>>>,
    /// 本方向发送计数器（会话期，严格递增）。
    session_seq: Arc<AtomicU64>,
    /// 本机中继路由密钥公钥（P1-7）：每次连接生成，随注册上报，中继头部用它寻址。
    relay_rk: RawKey,
    /// 本地别名表（client.json aliases，名称 → 虚拟 IP）。
    local_aliases: Arc<Mutex<BTreeMap<String, String>>>,
    /// 从服务端学到的别名（QUERY 响应 / NOTIFY），名称 → (虚拟 IP, 学习时间)。
    /// 带 TTL：过期条目在解析时被淘汰并重新查询服务端，限制恶意成员投毒条目的粘性
    /// （安全审计 N1）。
    learned_aliases: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    /// 内嵌 DNS 应答器的共享注册表（守护进程持有；JNI/测试为 None）。
    dns: Option<Arc<DnsRegistry>>,
    log: Logger,
    /// 数据面发送缓冲：就地加密封装复用其容量，减少每包一次堆分配 + 一次全量拷贝。
    /// 仅在单连接数据面热路径使用（send_data），短锁、无跨 await 数据借用问题。
    send_buf: Arc<tokio::sync::Mutex<Vec<u8>>>,
}

impl Outbox {
    /// 会话期信令（AUTH 握手完成后）：帧头 ek_c + SK 加密。
    /// 未建立会话时回退静态 ECDH（握手期）。`body` 为已编码的定长负载字节。
    async fn send_signaling(&self, msg_type: u8, body: &[u8]) -> Result<(), String> {
        let (sender, ct) = {
            let sk = self.session_sk.lock().await.clone();
            let session_pub = self.session_pub.lock().await;
            match (sk, *session_pub) {
                (Some(sk), Some(sender)) => {
                    let seq = self.session_seq.fetch_add(1, Ordering::SeqCst) + 1;
                    let nonce = crypto::session_nonce(seq, 0);
                    (sender, crypto::encrypt_with_nonce(sk.as_raw(), &nonce, body))
                }
                _ => (self.local_pub, crypto::encrypt(&self.server_shared, body)),
            }
        };
        let frame = frame_signaling(msg_type, &sender, &ct);
        self.main_sock
            .send_to(&frame, self.server_addr)
            .await
            .map_err(|e| format!("信令发送失败: {e}"))?;
        Ok(())
    }

    /// 查询对端坐标并创建会话（发起打洞）。按虚拟 IP 查询。
    async fn query_peer(&self, ip: &str) -> Option<Arc<Mutex<PeerSession>>> {
        self.query_impl(
            ip,
            QueryBody {
                ip: ip.to_string(),
                name: None,
            },
        )
        .await
        .map(|(s, _)| s)
    }

    /// 按别名查询对端（服务端在**同一房间内**解析），返回目标虚拟 IP。
    /// 命中后同样建立会话并打洞，使后续数据流直接可用。
    async fn query_by_name(&self, name: &str) -> Option<String> {
        self.query_impl(
            name,
            QueryBody {
                ip: String::new(),
                name: Some(name.to_string()),
            },
        )
        .await
        .map(|(_, ip)| ip)
    }

    /// 查询通用实现：key = 查询键（IP 或别名，作为 pending/inflight 去重键）。
    /// 返回（会话, 解析出的目标虚拟 IP）。
    async fn query_impl(
        &self,
        key: &str,
        body: QueryBody,
    ) -> Option<(Arc<Mutex<PeerSession>>, String)> {
        if self.inflight.lock().await.contains(key) {
            return None;
        }
        self.inflight.lock().await.insert(key.to_string());
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(key.to_string(), tx);

        let encoded = match encode_query(&body) {
            Ok(b) => b,
            Err(e) => {
                self.log.warn(format!("查询 {} 编码失败: {e}", key));
                self.inflight.lock().await.remove(key);
                self.pending.lock().await.remove(key);
                return None;
            }
        };
        if let Err(e) = self.send_signaling(MSG_QUERY, &encoded).await {
            self.log.warn(format!("查询 {} 发送失败: {e}", key));
            self.inflight.lock().await.remove(key);
            self.pending.lock().await.remove(key);
            return None;
        }

        let result = tokio::time::timeout(Duration::from_millis(self.hole_punch.timeout_ms), rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .and_then(|r| r.ok());
        self.inflight.lock().await.remove(key);
        self.pending.lock().await.remove(key);

        match result {
            Some(info) => {
                let Ok(pk) = crypto::parse_public_key(&info.public_key) else {
                    return None;
                };
                let ip = info.ip.clone().unwrap_or_default();
                // 学到别名（名称 → IP），供 DNS 应答器使用
                if let (Some(alias), Some(ip)) = (&info.alias, &info.ip) {
                    self.learn_alias(alias, ip).await;
                }
                if ip.is_empty() {
                    return None;
                }
                let shared = crypto::shared_secret(&self.local_priv, &pk);
                let endpoint = info.endpoint.parse().ok();
                let session = self
                    .get_or_create_session(pk, ip.clone(), shared, endpoint)
                    .await;
                if let Some(ep) = endpoint {
                    self.addr_index.lock().await.insert(ep, pk);
                }
                self.ip_index.lock().await.insert(ip.clone(), pk);
                // P1-7：记录对端中继路由密钥（中继头部用它寻址）
                if let Some(rk_b64) = &info.relay_rk {
                    if let Ok(rk) = crypto::parse_public_key(rk_b64) {
                        session.lock().await.peer_relay_rk = Some(rk);
                        self.rk_index.lock().await.insert(rk, pk);
                    }
                }
                self.spawn_punch(pk);
                self.log
                    .info(format!("发现对端 {}（公钥 {}）", ip, B64.encode(pk)));
                Some((session, ip))
            }
            None => {
                self.log.warn(format!("查询 {} 失败", key));
                None
            }
        }
    }

    /// 记录一条 名称 → 虚拟 IP 的别名映射（本地 + DNS 注册表）。
    async fn learn_alias(&self, name: &str, ip: &str) {
        let name = name.trim().to_lowercase();
        if name.is_empty() || ip.parse::<std::net::IpAddr>().is_err() {
            return;
        }
        {
            // 学到的别名有界：上限 256 条，超出后淘汰最早插入的一条，防止长期运行的
            // 客户端因服务器别名表增长而无限占用内存（安全审计 item D）。
            const MAX_LEARNED: usize = 256;
            let mut map = self.learned_aliases.lock().await;
            map.insert(name.clone(), (ip.to_string(), Instant::now()));
            if map.len() > MAX_LEARNED {
                if let Some(oldest) = map.keys().next().cloned() {
                    if oldest != name {
                        map.remove(&oldest);
                    }
                }
            }
        }
        if let Some(reg) = &self.dns {
            reg.insert(&name, ip).await;
        }
    }

    /// 解析别名：本地别名表 → 学到的别名 → 向服务器按名查询（房间内）。
    async fn resolve_name(&self, name: &str) -> Option<String> {
        let name = name.trim().to_lowercase();
        if name.is_empty() {
            return None;
        }
        // 本地别名（用户显式配置，最高优先）
        if let Some(ip) = self.local_aliases.lock().await.get(&name) {
            return Some(ip.clone());
        }
        // 已学到的别名：TTL 内命中；过期则淘汰并重新向服务器查询（防止恶意成员投毒条目的粘性劫持）
        {
            const LEARNED_TTL: std::time::Duration = std::time::Duration::from_secs(300);
            let mut map = self.learned_aliases.lock().await;
            if let Some((ip, at)) = map.get(&name) {
                if at.elapsed() < LEARNED_TTL {
                    return Some(ip.clone());
                } else {
                    map.remove(&name);
                }
            }
        }
        // 服务器按名查询（自动建立会话并缓存）
        self.query_by_name(&name).await
    }

    /// 构造注册到 DNS 应答器的解析器闭包（守护进程模式下启用）。
    fn make_resolver(&self) -> NameResolver {
        let outbox = self.clone();
        Arc::new(move |name: String| {
            let outbox = outbox.clone();
            Box::pin(async move { outbox.resolve_name(&name).await })
        })
    }

    async fn get_or_create_session(
        &self,
        pk: RawKey,
        ip: String,
        shared: RawKey,
        endpoint: Option<SocketAddr>,
    ) -> Arc<Mutex<PeerSession>> {
        let mut peers = self.peers.lock().await;
        if let Some(s) = peers.get(&pk) {
            s.clone()
        } else {
            let kp = crypto::generate_keypair();
            let salt = random_salt();
            let s = Arc::new(Mutex::new(PeerSession::new(
                pk,
                ip,
                shared,
                endpoint,
                SessionKey::new(kp.private),
                kp.public,
                salt,
            )));
            peers.insert(pk, s.clone());
            s
        }
    }

    /// 为对端启动 UDP 打洞任务：先直连，超时/错误超限则降级中继；打洞禁用则直接中继。
    fn spawn_punch(&self, pk: RawKey) {
        let this = self.clone();
        tokio::spawn(async move {
            let Some(session) = this.peers.lock().await.get(&pk).cloned() else {
                return;
            };
            if !this.hole_punch.enabled {
                {
                    let mut s = session.lock().await;
                    s.transport = Transport::Relay;
                }
                this.log
                    .info(format!("UDP 打洞已禁用，对端 {} 直接走中继", B64.encode(pk)));
                // 立即发一条中继 HELLO，完成 rk 握手（数据面 PFS）
                if let Some(hello) = this.build_hello_ct(&session).await {
                    this.relay_send(pk, &hello).await;
                }
                return;
            }
            let start = Instant::now();
            loop {
                sleep(Duration::from_millis(this.hole_punch.interval_ms)).await;
                let (transport, endpoint, attempts, error_count) = {
                    let s = session.lock().await;
                    (s.transport, s.endpoint, s.attempts, s.error_count)
                };
                match transport {
                    Transport::Direct | Transport::Relay => break,
                    Transport::Punching => {}
                }
                let timed_out = start.elapsed() >= Duration::from_millis(this.hole_punch.timeout_ms);
                if attempts >= this.hole_punch.max_retries
                    || error_count >= this.hole_punch.max_errors
                    || timed_out
                {
                    session.lock().await.transport = Transport::Relay;
                    this.log.info(format!("打洞失败，对端 {} 降级为中继", B64.encode(pk)));
                    break;
                }
                if let Some(ep) = endpoint {
                    if let Some(hello) = this.build_hello_ct(&session).await {
                        let _ = this.main_sock.send_to(&hello, ep).await;
                        // 错误探测：连上对端探测端口，若收到 ICMP 错误则计一次
                        if error_probe(ep).await {
                            session.lock().await.error_count += 1;
                        }
                        // 同时走一条中继 Hello，保证对端已建立本机会话
                        let frame = frame_relay(&pk, &this.local_pub, &hello);
                        let _ = this.main_sock.send_to(&frame, this.relay_addr).await;
                    }
                }
                session.lock().await.attempts += 1;
            }
        });
    }

    /// 构造 HELLO 帧密文：`rk_pub ‖ salt ‖ 本机 IP`，用当前密钥加密（握手前为静态 ECDH 密钥）。
    async fn build_hello_ct(&self, session: &Arc<Mutex<PeerSession>>) -> Option<Vec<u8>> {
        let s = session.lock().await;
        let rk_pub = s.rk_pub?;
        let salt = s.my_salt?;
        let payload = frame_hello_payload(&rk_pub, &salt, self.local_ip.as_bytes());
        let key = *s.current_key();
        Some(crypto::encrypt(
            &key,
            &frame_tunnel_packet(TUNNEL_HELLO, s.epoch, 0, &payload),
        ))
    }

    /// 数据面路由密钥轮换（PFS）：仅由公钥较大的主动方发起，避免双方并发轮换的竞态。
    ///
    /// 轮换本机 rk，用**旧**会话密钥加密 REKEY 帧返回；调用方须在释放会话锁后发送该帧。
    async fn maybe_rekey(&self, session: &Arc<Mutex<PeerSession>>) -> Option<Vec<u8>> {
        let mut s = session.lock().await;
        if !s.established() || self.local_pub <= s.public_key {
            return None;
        }
        let peer_rk = *s.peer_rk_pub.as_ref()?;
        let peer_salt = s.peer_salt.unwrap_or([0u8; 12]);
        let kp = crypto::generate_keypair();
        let new_salt = random_salt();
        let final_salt = xor_salt(new_salt, peer_salt);
        let new_key = crypto::derive_peer_key(
            &self.local_priv,
            &s.public_key,
            &kp.private,
            &peer_rk,
            &final_salt,
        );
        let old_key = *s.current_key();
        let payload = frame_rekey_payload(&kp.public, &new_salt);
        let ct = crypto::encrypt(&old_key, &frame_tunnel_packet(TUNNEL_REKEY, s.epoch, 0, &payload));
        s.rk_priv = Some(SessionKey::new(kp.private));
        s.rk_pub = Some(kp.public);
        s.my_salt = Some(new_salt);
        s.peer_key = Some(SessionKey::new(new_key));
        s.epoch += 1;
        // send_seq 跨 rekey 不重置：可靠传输用单调递增的 seq 做乱序缓冲与累计确认，
        // 仅 epoch 负责密钥选择（防重放靠「seq 单调 + 旧 epoch 解不开」双保险）。
        s.last_rekey = Instant::now();
        Some(ct)
    }

    async fn send_data(&self, session: Arc<Mutex<PeerSession>>, payload: &[u8]) {
        let pk = session.lock().await.public_key;
        // 条件判定：对端超过阈值无任何来包（重启/断链）时，主动重新查询其坐标，
        // 触发服务端 NOTIFY 让对方重建会话——修复「对端重启后数据静默丢失」的死锁。
        // 带最小间隔节流（inflight 去重 + last_requery 时间窗），避免通知风暴。
        {
            let (ip, stale, can_requery) = {
                let s = session.lock().await;
                let requery_ok = s
                    .last_requery
                    .map(|t| t.elapsed() >= Duration::from_secs(RE_QUERY_MIN_INTERVAL_SECS))
                    .unwrap_or(true);
                (
                    s.ip.clone(),
                    s.last_seen.elapsed() > Duration::from_secs(RE_QUERY_STALE_SECS),
                    requery_ok,
                )
            };
            if stale && can_requery && !ip.is_empty() {
                {
                    let mut s = session.lock().await;
                    s.last_requery = Some(Instant::now());
                }
                let outbox = self.clone();
                tokio::spawn(async move {
                    if let Some(s2) = outbox.query_peer(&ip).await {
                        outbox
                            .log
                            .info(format!("对端 {ip} 长时间无响应，已重新查询其坐标"));
                        let _ = s2;
                    }
                });
            }
        }
        // 按包数触发自动 rekey（主动方）
        {
            let mut s = session.lock().await;
            s.sent_pkts += 1;
            if self.rekey_every_pkts > 0 && s.sent_pkts % self.rekey_every_pkts == 0 {
                drop(s);
                if let Some(ct) = self.maybe_rekey(&session).await {
                    self.transport_send(pk, &ct).await;
                }
            }
        }
        let buf = {
            let mut s = session.lock().await;
            if !s.established() {
                // 握手未完成：缓冲数据，等待对端 HELLO 完成后按序发送
                if s.pending.len() >= PENDING_CAP {
                    s.pending.pop_front();
                }
                s.pending.push_back(payload.to_vec());
                return;
            }
            s.send_seq += 1;
            let seq = s.send_seq;
            let epoch = s.epoch;
            // 可靠发送窗口：未确认前保留明文，供超时重传（断了就重传直至对端 ACK）。
            // 窗口打满说明对端长时间未确认（可能失联/重启），此时丢弃新包并告警——
            // 既避免内存无限膨胀，又由 requery/重连恢复链路后继续重传已入窗数据。
            if s.send_unacked.len() >= RELIABLE_WINDOW {
                self.log.warn(format!(
                    "对端 {} 可靠发送窗口已满（{RELIABLE_WINDOW}），丢弃新包",
                    B64.encode(pk)[..16].to_string()
                ));
                return;
            }
            s.send_unacked.insert(seq, (Instant::now(), 0, payload.to_vec()));
            let frame = frame_tunnel_packet(TUNNEL_DATA, epoch, seq, payload);
            let nonce = data_nonce(epoch, seq);
            // 就地加密到复用缓冲（encrypt_with_nonce_into）：复用容量避免每包一次堆分配。
            let mut buf = self.send_buf.lock().await;
            crypto::encrypt_with_nonce_into(s.current_key(), &nonce, &frame, &mut buf);
            buf
        };
        // 缓冲在传输（send_to，可能 await）期间保持持锁；send_data 是单连接数据面唯一
        // 写者，短锁且不跨包借用，正确性不受影响。
        self.transport_send(pk, &buf).await;
    }

    async fn transport_send(&self, pk: RawKey, ct: &[u8]) {
        let (transport, endpoint) = {
            let peers = self.peers.lock().await;
            match peers.get(&pk) {
                Some(s) => {
                    let s = s.lock().await;
                    (s.transport, s.endpoint)
                }
                None => (Transport::Relay, None),
            }
        };
        match transport {
            Transport::Direct if !self.hole_punch.enabled => {
                // 防御性判定：打洞禁用时即使会话被标记直连也走中继
                self.relay_send(pk, ct).await;
            }
            Transport::Direct => {
                if let Some(ep) = endpoint {
                    // 直连存活检测：超过阈值未收到对端直连数据则切中继兜底（修复直连黑洞）
                    let stale = {
                        let peers = self.peers.lock().await;
                        match peers.get(&pk) {
                            Some(s) => {
                                let s = s.lock().await;
                                s.last_direct
                                    .map(|t| t.elapsed() >= Duration::from_secs(DIRECT_STALE_SECS))
                                    .unwrap_or(true)
                            }
                            None => true,
                        }
                    };
                    if stale {
                        {
                            let peers = self.peers.lock().await;
                            if let Some(s) = peers.get(&pk) {
                                s.lock().await.transport = Transport::Relay;
                            }
                        }
                        self.relay_send(pk, ct).await;
                    } else if self.main_sock.send_to(ct, ep).await.is_ok() {
                        self.bump_tx(&pk, ct.len() as u64).await;
                    }
                } else {
                    self.relay_send(pk, ct).await;
                }
            }
            Transport::Punching => {
                // 打洞尚未确认：数据只走中继，避免「直连+中继」双发造成 DUP! 重复包。
                // 打洞探测由 spawn_punch 单独发 HELLO 完成；对端直连包到达后传输方式
                // 自然切换为直连，此后再单走直连。
                self.relay_send(pk, ct).await;
            }
            Transport::Relay => {
                self.relay_send(pk, ct).await;
            }
        }
    }

    async fn relay_send(&self, pk: RawKey, ct: &[u8]) {
        // P1-7：中继头部一律使用短期路由密钥 rk（目标/来源），不暴露长期身份 ik_x。
        // 对端 rk 经 QUERY 响应 / NOTIFY / HELLO 学到；尚未学到时（首次联系）回退
        // ik_x 头部（服务端转发后对端回 HELLO 携带其 rk，此后即切换为 rk）。
        let peer_rk = {
            let peers = self.peers.lock().await;
            match peers.get(&pk) {
                Some(s) => {
                    let s = s.lock().await;
                    // 对端长时间无来包（重启/断链后 rk 已失效）：回退 ik_x 头部，
                    // 让服务端按 ik_x 路由到对端当前入口，触发对端重建（回 HELLO）。
                    // 对端恢复来包后 last_seen 刷新，本函数切回 rk。
                    // 阈值与 HELLO keepalive 同量级（relay_recover_stale），正常空闲/单向
                    // 流量下不会误触发，确保 rk 中继头成为常态（P1-7 隐私）。
                    if s.last_seen.elapsed() > self.relay_recover_stale {
                        None
                    } else {
                        s.peer_relay_rk
                    }
                }
                None => None,
            }
        };
        let frame = match peer_rk {
            Some(dest_rk) => frame_relay_rk(&dest_rk, &self.relay_rk, ct),
            None => frame_relay(&pk, &self.local_pub, ct),
        };
        if self.main_sock.send_to(&frame, self.relay_addr).await.is_ok() {
            self.bump_tx(&pk, ct.len() as u64).await;
        }
    }

    /// 向对端发送累计 ACK：`ack` 为本端已连续收到的最大 seq。ACK 用随机 nonce 加密
    /// （与 HELLO/REKEY 相同，无确定性 nonce 冲突），是尽力而为的确认——丢失后由对端
    /// 重传数据再次触发。帧头 seq 恒为 0，接收端按帧类型 TUNNEL_ACK 识别，不走数据去重。
    async fn send_ack(&self, session: &Arc<Mutex<PeerSession>>, ack: u64) {
        let (pk, ct) = {
            let s = session.lock().await;
            if !s.established() {
                return;
            }
            let payload = ack_payload(ack);
            let frame = frame_tunnel_packet(TUNNEL_ACK, s.epoch, 0, &payload);
            let key = *s.current_key();
            (s.public_key, crypto::encrypt(&key, &frame))
        };
        self.transport_send(pk, &ct).await;
    }

    /// 处理对端累计 ACK：移除发送窗口内所有 `seq <= ack` 的未确认包。幂等：重复/重放的
    /// 旧 ACK 只会移除已移除项，无害。任何合法 ACK 都证明对端存活，刷新 last_seen
    /// （供 requery/ik_x 回退判定使用）。
    async fn handle_ack(&self, session: &Arc<Mutex<PeerSession>>, ack: u64) {
        let mut s = session.lock().await;
        if !s.established() {
            return;
        }
        s.send_unacked.retain(|k, _| *k > ack);
        s.last_seen = Instant::now();
    }

    /// 可靠传输重传：扫描所有对端的可靠发送窗口，对「入窗超过 RETRANSMIT_TIMEOUT 仍未
    /// 被 ACK」的包用**当前** epoch/密钥重新加密（seq 不变，接收端按 seq 去重）并重发。
    /// 重传次数达上限则暂停该包（避免对永久失联对端无限刷带宽），数据仍保留在窗口内，
    /// 待重连恢复（HELLO 重建）时由 `handle_hello` 重置计时后继续重传直至确认。
    async fn retransmit(&self) {
        let peers: Vec<RawKey> = self.peers.lock().await.keys().copied().collect();
        for pk in peers {
            // 需重传的 (seq, payload)：入窗超时且未达重传上限
            let expired: Vec<(u64, Vec<u8>)> = {
                let s = self.peers.lock().await;
                let Some(session) = s.get(&pk).cloned() else { continue };
                let guard = session.lock().await;
                guard
                    .send_unacked
                    .iter()
                    .filter_map(|(seq, (t, retries, payload))| {
                        if *retries >= MAX_RETRIES {
                            return None;
                        }
                        if t.elapsed() < Duration::from_millis(RETRANSMIT_TIMEOUT_MS) {
                            return None;
                        }
                        Some((*seq, payload.clone()))
                    })
                    .collect()
            };
            if expired.is_empty() {
                continue;
            }
            let session = {
                let s = self.peers.lock().await;
                s.get(&pk).cloned()
            };
            let Some(session) = session else { continue };
            for (seq, payload) in expired {
                let ct = {
                    let s = session.lock().await;
                    if !s.established() {
                        continue;
                    }
                    let frame = frame_tunnel_packet(TUNNEL_DATA, s.epoch, seq, &payload);
                    let nonce = data_nonce(s.epoch, seq);
                    let key = *s.current_key();
                    crypto::encrypt_with_nonce(&key, &nonce, &frame)
                };
                // 递增该包重传计数（入窗超时重发后即重新计时）
                if let Some(entry) = session.lock().await.send_unacked.get_mut(&seq) {
                    entry.0 = Instant::now();
                    entry.1 += 1;
                }
                self.transport_send(pk, &ct).await;
            }
        }
    }

    async fn bump_tx(&self, pk: &RawKey, n: u64) {
        self.state.tx_bytes.fetch_add(n, Ordering::Relaxed);
        let peers = self.peers.lock().await;
        if let Some(s) = peers.get(pk) {
            s.lock().await.tx_bytes += n;
        }
    }

    /// P1-7：把中继帧头部的对端路由密钥 rk 解析回对端 ik_x（按 peer_relay_rk 匹配）。
    ///
    /// O(1)：查维护好的 rk→ik_x 反向索引，不再每包遍历全部对端。
    async fn resolve_rk_src(&self, src_rk: &RawKey) -> Option<RawKey> {
        self.rk_index.lock().await.get(src_rk).copied()
    }
}

/// 单条连接的任务主体。
pub struct Conn {
    pub state: Arc<ConnectionState>,
    pub peers: Arc<Mutex<HashMap<RawKey, Arc<Mutex<PeerSession>>>>>,
    outbox: Outbox,
    server: ServerEntry,
    vmnic: VmNicConfig,
    server_pub: RawKey,
    heartbeat: Duration,
    quit: watch::Receiver<bool>,
    tun: Option<TunDevice>,
    /// 测试专用：为 true 时跳过 TUN 创建（数据面走注入/输出通道）。
    pub skip_tun: bool,
    pub inject_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub tun_sink: Option<mpsc::Sender<Vec<u8>>>,
    /// 连续心跳发送失败次数（服务器失联检测）。
    failed_heartbeats: u32,
    /// 内嵌 DNS 应答器注册表（守护进程模式下由 ConnManager 注入；JNI/测试为 None）。
    pub dns: Option<Arc<DnsRegistry>>,
    /// 本连接在 DNS 注册表上的解析器 id（退出时注销）。
    dns_resolver_id: Option<u64>,
    /// 配置文件路径（守护进程注入）：心跳时重读 aliases，使 `--alias` 修改即时生效。
    pub config_path: Option<PathBuf>,
}

/// 连接退出原因（供自动重连判定）。
#[derive(Debug)]
pub enum ConnExit {
    /// 收到退出信号（手动断开/守护进程停止），不重连。
    Stopped,
    /// 连接异常失败（认证失败/服务器不可达等）。守护进程按 `reconnect_secs` 自动重连。
    Error(String),
}

impl Conn {
    /// 从配置创建连接任务。数据面注入/输出通道供测试使用。
    pub async fn new(
        cfg: &ClientConfig,
        conn: &ConnectionEntry,
        quit: watch::Receiver<bool>,
        log: Logger,
    ) -> Result<(Conn, ConnectionHandle), String> {
        let server = cfg
            .find_server(&conn.server)
            .cloned()
            .ok_or_else(|| format!("服务器 {} 未配置", conn.server))?;
        let vmnic = cfg
            .find_vmnic(&conn.vm_nic)
            .cloned()
            .ok_or_else(|| format!("虚拟网卡 {} 未配置", conn.vm_nic))?;
        let local_priv = cfg.private_key()?;
        let local_pub = cfg.public_key()?;
        let server_addr: SocketAddr = server
            .endpoint
            .parse()
            .map_err(|e| format!("服务器地址 {} 解析失败: {e}", server.endpoint))?;
        let relay_addr: SocketAddr = if server.relay.enabled && !server.relay.endpoint.is_empty() {
            match server.relay.endpoint.parse() {
                Ok(a) => a,
                // 中继端点配置不合法时降级为服务器自身，避免整条连接失败
                Err(e) => {
                    log.warn(format!(
                        "中继地址 {} 解析失败（{e}），降级为使用服务器自身 {}",
                        server.relay.endpoint, server_addr
                    ));
                    server_addr
                }
            }
        } else {
            server_addr
        };

        let state = Arc::new(ConnectionState::new(conn.server.clone(), conn.vm_nic.clone()));
        let peers: Arc<Mutex<HashMap<RawKey, Arc<Mutex<PeerSession>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        // 加大 UDP 收发缓冲：默认值（Windows 仅 ~8KB）在突发中继/批量转发时会导致内核丢包。
        let std_sock = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("绑定 UDP 套接字失败: {e}"))?;
        enlarge_udp_buffers(&std_sock, 4 * 1024 * 1024);
        std_sock
            .set_nonblocking(true)
            .map_err(|e| format!("设置非阻塞失败: {e}"))?;
        let main_sock = Arc::new(
            tokio::net::UdpSocket::from_std(std_sock)
                .map_err(|e| format!("转换套接字失败: {e}"))?,
        );

        let heartbeat = Duration::from_secs(cfg.heartbeat_sec.max(5));
        let outbox = Outbox {
            peers: peers.clone(),
            ip_index: Arc::new(Mutex::new(HashMap::new())),
            addr_index: Arc::new(Mutex::new(HashMap::new())),
            rk_index: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashSet::new())),
            main_sock: main_sock.clone(),
            server_addr,
            relay_addr,
            server_shared: [0u8; 32],
            local_pub,
            local_priv,
            local_ip: vmnic.ip.clone(),
            hole_punch: cfg.hole_punch.clone(),
            rekey_every_pkts: cfg.rekey_every_pkts,
            rekey_every_secs: cfg.rekey_every_secs,
            relay_recover_stale: heartbeat * 2,
            state: state.clone(),
            session_sk: Arc::new(Mutex::new(None)),
            session_pub: Arc::new(Mutex::new(None)),
            session_seq: Arc::new(AtomicU64::new(0)),
            relay_rk: crypto::generate_keypair().public,
            local_aliases: Arc::new(Mutex::new(cfg.aliases.clone())),
            learned_aliases: Arc::new(Mutex::new(HashMap::new())),
            dns: None,
            log: log.clone(),
            send_buf: Arc::new(Mutex::new(Vec::new())),
        };

        let conn = Conn {
            state: state.clone(),
            peers: peers.clone(),
            outbox,
            server,
            vmnic,
            server_pub: [0u8; 32],
            heartbeat,
            quit,
            tun: None,
            skip_tun: false,
            inject_rx: None,
            tun_sink: None,
            failed_heartbeats: 0,
            dns: None,
            dns_resolver_id: None,
            config_path: None,
        };

        let handle = ConnectionHandle { state, peers };
        Ok((conn, handle))
    }

    /// 注入 DNS 注册表（守护进程模式下由 ConnManager 调用；JNI/测试不调用）。
    pub fn set_dns(&mut self, dns: Option<Arc<DnsRegistry>>) {
        self.dns = dns.clone();
        self.outbox.dns = dns;
    }

    /// 本机自报别名：本地别名表中 IP 与本机虚拟 IP 一致的那条（如 computer → 本机 IP）。
    async fn self_alias(&self) -> Option<String> {
        let map = self.outbox.local_aliases.lock().await;
        map.iter()
            .find(|(_, ip)| **ip == self.outbox.local_ip)
            .map(|(name, _)| name.clone())
    }

    /// 注册 DNS 解析器（守护进程模式下启用）。
    async fn register_dns(&mut self) {
        if let Some(reg) = &self.dns {
            self.dns_resolver_id = Some(reg.register(self.outbox.make_resolver()).await);
            self.log().info("已注册到内嵌 DNS 应答器（解析网格别名）");
        }
    }

    /// 注销 DNS 解析器。
    async fn unregister_dns(&mut self) {
        if let Some(reg) = &self.dns {
            if let Some(id) = self.dns_resolver_id.take() {
                reg.unregister(id).await;
            }
        }
    }

    /// 主流程。返回 [ConnExit]：手动停止 = Stopped，异常失败 = Error（供自动重连判定）。
    pub async fn run(mut self) -> ConnExit {
        let server_name = self.state.server.clone();
        if let Err(e) = self.ensure_server_pubkey().await {
            self.state.set_error(e.clone());
            self.log().error(format!("连接 {server_name} 初始化失败: {e}"));
            return ConnExit::Error(e);
        }
        if let Err(e) = self.auth_and_register().await {
            self.state.set_error(e.clone());
            self.log().error(format!("连接 {server_name} 认证/注册失败: {e}"));
            return ConnExit::Error(e);
        }
        if self.skip_tun {
            self.log().warn("跳过虚拟网卡创建（测试模式，数据面走注入/输出通道）");
        } else {
            match TunDevice::create(&self.vmnic) {
                Ok(dev) => {
                    self.tun = Some(dev);
                    self.log().info(format!(
                        "虚拟网卡 {} ({}) 已就绪",
                        self.vmnic.name, self.vmnic.ip
                    ));
                }
                Err(e) => {
                    self.log().warn(format!(
                        "创建虚拟网卡 {} 失败，数据面不可用（仅信令/中继可测试）: {e}",
                        self.vmnic.name
                    ));
                }
            }
        }
        self.register_dns().await;
        self.state.set_status("已连接");
        self.log().info(format!(
            "已连接服务器 {}，虚拟 IP {}",
            self.server.name, self.outbox.local_ip
        ));

        let sock = self.outbox.main_sock.clone();
        let mut quit = self.quit.clone();
        let mut heartbeat = tokio::time::interval(self.heartbeat);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut keepalive = tokio::time::interval(self.heartbeat);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut retransmit = tokio::time::interval(Duration::from_millis(RETRANSMIT_INTERVAL_MS));
        retransmit.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = vec![0u8; 65536];
        let mut tun_buf = vec![0u8; self.vmnic.mtu + 64];

        loop {
            tokio::select! {
                _ = quit.changed() => {
                    self.log().info(format!("连接 {} 已断开", self.state.server));
                    break;
                }
                r = sock.recv_from(&mut buf) => {
                    if let Ok((len, src)) = r {
                        let pkt = buf[..len].to_vec();
                        self.handle_udp(&pkt, src, self.tun.as_ref()).await;
                    }
                }
                r = async {
                    match self.tun.as_ref() {
                        Some(t) => t.recv(&mut tun_buf).await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Ok(n) = r {
                        let pkt = tun_buf[..n].to_vec();
                        self.route_forward(pkt).await;
                    }
                }
                r = async {
                    match &mut self.inject_rx {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(pkt) = r {
                        self.route_forward(pkt).await;
                    }
                }
                _ = heartbeat.tick() => {
                    // 条件判定：心跳发送失败累计达到阈值即标记服务器失联；恢复后自动清除
                    if self.heartbeat().await.is_err() {
                        self.failed_heartbeats += 1;
                        if self.failed_heartbeats >= 3 {
                            self.state.set_status("服务器失联");
                            self.log().warn(format!(
                                "连续 {} 次心跳发送失败，服务器可能不可达",
                                self.failed_heartbeats
                            ));
                        }
                    } else if self.failed_heartbeats > 0 {
                        self.failed_heartbeats = 0;
                        self.state.set_status("已连接");
                        self.log().info("服务器心跳恢复");
                    }
                }
                _ = keepalive.tick() => {
                    self.relay_keepalive().await;
                }
                _ = retransmit.tick() => {
                    // 可靠传输：重传未确认的超时数据包（断了就重传直至对端 ACK）
                    self.outbox.retransmit().await;
                }
            }
        }
        self.unregister_dns().await;
        let body = RegisterBody {
            ip: self.outbox.local_ip.clone(),
            relay_rk: Some(B64.encode(self.outbox.relay_rk)),
            token: self.server.token.clone(),
            alias: self.self_alias().await,
        };
        let pt = encode_register(&body);
        if let Ok(pt) = pt {
            let _ = self.outbox.send_signaling(MSG_BYE, &pt).await;
        }
        ConnExit::Stopped
    }

    fn log(&self) -> &Logger {
        &self.outbox.log
    }

    /// TOFU / 认证预备：向服务器索取 root 签名的 ServerInfo（KEYQUERY → MSG_SERVERINFO），
    /// 校验本机已加入该网格（固定了 root 且持有设备证书），并把服务器公钥纳入比对。
    ///
    /// 服务器公钥不一致直接拒绝（防中间人/密钥轮换未登记）；未加入网格时提示 --join。
    /// 虚拟 IP 不在本阶段解析——mesh 模式下由 AUTH_RESP 下发（见 auth_handshake）。
    async fn ensure_server_pubkey(&mut self) -> Result<(), String> {
        let info = fetch_server_key_info(
            self.outbox.server_addr,
            &self.outbox.local_pub,
            &self.log(),
        )
        .await?;
        let received = info.pubkey;
        match &self.server.public_key {
            Some(stored) => {
                let stored_raw = crypto::parse_public_key(stored)?;
                if received != stored_raw {
                    self.state.set_status("服务器公钥不一致");
                    return Err(format!(
                        "服务器 {} 的公钥与本地已保存的公钥不一致（服务器可能已更换密钥，或存在中间人攻击）。\
                         请核实后更新 client.json 中该服务器的 public_key，或重新 --join 完成信任确认",
                        self.server.name
                    ));
                }
            }
            None => {
                return Err(format!(
                    "服务器 {} 的公钥尚未保存。请先执行 linkmesh-client --join \"{}\" \"{}\" --code LMJ-... 加入网格",
                    self.server.name, self.server.name, self.vmnic.name
                ));
            }
        }
        // mesh 模式：必须已加入（有证书），且本地固定的 root 与服务器一致
        if self.server.mesh_root_pub.is_none() {
            return Err(format!(
                "服务器 {} 未加入网格。请先执行 linkmesh-client --join \"{}\" \"{}\" --code LMJ-... 加入网格",
                self.server.name, self.server.name, self.vmnic.name
            ));
        }
        if self.server.device_cert.is_none() {
            return Err(format!(
                "服务器 {} 启用了网格认证但本机尚未加入。请先执行 linkmesh-client --join \"{}\" \"{}\" --code LMJ-...",
                self.server.name, self.server.name, self.vmnic.name
            ));
        }
        // 证书有效期检查（过期则拒绝）
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cert = self.server.device_cert.as_ref().unwrap();
        if now < cert.valid_from || now > cert.not_after {
            return Err("设备证书已过期，请重新 --join".into());
        }
        self.server_pub = received;
        self.outbox.server_shared = crypto::shared_secret(&self.outbox.local_priv, &received);
        Ok(())
    }

    /// mesh 模式：AUTH 握手 → 建立会话密钥 SK → 会话期注册。
    async fn auth_and_register(&mut self) -> Result<(), String> {
        self.auth_handshake().await?;
        self.log().info("AUTH 握手成功，会话密钥已建立");
        self.register_and_wait().await
    }

    /// MSG_AUTH：发送设备证书 + 客户端临时公钥 → 接收 AUTH_RESP → 派生 3-DH 会话密钥 SK。
    async fn auth_handshake(&mut self) -> Result<(), String> {
        let cert = self
            .server
            .device_cert
            .clone()
            .ok_or("未加入网格，缺少设备证书")?;
        // 生成客户端临时密钥 ek_c
        let ek_c = crypto::generate_keypair();
        // 随机握手 nonce（12B）
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let body = AuthBody {
            device_id: cert.device_id.clone(),
            cert: cert.clone(),
            ek_c: B64.encode(ek_c.public),
            timestamp,
            nonce: B64.encode(nonce_bytes),
            token: self.server.token.clone(),
        };
        // 握手期帧：静态 ECDH 加密，sender = ik_x
        let pt = encode_auth(&body).map_err(|e| format!("序列化失败: {e}"))?;
        let ct = crypto::encrypt(&self.outbox.server_shared, &pt);
        let frame = frame_signaling(MSG_AUTH, &self.outbox.local_pub, &ct);
        self.outbox
            .main_sock
            .send_to(&frame, self.outbox.server_addr)
            .await
            .map_err(|e| format!("AUTH 发送失败: {e}"))?;

        // 等待 MSG_AUTH_RESP
        let mut buf = vec![0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(5);
        let resp_body = loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            let (len, src) = match tokio::time::timeout(
                remain,
                self.outbox.main_sock.recv_from(&mut buf),
            )
            .await
            {
                Err(_) => return Err("等待 AUTH_RESP 超时".into()),
                Ok(Err(e)) => return Err(format!("接收失败: {e}")),
                Ok(Ok(v)) => v,
            };
            if src != self.outbox.server_addr {
                continue;
            }
            let Ok(hdr) = parse_header(&buf[..len]) else {
                continue;
            };
            if hdr.msg_type == MSG_AUTH_RESP {
                break crypto::decrypt(&self.outbox.server_shared, &buf[HEADER_LEN..len])?;
            }
            if hdr.msg_type == MSG_RESPONSE {
                // 服务端拒绝：解析错误信息
                if let Ok(plain) = crypto::decrypt(&self.outbox.server_shared, &buf[HEADER_LEN..len])
                {
                    if let Ok(resp) = decode_response(&plain) {
                        return Err(resp.error.unwrap_or_else(|| "认证被拒绝".into()));
                    }
                }
            }
        };
        let auth_resp: AuthRespBody = decode_auth_resp(&resp_body)
            .map_err(|e| format!("AUTH_RESP 解析失败: {e}"))?;
        // 校验 ServerInfo 与本地固定 root 一致
        let ek_s = crypto::parse_public_key(&auth_resp.ek_s)?;
        let sk = crypto::derive_session_key_client(
            &ek_c.private,
            &self.outbox.local_priv,
            &self.server_pub,
            &ek_s,
            &nonce_bytes,
        );
        // 保存会话状态：后续信令用 SK + 计数器 nonce
        *self.outbox.session_sk.lock().await = Some(SessionKey::new(sk));
        *self.outbox.session_pub.lock().await = Some(ek_c.public);
        self.outbox.session_seq.store(0, Ordering::SeqCst);
        // 虚拟 IP 生效：mesh 模式下以服务端证书绑定 IP 为准（AUTH_RESP 下发），
        // 与本地占位不一致时自动更新（静态占位 / 空占位均统一处理）。
        if auth_resp.allocated_ip.is_empty() {
            return Err("服务端未分配虚拟 IP（请确认已 --join 加入网格并持有设备证书）".into());
        }
        // 条件判定：分配 IP 必须是合法 IP，防响应损坏/伪造
        if auth_resp.allocated_ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "服务端分配的虚拟 IP {:?} 非法",
                auth_resp.allocated_ip
            ));
        }
        if auth_resp.allocated_ip != self.outbox.local_ip {
            self.log().info(format!(
                "采用服务端分配虚拟 IP {}（证书绑定，覆盖本地占位 {}）",
                auth_resp.allocated_ip, self.outbox.local_ip
            ));
        }
        self.outbox.local_ip = auth_resp.allocated_ip.clone();
        self.vmnic.ip = auth_resp.allocated_ip.clone();
        // 校验 AUTH_RESP 携带的 ServerInfo：root 签名 + 网格根一致性 + CRL 版本防回退。
        // （此前该处为空实现，未做任何校验——攻击者无法伪造 SK，但固根设备必须验证
        //   服务器出示的网格身份，防止被切换到同名异构网格。）
        if let Some(mesh_root_b64) = &self.server.mesh_root_pub {
            let si = &auth_resp.server_info;
            let root_pub = linkmesh_shared::identity::parse_sig_public(mesh_root_b64)?;
            si.verify(&root_pub)
                .map_err(|e| format!("AUTH_RESP ServerInfo 签名校验失败: {e}"))?;
            if si.mesh_root_pub != *mesh_root_b64 {
                return Err("服务器出示的网格根与本地固定根不一致（可能已更换网格或遭中间人）".into());
            }
            // CRL 版本只进不退（防回退降级绕过吊销）
            if let Some(prev) = self.server.crl_version {
                if si.crl_version < prev {
                    return Err(format!(
                        "服务器 CRL 版本回退（{} -> {}），拒绝连接",
                        prev, si.crl_version
                    )
                    .into());
                }
            }
            self.server.crl_version = Some(si.crl_version);
            // 兜底校验：本设备是否已被吊销（服务端已强制拒绝，此处双保险）
            if let Some(cert) = &self.server.device_cert {
                if auth_resp
                    .crl
                    .entries
                    .iter()
                    .any(|e| e.device_id == cert.device_id)
                {
                    return Err("本设备已被吊销，无法连接（请联系管理员重新签发）".into());
                }
            }
        }
        Ok(())
    }

    async fn register_and_wait(&self) -> Result<(), String> {
        let body = RegisterBody {
            ip: self.outbox.local_ip.clone(),
            relay_rk: Some(B64.encode(self.outbox.relay_rk)),
            token: self.server.token.clone(),
            alias: self.self_alias().await,
        };
        let pt = encode_register(&body).map_err(|e| format!("序列化失败: {e}"))?;
        self.outbox.send_signaling(MSG_REGISTER, &pt).await?;
        let resp = self.recv_response(Duration::from_secs(5)).await?;
        if resp.ok {
            Ok(())
        } else {
            Err(resp.error.unwrap_or_else(|| "注册失败".into()))
        }
    }

    /// 心跳：注册刷新 + 数据面 rk 按时间轮换 + 失效会话清理。
    /// 返回 Err 表示心跳发送失败（服务器失联检测用）。
    async fn heartbeat(&self) -> Result<(), String> {
        // 条件判定：重读 client.json 的 aliases，使 `--alias`/`--alias-del` 修改
        // 在下一个心跳周期生效（无需断开重连），并同步到 DNS 注册表。
        if let Some(p) = &self.config_path {
            if let Ok(cfg) = ClientConfig::load(p) {
                {
                    let mut local = self.outbox.local_aliases.lock().await;
                    if *local != cfg.aliases {
                        *local = cfg.aliases.clone();
                        if let Some(reg) = &self.dns {
                            for (name, ip) in &cfg.aliases {
                                reg.insert(name, ip).await;
                            }
                        }
                        self.log().info(format!(
                            "已重载本地别名表（{} 条）",
                            cfg.aliases.len()
                        ));
                    }
                }
            }
        }
        let body = RegisterBody {
            ip: self.outbox.local_ip.clone(),
            relay_rk: Some(B64.encode(self.outbox.relay_rk)),
            token: self.server.token.clone(),
            alias: self.self_alias().await,
        };
        let pt = encode_register(&body).map_err(|e| format!("序列化失败: {e}"))?;
        let send_ok = self.outbox.send_signaling(MSG_REGISTER, &pt).await;
        self.prune_peers().await;
        // 数据面 rk 按时间自动轮换（主动方，PFS）
        if self.outbox.rekey_every_secs > 0 {
            let keys: Vec<RawKey> = self.peers.lock().await.keys().cloned().collect();
            for pk in keys {
                let need = {
                    let peers = self.peers.lock().await;
                    match peers.get(&pk) {
                        Some(s) => {
                            let s = s.lock().await;
                            s.established() && s.last_rekey.elapsed() >= Duration::from_secs(self.outbox.rekey_every_secs)
                        }
                        None => false,
                    }
                };
                if need {
                    let peers = self.peers.lock().await;
                    if let Some(s) = peers.get(&pk).cloned() {
                        drop(peers);
                        if let Some(ct) = self.outbox.maybe_rekey(&s).await {
                            self.outbox.transport_send(pk, &ct).await;
                        }
                    }
                }
            }
        }
        send_ok
    }

    /// 清理失效对端会话（条件判定，防会话表无限膨胀）：
    /// - 握手未完成且超过打洞窗口 ×2 无进展：对端从未应答，删除；
    /// - 已建立但超过 15 分钟无任何流量：对端已下线，删除（后续流量会自动重新发现）。
    async fn prune_peers(&self) {
        let now = Instant::now();
        let unest_timeout =
            Duration::from_millis(self.outbox.hole_punch.timeout_ms.max(5000)) * 2;
        // 先快照各会话状态（async 闭包不允许，用循环）
        let snapshot: Vec<(RawKey, bool, Duration)> = {
            let peers = self.peers.lock().await;
            let mut v = Vec::with_capacity(peers.len());
            for (k, s) in peers.iter() {
                let s = s.lock().await;
                v.push((*k, s.established(), now.saturating_duration_since(s.last_seen)));
            }
            v
        };
        let dead: Vec<RawKey> = snapshot
            .into_iter()
            .filter(|(_, est, idle)| {
                (!est && *idle > unest_timeout) || (*est && *idle > Duration::from_secs(900))
            })
            .map(|(k, _, _)| k)
            .collect();
        for pk in dead {
            let ip = {
                let mut peers = self.peers.lock().await;
                match peers.remove(&pk) {
                    Some(s) => {
                        let s = s.lock().await;
                        // 清理 rk 反向索引（若有）
                        if let Some(rk) = s.peer_relay_rk {
                            let mut rk_idx = self.outbox.rk_index.lock().await;
                            if rk_idx.get(&rk) == Some(&pk) {
                                rk_idx.remove(&rk);
                            }
                        }
                        s.ip.clone()
                    }
                    None => String::new(),
                }
            };
            if !ip.is_empty() {
                let mut idx = self.outbox.ip_index.lock().await;
                if idx.get(&ip) == Some(&pk) {
                    idx.remove(&ip);
                }
            }
            self.outbox.log.info(format!(
                "清理失效对端会话 {}",
                B64.encode(pk)[..16].to_string()
            ));
        }
    }

    /// 周期性地向所有对端发中继 Hello，保持双方会话与服务器路由新鲜（含 rk 握手信息）。
    async fn relay_keepalive(&self) {
        let keys: Vec<RawKey> = self.peers.lock().await.keys().cloned().collect();
        for pk in keys {
            let transport = {
                let peers = self.peers.lock().await;
                match peers.get(&pk) {
                    Some(s) => s.lock().await.transport,
                    None => continue,
                }
            };
            if transport == Transport::Direct {
                continue;
            }
            let peers = self.peers.lock().await;
            let Some(session) = peers.get(&pk).cloned() else {
                continue;
            };
            drop(peers);
            if let Some(hello) = self.outbox.build_hello_ct(&session).await {
                self.outbox.relay_send(pk, &hello).await;
            }
        }
    }

    /// 阻塞读取直到收到下一条 RESPONSE（会话期用 SK + 方向位 nonce 解密）。
    async fn recv_response(&self, timeout: Duration) -> Result<ResponseBody, String> {
        let mut buf = vec![0u8; 65536];
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let remain = deadline.saturating_duration_since(Instant::now());
            let (len, _) = match tokio::time::timeout(
                remain,
                self.outbox.main_sock.recv_from(&mut buf),
            )
            .await
            {
                Err(_) => return Err("等待响应超时".into()),
                Ok(Err(e)) => return Err(format!("接收失败: {e}")),
                Ok(Ok(v)) => v,
            };
            let Ok(hdr) = parse_header(&buf[..len]) else {
                continue;
            };
            if hdr.msg_type == MSG_RESPONSE {
                let sk = self.outbox.session_sk.lock().await.clone();
                let plain = if let Some(sk) = sk {
                    // 会话期：方向位 1，计数器为最近发送序号（窗口内乱序也容错）
                    let seq = self.outbox.session_seq.load(Ordering::SeqCst);
                    match decrypt_session_response(sk.as_raw(), seq, &buf[HEADER_LEN..len]) {
                        Some(p) => p,
                        None => continue,
                    }
                } else {
                    match crypto::decrypt(&self.outbox.server_shared, &buf[HEADER_LEN..len]) {
                        Ok(p) => p,
                        Err(_) => continue,
                    }
                };
                return decode_response(&plain).map_err(|e| format!("响应解析失败: {e}"));
            }
        }
        Err("等待响应超时".into())
    }

    /// 处理来自主套接字的 UDP 封包（信令 / 中继 / 直连数据）。
    async fn handle_udp(&self, pkt: &[u8], src: SocketAddr, tun: Option<&TunDevice>) {
        if let Ok(hdr) = parse_header(pkt) {
            // 来源校验（条件判定）：服务端信令必须来自 server_addr，中继帧必须来自
            // relay_addr（默认即 server_addr）。其余来源的「LM」帧一律丢弃，
            // 防止伪造来源投毒/CPU 消耗（帧内容虽经 AEAD 校验，但头部解析本身是成本）。
            match hdr.msg_type {
                MSG_RELAY | MSG_RELAY_RK | MSG_RELAY_BATCH => {
                    if src != self.outbox.relay_addr {
                        self.outbox
                            .log
                            .warn(format!("忽略来自 {src} 的非中继来源封包（type={}）", hdr.msg_type));
                        return;
                    }
                }
                _ => {
                    if src != self.outbox.server_addr {
                        self.outbox
                            .log
                            .warn(format!("忽略来自 {src} 的非服务器信令封包（type={}）", hdr.msg_type));
                        return;
                    }
                }
            }
            match hdr.msg_type {
                MSG_RELAY => {
                    if let Ok((_dest, src_pub, ct)) = parse_relay(pkt) {
                        self.handle_peer_data(src_pub, ct, false, src, tun).await;
                    }
                }
                MSG_RELAY_RK => {
                    if let Ok((_dest, src_rk, ct)) = parse_relay(pkt) {
                        // 头部是短期路由密钥 rk：解析回对端 ik_x 再走统一处理
                        if let Some(pk) = self.outbox.resolve_rk_src(&src_rk).await {
                            self.handle_peer_data(pk, ct, false, src, tun).await;
                        }
                    }
                }
                MSG_RELAY_BATCH => {
                    if let Ok((_dest, subframes)) = parse_relay_batch(pkt) {
                        for sf in subframes {
                            // 每个子帧 = src(32B) + ciphertext。src 通常是 rk（P1-7），
                            // 首次联系（对端未知本机 rk）时可能是 ik_x——先按 ik_x 直查，
                            // 查不到再按 rk 解析。
                            if sf.len() < 32 {
                                continue;
                            }
                            let mut src_key = [0u8; 32];
                            src_key.copy_from_slice(&sf[..32]);
                            let ct = &sf[32..];
                            let pk = {
                                let peers = self.outbox.peers.lock().await;
                                if peers.contains_key(&src_key) {
                                    Some(src_key)
                                } else {
                                    None
                                }
                            };
                            match pk {
                                Some(pk) => {
                                    self.handle_peer_data(pk, ct, false, src, tun).await;
                                }
                                None => {
                                    if let Some(pk) = self.outbox.resolve_rk_src(&src_key).await {
                                        self.handle_peer_data(pk, ct, false, src, tun).await;
                                    } else {
                                        // 未知来源（ik_x 直查不到 / rk 未登记）：
                                        // 交给 handle_peer_data——它会为合法 ik_x 建立会话并主动回
                                        // HELLO 完成重连握手（对端重启后会话表清空的恢复路径）。
                                        self.handle_peer_data(src_key, ct, false, src, tun).await;
                                    }
                                }
                            }
                        }
                    }
                }
                MSG_RESPONSE => {
                    let sk = self.outbox.session_sk.lock().await.clone();
                    let plain = if let Some(sk) = sk {
                        let seq = self.outbox.session_seq.load(Ordering::SeqCst);
                        decrypt_session_response(sk.as_raw(), seq, &pkt[HEADER_LEN..])
                    } else {
                        crypto::decrypt(&self.outbox.server_shared, &pkt[HEADER_LEN..]).ok()
                    };
                    if let Some(plain) = plain {
                        if let Ok(resp) = decode_response(&plain) {
                            self.handle_server_response(resp).await;
                        }
                    }
                }
                MSG_NOTIFY => {
                    // NOTIFY 目前仍用静态密钥加密（服务端不知对端会话密钥）
                    if let Ok(plain) =
                        crypto::decrypt(&self.outbox.server_shared, &pkt[HEADER_LEN..])
                    {
                        if let Ok(nb) = decode_notify(&plain) {
                            self.handle_notify(nb).await;
                        }
                    }
                }
                MSG_AUTH_RESP => {
                    // AUTH 握手期由 auth_handshake 阻塞式等待处理，此处兜底忽略
                }
                _ => {}
            }
            return;
        }
        // 直连数据：无魔数，源地址应命中已知对端坐标
        let key = self.outbox.addr_index.lock().await.get(&src).copied();
        if let Some(pk) = key {
            self.handle_peer_data(pk, pkt, true, src, tun).await;
        }
    }

    async fn handle_server_response(&self, resp: ResponseBody) {
        let req_key = match &resp.data {
            ResponseData::QueryHit { req, .. } | ResponseData::QueryMiss { req, .. } => req.clone(),
            _ => String::new(),
        };
        let tx = self.outbox.pending.lock().await.remove(&req_key);
        if let Some(tx) = tx {
            let result = match resp.data {
                ResponseData::QueryHit {
                    req: _,
                    ip,
                    public_key,
                    endpoint,
                    relay_rk,
                    alias,
                } => {
                    // 学到别名映射（响应附带 alias → IP），供 DNS 应答器使用
                    if !alias.is_empty() {
                        self.outbox.learn_alias(&alias, &ip).await;
                    }
                    Ok(PeerInfo {
                        public_key,
                        endpoint,
                        relay_rk,
                        alias: if alias.is_empty() { None } else { Some(alias) },
                        ip: Some(ip),
                    })
                }
                _ => Err(resp.error.unwrap_or_else(|| "查询失败".into())),
            };
            let _ = tx.send(result);
        }
    }

    async fn handle_notify(&self, nb: NotifyBody) {
        let Ok(pk) = crypto::parse_public_key(&nb.peer.public_key) else {
            return;
        };
        // 学到通知方的别名（名称 → IP），供 DNS 应答器使用
        if let (Some(alias), Some(ip)) = (&nb.peer.alias, &nb.peer.ip) {
            self.outbox.learn_alias(alias, ip).await;
        }
        let endpoint = nb.peer.endpoint.parse().ok();
        let shared = crypto::shared_secret(&self.outbox.local_priv, &pk);
        let session = self
            .outbox
            .get_or_create_session(pk, String::new(), shared, endpoint)
            .await;
        if let Some(ep) = endpoint {
            let mut s = session.lock().await;
            if s.endpoint.is_none() {
                s.endpoint = Some(ep);
            }
            drop(s);
            self.outbox.addr_index.lock().await.insert(ep, pk);
        }
        // P1-7：记录对端中继路由密钥（仅记录解析成功的合法 rk）
        if let Some(rk_b64) = &nb.peer.relay_rk {
            if let Ok(rk) = crypto::parse_public_key(rk_b64) {
                session.lock().await.peer_relay_rk = Some(rk);
                self.outbox.rk_index.lock().await.insert(rk, pk);
            } else {
                self.outbox.log.warn("NOTIFY 携带的 relay_rk 非法，已忽略");
            }
        }
        self.outbox.spawn_punch(pk);
    }

    /// 处理来自对端的加密隧道数据（直连或中继到达）。
    ///
    /// 解密策略：先试当前数据面密钥（会话密钥或握手期静态密钥），失败再试另一个，
    /// 以兼容「对端已切换密钥而我方尚未收到对应握手帧」的过渡窗口。
    async fn handle_peer_data(
        &self,
        src_pub: RawKey,
        ct: &[u8],
        direct: bool,
        src: SocketAddr,
        tun: Option<&TunDevice>,
    ) {
        let session = {
            let peers = self.peers.lock().await;
            peers.get(&src_pub).cloned()
        };
        let session = match session {
            Some(s) => s,
            None => {
                let shared = crypto::shared_secret(&self.outbox.local_priv, &src_pub);
                let s = self
                    .outbox
                    .get_or_create_session(src_pub, String::new(), shared, None)
                    .await;
                if direct {
                    s.lock().await.endpoint = Some(src);
                    self.outbox.addr_index.lock().await.insert(src, src_pub);
                }
                // 条件判定：陌生对端经中继首次出现（如对方刚重启、丢失了本机会话）——
                // 主动回一条中继 HELLO，携带本机新 rk/盐，让对方重新派生会话密钥。
                // （直连路径由 spawn_punch 负责 HELLO；中继路径对端不知本机 rk，必须主动告知。）
                if !direct {
                    self.outbox
                        .log
                        .info(format!("发现陌生对端 {} 经中继来包，主动回 HELLO", B64.encode(src_pub)[..16].to_string()));
                    if let Some(hello) = self.outbox.build_hello_ct(&s).await {
                        self.outbox.relay_send(src_pub, &hello).await;
                    }
                }
                s
            }
        };

        if direct {
            let mut s = session.lock().await;
            s.endpoint = Some(src);
            s.last_direct = Some(Instant::now());
            // 条件判定：打洞禁用（hole_punch.enabled=false）时禁止进入直连，
            // 保证「关闭打洞 = 全程中继」语义；打洞启用时才允许直连。
            if self.outbox.hole_punch.enabled && s.transport != Transport::Direct {
                s.transport = Transport::Direct;
            }
            s.last_seen = Instant::now();
            drop(s);
            self.outbox.addr_index.lock().await.insert(src, src_pub);
        }

        // 解密：当前密钥优先，失败回退握手期静态密钥
        let plain = {
            let s = session.lock().await;
            let cur = *s.current_key();
            match crypto::decrypt(&cur, ct) {
                Ok(p) => p,
                Err(_) => {
                    let hk = s.handshake_key;
                    if hk != cur {
                        match crypto::decrypt(&hk, ct) {
                            Ok(p) => p,
                            Err(_) => return,
                        }
                    } else {
                        return;
                    }
                }
            }
        };
        let Some((typ, epoch, seq, payload)) = parse_tunnel_packet(&plain) else {
            return;
        };

        if !direct {
            // 经中继到达而对端仍标记直连时的兜底判定（需先解析出帧类型）：
            // - TUNNEL_DATA：对端已在用中继传数据 → 说明直连回程已不可用（如单向 NAT），
            //   立即切中继兜底（不等超时阈值）；
            // - HELLO（打洞/保活的冗余中继副本）：仅当直连数据超过阈值未到时才切，
            //   避免打洞过渡期的冗余 HELLO 把已建立的直连抖动回中继。
            let flip = {
                let s = session.lock().await;
                if s.transport != Transport::Direct {
                    false
                } else if typ == TUNNEL_DATA {
                    true
                } else {
                    s.last_direct
                        .map(|t| t.elapsed() >= Duration::from_secs(DIRECT_STALE_SECS))
                        .unwrap_or(true)
                }
            };
            if flip {
                session.lock().await.transport = Transport::Relay;
            }
        }

        match typ {
            TUNNEL_HELLO => {
                self.handle_hello(&session, src_pub, payload).await;
            }
            TUNNEL_REKEY => {
                self.handle_rekey(&session, epoch, payload).await;
            }
            TUNNEL_ACK => {
                if let Some(ack) = parse_ack_payload(payload) {
                    self.outbox.handle_ack(&session, ack).await;
                }
            }
            TUNNEL_DATA => {
                // 可靠接收：乱序缓冲 + 按序投递 + 累计 ACK。
                // 防重放/防旧密钥：epoch 必须匹配（旧 epoch 解不开，见上）；seq 去重交给
                // 高水位（recv_seq）判定——seq <= recv_seq 的重复/重放直接忽略，仅回 ACK。
                let (delivered, ack) = {
                    let mut s = session.lock().await;
                    if !s.established() || epoch != s.epoch {
                        return;
                    }
                    s.last_seen = Instant::now();
                    if direct {
                        s.last_direct = Some(Instant::now());
                    }
                    let (delivered, new_high) =
                        reorder_deliver(s.recv_seq, &mut s.recv_buf, seq, payload);
                    let bytes: u64 = delivered.iter().map(|p| p.len() as u64).sum();
                    s.rx_bytes += bytes;
                    s.recv_seq = new_high;
                    (delivered, new_high)
                };
                // 在锁外交付（避免持锁 await TUN send）
                for p in &delivered {
                    self.state
                        .rx_bytes
                        .fetch_add(p.len() as u64, Ordering::Relaxed);
                    if let Some(t) = tun {
                        let _ = t.send(p).await;
                    } else if let Some(sink) = &self.tun_sink {
                        let _ = sink.try_send(p.clone());
                    }
                }
                // 无论是否新交付，都回累计 ACK：对端据此移除发送窗口中的已确认包。
                // 重复/重放 DATA 也回 ACK，帮助对端在 ACK 丢失时尽快收敛。
                self.outbox.send_ack(&session, ack).await;
            }
            _ => {}
        }
    }

    /// 处理 HELLO：完成 rk 握手（派生会话密钥）或保活刷新；首次收到时回 HELLO 并冲刷缓冲。
    async fn handle_hello(
        &self,
        session: &Arc<Mutex<PeerSession>>,
        src_pub: RawKey,
        payload: &[u8],
    ) {
        if payload.len() < 44 {
            return;
        }
        let mut peer_rk = [0u8; 32];
        peer_rk.copy_from_slice(&payload[..32]);
        let mut peer_salt = [0u8; 12];
        peer_salt.copy_from_slice(&payload[32..44]);
        let ip = String::from_utf8_lossy(&payload[44..]).to_string();

        let (is_first, reply_hello) = {
            let mut s = session.lock().await;
            // 首次派生会话密钥才算握手完成（会话可能已从查询带 IP 创建，不能用 ip 判空）
            let is_first = s.peer_key.is_none();
            // 派生对端会话密钥：DH(ik)‖DH(rk)，盐 = XOR(双方盐)
            let final_salt = xor_salt(s.my_salt.unwrap_or([0u8; 12]), peer_salt);
            let (rk_priv, _rk_pub) = s.ensure_rk();
            let new_key = crypto::derive_peer_key(
                &self.outbox.local_priv,
                &s.public_key,
                rk_priv.as_raw(),
                &peer_rk,
                &final_salt,
            );
            s.peer_key = Some(SessionKey::new(new_key));
            // 条件判定：对端 rk 变化（重连/换钥）时也必须回 HELLO——
            // 否则已建立会话的对端（B）收到重连方（A）的新 rk 后静默重派生，
            // 而 A 是新会话（无会话密钥）永远等不到 HELLO 应答，握手无法完成。
            let rk_changed = s.peer_rk_pub != Some(peer_rk);
            s.peer_rk_pub = Some(peer_rk);
            s.peer_salt = Some(peer_salt);
            if is_first {
                s.epoch = 0;
                s.recv_seq = 0;
                s.ip = ip.clone();
            }
            // 对端重连/换钥（is_first 或 rk_changed）：恢复链路后重建会话——seq 序号空间
            // 归零重新开始（新会话独立），并把可靠发送窗口按原序重新编号（seq 1..N），
            // 让未确认数据在恢复后按序重传直至对端 ACK（数据不丢，仅延迟）。
            if is_first || rk_changed {
                let window: Vec<Vec<u8>> = s
                    .send_unacked
                    .values()
                    .map(|(_, _, p)| p.clone())
                    .collect();
                s.send_seq = 0;
                s.send_unacked.clear();
                let now = Instant::now();
                let mut seq = 0u64;
                for p in window {
                    seq += 1;
                    s.send_seq = seq;
                    s.send_unacked.insert(seq, (now, 0, p));
                }
            }
            // 任何合法 HELLO 都视为对端存活（保活/重握），刷新 last_seen
            s.last_seen = Instant::now();
            let hello = if is_first || rk_changed {
                // 用握手期静态密钥回 HELLO：对端（重连方）尚无本机会话密钥，须能解密
                let (my_rk, my_salt) = (s.rk_pub, s.my_salt);
                match (my_rk, my_salt) {
                    (Some(rkp), Some(saltp)) => {
                        let payload2 = frame_hello_payload(&rkp, &saltp, self.outbox.local_ip.as_bytes());
                        Some(crypto::encrypt(
                            &s.handshake_key,
                            &frame_tunnel_packet(TUNNEL_HELLO, s.epoch, 0, &payload2),
                        ))
                    }
                    _ => None,
                }
            } else {
                None
            };
            (is_first, hello)
        };
        if !ip.is_empty() {
            // 条件判定：HELLO 载荷中的对端虚拟 IP 必须是合法 IP 才写入索引，
            // 防止伪造/损坏的 HELLO 把垃圾字符串注入 ip_index。
            if ip.parse::<std::net::IpAddr>().is_ok() {
                let mut idx = self.outbox.ip_index.lock().await;
                if bind_ip_ownership(&mut idx, &ip, &src_pub) {
                    // 绑定成功或幂等保留。
                } else {
                    self.outbox.log.warn(format!(
                        "拒绝把虚拟 IP {ip} 绑定到对端 {}（该 IP 已被其他对端占用）",
                        B64.encode(src_pub)[..16].to_string()
                    ));
                }
            } else {
                self.outbox
                    .log
                    .warn(format!("忽略 HELLO 中的非法对端 IP {ip:?}"));
            }
        }
        if let Some(hello) = reply_hello {
            // 条件判定：HELLO 应答在直连模式下「直连 + 中继」双发（HELLO 幂等，无 DUP 问题）。
            // 修复单向直连（如模拟器 NAT、非对称 NAT）下「应答只走直连被吞，
            // 对端永远无法建立会话」的问题；打洞/中继模式则按传输方式单发。
            let transport = { session.lock().await.transport };
            if transport == Transport::Direct {
                self.outbox.relay_send(src_pub, &hello).await;
            }
            self.outbox.transport_send(src_pub, &hello).await;
        }
        if is_first {
            // 握手完成：冲刷握手前缓冲的数据包
            let pending: Vec<Vec<u8>> = {
                let mut s = session.lock().await;
                s.pending.drain(..).collect()
            };
            for p in pending {
                self.outbox.send_data(session.clone(), &p).await;
            }
        }
    }

    /// 处理 REKEY：对端轮换 rk，用其新 rk 派生新会话密钥并推进 epoch。
    ///
    /// 防重放条件：帧头 `epoch` 必须等于当前密钥代数，旧 epoch 的 REKEY 帧一律丢弃
    /// （防止重放旧轮换帧把密钥回滚到已废弃代数）。
    async fn handle_rekey(&self, session: &Arc<Mutex<PeerSession>>, epoch: u32, payload: &[u8]) {
        if payload.len() < 44 {
            return;
        }
        {
            let s = session.lock().await;
            if !s.established() || epoch != s.epoch {
                return;
            }
        }
        let mut new_peer_rk = [0u8; 32];
        new_peer_rk.copy_from_slice(&payload[..32]);
        let mut new_peer_salt = [0u8; 12];
        new_peer_salt.copy_from_slice(&payload[32..44]);
        let mut s = session.lock().await;
        if !s.established() {
            return;
        }
        let Some(rk_priv) = s.rk_priv.as_ref() else {
            return;
        };
        let final_salt = xor_salt(s.my_salt.unwrap_or([0u8; 12]), new_peer_salt);
        let new_key = crypto::derive_peer_key(
            &self.outbox.local_priv,
            &s.public_key,
            rk_priv.as_raw(),
            &new_peer_rk,
            &final_salt,
        );
        s.peer_key = Some(SessionKey::new(new_key));
        s.peer_rk_pub = Some(new_peer_rk);
        s.peer_salt = Some(new_peer_salt);
        s.epoch += 1;
        // recv_seq 跨 rekey 不重置（保持单调高水位），可靠传输的乱序缓冲据此连续投递。
        s.last_rekey = Instant::now();
        self.outbox.log.info(format!(
            "对端 {} 轮换路由密钥，数据面密钥推进至 epoch {}",
            B64.encode(s.public_key)[..16].to_string(),
            s.epoch
        ));
    }

    /// 按目的 IP 转发来自 TUN/注入的 IP 包。
    async fn route_forward(&self, pkt: Vec<u8>) {
        let Some(dst) = extract_dst_ip(&pkt) else {
            return;
        };
        // 本机虚拟子网的定向广播地址（如 10.13.13.255/24）：没有对端，直接丢弃。
        // 条件判定：is_broadcast() 只覆盖 255.255.255.255，定向广播需按掩码计算，
        // 否则 Windows 等系统周期性的广播探测会触发无谓的信令查询。
        let local_subnet_broadcast = {
            let ip = self.outbox.local_ip.parse::<std::net::Ipv4Addr>().ok();
            let mask = self.vmnic.netmask.parse::<std::net::Ipv4Addr>().ok();
            match (ip, mask) {
                (Some(ip), Some(mask)) => {
                    let ip_b = u32::from(ip);
                    let m_b = u32::from(mask);
                    let bc = ip_b | !m_b;
                    Some(std::net::Ipv4Addr::from(bc))
                }
                _ => None,
            }
        };
        // 多播/广播/链路本地地址没有对端，直接丢弃，避免无谓的信令查询
        if dst.is_multicast()
            || dst.is_loopback()
            || matches!(dst, std::net::IpAddr::V4(v4) if v4.is_broadcast())
            || matches!(dst, std::net::IpAddr::V6(v6) if v6.is_unicast_link_local())
            || matches!(dst, std::net::IpAddr::V4(v4) if v4.octets()[0] == 169 && v4.octets()[1] == 254)
            || Some(dst) == local_subnet_broadcast.map(std::net::IpAddr::V4)
        {
            return;
        }
        // 条件判定：发往本机自身虚拟 IP 的包直接丢弃，防止转发回环
        if dst.to_string() == self.outbox.local_ip {
            return;
        }
        let dst = dst.to_string();

        if let Some(pk) = self.outbox.ip_index.lock().await.get(&dst).copied() {
            let peers = self.peers.lock().await;
            if let Some(s) = peers.get(&pk).cloned() {
                drop(peers);
                self.outbox.send_data(s, &pkt).await;
                return;
            }
        }
        // 未知对端：查询会阻塞数秒，必须放到独立任务，避免阻塞主循环收发。
        let outbox = self.outbox.clone();
        tokio::spawn(async move {
            if let Some(session) = outbox.query_peer(&dst).await {
                outbox.send_data(session, &pkt).await;
            }
        });
    }
}

/// 会话期响应解密窗口：服务端响应与请求一一对应（nonce = 请求序号），
/// 但心跳/查询交错时响应可能乱序到达，仅用「最后发送序号」会丢响应；
/// 故用最近 N 个发送序号逐一尝试（AEAD 校验保证不会误解密）。
const SESSION_RESP_WINDOW: u64 = 32;

fn decrypt_session_response(sk: &[u8; 32], last_send_seq: u64, ct: &[u8]) -> Option<Vec<u8>> {
    let lo = last_send_seq.saturating_sub(SESSION_RESP_WINDOW);
    for seq in (lo..=last_send_seq).rev() {
        let nonce = crypto::session_nonce(seq, 1);
        if let Ok(p) = crypto::decrypt_with_nonce(sk, &nonce, ct) {
            return Some(p);
        }
    }
    None
}

/// 加大 UDP 套接字收发缓冲（默认值在 Windows 上仅 ~8KB，突发中继/批量转发会内核丢包）。
pub fn enlarge_udp_buffers(sock: &std::net::UdpSocket, size: usize) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        unsafe {
            let v = size as libc::c_int;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &v as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &v as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        let s = sock.as_raw_socket();
        // WinSock 常量（libc crate 未导出）：SOL_SOCKET=0xffff, SO_RCVBUF=0x1002, SO_SNDBUF=0x1001
        const SOL_SOCKET: libc::c_int = 0xffff;
        const SO_RCVBUF: libc::c_int = 0x1002;
        const SO_SNDBUF: libc::c_int = 0x1001;
        unsafe {
            let v = size as libc::c_int;
            let sock = s as libc::SOCKET;
            libc::setsockopt(
                sock,
                SOL_SOCKET,
                SO_RCVBUF,
                &v as *const _ as *const libc::c_char,
                std::mem::size_of::<libc::c_int>() as libc::c_int,
            );
            libc::setsockopt(
                sock,
                SOL_SOCKET,
                SO_SNDBUF,
                &v as *const _ as *const libc::c_char,
                std::mem::size_of::<libc::c_int>() as libc::c_int,
            );
        }
    }
}

/// 连接管理器：守护进程内动态启动/停止连接，供控制通道调用。
pub struct ConnManager {
    config_path: PathBuf,
    pub handles: Arc<Mutex<HashMap<String, ConnectionHandle>>>,
    pub quitters: Arc<Mutex<HashMap<String, watch::Sender<bool>>>>,
    /// 内嵌 DNS 应答器注册表（守护进程注入；None = 不启用 DNS 别名解析）。
    pub dns: Option<Arc<DnsRegistry>>,
    logger: Logger,
}

impl ConnManager {
    pub fn new(config_path: PathBuf, logger: Logger) -> Self {
        ConnManager {
            config_path,
            handles: Arc::new(Mutex::new(HashMap::new())),
            quitters: Arc::new(Mutex::new(HashMap::new())),
            dns: None,
            logger,
        }
    }

    pub fn handles(&self) -> Arc<Mutex<HashMap<String, ConnectionHandle>>> {
        self.handles.clone()
    }

    /// 启动配置中指定服务器的连接。
    ///
    /// 自动重连：连接异常退出（[ConnExit::Error]）且 `client.json` 的 `reconnect_secs > 0` 时，
    /// 守护进程按该间隔自动重连（与 Android 的「断线自动重连」对齐）；`reconnect_secs = 0`
    /// 表示不自动重连（连接失败后保持断开）。手动断开（--disconnect/--stop）不会重连。
    pub async fn start(&self, server: &str) -> Result<(), String> {
        let server = server.to_string();
        if self.quitters.lock().await.contains_key(&server) {
            return Err(format!("连接 {server} 已在运行"));
        }
        let cfg = ClientConfig::load(&self.config_path)?;
        let conn = cfg
            .find_connection(&server)
            .cloned()
            .ok_or_else(|| format!("连接 {server} 未配置"))?;
        let reconnect_secs = cfg.reconnect_secs;
        let (quit_tx, _) = watch::channel(false);
        // 任务循环持有自己的 quit 接收器；每次重建连接用 subscribe 派生新接收器
        let mut quit_rx = quit_tx.subscribe();
        let (mut conn_task, handle) =
            Conn::new(&cfg, &conn, quit_tx.subscribe(), self.logger.clone()).await?;
        conn_task.config_path = Some(self.config_path.clone());
        conn_task.set_dns(self.dns.clone());
        self.handles
            .lock()
            .await
            .insert(server.clone(), handle);
        // 地图存一份 sender（供 --disconnect 中断），任务内保留原 sender 用于重建连接时 subscribe
        self.quitters
            .lock()
            .await
            .insert(server.clone(), quit_tx.clone());
        self.logger
            .info(format!("启动连接 {server}（自动重连={reconnect_secs} 秒）"));

        let this = Arc::new(ConnManager {
            config_path: self.config_path.clone(),
            handles: self.handles.clone(),
            quitters: self.quitters.clone(),
            dns: self.dns.clone(),
            logger: self.logger.clone(),
        });
        tokio::spawn(async move {
            let mut attempt: u64 = 1;
            let mut running: Option<Conn> = Some(conn_task);
            loop {
                let conn = match running.take() {
                    Some(c) => c,
                    None => break,
                };
                let exit = conn.run().await;
                // 手动断开（quit 已置位）或禁用自动重连 → 退出
                let stopped = *quit_rx.borrow();
                if stopped || reconnect_secs == 0 {
                    break;
                }
                match &exit {
                    ConnExit::Stopped => break,
                    ConnExit::Error(e) => {
                        this.logger.error(format!(
                            "连接 {server} 异常退出（第 {attempt} 次）: {e}"
                        ));
                    }
                }
                attempt += 1;
                this.logger.info(format!(
                    "连接 {server} 将在 {reconnect_secs} 秒后自动重连（第 {attempt} 次）…"
                ));
                // 睡眠期间检测到 quit（手动断开）立即退出
                let sleep = tokio::time::sleep(Duration::from_secs(reconnect_secs));
                tokio::pin!(sleep);
                tokio::select! {
                    _ = sleep.as_mut() => {}
                    _ = quit_rx.changed() => break,
                }
                if *quit_rx.borrow() {
                    break;
                }
                // 重新加载配置（令牌/IP 可能在重连间隙被修改）并重建连接
                let fresh_rx = quit_tx.subscribe();
                match Self::recreate_conn(&this, &server, fresh_rx).await {
                    Some((c, h)) => {
                        let mut c = c;
                        c.config_path = Some(this.config_path.clone());
                        c.set_dns(this.dns.clone());
                        this.handles.lock().await.insert(server.clone(), h);
                        running = Some(c);
                    }
                    None => continue,
                }
            }
            this.handles.lock().await.remove(&server);
            this.quitters.lock().await.remove(&server);
            this.logger.info(format!("连接 {server} 已结束"));
        });
        Ok(())
    }

    /// 重建连接（自动重连用）。失败时记录日志并返回 None。
    async fn recreate_conn(
        this: &ConnManager,
        server: &str,
        quit_rx: watch::Receiver<bool>,
    ) -> Option<(Conn, ConnectionHandle)> {
        match ClientConfig::load(&this.config_path) {
            Ok(cfg) => {
                let conn = match cfg.find_connection(server) {
                    Some(c) => c.clone(),
                    None => {
                        this.logger.error(format!("重连失败：连接 {server} 已从配置移除"));
                        return None;
                    }
                };
                match Conn::new(&cfg, &conn, quit_rx, this.logger.clone()).await {
                    Ok(v) => Some(v),
                    Err(e) => {
                        this.logger.error(format!("重连 {server} 失败: {e}"));
                        None
                    }
                }
            }
            Err(e) => {
                this.logger.error(format!("重连 {server} 加载配置失败: {e}"));
                None
            }
        }
    }

    /// 停止指定服务器的连接（异步结束，稍后自然退出）。
    pub async fn stop(&self, server: &str) -> Result<(), String> {
        let tx = self.quitters.lock().await.remove(server);
        match tx {
            Some(tx) => {
                let _ = tx.send(true);
                self.handles.lock().await.remove(server);
                self.logger.info(format!("停止连接 {server}"));
                Ok(())
            }
            None => Err(format!("连接 {server} 不存在")),
        }
    }

    /// 启动配置中的全部连接。
    pub async fn start_all(&self) {
        let cfg = match ClientConfig::load(&self.config_path) {
            Ok(c) => c,
            Err(e) => {
                self.logger.error(format!("加载配置失败: {e}"));
                return;
            }
        };
        let names: Vec<String> = cfg.connections.iter().map(|c| c.server.clone()).collect();
        for name in names {
            if let Err(e) = self.start(&name).await {
                self.logger.error(format!("启动连接 {name} 失败: {e}"));
            }
        }
    }

    /// 优雅停止全部连接：给每条连接发退出信号，让 Conn 主循环发送 MSG_BYE 再退出。
    pub async fn shutdown_all(&self) {
        let names: Vec<String> = self.quitters.lock().await.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.stop(&name).await {
                self.logger.warn(format!("停止连接 {name} 失败: {e}"));
            }
        }
        // 留出窗口让各 Conn 任务完成 MSG_BYE 发送（避免进程退出时被强杀而漏发）
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// 错误探测：用临时连接套接字向对端端点发包，若收到 ICMP 错误则视为打洞失败信号。
async fn error_probe(endpoint: SocketAddr) -> bool {    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return false;
    };
    if sock.connect(endpoint).await.is_err() {
        return false;
    }
    let _ = sock.send(&[0]).await;
    let mut b = [0u8; 16];
    match tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut b)).await {
        Ok(Ok(_)) => false,
        Ok(Err(e)) => matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
        ),
        Err(_) => false,
    }
}

/// TOFU 握手结果：服务器公钥 + 是否属于网格（mesh 模式）。
#[derive(Debug, Clone)]
pub struct ServerKeyInfo {
    pub pubkey: RawKey,
    /// 服务器是否属于网格（mesh 模式，需 --join 认证）。
    pub mesh: bool,
}

/// TOFU 握手：向服务器索取公钥（兼容入口，仅返回公钥）。
/// 仅接受来自所配置 `server_addr` 的 MSG_SERVERINFO，其余来源一律忽略，防止在途伪造。
/// 前台 `--connect` 与后台连接任务共用此函数。
pub async fn fetch_server_pubkey(
    server_addr: SocketAddr,
    local_pub: &RawKey,
    log: &Logger,
) -> Result<RawKey, String> {
    Ok(fetch_server_key_info(server_addr, local_pub, log).await?.pubkey)
}

/// TOFU 握手：向服务器索取 root 签名的 ServerInfo（KEYQUERY → MSG_SERVERINFO），
/// 取其中服务器 X25519 公钥（server_ik_x）与网格信息。
pub async fn fetch_server_key_info(
    server_addr: SocketAddr,
    local_pub: &RawKey,
    log: &Logger,
) -> Result<ServerKeyInfo, String> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("绑定 UDP 套接字失败: {e}"))?;
    let frame = frame_signaling(MSG_KEYQUERY, local_pub, &[]);
    sock.send_to(&frame, server_addr)
        .await
        .map_err(|e| format!("发送公钥请求失败: {e}"))?;
    log.info("请求服务器信息（ServerInfo）");
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(Instant::now());
        let (len, src) = match tokio::time::timeout(remain, sock.recv_from(&mut buf)).await {
            Err(_) => return Err("等待服务器信息超时".into()),
            Ok(Err(e)) => return Err(format!("接收失败: {e}")),
            Ok(Ok(v)) => v,
        };
        if src != server_addr {
            log.warn(format!("忽略来自 {src} 的疑似伪造响应"));
            continue;
        }
        let Ok(hdr) = parse_header(&buf[..len]) else {
            continue;
        };
        if hdr.msg_type == MSG_SERVERINFO {
            let body: ServerInfoBody = decode_server_info_body(&buf[HEADER_LEN..len])
                .map_err(|e| format!("解析 ServerInfo 失败: {e}"))?;
            log.info(format!(
                "服务器属于网格 {}（CRL v{}，需认证）",
                body.server_info.mesh_id, body.server_info.crl_version
            ));
            let raw = crypto::parse_public_key(&body.server_info.server_ik_x)?;
            return Ok(ServerKeyInfo {
                pubkey: raw,
                mesh: true,
            });
        }
    }
    Err("未收到服务器信息".into())
}

/// 索取 root 签名的 ServerInfo（`--join` 用）。
/// 服务器未初始化网格时返回错误（服务器现在强制 mesh）。
pub async fn fetch_server_info(
    server_addr: SocketAddr,
    local_pub: &RawKey,
    log: &Logger,
) -> Result<linkmesh_shared::cert::ServerInfo, String> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("绑定 UDP 套接字失败: {e}"))?;
    let frame = frame_signaling(MSG_KEYQUERY, local_pub, &[]);
    sock.send_to(&frame, server_addr)
        .await
        .map_err(|e| format!("发送 ServerInfo 请求失败: {e}"))?;
    log.info("请求服务器信息（ServerInfo）");
    let mut buf = vec![0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(Instant::now());
        let (len, src) = match tokio::time::timeout(remain, sock.recv_from(&mut buf)).await {
            Err(_) => return Err("等待 ServerInfo 超时".into()),
            Ok(Err(e)) => return Err(format!("接收失败: {e}")),
            Ok(Ok(v)) => v,
        };
        if src != server_addr {
            log.warn(format!("忽略来自 {src} 的疑似伪造响应"));
            continue;
        }
        let Ok(hdr) = parse_header(&buf[..len]) else {
            continue;
        };
        if hdr.msg_type == MSG_SERVERINFO {
            let body: ServerInfoBody = decode_server_info_body(&buf[HEADER_LEN..len])
                .map_err(|e| format!("解析 ServerInfo 失败: {e}"))?;
            return Ok(body.server_info);
        }
    }
    Err("未收到服务器信息".into())
}

/// 尝试把 `ip` 绑定到 `owner`（HELLO 载荷中的对端虚拟 IP 所有权校验）。
///
/// 返回 `true` 表示绑定成功或幂等保留（本对端重连/保活刷新）；`false` 表示拒绝
/// （该 IP 已被**其他对端**占用）。防止恶意设备用合法 HELLO 声明任意 IP 劫持
/// 发往受害者 IP 的数据面流量（高危，见审计 HELLO IP 抢占）。
///
/// 纯函数便于安全单测。
fn bind_ip_ownership(idx: &mut HashMap<String, RawKey>, ip: &str, owner: &RawKey) -> bool {
    match idx.get(ip) {
        // 已被本对端占用：幂等允许（重连/保活刷新）。
        Some(&cur) if &cur == owner => {
            idx.insert(ip.to_string(), *owner);
            true
        }
        // 已被其他对端占用：拒绝覆盖。
        Some(_) => false,
        // 空闲：绑定。
        None => {
            idx.insert(ip.to_string(), *owner);
            true
        }
    }
}

/// 可靠接收的乱序缓冲状态机：把 `(seq, payload)` 并入接收窗口，返回「本批按序交付的载荷」
/// 与推进后的接收高水位。规则：
/// - `seq == recv_high + 1`：交付该包并推进高水位，再冲刷乱序缓冲中紧随其后的包；
/// - `seq > recv_high + 1`：乱序，缓存待中间缺失包到达后统一交付（上限保护丢弃最老）；
/// - `seq <= recv_high`：重复/重放，不交付（返回原高水位，调用方仍回 ACK 帮助对端收敛）。
fn reorder_deliver(
    recv_high: u64,
    recv_buf: &mut BTreeMap<u64, Vec<u8>>,
    seq: u64,
    payload: &[u8],
) -> (Vec<Vec<u8>>, u64) {    let mut delivered: Vec<Vec<u8>> = Vec::new();
    if seq == recv_high + 1 {
        let mut high = seq;
        delivered.push(payload.to_vec());
        while let Some(p) = {
            let next = high + 1;
            recv_buf.remove(&next)
        } {
            high += 1;
            delivered.push(p);
        }
        (delivered, high)
    } else if seq > recv_high + 1 {
        recv_buf.insert(seq, payload.to_vec());
        // 乱序缓冲上限保护（丢弃最老，防止对端恶意灌乱序导致内存膨胀）
        if recv_buf.len() > RELIABLE_WINDOW {
            if let Some(&oldest) = recv_buf.keys().next() {
                recv_buf.remove(&oldest);
            }
        }
        (delivered, recv_high)
    } else {
        // seq <= recv_high：重复/重放
        (delivered, recv_high)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linkmesh_shared::crypto;

    /// 可靠接收状态机：乱序到达 → 缓冲；缺失包到达 → 按序冲刷交付并推进高水位。
    #[test]
    fn reorder_deliver_buffers_then_flushes_in_order() {
        let mut buf = BTreeMap::new();
        // 1 到达并交付；2 丢失；3、4 乱序先到被缓冲
        let (d, high) = reorder_deliver(0, &mut buf, 1, b"p1");
        assert_eq!(d, vec![b"p1".to_vec()]);
        assert_eq!(high, 1);
        let (d, high) = reorder_deliver(1, &mut buf, 3, b"p3");
        assert!(d.is_empty());
        assert_eq!(high, 1);
        let (d, high) = reorder_deliver(1, &mut buf, 4, b"p4");
        assert!(d.is_empty());
        assert_eq!(high, 1);
        assert_eq!(buf.len(), 2);
        // 2 补齐 → 按序冲刷 2、3、4
        let (d, high) = reorder_deliver(1, &mut buf, 2, b"p2");
        assert_eq!(
            d,
            vec![b"p2".to_vec(), b"p3".to_vec(), b"p4".to_vec()]
        );
        assert_eq!(high, 4);
        assert!(buf.is_empty());
    }

    /// 可靠接收状态机：重复/重放的旧 seq 不交付、不改变高水位。
    #[test]
    fn reorder_deliver_dedups_replay() {
        let mut buf = BTreeMap::new();
        let (_, high) = reorder_deliver(0, &mut buf, 1, b"p1");
        assert_eq!(high, 1);
        let (d, high) = reorder_deliver(1, &mut buf, 1, b"p1-replay");
        assert!(d.is_empty());
        assert_eq!(high, 1);
        assert!(buf.is_empty());
    }

    /// 可靠接收状态机：乱序缓冲超过上限时丢弃最老，防止内存膨胀。
    #[test]
    fn reorder_deliver_caps_buffer() {
        let mut buf = BTreeMap::new();
        // 从 recv_high=0 开始，把超过 RELIABLE_WINDOW 个乱序包塞入
        for seq in 2..=(1 + RELIABLE_WINDOW as u64 + 5) {
            let (_, high) = reorder_deliver(0, &mut buf, seq, b"x");
            assert_eq!(high, 0);
        }
        assert!(buf.len() <= RELIABLE_WINDOW);
        // 最老（最小 seq）被丢弃，窗口内容单调
        let first = *buf.keys().next().unwrap();
        assert!(first > 1, "最老的乱序包应被丢弃");
    }

    /// 可靠传输端到端单测（真实 UDP 套接字）：发包入窗 → 对端不 ACK → 超时重传 →
    /// 收到累计 ACK → 窗口清空。验证「丢了就重传直至确认」的核心链路。
    #[tokio::test(flavor = "multi_thread")]
    async fn reliable_retransmit_and_ack_flow() {
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        b.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let b_addr = b.local_addr().unwrap();
        let std_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std_a.set_nonblocking(true).unwrap();
        let a = tokio::net::UdpSocket::from_std(std_a).unwrap();

        let local_pub = [1u8; 32];
        let local_priv = [2u8; 32];
        let peer_pub = [4u8; 32];
        let shared = [3u8; 32];
        let mut session = PeerSession::new(
            peer_pub,
            String::new(),
            shared,
            None,
            SessionKey::new([5u8; 32]),
            [6u8; 32],
            [7u8; 12],
        );
        session.transport = Transport::Relay;
        session.peer_key = Some(SessionKey::new([8u8; 32])); // 已建立会话
        session.epoch = 0;

        let peers: Arc<Mutex<HashMap<RawKey, Arc<Mutex<PeerSession>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        peers.lock().await.insert(peer_pub, Arc::new(Mutex::new(session)));
        let session = peers.lock().await.get(&peer_pub).cloned().unwrap();

        let outbox = Outbox {
            peers: peers.clone(),
            ip_index: Arc::new(Mutex::new(HashMap::new())),
            addr_index: Arc::new(Mutex::new(HashMap::new())),
            rk_index: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashSet::new())),
            main_sock: Arc::new(a),
            server_addr: b_addr,
            relay_addr: b_addr,
            server_shared: [0u8; 32],
            local_pub,
            local_priv,
            local_ip: "10.0.0.1".into(),
            hole_punch: HolePunchConfig::default(),
            rekey_every_pkts: 0,
            rekey_every_secs: 0,
            relay_recover_stale: Duration::from_secs(40),
            state: Arc::new(ConnectionState::new("test-server".into(), "lm0".into())),
            session_sk: Arc::new(Mutex::new(None)),
            session_pub: Arc::new(Mutex::new(None)),
            session_seq: Arc::new(AtomicU64::new(0)),
            relay_rk: [9u8; 32],
            local_aliases: Arc::new(Mutex::new(BTreeMap::new())),
            learned_aliases: Arc::new(Mutex::new(HashMap::new())),
            dns: None,
            log: Logger::new(std::env::temp_dir().join("reliable_test.log")),
            send_buf: Arc::new(Mutex::new(Vec::new())),
        };

        // 1) 发包 → 入可靠发送窗口
        outbox.send_data(session.clone(), b"payload-1").await;
        {
            let s = session.lock().await;
            assert_eq!(s.send_unacked.len(), 1, "发包后应进入未确认窗口");
            assert!(s.established());
        }
        // 对端应收到一帧
        let mut buf = [0u8; 65536];
        assert!(
            b.recv(&mut buf).map(|l| l > 0).unwrap_or(false),
            "首次发送后对端应收到数据帧"
        );

        // 2) 对端不 ACK → 让该包超时 → 触发重传
        {
            let mut s = session.lock().await;
            for (_, e) in s.send_unacked.iter_mut() {
                e.0 = Instant::now() - Duration::from_millis(600);
            }
        }
        outbox.retransmit().await;
        assert!(
            b.recv(&mut buf).map(|l| l > 0).unwrap_or(false),
            "超时后必须重传未确认数据包"
        );
        {
            let s = session.lock().await;
            assert_eq!(s.send_unacked.len(), 1, "未 ACK 前窗口不得清空");
        }

        // 3) 对端累计 ACK → 窗口清空
        let seq = {
            let s = session.lock().await;
            *s.send_unacked.keys().next().unwrap()
        };
        outbox.handle_ack(&session, seq).await;
        {
            let s = session.lock().await;
            assert!(s.send_unacked.is_empty(), "收到 ACK 后窗口必须清空");
        }
    }

    /// 会话期响应解密窗口：乱序到达的响应（窗口内任意发送序号）必须能解出；
    /// 窗口外的旧响应必须解不出（防重放窗口本身即安全边界）。
    #[test]
    fn session_response_window_decrypts_out_of_order() {
        let key = [7u8; 32];
        for send_seq in [10u64, 25, 40] {
            let ct = crypto::encrypt_with_nonce(
                &key,
                &crypto::session_nonce(send_seq, 1),
                b"hello-resp",
            );
            let pt = decrypt_session_response(&key, 40, &ct).expect("窗口内必须能解出");
            assert_eq!(pt, b"hello-resp");
        }
        let ct_old = crypto::encrypt_with_nonce(&key, &crypto::session_nonce(1, 1), b"old");
        assert!(
            decrypt_session_response(&key, 40, &ct_old).is_none(),
            "窗口外的旧响应必须解不出"
        );
    }

    /// 安全：HELLO 虚拟 IP 所有权校验——空闲 IP 可绑定，本对端幂等，其他对端拒绝覆盖。
    #[test]
    fn bind_ip_ownership_rejects_other_peer_steal() {
        let mut idx: HashMap<String, RawKey> = HashMap::new();
        let victim = [1u8; 32];
        let attacker = [2u8; 32];
        // 空闲 IP：可绑定
        assert!(bind_ip_ownership(&mut idx, "10.13.13.5", &victim));
        assert_eq!(idx["10.13.13.5"], victim);
        // 同对端重连/刷新：幂等允许
        assert!(bind_ip_ownership(&mut idx, "10.13.13.5", &victim));
        // 攻击者尝试抢占受害者 IP：必须拒绝
        assert!(!bind_ip_ownership(&mut idx, "10.13.13.5", &attacker));
        assert_eq!(idx["10.13.13.5"], victim, "受害者 IP 归属不得被覆盖");
        // 攻击者声明一个空闲 IP：允许（合法新对端）
        assert!(bind_ip_ownership(&mut idx, "10.13.13.6", &attacker));
        assert_eq!(idx["10.13.13.6"], attacker);
    }
}
