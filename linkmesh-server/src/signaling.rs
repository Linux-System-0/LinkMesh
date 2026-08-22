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

//! 信令服务：注册、坐标查询、对端通知，以及数据面中继转发。
//!
//! - 私钥仅在服务端本机，用于解密客户端发来的信令。
//! - 中继只负责把密文按目标公钥原样转发，不解密任何业务数据。
//!
//! # 认证体系（强制 mesh 认证）
//!
//! 服务端必须先用 `--mesh-init` 初始化网格（`mesh.json`）才能启动，此后强制认证：
//! - `KEYQUERY` 返回 root 签名的 `ServerInfo`（`MSG_SERVERINFO`），客户端 TOFU 网格根指纹；
//! - `JOIN`：一次性加入码 + 设备双公钥 → 服务端分配虚拟 IP 并签发 `DeviceCert`；
//! - `AUTH`：设备证书 + 客户端临时公钥 → 3-DH 会话密钥 SK + 会话表登记；
//! - 会话期信令（REGISTER/QUERY/HEARTBEAT/BYE）帧头携带 `session_pub = ek_c`，
//!   负载用 SK + 递增计数器 nonce 加密（防重放），sender 不在会话表中即拒绝；
//! - 中继来源必须是活跃会话（`relay_forward` 校验），吊销（CRL）立即生效。

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_shared::cert::ServerInfo;
use linkmesh_shared::crypto::{self, RawKey, SessionKey};
use linkmesh_shared::protocol::{
    decode_auth, decode_join, decode_query, decode_register, encode_auth_resp, encode_notify,
    encode_response, encode_server_info_body, frame_relay_batch, frame_signaling, parse_header,
    parse_relay, AuthBody, AuthRespBody, Endpoint, JoinBody, MSG_AUTH, MSG_AUTH_RESP, MSG_BYE,
    MSG_HEARTBEAT, MSG_JOIN, MSG_KEYQUERY, MSG_NOTIFY, MSG_QUERY, MSG_REGISTER, MSG_RELAY,
    MSG_RELAY_RK, MSG_RESPONSE, MSG_SERVERINFO, NotifyBody, QueryBody, RegisterBody, ResponseBody,
    ResponseData, ServerInfoBody, HEADER_LEN, RELAY_HEADER_LEN, PROTOCOL_VER,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

use crate::config::{RelayBatchConfig, RoomEntry, ServerConfig, validate_alias};
use crate::log::{Logger, LogLimiter};
use crate::mesh::MeshConfig;

/// 路由表条目：公钥 → { 虚拟 IP, Endpoint, 中继路由密钥 }。
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub public_key: RawKey,
    pub ip: String,
    pub endpoint: Endpoint,
    pub last_seen: u64,
    /// 中继路由密钥 rk（base64，P1-7）：随注册/心跳上报，中继头部用它寻址。
    pub relay_rk: Option<String>,
    /// 所属房间（令牌验证开启时由令牌决定；未开启 = "default"）。
    pub room: String,
    /// 设备自报别名（REGISTER 携带，可选）。
    pub alias: Option<String>,
}

/// 并发安全的路由表。keyed by 公钥，另建虚拟 IP 索引。
pub struct RouteTable {
    by_key: HashMap<RawKey, RouteEntry>,
    by_ip: HashMap<String, RawKey>,
    /// rk → 公钥（P1-7 中继寻址）。
    by_rk: HashMap<String, RawKey>,
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteTable {
    pub fn new() -> Self {
        RouteTable {
            by_key: HashMap::new(),
            by_ip: HashMap::new(),
            by_rk: HashMap::new(),
        }
    }

    pub fn upsert(&mut self, entry: RouteEntry) {
        if let Some(old) = self.by_key.get(&entry.public_key) {
            if old.ip != entry.ip {
                self.by_ip.remove(&old.ip);
            }
            if let Some(old_rk) = &old.relay_rk {
                self.by_rk.remove(old_rk);
            }
        }
        if entry.ip.is_empty() {
            if let Some(old) = self.by_key.get(&entry.public_key) {
                self.by_ip.remove(&old.ip);
            }
        } else {
            if let Some(old_key) = self.by_ip.insert(entry.ip.clone(), entry.public_key) {
                if old_key != entry.public_key {
                    // 同一 IP 被不同公钥占用时，释放旧公钥对应的条目
                    self.by_key.remove(&old_key);
                }
            }
        }
        if let Some(rk) = &entry.relay_rk {
            // rk 冲突检测（防入站中继劫持）：rk 以明文出现在中继帧头，同房间成员可学得
            // 对端 rk 并在自己 REGISTER 里冒用。若该 rk 已被**其他公钥**占用，拒绝覆盖，
            // 保持「rk 唯一绑定首个合法登记设备」，避免把对端入站流量改投给冒用者。
            // 合法所有者在相同 public_key 下重复上报自己的 rk 仍被允许。
            match self.by_rk.get(rk) {
                Some(existing) if *existing != entry.public_key => {
                    // 冒用/碰撞：不覆盖，静默保留原绑定（原设备 rk 仍可正常寻址）。
                }
                _ => {
                    self.by_rk.insert(rk.clone(), entry.public_key);
                }
            }
        }
        self.by_key.insert(entry.public_key, entry);
    }

    pub fn get(&self, key: &RawKey) -> Option<&RouteEntry> {
        self.by_key.get(key)
    }

    pub fn get_by_ip(&self, ip: &str) -> Option<&RouteEntry> {
        self.by_ip.get(ip).and_then(|k| self.by_key.get(k))
    }

    /// 按中继路由密钥 rk 查条目（P1-7）。
    pub fn get_by_rk(&self, rk: &str) -> Option<&RouteEntry> {
        self.by_rk.get(rk).and_then(|k| self.by_key.get(k))
    }

    pub fn remove(&mut self, key: &RawKey) {
        if let Some(e) = self.by_key.remove(key) {
            self.by_ip.remove(&e.ip);
            if let Some(rk) = &e.relay_rk {
                self.by_rk.remove(rk);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn snapshot(&self) -> Vec<RouteEntry> {
        let mut v: Vec<RouteEntry> = self.by_key.values().cloned().collect();
        v.sort_by_key(|a| a.public_key);
        v
    }

    pub fn cleanup(&mut self, now: u64, ttl_sec: u64) {
        let expired: Vec<RawKey> = self
            .by_key
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.last_seen) > ttl_sec)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            self.remove(&k);
        }
    }
}

#[derive(Default)]
pub struct Stats {
    /// 原子计数器：数据面每包路径上频繁自增，用原子计数避免全局互斥锁竞争。
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub bytes_relayed: AtomicU64,
    /// 因 worker 队列满而被丢弃的封包数（过载/洪泛时计数，避免收包循环队头阻塞）。
    pub packets_dropped: AtomicU64,
}

/// 待聚合的一个中继子帧：目标公钥、目标端点与子帧载荷（src_pub + ciphertext）。
pub struct BatchItem {
    pub dest: RawKey,
    pub addr: SocketAddr,
    pub subframe: Vec<u8>,
}

/// 累积中的批量缓冲：同一目标公钥的多个子帧。
struct PendingBatch {
    addr: SocketAddr,
    frames: Vec<Vec<u8>>,
    bytes: usize,
}

/// 批量中继发送器：把短时间内到达的多个小中继帧拼成一个大 UDP 载荷再发出。
///
/// 每个目标公钥维护一个累积缓冲，满足以下任一条件即触发发送：
/// - 缓冲字节数达到 `max_bytes`（立即）；
/// - 距离第一条子帧入队超过聚合时间窗 `window`（由工作线程轮询）。
pub struct RelayBatcher {
    tx: mpsc::Sender<BatchItem>,
}

impl RelayBatcher {
    /// 启动批量工作线程。`enabled=false` 时返回 None（退化为逐帧直发）。
    pub fn spawn(
        cfg: &RelayBatchConfig,
        sock: Arc<UdpSocket>,
        stats: Arc<Stats>,
    ) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let window = Duration::from_millis(cfg.window_ms.max(1));
        let max_bytes = cfg.max_bytes.max(1);
        let (tx, rx) = mpsc::channel(4096);
        tokio::spawn(batch_worker(rx, sock, stats, window, max_bytes));
        Some(RelayBatcher { tx })
    }

    /// 投递一个子帧。返回 true 表示已入队待拼接，false 表示应直发。
    pub fn enqueue(&self, item: BatchItem) -> bool {
        self.tx.try_send(item).is_ok()
    }
}

async fn batch_worker(
    mut rx: mpsc::Receiver<BatchItem>,
    sock: Arc<UdpSocket>,
    stats: Arc<Stats>,
    window: Duration,
    max_bytes: usize,
) {
    let mut pending: HashMap<RawKey, PendingBatch> = HashMap::new();
    let mut ticker = tokio::time::interval(window);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some(it) => {
                        let pb = pending.entry(it.dest).or_insert(PendingBatch {
                            addr: it.addr,
                            frames: Vec::new(),
                            bytes: 0,
                        });
                        pb.addr = it.addr;
                        pb.bytes += it.subframe.len();
                        pb.frames.push(it.subframe);
                        if pb.bytes >= max_bytes {
                            if let Some(pb) = pending.remove(&it.dest) {
                                flush_batch(&sock, &stats, it.dest, pb).await;
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                let keys: Vec<RawKey> = pending.keys().copied().collect();
                for k in keys {
                    if let Some(pb) = pending.remove(&k) {
                        flush_batch(&sock, &stats, k, pb).await;
                    }
                }
            }
        }
    }
}

async fn flush_batch(sock: &Arc<UdpSocket>, stats: &Arc<Stats>, dest: RawKey, pb: PendingBatch) {
    if pb.frames.is_empty() {
        return;
    }
    let refs: Vec<&[u8]> = pb.frames.iter().map(|f| f.as_slice()).collect();
    let pkt = frame_relay_batch(&dest, &refs);
    if sock.send_to(&pkt, pb.addr).await.is_err() {
        return;
    }
    stats.packets_out.fetch_add(1, Ordering::Relaxed);
    stats.bytes_relayed.fetch_add(pkt.len() as u64, Ordering::Relaxed);
}

/// 已认证会话：握手成功后登记，会话期信令/中继凭此放行。
///
/// 会话密钥 SK 为 3-DH 派生（含双方临时密钥成分），`Drop` 清零，连接结束即失效。
/// 会话期帧头携带 `session_pub = ek_c`，服务端据此定位会话并防重放。
#[derive(Debug)]
pub struct SessionEntry {
    /// 客户端临时公钥（ek_c，即会话期帧头 sender）。
    pub session_pub: RawKey,
    /// 设备 ID（base64）。
    pub device_id: String,
    /// 客户端静态 X25519 公钥（ik_x，用于路由表与对端寻址）。
    pub ik_x: RawKey,
    /// 证书绑定的虚拟 IP。
    pub ip: String,
    /// 3-DH 会话密钥（Drop 清零）。
    pub sk: SessionKey,
    /// 本会话已接收的计数器（防重放，严格递增）。
    pub counter_rx: u64,
    pub last_seen: u64,
    /// 所属房间（令牌验证开启时由 AUTH 携带的令牌决定）。
    pub room: String,
}

/// 信令 + 中继服务主体。
pub struct Signaling {
    pub sock: Arc<UdpSocket>,
    pub routes: Arc<Mutex<RouteTable>>,
    pub stats: Arc<Stats>,
    batcher: Option<RelayBatcher>,
    server_pub: RawKey,
    server_priv: RawKey,
    server_ik_s_pub: String,
    route_ttl_sec: u64,
    /// 网格状态（mesh.json）：`Signaling::new` 强制要求已初始化，否则拒绝启动。
    pub mesh: Arc<Mutex<MeshConfig>>,
    /// 已认证会话：ek_c → SessionEntry。
    pub sessions: Arc<Mutex<HashMap<RawKey, SessionEntry>>>,
    /// 活跃会话的 ik_x 索引（O(1) 中继来源校验）。会话增删后重建，热点读零扫描。
    pub active_ik_x: Arc<Mutex<std::collections::HashSet<RawKey>>>,
    /// 握手期 nonce 重放缓存（每设备最近 N 个，防 AUTH/JOIN 重放）。
    replay: Arc<Mutex<HashMap<RawKey, VecDeque<[u8; 12]>>>>,
    /// AUTH/JOIN 限速：源 IP → (窗口起始秒, 次数)。
    ///
    /// 以「IP」为键而非 `SocketAddr`（含端口）：攻击者可轮换源端口无限制造新条目，
    /// 导致限速表无界增长并绕过限速。键为 IP 后条目数与「不同来源 IP」绑定，
    /// 数量有限且可被定期清理（见 [`cleanup_loop`]）。
    rate_limits: Arc<Mutex<HashMap<std::net::IpAddr, (u64, usize)>>>,
    /// JOIN/AUTH 每源 IP 每分钟上限（0 = 不限速），见 `ServerConfig.join_rate_per_min_per_ip`。
    join_rate_limit: usize,
    /// 房间令牌表（运行中可经控制通道增删并持久化）。空 = 单房间开放（启动时警告）。
    pub rooms: Arc<Mutex<Vec<RoomEntry>>>,
    /// 管理员别名表（名称 → 虚拟 IP，运行中可经控制通道增删并持久化）。
    pub aliases: Arc<Mutex<HashMap<String, String>>>,
    /// 服务器显示名称（ServerInfo 用）。
    server_name: String,
    /// mesh.json 路径（持久化用）。
    mesh_path: String,
    log: Logger,
    /// 高频低价值警告限流器（垃圾帧日志放大防护，见 §5.2）。
    warn_limiter: LogLimiter,
    /// KEYQUERY ServerInfo 响应缓存：(CRL 版本, 编码后的 SERVERINFO 帧字节)。
    ///
    /// `KEYQUERY` 是唯一不加密、可伪造源地址的请求，放大比约 10x。缓存签名后的
    /// 响应并在 CRL 版本不变时复用，避免每次请求都重新做 Ed25519 签名、并大幅缩短
    /// 全局 mesh 锁的持有时间（防 KEYQUERY 洪泛把 JOIN/AUTH 全部串行卡死）。
    serverinfo_cache: Arc<Mutex<Option<(u64, Vec<u8>)>>>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 并行处理 worker：每个 worker 串行处理分配到的封包，不同 worker 并行。
///
/// 通过按 `SocketAddr` 哈希分片，保证同一来源的封包始终落在同一 worker、按到达顺序串行处理，
/// 从而维持会话计数器/防重放语义；不同来源则跨 worker 并行，突破单飞模型的吞吐/延迟天花板。
struct Worker {
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

/// 把来源地址散列到 `[0, n)`，保证同源同分片。
fn shard_index(src: &SocketAddr, n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    // FNV-1a，直接哈希 SocketAddr 的 IP+端口字节，避免每包 `to_string` 分配。
    let mut h = 0xcbf29ce484222325u64;
    match src {
        SocketAddr::V4(v4) => {
            for b in v4.ip().octets() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h ^= v4.port() as u64;
        }
        SocketAddr::V6(v6) => {
            for b in v6.ip().octets() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h ^= v6.port() as u64;
        }
    }
    (h as usize) % n
}

/// 默认并行 worker 数：按可用核数取 2~8（更多 worker 会加剧锁竞争，收益递减）。
fn default_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get().clamp(2, 8))
        .unwrap_or(4)
}

impl Signaling {
    pub fn server_pub(&self) -> RawKey {
        self.server_pub
    }

    pub fn new(sock: UdpSocket, cfg: &ServerConfig, log: Logger) -> Result<Self, String> {
        let sock = Arc::new(sock);
        let stats = Arc::new(Stats::default());
        let batcher = RelayBatcher::spawn(&cfg.relay.batch, sock.clone(), stats.clone());
        if cfg.relay.enabled && batcher.is_some() {
            log.info(format!(
                "中继批量转发已启用（窗口 {}ms / 上限 {}B）",
                cfg.relay.batch.window_ms, cfg.relay.batch.max_bytes
            ));
        }
        // 网格（强制 mesh 认证）：必须先 --mesh-init 初始化，否则拒绝启动
        let mesh = match MeshConfig::load(Path::new(&cfg.mesh_path)) {
            Ok(Some(m)) => {
                if let Err(e) = m.verify_integrity() {
                    return Err(format!(
                        "{} 完整性校验失败: {e}",
                        cfg.mesh_path
                    ));
                }
                log.info(format!(
                    "网格已加载：mesh_id={}，成员 {} 台，CRL v{}，根指纹 {}",
                    m.mesh_id,
                    m.members.len(),
                    m.crl.version,
                    m.root_fingerprint().unwrap_or_default()
                ));
                Arc::new(Mutex::new(m))
            }
            Ok(None) => {
                return Err(format!(
                    "{} 不存在，请先执行 --mesh-init 初始化网格",
                    cfg.mesh_path
                ));
            }
            Err(e) => {
                return Err(format!("加载 {} 失败: {e}", cfg.mesh_path));
            }
        };
        // ServerInfo 需要服务端签名公钥；mesh 模式下必须已配置（--genkey 生成）
        let server_ik_s_pub = cfg.signing_public_b64()?;
        // 房间令牌（令牌验证）：rooms 非空时客户端必须携带有效令牌，令牌决定房间隔离。
        let rooms = Arc::new(Mutex::new(cfg.rooms.clone()));
        if let Ok(guard) = rooms.try_lock() {
            if guard.is_empty() {
                log.warn(
                    "未配置房间令牌（rooms 为空）：所有设备同处一个开放房间，无令牌验证。\
                     建议 linkmesh-server --add-room <房间名> <令牌> 启用分房间隔离",
                );
            } else {
                log.info(format!(
                    "令牌验证已启用：{} 个房间，设备须携带有效令牌入网并限同房间互通",
                    guard.len()
                ));
            }
        }
        // 管理员别名表
        let mut aliases = HashMap::new();
        for a in &cfg.aliases {
            aliases.insert(a.name.clone(), a.ip.clone());
        }
        Ok(Signaling {
            sock,
            routes: Arc::new(Mutex::new(RouteTable::new())),
            stats,
            batcher,
            server_pub: cfg.public_key()?,
            server_priv: cfg.private_key()?,
            server_ik_s_pub,
            route_ttl_sec: cfg.route_ttl_sec,
            mesh,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            active_ik_x: Arc::new(Mutex::new(std::collections::HashSet::new())),
            replay: Arc::new(Mutex::new(HashMap::new())),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            join_rate_limit: cfg.join_rate_per_min_per_ip,
            rooms,
            aliases: Arc::new(Mutex::new(aliases)),
            server_name: cfg.server_name.clone(),
            mesh_path: cfg.mesh_path.clone(),
            log: log.clone(),
            warn_limiter: LogLimiter::new(log, 10, 4096),
            serverinfo_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// 房间令牌表当前快照（供控制通道展示）。
    pub async fn rooms_snapshot(&self) -> Vec<RoomEntry> {
        self.rooms.lock().await.clone()
    }

    /// 令牌 → 房间名。rooms 为空（未启用令牌验证）时任何令牌/无令牌都进入 "default"。
    /// rooms 非空时：缺令牌 / 令牌无效均返回错误（默认拒绝）。
    async fn resolve_room(&self, token: Option<&str>) -> Result<String, String> {
        let rooms = self.rooms.lock().await;
        if rooms.is_empty() {
            return Ok("default".to_string());
        }
        let tok = token.map(str::trim).filter(|t| !t.is_empty());
        match tok {
            Some(t) => {
                let hash = ServerConfig::hash_token(t);
                rooms
                    .iter()
                    .find(|r| r.token_hash == hash)
                    .map(|r| r.name.clone())
                    .ok_or_else(|| "房间令牌无效（请核对令牌后重试）".to_string())
            }
            None => Err("缺少房间令牌（服务器启用了令牌验证，请用 --token 指定）".into()),
        }
    }

    /// 解析别名 → 虚拟 IP。优先级：管理员别名（server.json aliases）→ 在线设备自报别名。
    /// 未解析到返回 None。
    async fn resolve_alias(&self, name: &str) -> Option<String> {
        if let Some(ip) = self.aliases.lock().await.get(name).cloned() {
            return Some(ip);
        }
        let routes = self.routes.lock().await;
        routes
            .snapshot()
            .iter()
            .find(|e| e.alias.as_deref() == Some(name))
            .map(|e| e.ip.clone())
    }

    /// 校验并规范化设备自报别名；格式非法返回 Err（调用方拒绝注册并提示）。
    fn normalize_self_alias(alias: Option<&str>) -> Result<Option<String>, String> {
        match alias {
            Some(a) if !a.trim().is_empty() => Ok(Some(validate_alias(a)?)),
            _ => Ok(None),
        }
    }

    /// 发送一条加密的拒绝响应。
    async fn send_error(&self, shared: &RawKey, src: SocketAddr, msg: &str) -> Result<(), String> {
        let resp_pt = encode_response(&ResponseBody::err(msg)).map_err(|e| format!("序列化失败: {e}"))?;
        let ct = crypto::encrypt(shared, &resp_pt);
        let frame = frame_signaling(MSG_RESPONSE, &self.server_pub, &ct);
        self.sock
            .send_to(&frame, src)
            .await
            .map(|_| ())
            .map_err(|e| format!("拒绝响应发送失败: {e}"))
    }

    /// 对 `(category, src)` 限速写 WARN（日志放大防护）。
    fn warn_limited(&self, category: &str, src: &SocketAddr, msg: &str) {
        self.warn_limiter.warn(category, &src.to_string(), msg);
    }

    /// 主循环：接收 UDP 封包，按来源哈希分片到并行 worker 处理。
    ///
    /// 由 `tokio::sync::mpsc` 有界信道 + 按 `SocketAddr` 分片保证：
    /// - 同源串行（维持会话计数器/防重放顺序）；
    /// - 跨源并行（突破单飞模型在高并发下的延迟/吞吐天花板，见测试报告 §5.1）。
    pub async fn run(self: Arc<Self>) {
        let n = default_worker_count();
        let mut workers = Vec::with_capacity(n);
        for _ in 0..n {
            let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
            let s = self.clone();
            tokio::spawn(async move {
                while let Some((packet, src)) = rx.recv().await {
                    if let Err(e) = s.handle(&packet, src).await {
                        s.warn_limited(
                            "处理封包失败",
                            &src,
                            &format!("处理 {} 的封包失败: {e}", src),
                        );
                    }
                }
            });
            workers.push(Worker { tx });
        }
        let mut buf = vec![0u8; 65536];
        loop {
            match self.sock.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let packet = buf[..len].to_vec();
                    self.stats.packets_in.fetch_add(1, Ordering::Relaxed);
                    let shard = shard_index(&src, workers.len());
                    // 有界信道 + 非阻塞投递：worker 繁忙（队列满）时丢弃该包而不是
                    // 阻塞收包循环。若这里 `await` 背压，单一来源的洪泛会把某个 shard 的
                    // 队列打满，从而让收包循环（所有来源共用）整体停摆，造成全局 DoS。
                    // UDP 本身允许丢包，过载时丢弃并计数是最稳妥的降级策略。
                    if workers[shard].tx.try_send((packet, src)).is_err() {
                        self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    self.log.error(format!("UDP 接收失败: {e}"));
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle(&self, packet: &[u8], src: SocketAddr) -> Result<(), String> {
        if let Ok(hdr) = parse_header(packet) {
            if hdr.msg_type == MSG_RELAY || hdr.msg_type == MSG_RELAY_RK {
                self.handle_relay(packet, src).await?;
                return Ok(());
            }
            if hdr.msg_type == MSG_QUERY
                || hdr.msg_type == MSG_REGISTER
                || hdr.msg_type == MSG_HEARTBEAT
                || hdr.msg_type == MSG_BYE
                || hdr.msg_type == MSG_KEYQUERY
                || hdr.msg_type == MSG_JOIN
                || hdr.msg_type == MSG_AUTH
            {
                self.handle_signaling(&hdr, packet, src).await?;
                return Ok(());
            }
            self.warn_limited("未知消息类型", &src, &format!("未知消息类型 {}", hdr.msg_type));
            return Ok(());
        }
        self.warn_limited("无法解析的封包", &src, "无法解析的封包");
        Ok(())
    }

    /// 中继转发：优先聚合到批量缓冲，聚合不可用时逐帧直发。
    async fn handle_relay(&self, packet: &[u8], src: SocketAddr) -> Result<(), String> {
        relay_forward(
            self.sock.clone(),
            self.routes.clone(),
            self.stats.clone(),
            self.batcher.as_ref(),
            &self.active_ik_x,
            &self.rooms,
            packet,
            src,
        )
        .await
    }

    /// 处理信令消息：解密 → 业务逻辑 → 加密响应。
    ///
    /// 两条路径：
    /// - **握手期**：帧头 sender = ik_x（静态），负载用 `ECDH(ik_x, ik_x_s)` 共享密钥加密
    ///   （随机 nonce）。覆盖 KEYQUERY / JOIN / AUTH / BYE。
    /// - **会话期**（mesh 模式）：帧头 sender = ek_c（session_pub），负载用会话密钥 SK +
    ///   确定性计数器 nonce 加密（`session_nonce(seq, dir)`），防重放。覆盖 REGISTER / QUERY /
    ///   HEARTBEAT / BYE。
    async fn handle_signaling(
        &self,
        hdr: &linkmesh_shared::protocol::PacketHeader,
        packet: &[u8],
        src: SocketAddr,
    ) -> Result<(), String> {
        // 首次接触：客户端尚无本机公钥，无法加密交互。
        if hdr.msg_type == MSG_KEYQUERY {
            return self.handle_keyquery(src).await;
        }

        // 若 sender 是已认证会话（ek_c），走会话期 SK 路径
        let is_session = {
            let sessions = self.sessions.lock().await;
            sessions.contains_key(&hdr.sender_public_key)
        };
        if is_session {
            return self.handle_session_signaling(hdr, packet, src).await;
        }

        // 握手期：静态 ECDH 共享密钥，只接受 JOIN / AUTH / BYE
        let shared = crypto::shared_secret(&self.server_priv, &hdr.sender_public_key);
        let plaintext = crypto::decrypt(&shared, &packet[linkmesh_shared::protocol::HEADER_LEN..])?;
        match hdr.msg_type {
            MSG_JOIN => {
                let jb = decode_join(&plaintext).map_err(|e| format!("JOIN 消息格式错误: {e}"))?;
                return self.handle_join(hdr, &jb, src).await;
            }
            MSG_AUTH => {
                let ab = decode_auth(&plaintext).map_err(|e| format!("AUTH 消息格式错误: {e}"))?;
                return self.handle_auth(hdr, &ab, src).await;
            }
            MSG_BYE => {
                self.routes.lock().await.remove(&hdr.sender_public_key);
                return self
                    .send_ok(&shared, src)
                    .await;
            }
            _ => {
                self.log.warn(format!(
                    "拒绝未认证设备 {} 的信令（type={})",
                    B64.encode(hdr.sender_public_key)[..16].to_string(),
                    hdr.msg_type
                ));
                return self
                    .send_error(&shared, src, "尚未认证（请先 --join 并完成 AUTH 握手）")
                    .await;
            }
        }
    }

    // ---------- 认证握手（mesh 模式） ----------

    /// KEYQUERY：返回 root 签名的 ServerInfo（`MSG_SERVERINFO`）。mesh 强制认证，
    /// 客户端据此 TOFU 网格根指纹。
    async fn handle_keyquery(&self, src: SocketAddr) -> Result<(), String> {
        // 先读 CRL 版本（短暂持有 mesh 锁仅取版本号），据此命中缓存。
        let crl_version = self.mesh.lock().await.crl.version;
        let frame = {
            let mut cache = self.serverinfo_cache.lock().await;
            let fresh = cache
                .as_ref()
                .filter(|(v, _)| *v == crl_version)
                .map(|(_, f)| f.clone());
            match fresh {
                Some(f) => f,
                None => {
                    // 版本变化或首次：在 mesh 锁内重建签名一次并缓存，此后复用。
                    // 避免每次 KEYQUERY 重做 Ed25519 签名并长时间占用全局 mesh 锁。
                    let m = self.mesh.lock().await;
                    let info = self.build_server_info(&m)?;
                    let body = ServerInfoBody { server_info: info };
                    let pt =
                        encode_server_info_body(&body).map_err(|e| format!("序列化失败: {e}"))?;
                    let f = frame_signaling(MSG_SERVERINFO, &self.server_pub, &pt);
                    cache.replace((crl_version, f.clone()));
                    f
                }
            }
        };
        // 发送在锁外进行（不占用 mesh 锁）。
        self.sock
            .send_to(&frame, src)
            .await
            .map_err(|e| format!("ServerInfo 响应发送失败: {e}"))?;
        Ok(())
    }

    /// 构建 root 签名的 ServerInfo（含网格根公钥 / 服务器双公钥 / 协议与 CRL 版本）。
    fn build_server_info(&self, mesh: &MeshConfig) -> Result<ServerInfo, String> {
        let root_pub = mesh.root_public_raw()?;
        let mut info = ServerInfo {
            mesh_id: mesh.mesh_id.clone(),
            server_name: self.server_name.clone(),
            mesh_root_pub: B64.encode(root_pub),
            server_ik_x: B64.encode(self.server_pub),
            server_ik_s_pub: self.server_ik_s_pub.clone(),
            protocol_ver: PROTOCOL_VER,
            crl_version: mesh.crl.version,
            auth_required: true,
            signature: None,
        };
        info.sign(&mesh.root_seed()?);
        Ok(info)
    }

    /// MSG_JOIN：校验一次性加入码 → 分配虚拟 IP → 签发 DeviceCert → 返回证书与 ServerInfo。
    async fn handle_join(
        &self,
        hdr: &linkmesh_shared::protocol::PacketHeader,
        jb: &JoinBody,
        src: SocketAddr,
    ) -> Result<(), String> {
        let mesh = &self.mesh;
        // 帧头 ik_x 必须与 JOIN 载荷一致
        if B64.encode(hdr.sender_public_key) != jb.ik_x {
            return self
                .send_error(
                    &crypto::shared_secret(&self.server_priv, &hdr.sender_public_key),
                    src,
                    "JOIN 载荷公钥与帧头不一致",
                )
                .await;
        }
        // 限速：每源 IP 每分钟最多 N 次 JOIN/AUTH（防枚举与刷码）
        if self.rate_limited(src).await {
            self.log.warn(format!("JOIN 限速触发：{src}"));
            return Ok(());
        }
        let shared = crypto::shared_secret(&self.server_priv, &hdr.sender_public_key);
        // 令牌验证：加入时必须携带有效房间令牌（rooms 为空时自动放行）
        let _room = match self.resolve_room(jb.token.as_deref()).await {
            Ok(r) => r,
            Err(e) => return self.send_error(&shared, src, &e).await,
        };
        let mut mesh = mesh.lock().await;
        // 只校验加入码（不消费）：先做后续全部校验（公钥一致性 / device_id / IP 可分配 /
        // 证书签发），全部通过后再消费，避免一次性加入码被错误参数或失败的加入烧毁。
        // 整个函数持有 mesh 锁，peek 与最终 consume 之间不存在并发竞争。
        let bound_ip = match mesh.peek_invite(&jb.code) {
            Ok(ip) => ip,
            Err(e) => {
                self.log.warn(format!("JOIN 加入码校验失败: {e}"));
                return self.send_error(&shared, src, &format!("加入失败: {e}")).await;
            }
        };
        // 校验 device_id 与双公钥一致
        let ik_x = match linkmesh_shared::crypto::parse_public_key(&jb.ik_x) {
            Ok(k) => k,
            Err(e) => return self.send_error(&shared, src, &e).await,
        };
        let ik_s_pub = match linkmesh_shared::identity::parse_sig_public(&jb.ik_s_pub) {
            Ok(k) => k,
            Err(e) => return self.send_error(&shared, src, &e).await,
        };
        let expect_id = linkmesh_shared::identity::device_id_b64(&ik_x, &ik_s_pub);
        if jb.device_id != expect_id {
            return self
                .send_error(&shared, src, "device_id 与设备双公钥不匹配")
                .await;
        }
        // 分配 IP：加入码预绑定优先，否则请求 IP，否则池内分配
        let preferred = bound_ip.or(jb.requested_ip.clone());
        let ip = match mesh.allocate_ip(preferred.as_deref()) {
            Ok(ip) => ip,
            Err(e) => return self.send_error(&shared, src, &e).await,
        };
        let cert = match mesh.issue_cert(&jb.ik_x, &jb.ik_s_pub, &ip, Some(&jb.device_id)) {
            Ok(c) => c,
            Err(e) => return self.send_error(&shared, src, &format!("签发证书失败: {e}")).await,
        };
        // 设备自报别名（格式非法则拒绝加入）
        let alias = match Self::normalize_self_alias(jb.alias.as_deref()) {
            Ok(a) => a,
            Err(e) => return self.send_error(&shared, src, &e).await,
        };
        if let Some(a) = &alias {
            mesh.set_member_alias(&cert.device_id, a);
        }
        // 至此全部校验通过，才消费（标记 used）一次性加入码。
        if let Err(e) = mesh.consume_invite(&jb.code) {
            self.log.warn(format!("JOIN 加入码最终消费失败（不应发生）: {e}"));
        }
        let info = self.build_server_info(&mesh)?;
        let crl = mesh.crl.clone();
        // 在锁内完成所有读与序列化，随后释放 mesh 锁再做磁盘写与网络发送，
        // 避免并发 JOIN 因长持全局 mesh 锁被串行化（高并发入网瓶颈）。
        let mesh_json = mesh.to_json();
        drop(mesh);
        let mesh_path = self.mesh_path.clone();
        if let Ok(text) = mesh_json {
            if let Err(e) = MeshConfig::save_json(Path::new(&mesh_path), &text) {
                self.log.warn(format!("mesh.json 持久化失败: {e}"));
            }
        }
        let resp = ResponseBody::ok_with_data(ResponseData::Join {
            device_id: cert.device_id.clone(),
            allocated_ip: ip.clone(),
            cert: cert.clone(),
            server_info: info,
            crl,
        });
        let resp_pt = encode_response(&resp).map_err(|e| format!("序列化失败: {e}"))?;
        let ct = crypto::encrypt(&shared, &resp_pt);
        let frame = frame_signaling(MSG_RESPONSE, &self.server_pub, &ct);
        self.sock
            .send_to(&frame, src)
            .await
            .map_err(|e| format!("JOIN 响应发送失败: {e}"))?;
        self.log.info(format!("设备 {} 已加入网格（IP {ip}）", jb.device_id));
        Ok(())
    }

    /// MSG_AUTH：校验证书/时间戳/nonce → 3-DH 会话密钥 → 登记会话 → AUTH_RESP。
    async fn handle_auth(
        &self,
        hdr: &linkmesh_shared::protocol::PacketHeader,
        ab: &AuthBody,
        src: SocketAddr,
    ) -> Result<(), String> {
        let mesh = &self.mesh;
        if self.rate_limited(src).await {
            self.log.warn(format!("AUTH 限速触发：{src}"));
            return Ok(());
        }
        let shared = crypto::shared_secret(&self.server_priv, &hdr.sender_public_key);
        // 令牌验证：认证会话绑定房间（rooms 为空时 = "default"）
        let room = match self.resolve_room(ab.token.as_deref()).await {
            Ok(r) => r,
            Err(e) => return self.send_error(&shared, src, &e).await,
        };
        let mesh = mesh.lock().await;
        let root_pub = mesh.root_public_raw()?;
        let now = now_secs();
        // 1) 证书签名与有效期
        if let Err(e) = ab.cert.verify(&root_pub, now) {
            return self.send_error(&shared, src, &e).await;
        }
        // 2) 证书与帧头 ik_x / 载荷 device_id 一致
        let cert_ik_s_pub = match linkmesh_shared::identity::parse_sig_public(&ab.cert.ik_s_pub) {
            Ok(k) => k,
            Err(e) => return self.send_error(&shared, src, &e).await,
        };
        if let Err(e) = ab.cert.matches_keys(&hdr.sender_public_key, &cert_ik_s_pub) {
            return self.send_error(&shared, src, &e).await;
        }
        if ab.device_id != ab.cert.device_id {
            return self.send_error(&shared, src, "AUTH 载荷 device_id 与证书不一致").await;
        }
        // 3) 未吊销
        if mesh.is_revoked(&ab.device_id) {
            self.log.warn(format!("拒绝已吊销设备 {} 的认证", ab.device_id));
            return self.send_error(&shared, src, "设备已被吊销").await;
        }
        // 4) 时间戳窗 ±30s
        let ts = ab.timestamp as i64;
        if (ts - now as i64).abs() > 30 {
            return self.send_error(&shared, src, "时间戳超出允许窗口（±30s），请校准设备时钟").await;
        }
        // 5) nonce 重放缓存
        let nonce_bytes: [u8; 12] = match B64.decode(ab.nonce.trim()) {
            Ok(b) => match b.try_into() {
                Ok(n) => n,
                Err(_) => return self.send_error(&shared, src, "nonce 长度错误").await,
            },
            Err(_) => return self.send_error(&shared, src, "nonce base64 非法").await,
        };
        if !self.replay_check(&hdr.sender_public_key, &nonce_bytes).await {
            return self.send_error(&shared, src, "nonce 重放，拒绝认证").await;
        }
        // 6) 3-DH 会话密钥
        let ek_c = match linkmesh_shared::crypto::parse_public_key(&ab.ek_c) {
            Ok(k) => k,
            Err(e) => return self.send_error(&shared, src, &e).await,
        };
        let ek_s_kp = linkmesh_shared::crypto::generate_keypair();
        let sk = crypto::derive_session_key_server(
            &ek_s_kp.private,
            &self.server_priv,
            &ek_c,
            &hdr.sender_public_key,
            &nonce_bytes,
        );
        let session_id = {
            let mut b = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
            B64.encode(b)
        };
        let session_short = session_id[..8].to_string();
        // 7) 登记会话
        let mut evicted_ik_x: Vec<RawKey> = Vec::new();
        {
            let mut sessions = self.sessions.lock().await;
            // 有界会话表（防已认证设备轮换 ek_c 无限制造会话，安全审计 A1/N2）：
            // - 每设备（device_id）最多 MAX_SESSIONS_PER_DEVICE 个会话，超出后淘汰该设备最旧的一条；
            // - 全局总数上限 MAX_TOTAL_SESSIONS，超出后淘汰全局最旧的会话。
            const MAX_SESSIONS_PER_DEVICE: usize = 8;
            const MAX_TOTAL_SESSIONS: usize = 4096;
            if sessions.len() >= MAX_TOTAL_SESSIONS {
                if let Some((oldest_key, _s)) = sessions.iter().min_by_key(|(_, s)| s.last_seen) {
                    let oldest_key = *oldest_key;
                    let removed = sessions.remove(&oldest_key);
                    if let Some(r) = removed {
                        evicted_ik_x.push(r.ik_x);
                    }
                }
            }
            let device_sessions: Vec<RawKey> = sessions
                .iter()
                .filter(|(_, s)| s.device_id == ab.device_id)
                .map(|(k, _)| *k)
                .collect();
            if device_sessions.len() >= MAX_SESSIONS_PER_DEVICE {
                if let Some((oldest_key, _s)) = sessions
                    .iter()
                    .filter(|(_, s)| s.device_id == ab.device_id)
                    .min_by_key(|(_, s)| s.last_seen)
                {
                    let oldest_key = *oldest_key;
                    let removed = sessions.remove(&oldest_key);
                    if let Some(r) = removed {
                        evicted_ik_x.push(r.ik_x);
                    }
                }
            }
            sessions.insert(
                ek_c,
                SessionEntry {
                    session_pub: ek_c,
                    device_id: ab.device_id.clone(),
                    ik_x: hdr.sender_public_key,
                    ip: ab.cert.allowed_ip.clone(),
                    sk: SessionKey::new(sk),
                    counter_rx: 0,
                    last_seen: now,
                    room,
                },
            );
        }
        // 增量维护活跃 ik_x 索引（O(1)）：新会话的 ik_x 必须入集；被淘汰会话的 ik_x
        // 仅当已无任何会话引用时才移除。取代每次 AUTH 全表重建 O(S)，避免并发认证串行化。
        {
            let mut active = self.active_ik_x.lock().await;
            active.insert(hdr.sender_public_key);
            for ik in evicted_ik_x {
                if !self.sessions.lock().await.values().any(|s| s.ik_x == ik) {
                    active.remove(&ik);
                }
            }
        }
        // 8) AUTH_RESP（用握手期静态密钥加密：客户端尚不知 SK）
        // 在锁内构造好响应（需读 mesh CRL/ServerInfo），随后释放 mesh 锁再异步发送，
        // 避免长持全局 mesh 锁把并发 AUTH/JOIN 串行化。
        let info = self.build_server_info(&mesh)?;
        let crl = mesh.crl.clone();
        drop(mesh);
        let resp = AuthRespBody {
            ek_s: B64.encode(ek_s_kp.public),
            session_id,
            crl,
            server_info: info,
            allocated_ip: ab.cert.allowed_ip.clone(),
        };
        let resp_pt = encode_auth_resp(&resp).map_err(|e| format!("序列化失败: {e}"))?;
        let ct = crypto::encrypt(&shared, &resp_pt);
        let frame = frame_signaling(MSG_AUTH_RESP, &self.server_pub, &ct);
        self.sock
            .send_to(&frame, src)
            .await
            .map_err(|e| format!("AUTH_RESP 发送失败: {e}"))?;
        self.log.info(format!(
            "设备 {} 认证成功（session {}，IP {}）",
            ab.device_id,
            session_short,
            ab.cert.allowed_ip
        ));
        Ok(())
    }
    /// 会话期信令：sender = ek_c，负载用 SK + 计数器 nonce 加密。
    async fn handle_session_signaling(
        &self,
        hdr: &linkmesh_shared::protocol::PacketHeader,
        packet: &[u8],
        src: SocketAddr,
    ) -> Result<(), String> {
        let (session_sk, session_ik_x, session_ip, next_seq, session_id, session_room) = {
            let sessions = self.sessions.lock().await;
            let s = match sessions.get(&hdr.sender_public_key) {
                Some(s) => s,
                None => {
                    self.log.warn("会话期信令来自未知会话");
                    return Ok(());
                }
            };
            (
                *s.sk.as_raw(),
                s.ik_x,
                s.ip.clone(),
                s.counter_rx + 1,
                s.device_id.clone(),
                s.room.clone(),
            )
        };
        // 确定性 nonce：方向位 0（客户端→服务端），计数器必须严格递增
        let nonce = crypto::session_nonce(next_seq, 0);
        let plaintext = match crypto::decrypt_with_nonce(&session_sk, &nonce, &packet[HEADER_LEN..]) {
            Ok(p) => p,
            Err(_) => {
                self.log.warn(format!("会话 {session_id} 信令计数器/nonce 校验失败（重放或乱序）"));
                return Ok(());
            }
        };
        // 推进计数器（仅在校验通过后）
        {
            let mut sessions = self.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&hdr.sender_public_key) {
                s.counter_rx = next_seq;
                s.last_seen = now_secs();
            }
        }

        let resp: ResponseBody = match hdr.msg_type {
            MSG_REGISTER => {
                let rb: RegisterBody = decode_register(&plaintext)
                    .map_err(|e| format!("注册消息格式错误: {e}"))?;
                // 上报 IP 必须与证书绑定一致（防 IP 抢占）
                if rb.ip != session_ip {
                    return self
                        .send_error(
                            &session_sk,
                            src,
                            &format!("虚拟 IP {} 与证书绑定不符（应注册 {session_ip}），拒绝注册", rb.ip),
                        )
                        .await;
                }
                // 会话期令牌不得与 AUTH 绑定的房间冲突（房间以 AUTH 为准）
                if let Some(tok) = rb.token.as_deref() {
                    if !tok.trim().is_empty() {
                        let tok_room = match self.resolve_room(Some(tok)).await {
                            Ok(r) => r,
                            Err(_) => session_room.clone(),
                        };
                        if tok_room != session_room {
                            self.log.warn(format!(
                                "会话 {} 令牌与 AUTH 房间不一致（{} vs {}），以 AUTH 为准",
                                session_id, tok_room, session_room
                            ));
                        }
                    }
                }
                // 设备自报别名（格式校验；优先使用 JOIN 登记的成员别名）
                let alias = match Self::normalize_self_alias(rb.alias.as_deref()) {
                    Ok(a) => a,
                    Err(e) => return self.send_error(&session_sk, src, &e).await,
                };
                self.routes.lock().await.upsert(RouteEntry {
                    public_key: session_ik_x,
                    ip: session_ip.clone(),
                    endpoint: src.to_string(),
                    last_seen: now_secs(),
                    relay_rk: rb.relay_rk,
                    room: session_room.clone(),
                    alias,
                });
                ResponseBody::ok()
            }
            MSG_HEARTBEAT => {
                let mut routes = self.routes.lock().await;
                if let Some(e) = routes.get(&session_ik_x) {
                    let ip = e.ip.clone();
                    let relay_rk = e.relay_rk.clone();
                    let alias = e.alias.clone();
                    routes.upsert(RouteEntry {
                        public_key: session_ik_x,
                        ip,
                        endpoint: src.to_string(),
                        last_seen: now_secs(),
                        relay_rk,
                        room: session_room.clone(),
                        alias,
                    });
                }
                ResponseBody::ok()
            }
            MSG_BYE => {
                self.routes.lock().await.remove(&session_ik_x);
                self.sessions.lock().await.remove(&hdr.sender_public_key);
                self.rebuild_active_ik_x().await;
                ResponseBody::ok()
            }
            MSG_QUERY => {
                let qb: QueryBody =
                    decode_query(&plaintext).map_err(|e| format!("查询消息格式错误: {e}"))?;
                // 目标解析：按别名或按 IP（仅限同房间）
                let target_ip = match &qb.name {
                    Some(name) => {
                        let name = name.trim().to_lowercase();
                        if name.is_empty() {
                            None
                        } else {
                            self.resolve_alias(&name).await
                        }
                    }
                    None => Some(qb.ip.clone()),
                };
                let target = match target_ip {
                    Some(ip) => {
                        let routes = self.routes.lock().await;
                        routes.get_by_ip(&ip).cloned()
                    }
                    None => None,
                };
                // 条件判定：跨房间查询按「目标未上线」响应，不泄露目标是否存在
                let target = target.filter(|e| e.room == session_room);
                match target {
                    Some(entry) => {
                        let data = ResponseData::QueryHit {
                            req: qb.name.clone().unwrap_or(qb.ip.clone()),
                            ip: entry.ip.clone(),
                            public_key: B64.encode(entry.public_key),
                            endpoint: entry.endpoint.clone(),
                            relay_rk: entry.relay_rk.clone(),
                            alias: qb.name.clone().or(entry.alias.clone()).unwrap_or_default(),
                        };
                        self.notify_peer(&entry, session_ik_x, src, &session_room).await;
                        ResponseBody::ok_with_data(data)
                    }
                    None => ResponseBody {
                        ok: false,
                        data: ResponseData::QueryMiss {
                            req: qb.name.clone().unwrap_or(qb.ip.clone()),
                            error: format!("目标 {} 未上线", qb.name.clone().unwrap_or(qb.ip.clone())),
                        },
                        error: Some(format!("目标 {} 未上线", qb.name.clone().unwrap_or(qb.ip.clone()))),
                    },
                }
            }
            _ => ResponseBody::err("不支持的消息类型"),
        };

        // 会话期响应：方向位 1，同计数器
        let resp_pt = encode_response(&resp).map_err(|e| format!("响应序列化失败: {e}"))?;
        let nonce = crypto::session_nonce(next_seq, 1);
        let ct = crypto::encrypt_with_nonce(&session_sk, &nonce, &resp_pt);
        let frame = frame_signaling(MSG_RESPONSE, &self.server_pub, &ct);
        self.sock
            .send_to(&frame, src)
            .await
            .map_err(|e| format!("响应发送失败: {e}"))?;
        Ok(())
    }

    /// 握手期 nonce 重放缓存：每设备环形缓存最近 64 个 nonce。
    async fn replay_check(&self, ik_x: &RawKey, nonce: &[u8; 12]) -> bool {
        let mut replay = self.replay.lock().await;
        let q = replay.entry(*ik_x).or_insert_with(VecDeque::new);
        if q.iter().any(|n| n == nonce) {
            return false;
        }
        q.push_back(*nonce);
        if q.len() > 64 {
            q.pop_front();
        }
        true
    }

    /// AUTH/JOIN 限速：每源 IP 每分钟最多 20 次（防枚举与刷码）。
    async fn rate_limited(&self, src: SocketAddr) -> bool {
        const WINDOW: u64 = 60;
        // 0 = 不限速；其余为每源 IP 每窗口上限。
        if self.join_rate_limit == 0 {
            return false;
        }
        let limit = self.join_rate_limit;
        let now = now_secs();
        let mut l = self.rate_limits.lock().await;
        // 按 IP 聚合（忽略端口）：防止攻击者轮换源端口绕过限速并无限增长限速表。
        let key = src.ip();
        let e = l.entry(key).or_insert((now, 0usize));
        if now.saturating_sub(e.0) >= WINDOW {
            *e = (now, 1);
            return false;
        }
        e.1 += 1;
        e.1 > limit
    }

    async fn send_ok(&self, shared: &RawKey, src: SocketAddr) -> Result<(), String> {
        let pt = encode_response(&ResponseBody::ok()).map_err(|e| format!("序列化失败: {e}"))?;
        let ct = crypto::encrypt(shared, &pt);
        let frame = frame_signaling(MSG_RESPONSE, &self.server_pub, &ct);
        self.sock
            .send_to(&frame, src)
            .await
            .map(|_| ())
            .map_err(|e| format!("响应发送失败: {e}"))
    }

    /// 吊销设备：更新 mesh CRL 并立即踢掉该设备全部会话与路由条目。
    pub async fn revoke_device(&self, device_id: &str, reason: linkmesh_shared::cert::RevokeReason) -> Result<u64, String> {
        let mesh = &self.mesh;
        let new_version = {
            let mut mesh = mesh.lock().await;
            let crl = mesh.revoke(device_id, reason)?;
            if let Err(e) = mesh.save(Path::new(&self.mesh_path)) {
                self.log.warn(format!("mesh.json 持久化失败: {e}"));
            }
            crl.version
        };
        // 踢掉该设备全部会话
        let kicked = {
            let mut sessions = self.sessions.lock().await;
            let victims: Vec<(RawKey, RawKey)> = sessions
                .iter()
                .filter(|(_, s)| s.device_id == device_id)
                .map(|(k, s)| (*k, s.ik_x))
                .collect();
            for (k, _) in &victims {
                sessions.remove(k);
            }
            victims
        };
        self.rebuild_active_ik_x().await;
        for (_, ik_x) in &kicked {
            self.routes.lock().await.remove(ik_x);
        }
        self.log.info(format!(
            "设备 {device_id} 已吊销（CRL v{new_version}），踢掉 {} 个活动会话",
            kicked.len()
        ));
        Ok(new_version)
    }

    /// 主动通知目标 peer：查询者（sender_pub, src）正在找你。
    /// 仅通知同房间目标（跨房间不通知，防信息泄露）。
    async fn notify_peer(
        &self,
        target: &RouteEntry,
        sender_pub: RawKey,
        src: SocketAddr,
        querier_room: &str,
    ) {
        if target.room != querier_room {
            return;
        }
        // 通知内容应描述「查询者」（sender）：其公钥、坐标、IP 与别名
        let sender_info = {
            let routes = self.routes.lock().await;
            routes.get(&sender_pub).cloned()
        };
        let (sender_rk, sender_alias, sender_ip) = sender_info
            .map(|e| (e.relay_rk, e.alias, Some(e.ip)))
            .unwrap_or((None, None, None));
        let body = NotifyBody {
            peer: linkmesh_shared::protocol::PeerInfo {
                public_key: B64.encode(sender_pub),
                endpoint: src.to_string(),
                relay_rk: sender_rk,
                alias: sender_alias,
                ip: sender_ip,
            },
        };
        let Ok(pt) = encode_notify(&body) else {
            return;
        };
        let shared = crypto::shared_secret(&self.server_priv, &target.public_key);
        let ct = crypto::encrypt(&shared, &pt);
        let frame = frame_signaling(MSG_NOTIFY, &self.server_pub, &ct);
        let Ok(addr) = target.endpoint.parse::<SocketAddr>() else {
            return;
        };
        let _ = self.sock.send_to(&frame, addr).await;
    }

    /// 路由表与认证会话定期清理过期条目。
    ///
    /// 条件判定：认证会话（sessions）超过 route_ttl_sec 无任何会话期信令即视为失联，
    /// 连同其路由条目一并移除——客户端每 20s 心跳刷新，正常在线不会误删；
    /// 突然掉线（无 BYE）的客户端在此处被回收，防止会话表无限膨胀。
    pub async fn cleanup_loop(self: Arc<Self>) {
        loop {
            sleep(Duration::from_secs(self.route_ttl_sec.max(10))).await;
            let now = now_secs();
            self.routes.lock().await.cleanup(now, self.route_ttl_sec);
            // 定期裁剪限速表：窗口翻转后条目已失去价值，清理避免长期运行无界增长
            {
                let mut rl = self.rate_limits.lock().await;
                rl.retain(|_, (t, _)| now.saturating_sub(*t) < 60);
            }
            let ttl = self.route_ttl_sec.max(60);
            let expired: Vec<RawKey> = {
                let sessions = self.sessions.lock().await;
                sessions
                    .iter()
                    .filter(|(_, s)| now.saturating_sub(s.last_seen) > ttl)
                    .map(|(k, _)| *k)
                    .collect()
            };
            for k in &expired {
                let ik_x = {
                    self.sessions.lock().await.remove(k).map(|s| s.ik_x)
                };
                if let Some(ik) = ik_x {
                    self.routes.lock().await.remove(&ik);
                }
            }
            if !expired.is_empty() {
                self.rebuild_active_ik_x().await;
                self.log.info(format!("清理 {} 个过期认证会话", expired.len()));
            }
        }
    }

    /// 会话表增删后重建活跃 ik_x 索引（O(1) 中继来源校验）。
    ///
    /// 会话增删是低频事件（AUTH/BYE/吊销/清理），重建开销可忽略；
    /// 换取数据面每包来源校验从 O(会话数) 降到 O(1)。
    pub async fn rebuild_active_ik_x(&self) {
        let mut active = self.active_ik_x.lock().await;
        active.clear();
        let sessions = self.sessions.lock().await;
        for s in sessions.values() {
            active.insert(s.ik_x);
        }
    }
}

/// 判断来源公钥是否有活跃会话（中继来源校验，mesh 模式）。
///
/// O(1)：查维护好的活跃 ik_x 索引，不再每包遍历整个会话表。
async fn sessions_has_active(active_ik_x: &Arc<Mutex<std::collections::HashSet<RawKey>>>, src_key: &RawKey) -> bool {
    active_ik_x.lock().await.contains(src_key)
}
/// 通用中继转发：读取目标公钥/路由密钥，更新来源端点，把封包投递给目标。
///
/// 若批量中继可用（`batcher` 为 Some），把子帧（src_pub + ciphertext）入队聚合，
/// 由工作线程按窗口/上限拼成大 UDP 载荷发出；否则按原有逻辑逐帧直发。
///
/// 支持两种中继格式：
/// - `MSG_RELAY`（旧）：头部为长期身份密钥 ik_x，dest 直接查路由表；
/// - `MSG_RELAY_RK`（P1-7）：头部为短期路由密钥 rk，dest 经 rk 索引查路由，
///   线上不再暴露长期身份密钥。
///
/// 来源校验（堵住「伪造来源投毒」）：来源必须是**活跃会话**的 ik_x（或已登记 rk）。
/// mesh 强制认证下，无活跃会话即无中继资格。
///
/// 房间隔离（令牌验证开启时）：来源房间与目标房间必须一致，否则静默丢弃——
/// 跨房间设备既不能互相中继数据，也不能借中继探测对方存在。
#[allow(clippy::too_many_arguments)]
pub async fn relay_forward(
    sock: Arc<UdpSocket>,
    routes: Arc<Mutex<RouteTable>>,
    stats: Arc<Stats>,
    batcher: Option<&RelayBatcher>,
    active_ik_x: &Arc<Mutex<std::collections::HashSet<RawKey>>>,
    rooms: &Arc<Mutex<Vec<RoomEntry>>>,
    packet: &[u8],
    _src: SocketAddr,
) -> Result<(), String> {
    let is_rk = packet.len() >= RELAY_HEADER_LEN && packet[3] == MSG_RELAY_RK;
    let (dest, src_key, ct) = parse_relay(packet)?;

    if is_rk {
        // rk 帧：来源 rk 必须已登记（路由表 by_rk），且对应公钥有活跃会话
        let src_b64 = B64.encode(src_key);
        let ok = {
            let routes = routes.lock().await;
            match routes.get_by_rk(&src_b64) {
                Some(e) => sessions_has_active(active_ik_x, &e.public_key).await,
                None => false,
            }
        };
        if !ok {
            return Ok(()); // 未登记 rk 或对应会话不活跃：丢弃
        }
    } else if !sessions_has_active(active_ik_x, &src_key).await {
        return Ok(()); // 无活跃会话的来源：静默丢弃（防伪造投毒）
    }
    // 刷新来源路由条目（仅 ik_x 格式可映射到公钥路由；rk 格式由注册/心跳刷新）
    if !is_rk {
        let mut routes = routes.lock().await;
        if let Some(entry) = routes.get(&src_key) {
            let ip = entry.ip.clone();
            let endpoint = entry.endpoint.clone();
            let relay_rk = entry.relay_rk.clone();
            let room = entry.room.clone();
            let alias = entry.alias.clone();
            routes.upsert(RouteEntry {
                public_key: src_key,
                ip,
                endpoint,
                last_seen: now_secs(),
                relay_rk,
                room,
                alias,
            });
        }
    }
    let (dest_entry, src_room) = {
        let routes = routes.lock().await;
        let src_entry = if is_rk {
            routes.get_by_rk(&B64.encode(src_key)).cloned()
        } else {
            routes.get(&src_key).cloned()
        };
        let de = if is_rk {
            routes.get_by_rk(&B64.encode(dest)).cloned()
        } else {
            routes.get(&dest).cloned()
        };
        (de, src_entry.map(|e| e.room))
    };
    // 房间隔离：来源房间与目标房间必须一致，否则静默丢弃（不泄露目标存在性）。
    // 启用令牌验证时，无法确定来源房间（未注册/无路由条目）的来源一律丢弃。
    {
        let rooms_enabled = !rooms.lock().await.is_empty();
        let dest_room = dest_entry.as_ref().map(|e| e.room.clone());
        match (src_room, dest_room) {
            (Some(sr), Some(dr)) => {
                if sr != dr {
                    return Ok(());
                }
            }
            (None, _) if rooms_enabled => return Ok(()),
            _ => {}
        }
    }
    if let Some(entry) = dest_entry {
        let addr: SocketAddr = entry
            .endpoint
            .parse()
            .map_err(|e| format!("端点解析失败: {e}"))?;

        // 批量路径：子帧 = src_pub + ciphertext，接收端按批量头拆分还原
        if let Some(b) = batcher {
            let mut subframe = Vec::with_capacity(32 + ct.len());
            subframe.extend_from_slice(&src_key);
            subframe.extend_from_slice(ct);
            if b.enqueue(BatchItem {
                dest,
                addr,
                subframe,
            }) {
                return Ok(());
            }
        }

        sock.send_to(packet, addr)
            .await
            .map_err(|e| format!("中继转发失败: {e}"))?;
        stats.packets_out.fetch_add(1, Ordering::Relaxed);
        stats.bytes_relayed.fetch_add(packet.len() as u64, Ordering::Relaxed);
    }
    // 目标不在线：丢弃（数据面不可靠，由客户端心跳/重试兜底）
    Ok(())
}

/// 独立中继端口的主循环。
pub async fn relay_loop(
    sock: Arc<UdpSocket>,
    routes: Arc<Mutex<RouteTable>>,
    stats: Arc<Stats>,
    batcher: Option<RelayBatcher>,
    active_ik_x: Arc<Mutex<std::collections::HashSet<RawKey>>>,
    rooms: Arc<Mutex<Vec<RoomEntry>>>,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let packet = buf[..len].to_vec();
                if let Err(_e) = relay_forward(
                    sock.clone(),
                    routes.clone(),
                    stats.clone(),
                    batcher.as_ref(),
                    &active_ik_x,
                    &rooms,
                    &packet,
                    src,
                )
                .await
                {
                    // 解析失败的中继封包直接丢弃
                }
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

