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

//! 内嵌 DNS 应答器：把网格内别名（如 `computer`）解析为虚拟 IP，
//! 使系统应用可以直接使用 `computer:8080` 这类地址访问对端（无需手写 IP）。
//!
//! 解析来源（按顺序）：
//! 1. 本地 `client.json` 的 `aliases`（管理员/用户自定义）；
//! 2. 从服务端学到的别名映射（QUERY 响应 / NOTIFY 携带的 alias，带 60s 缓存）；
//! 3. 逐条已连接（Conn 注册的解析器）：向所属服务器按名查询（服务端在**同一房间内**
//!    解析管理员别名表与设备自报别名，跨房间一律视为未知）。
//!
//! 安全边界：
//! - 只回答本网格已知别名，**不向任何上游 DNS 转发**（杜绝开放解析器滥用/信息泄露）；
//! - 未知名称返回 NXDOMAIN；非 A 记录返回 NOERROR 空应答；
//! - 仅监听本地回环（默认 `127.0.0.1:5353`，可配置为 0.0.0.0）。

use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};

use crate::log::Logger;

/// 名称解析器：由每条已连接的 Conn 注册，DNS 服务器对未命中缓存的名称逐个询问。
/// 每个解析器在其所属服务器的**房间内**解析（服务端强制同房间隔离）。
pub type NameResolver =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> + Send + Sync>;

/// 名称 → IP 缓存（带时间戳，TTL 内复用）与活动解析器注册表。
#[derive(Clone)]
pub struct DnsRegistry {
    cache: Arc<Mutex<HashMap<String, (String, Instant)>>>,
    resolvers: Arc<Mutex<Vec<(u64, NameResolver)>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

/// 缓存有效期。
const CACHE_TTL: Duration = Duration::from_secs(60);

impl Default for DnsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsRegistry {
    pub fn new() -> Self {
        DnsRegistry {
            cache: Arc::new(Mutex::new(HashMap::new())),
            resolvers: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// 直接写入一条 名称→IP（本地别名 / 服务端学到的别名）。
    pub async fn insert(&self, name: &str, ip: &str) {
        let name = name.trim().to_lowercase();
        if name.is_empty() || ip.parse::<Ipv4Addr>().is_err() {
            return;
        }
        self.cache
            .lock()
            .await
            .insert(name.to_string(), (ip.to_string(), Instant::now()));
    }

    /// 注册一个解析器，返回注册 id（断开时用 [DnsRegistry::unregister] 移除）。
    pub async fn register(&self, r: NameResolver) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.resolvers.lock().await.push((id, r));
        id
    }

    /// 注销解析器。
    pub async fn unregister(&self, id: u64) {
        self.resolvers.lock().await.retain(|(i, _)| *i != id);
    }

    /// 解析名称：缓存 → 活动解析器（首中即返）。未解析到返回 None。
    pub async fn resolve(&self, name: &str) -> Option<String> {
        let key = name.trim().to_lowercase();
        if key.is_empty() {
            return None;
        }
        {
            let cache = self.cache.lock().await;
            if let Some((ip, at)) = cache.get(&key) {
                if at.elapsed() < CACHE_TTL {
                    return Some(ip.clone());
                }
            }
        }
        let resolvers = self.resolvers.lock().await.clone();
        for (_, r) in resolvers {
            if let Some(ip) = r(key.clone()).await {
                self.cache.lock().await.insert(key.clone(), (ip.clone(), Instant::now()));
                return Some(ip);
            }
        }
        None
    }

    /// 缓存的名称快照（供 `--resolve --list` / 调试）。
    pub async fn cached_names(&self) -> Vec<(String, String)> {
        let cache = self.cache.lock().await;
        let mut v: Vec<(String, String)> = cache
            .iter()
            .map(|(n, (ip, _))| (n.clone(), ip.clone()))
            .collect();
        v.sort();
        v
    }
}

// ---------- DNS 报文 ----------

/// 解析一条 DNS 查询，返回 (事务 ID, 规范化名称, QTYPE)。非法/非标准查询返回 None。
fn parse_query(pkt: &[u8]) -> Option<(u16, String, u16)> {
    if pkt.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    // 必须是查询方向（QR=0）且只有 1 个问题（多问题/响应一律忽略）
    if flags & 0x8000 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut pos = 12;
    let mut name = String::new();
    loop {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 || pos + len > pkt.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&pkt[pos..pos + len]));
        pos += len;
    }
    if pos + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    Some((txid, name.trim_end_matches('.').to_lowercase(), qtype))
}

/// 编码 DNS 名称（长度前缀标签）。
fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// 构造 DNS 应答。
/// - `ip = Some`：A 记录 + NOERROR；
/// - `ip = None, nxdomain = true`：NXDOMAIN（未知名称）；
/// - `ip = None, nxdomain = false`：NOERROR 空应答（如非 A 记录查询）。
fn build_response(txid: u16, qname: &str, qtype: u16, ip: Option<Ipv4Addr>, nxdomain: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&txid.to_be_bytes());
    let flags: u16 = if nxdomain { 0x8183 } else { 0x8180 };
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&u16::from(ip.is_some()).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT / ARCOUNT
    encode_name(&mut out, qname);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    if let Some(ip) = ip {
        out.extend_from_slice(&[0xC0, 0x0C]); // 指针指向 QNAME
        out.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        out.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// 处理一条 DNS 查询。非法查询返回 None（不响应）；合法查询总是返回应答。
async fn handle_query(registry: &DnsRegistry, pkt: &[u8]) -> Option<Vec<u8>> {
    let (txid, name, qtype) = parse_query(pkt)?;
    if name.is_empty() {
        return None;
    }
    if qtype != 1 {
        // 只应答 A 记录；其他类型返回 NOERROR 空应答（不泄露存在性）
        return Some(build_response(txid, &name, qtype, None, false));
    }
    let ip = registry
        .resolve(&name)
        .await
        .and_then(|s| s.parse::<Ipv4Addr>().ok());
    Some(build_response(txid, &name, qtype, ip, ip.is_none()))
}

/// 启动 DNS 应答器（绑定 `bind:port`）。`quit` 收到 true 时退出。
pub async fn serve(
    registry: Arc<DnsRegistry>,
    bind: &str,
    port: u16,
    quit: watch::Receiver<bool>,
    log: Logger,
) -> Result<(), String> {
    if port == 0 {
        return Err("dns.port 不能为 0".into());
    }
    let sock = UdpSocket::bind(format!("{bind}:{port}"))
        .await
        .map_err(|e| format!("DNS 监听 {bind}:{port} 失败: {e}（可调整 dns.bind/dns.port）"))?;
    let local = sock.local_addr().map_err(|e| e.to_string())?;
    log.info(format!("内嵌 DNS 应答器已启动：udp {local}（解析网格别名）"));
    serve_on(sock, registry, quit, log).await
}

/// 在已绑定的套接字上运行 DNS 应答器（供测试复用）。
pub async fn serve_on(
    sock: UdpSocket,
    registry: Arc<DnsRegistry>,
    mut quit: watch::Receiver<bool>,
    log: Logger,
) -> Result<(), String> {
    let mut buf = vec![0u8; 512];
    loop {
        tokio::select! {
            _ = quit.changed() => break,
            r = sock.recv_from(&mut buf) => {
                match r {
                    Ok((len, src)) => {
                        let pkt = buf[..len].to_vec();
                        if let Some(resp) = handle_query(&registry, &pkt).await {
                            let _ = sock.send_to(&resp, src).await;
                        }
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        }
    }
    log.info("内嵌 DNS 应答器已停止");
    Ok(())
}

/// 仅用于测试的同步查询入口。
pub async fn resolve_for_test(registry: &DnsRegistry, name: &str) -> Option<String> {
    registry.resolve(name).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_query(name: &str) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // txid
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.').filter(|l| !l.is_empty()) {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        pkt
    }

    #[test]
    fn parse_query_basic() {
        let (txid, name, qtype) = parse_query(&sample_query("computer.")).unwrap();
        assert_eq!(txid, 0x1234);
        assert_eq!(name, "computer");
        assert_eq!(qtype, 1);
        // 多级名称 + 尾点
        let (_, name2, _) = parse_query(&sample_query("nas.office.local.")).unwrap();
        assert_eq!(name2, "nas.office.local");
    }

    #[test]
    fn parse_query_rejects_garbage() {
        assert!(parse_query(&[0u8; 3]).is_none());
        assert!(parse_query(&[0u8; 12]).is_none()); // 无 QDCOUNT/名称
        let mut resp = sample_query("x.");
        resp[2] = 0x81; // 伪造 QR=1（响应方向）
        assert!(parse_query(&resp).is_none());
    }

    #[test]
    fn build_response_roundtrip() {
        let q = sample_query("computer.");
        let (txid, name, qtype) = parse_query(&q).unwrap();
        let resp = build_response(txid, &name, qtype, Some(Ipv4Addr::new(10, 13, 13, 5)), false);
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), txid);
        assert_eq!(resp[3] & 0x80, 0x80, "QR 位必须为响应");
        // ANCOUNT = 1
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        // 答案 RDATA = 10.13.13.5
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[10, 13, 13, 5]);
        // NXDOMAIN
        let nx = build_response(txid, &name, qtype, None, true);
        assert_eq!(nx[3] & 0x0F, 3, "rcode 应为 NXDOMAIN(3)");
        assert_eq!(u16::from_be_bytes([nx[6], nx[7]]), 0);
    }

    #[tokio::test]
    async fn registry_resolves_from_registered_resolver() {
        let reg = Arc::new(DnsRegistry::new());
        reg.insert("nas", "10.13.13.9").await;
        assert_eq!(resolve_for_test(&reg, "nas").await.as_deref(), Some("10.13.13.9"));
        // 未注册的名称走解析器
        let resolver: NameResolver = Arc::new(|name: String| {
            Box::pin(async move {
                if name == "computer" {
                    Some("10.13.13.5".to_string())
                } else {
                    None
                }
            })
        });
        let id = reg.register(resolver).await;
        assert_eq!(resolve_for_test(&reg, "computer").await.as_deref(), Some("10.13.13.5"));
        // 注销后：已缓存名称在 TTL 内仍可解析，但新名称不再走已注销的解析器
        reg.unregister(id).await;
        assert_eq!(resolve_for_test(&reg, "computer").await.as_deref(), Some("10.13.13.5"));
        assert_eq!(resolve_for_test(&reg, "another-new-name").await, None);
        // 大小写不敏感
        assert_eq!(resolve_for_test(&reg, "NAS").await.as_deref(), Some("10.13.13.9"));
    }

    #[tokio::test]
    async fn handle_query_end_to_end() {
        let reg = Arc::new(DnsRegistry::new());
        reg.insert("computer", "10.13.13.5").await;
        let q = sample_query("computer.");
        let resp = handle_query(&reg, &q).await.unwrap();
        assert_eq!(resp[3] & 0x80, 0x80);
        assert_eq!(&resp[resp.len() - 4..], &[10, 13, 13, 5]);
        // 未知名称 → NXDOMAIN
        let q2 = sample_query("ghost.");
        let resp2 = handle_query(&reg, &q2).await.unwrap();
        assert_eq!(resp2[3] & 0x0F, 3);
        // AAAA 查询 → NOERROR 空应答
        let mut q3 = sample_query("computer.");
        let n = q3.len();
        q3[n - 4] = 0;
        q3[n - 3] = 28; // QTYPE AAAA
        let resp3 = handle_query(&reg, &q3).await.unwrap();
        assert_eq!(resp3[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([resp3[6], resp3[7]]), 0);
    }

    #[tokio::test]
    async fn udp_server_answers_query() {
        use tokio::net::UdpSocket as TokioUdp;
        let reg = Arc::new(DnsRegistry::new());
        reg.insert("computer", "10.13.13.5").await;
        let (quit_tx, quit_rx) = watch::channel(false);
        let log = Logger::new(&std::env::temp_dir().join("linkmesh_test_dns.log"));
        let sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let reg2 = reg.clone();
        let server = tokio::spawn(async move {
            let _ = serve_on(sock, reg2, quit_rx, log).await;
        });
        // 客户端查询
        let client = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&sample_query("computer."), addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("DNS 应答超时")
            .unwrap();
        let resp = &buf[..n];
        assert_eq!(resp[3] & 0x80, 0x80, "QR 位必须为响应");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT=1");
        assert_eq!(&resp[n - 4..], &[10, 13, 13, 5]);
        // 未知名称 → NXDOMAIN
        client.send_to(&sample_query("ghost."), addr).await.unwrap();
        let (n2, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("NXDOMAIN 应答超时")
            .unwrap();
        let _ = n2;
        assert_eq!(buf[3] & 0x0F, 3, "rcode 应为 NXDOMAIN(3)");
        let _ = quit_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }
}
