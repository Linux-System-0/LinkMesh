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

//! 数据面基准 + 安全测试工具（无需 TUN / root）。
//!
//! 通过 `Conn` 的注入/输出通道收发 IP 包，走真实信令/中继/直连链路，
//! 用于模拟不同环境（直连/中继）、不同数据包大小、不同响应速度下的数据传输，
//! 以及安全验证（离线解密、伪造中继、重放、IP 抢占等）。
//!
//! 用法示例：
//!   bench --config a.json --mode send   --peer 10.13.13.3 --size 512 --count 50 --interval-ms 100
//!   bench --config b.json --mode recv   --peer 10.13.13.2
//!   bench --config a.json --decrypt cap.bin
//!   bench --config a.json --reg 10.13.13.99
//!   bench --config a.json --query 10.13.13.99
//!   bench --config a.json --flood <dest_pub_b64> 100 512

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_client::config::ClientConfig;
use linkmesh_client::connection::Conn;
use linkmesh_client::log::Logger;
use linkmesh_shared::crypto::{self, RawKey};
use linkmesh_shared::protocol::{
    decode_response, decode_server_info_body, encode_query, encode_register, frame_relay,
    frame_signaling, parse_header, parse_relay, HEADER_LEN, MSG_QUERY, MSG_REGISTER, MSG_SERVERINFO,
    QueryBody, RegisterBody, ResponseBody, ResponseData, ServerInfoBody,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

const PROBE_MAGIC: &[u8; 4] = b"LMB1";
const REPLY_MAGIC: &[u8; 4] = b"LMBR";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 构造最小合法 IPv4 包，目的 IP 为 `dst`，源 IP 为 `src`，载荷为 `payload`。
fn build_ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45);
    pkt.push(0);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0x4000u16.to_be_bytes());
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(payload);
    pkt
}

fn parse_ip(pkt: &[u8]) -> Option<([u8; 4], [u8; 4], &[u8])> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&pkt[12..16]);
    dst.copy_from_slice(&pkt[16..20]);
    Some((src, dst, &pkt[20..]))
}

/// 探测载荷：[LMB1][seq u64][send_ms u64][plen u16][filler]
fn build_probe(seq: u64, size: usize) -> Vec<u8> {
    let plen = size.saturating_sub(22);
    let mut v = Vec::with_capacity(size);
    v.extend_from_slice(PROBE_MAGIC);
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&now_ms().to_be_bytes());
    v.extend_from_slice(&(plen as u16).to_be_bytes());
    let fill = (seq as u8).wrapping_mul(31).wrapping_add(7);
    while v.len() < size {
        v.push(fill);
    }
    v
}

fn build_reply(probe: &[u8], recv_ms: u64) -> Option<Vec<u8>> {
    if probe.len() < 22 || &probe[..4] != PROBE_MAGIC {
        return None;
    }
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&probe[4..12]);
    let mut send = [0u8; 8];
    send.copy_from_slice(&probe[12..20]);
    let plen = u16::from_be_bytes([probe[20], probe[21]]) as usize;
    let size = 30 + plen;
    let mut v = Vec::with_capacity(size);
    v.extend_from_slice(REPLY_MAGIC);
    v.extend_from_slice(&seq);
    v.extend_from_slice(&send);
    v.extend_from_slice(&recv_ms.to_be_bytes());
    v.extend_from_slice(&(plen as u16).to_be_bytes());
    let fill = probe.get(22).copied().unwrap_or(0xAA);
    while v.len() < size {
        v.push(fill);
    }
    Some(v)
}

fn parse_reply(pkt: &[u8]) -> Option<(u64, u64, u64)> {
    if pkt.len() < 30 || &pkt[..4] != REPLY_MAGIC {
        return None;
    }
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&pkt[4..12]);
    let mut send = [0u8; 8];
    send.copy_from_slice(&pkt[12..20]);
    let mut recv = [0u8; 8];
    recv.copy_from_slice(&pkt[20..28]);
    Some((
        u64::from_be_bytes(seq),
        u64::from_be_bytes(send),
        u64::from_be_bytes(recv),
    ))
}

fn args() -> Vec<String> {
    std::env::args().skip(1).collect()
}

fn arg_val(args: &[String], name: &str, default: &str) -> String {
    for i in 0..args.len() {
        if args[i] == name {
            return args.get(i + 1).cloned().unwrap_or_else(|| default.to_string());
        }
    }
    default.to_string()
}

fn arg_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// 读取 UDP 套接字当前收发缓冲大小（调试用）。
fn get_udp_buffers(sock: &std::net::UdpSocket) -> (i32, i32) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        unsafe {
            let mut rcv: libc::c_int = 0;
            let mut snd: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &mut rcv as *mut _ as *mut libc::c_void,
                &mut len,
            );
            let mut len2 = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &mut snd as *mut _ as *mut libc::c_void,
                &mut len2,
            );
            (rcv, snd)
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        let s = sock.as_raw_socket() as libc::SOCKET;
        const SOL_SOCKET: libc::c_int = 0xffff;
        const SO_RCVBUF: libc::c_int = 0x1002;
        const SO_SNDBUF: libc::c_int = 0x1001;
        unsafe {
            let mut rcv: libc::c_int = 0;
            let mut snd: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::c_int;
            libc::getsockopt(
                s,
                SOL_SOCKET,
                SO_RCVBUF,
                &mut rcv as *mut _ as *mut libc::c_char,
                &mut len,
            );
            let mut len2 = std::mem::size_of::<libc::c_int>() as libc::c_int;
            libc::getsockopt(
                s,
                SOL_SOCKET,
                SO_SNDBUF,
                &mut snd as *mut _ as *mut libc::c_char,
                &mut len2,
            );
            (rcv, snd)
        }
    }
}

/// 从 client.json 构造 Conn（注入/输出通道），返回连接、句柄与退出信号。
async fn make_conn(
    cfg: &ClientConfig,
    log_path: &str,
) -> Result<(Conn, linkmesh_client::connection::ConnectionHandle, watch::Sender<bool>), String> {
    let conn_entry = cfg
        .connections
        .first()
        .cloned()
        .ok_or("配置中没有连接条目")?;
    let (quit_tx, quit_rx) = watch::channel(false);
    let logger = Logger::new(log_path);
    let (mut conn, handle) = Conn::new(cfg, &conn_entry, quit_rx, logger).await?;
    conn.skip_tun = true; // 测试模式：不创建 TUN，数据面走注入/输出通道
    if arg_flag(&args(), "--bufcheck") {
        // 检查与 Conn 同参数的临时套接字缓冲（Conn 内部套接字不可见，用相同配置复现）
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
        linkmesh_client::connection::enlarge_udp_buffers(&probe, 4 * 1024 * 1024);
        let (rcv, snd) = get_udp_buffers(&probe);
        println!("BUFCHECK rcv={rcv} snd={snd}");
    }
    Ok((conn, handle, quit_tx))
}

/// 发送模式：向对端注入探测包并统计 RTT / 丢包 / 吞吐。
async fn run_send(
    mut conn: Conn,
    handle: linkmesh_client::connection::ConnectionHandle,
    quit_tx: watch::Sender<bool>,
    my_ip: String,
    peer_ip: String,
    size: usize,
    count: usize,
    interval_ms: u64,
    timeout_s: u64,
    oneway: bool,
) {
    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(1024);
    conn.inject_rx = Some(inject_rx);
    conn.tun_sink = Some(sink_tx);
    let task = tokio::spawn(async move { conn.run().await });

    let my_bytes: [u8; 4] = parse_ipv4(&my_ip).expect("my IP 无效");
    let peer_bytes: [u8; 4] = parse_ipv4(&peer_ip).expect("peer IP 无效");

    // 回包收集器：独立任务，全程并发读取（预热期间也在收），避免阻塞测量
    let replies: Arc<tokio::sync::Mutex<Vec<(u64, u64, u64, u64, usize)>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let replies_c = replies.clone();
    let t_start = now_ms();
    let sends_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sends_done_c = sends_done.clone();
    let collector = tokio::spawn(async move {
        loop {
            let r = tokio::time::timeout(Duration::from_millis(100), sink_rx.recv()).await;
            match r {
                Ok(Some(pkt)) => {
                    if let Some((_src, _dst, payload)) = parse_ip(&pkt) {
                        if let Some((seq, send_ms, recv_ms)) = parse_reply(payload) {
                            let rtt = now_ms().saturating_sub(send_ms);
                            replies_c.lock().await.push((seq, send_ms, recv_ms, rtt, payload.len()));
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let done = sends_done_c.load(std::sync::atomic::Ordering::Relaxed);
                    let got = replies_c.lock().await.len();
                    let elapsed = now_ms().saturating_sub(t_start);
                    if done && got >= count {
                        break;
                    }
                    if elapsed > timeout_s * 1000 {
                        break;
                    }
                }
            }
        }
    });

    // 等待注册完成
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 预热：注入 3 个探测包触发对端发现（查询 + 打洞/中继 + 对端回包学习路由）
    for i in 0..3u64 {
        let warm = build_ipv4_packet(my_bytes, peer_bytes, &build_probe(i, 64));
        let _ = inject_tx.send(warm).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 打印对端状态（传输方式）
    let snap = handle.snapshot().await;
    println!("PEER_STATE {}", snap["peers"]);
    println!("BENCH send peer={peer_ip} size={size} count={count} interval_ms={interval_ms}");
    println!("seq,send_ms,rtt_ms,oneway_ms,recv_ms,reply_size");

    let t_send_start = now_ms();

    let send_task = tokio::spawn(async move {
        for i in 0..count as u64 {
            let seq = i + 1;
            let pkt = build_ipv4_packet(my_bytes, peer_bytes, &build_probe(seq, size));
            if inject_tx.send(pkt).await.is_err() {
                break;
            }
            if interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
        }
        sends_done.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    let _ = send_task; // 发送任务独立运行，收集器负责统计

    // 等待收集器结束（或超时）
    let deadline = Instant::now() + Duration::from_secs(timeout_s);
    if oneway {
        // 单向测试：发送循环可能只把包缓冲进注入通道，需给 Conn 留排空时间再收尾
        let _ = send_task.await;
        let drain_ms = (500 + count as u64 / 4).min(4000);
        tokio::time::sleep(Duration::from_millis(drain_ms)).await;
        let _ = quit_tx.send(true);
        task.abort();
        let t_elapsed = now_ms().saturating_sub(t_send_start).max(1);
        println!(
            "SUMMARY_ONEWAY sent={count} elapsed_ms={t_elapsed} goodput={:.3} Mbps (raw bytes)",
            (count * size) as f64 * 8.0 / (t_elapsed as f64) / 1000.0
        );
        return;
    }
    loop {
        if collector.is_finished() {
            break;
        }
        if Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let _ = quit_tx.send(true);
    task.abort();

    let mut collected = replies.lock().await.clone();
    collected.sort_by_key(|r| r.0);
    for (seq, send_ms, recv_ms, rtt, rsize) in &collected {
        let oneway = recv_ms.saturating_sub(*send_ms);
        println!("{seq},{send_ms},{rtt},{oneway},{recv_ms},{rsize}");
    }

    let t_elapsed = now_ms().saturating_sub(t_send_start).max(1);
    let recv_ok = collected.len().min(count);
    let loss = count.saturating_sub(recv_ok);
    let bytes_sent = count * size;
    let mbps = bytes_sent as f64 * 8.0 / (t_elapsed as f64) / 1000.0;
    println!("SUMMARY sent={count} replied={recv_ok} loss={loss} ({:.1}%) elapsed_ms={t_elapsed} goodput={:.3} Mbps (raw bytes)",
        loss as f64 * 100.0 / count.max(1) as f64, mbps);
    let rtts: Vec<u64> = collected.iter().map(|r| r.3).collect();
    if !rtts.is_empty() {
        let avg = rtts.iter().sum::<u64>() as f64 / rtts.len() as f64;
        let min = *rtts.iter().min().unwrap();
        let max = *rtts.iter().max().unwrap();
        let mut sorted = rtts.clone();
        sorted.sort_unstable();
        let p95 = sorted[(sorted.len() as f64 * 0.95) as usize];
        println!("RTT ms: avg={avg:.2} min={min} max={max} p95={p95} n={}", rtts.len());
    }
}

/// 接收模式：收到探测包即回包（--no-reply 时只计数），并打印到达记录（--quiet 时只计数）。
async fn run_recv(
    mut conn: Conn,
    quit_tx: watch::Sender<bool>,
    my_ip: String,
    timeout_s: u64,
    quiet: bool,
    no_reply: bool,
) {
    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(1024);
    conn.inject_rx = Some(inject_rx);
    conn.tun_sink = Some(sink_tx);
    let task = tokio::spawn(async move { conn.run().await });

    let my_bytes: [u8; 4] = parse_ipv4(&my_ip).expect("my IP 无效");
    if !quiet {
        println!("BENCH recv my_ip={my_ip}");
        println!("seq,size,recv_ms,src_ip");
    }
    let mut total: u64 = 0;
    let mut bytes: u64 = 0;
    let t0 = now_ms();

    let start = Instant::now();
    loop {
        let r = tokio::time::timeout(Duration::from_millis(200), sink_rx.recv()).await;
        match r {
            Ok(Some(pkt)) => {
                if let Some((src, _dst, payload)) = parse_ip(&pkt) {
                    if payload.len() >= 22 && &payload[..4] == PROBE_MAGIC {
                        let mut seq = [0u8; 8];
                        seq.copy_from_slice(&payload[4..12]);
                        let seq = u64::from_be_bytes(seq);
                        let recv_ms = now_ms();
                        total += 1;
                        bytes += payload.len() as u64;
                        if !quiet && total <= 5 {
                            println!("{seq},{},{recv_ms},{}.{}.{}.{}", payload.len(), src[0], src[1], src[2], src[3]);
                        }
                        // 回包
                        if !no_reply {
                            if let Some(reply) = build_reply(payload, recv_ms) {
                                let rpkt = build_ipv4_packet(my_bytes, src, &reply);
                                let _ = inject_tx.send(rpkt).await;
                            }
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
                if start.elapsed() > Duration::from_secs(timeout_s) {
                    if quiet {
                        println!("RECV_TOTAL {total} bytes={bytes} elapsed_ms {}", now_ms() - t0);
                    } else {
                        println!("RECV_TIMEOUT {timeout_s}s reached");
                    }
                    break;
                }
            }
        }
    }
    let _ = quit_tx.send(true);
    task.abort();
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

/// 离线解密一段抓包（中继帧或信令帧），证明静态密钥可解全部历史流量。
fn offline_decrypt(cfg: &ClientConfig, cap_file: &str) -> Result<(), String> {
    let data = std::fs::read(cap_file).map_err(|e| format!("读取抓包失败: {e}"))?;
    let my_priv = cfg.private_key()?;
    let my_pub = cfg.public_key()?;
    let hdr = linkmesh_shared::protocol::parse_header(&data)
        .map_err(|e| format!("不是 LinkMesh 封包: {e}"))?;
    println!("帧头: version={} msg_type=0x{:02x} sender_pub={}", hdr.version, hdr.msg_type, B64.encode(hdr.sender_public_key));
    let peer_pub: RawKey;
    let ct: &[u8];
    if hdr.msg_type == linkmesh_shared::protocol::MSG_RELAY {
        let (dest, src, ct_body) = parse_relay(&data)?;
        println!("中继帧 dest_pub={} src_pub={}", B64.encode(dest), B64.encode(src));
        peer_pub = if src == my_pub { dest } else { src };
        ct = ct_body;
    } else {
        peer_pub = hdr.sender_public_key;
        ct = &data[HEADER_LEN..];
    }
    let shared = crypto::shared_secret(&my_priv, &peer_pub);
    let plain = crypto::decrypt(&shared, ct).map_err(|e| format!("解密失败: {e}"))?;
    println!("解密成功! 共享密钥(静态 ECDH)= {}", B64.encode(shared));
    if !plain.is_empty() {
        println!("隧道明文类型: 0x{:02x}", plain[0]);
        println!("隧道明文 (hex): {}", hex_str(&plain));
        let text: String = plain.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
        println!("隧道明文 (ascii): {text}");
    }
    Ok(())
}

fn hex_str(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// 以本机身份注册一个虚拟 IP（演示 IP 抢占缺陷）。
async fn reg_ip(cfg: &ClientConfig, ip: &str) -> Result<(), String> {
    let server = cfg
        .find_server(&cfg.connections.first().ok_or("无连接")?.server)
        .cloned()
        .ok_or("服务器未配置")?;
    let addr: SocketAddr = server.endpoint.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let my_priv = cfg.private_key()?;
    let my_pub = cfg.public_key()?;
    // 服务器公钥：优先用已保存的
    let server_pub_raw = match &server.public_key {
        Some(pk) => crypto::parse_public_key(pk)?,
        None => {
            let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
            let f = frame_signaling(linkmesh_shared::protocol::MSG_KEYQUERY, &my_pub, &[]);
            sock.send_to(&f, addr).await.map_err(|e| e.to_string())?;
            let mut buf = [0u8; 2048];
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
                .await
                .map_err(|_| "KEYQUERY 超时")?
                .map_err(|e| e.to_string())?;
            let hdr = parse_header(&buf[..n]).map_err(|e| e.to_string())?; // 校验是 LinkMesh 封包
            if hdr.msg_type != MSG_SERVERINFO {
                return Err("服务器未返回 ServerInfo（非 mesh 服务器）".into());
            }
            let sib: ServerInfoBody =
                decode_server_info_body(&buf[HEADER_LEN..n]).map_err(|e| e.to_string())?;
            crypto::parse_public_key(&sib.server_info.server_ik_x)?
        }
    };
    let shared = crypto::shared_secret(&my_priv, &server_pub_raw);
    let body = encode_register(&RegisterBody { ip: ip.to_string(), relay_rk: None, token: None, alias: None })
        .map_err(|e| e.to_string())?;
    let ct = crypto::encrypt(&shared, &body);
    let frame = frame_signaling(MSG_REGISTER, &my_pub, &ct);
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    sock.send_to(&frame, addr).await.map_err(|e| e.to_string())?;
    println!("REGISTER ip={ip} pub={} -> {}", B64.encode(my_pub), addr);
    Ok(())
}

/// 查询一个虚拟 IP（演示查询被劫持/路由到攻击者）。
async fn query_ip(cfg: &ClientConfig, ip: &str) -> Result<(), String> {
    let server = cfg
        .find_server(&cfg.connections.first().ok_or("无连接")?.server)
        .cloned()
        .ok_or("服务器未配置")?;
    let addr: SocketAddr = server.endpoint.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let my_priv = cfg.private_key()?;
    let my_pub = cfg.public_key()?;
    let server_pub_raw = match &server.public_key {
        Some(pk) => crypto::parse_public_key(pk)?,
        None => return Err("服务器公钥未保存，先 --connect".into()),
    };
    let shared = crypto::shared_secret(&my_priv, &server_pub_raw);
    let body = encode_query(&QueryBody { ip: ip.to_string(), name: None }).map_err(|e| e.to_string())?;
    let ct = crypto::encrypt(&shared, &body);
    let frame = frame_signaling(MSG_QUERY, &my_pub, &ct);
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    sock.send_to(&frame, addr).await.map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4096];
    let mut got = false;
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        let (n, _) = tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf))
            .await
            .map_err(|_| "超时")?
            .map_err(|e| e.to_string())?;
        let hdr = parse_header(&buf[..n]).map_err(|e| e.to_string())?;
        if hdr.msg_type == linkmesh_shared::protocol::MSG_RESPONSE {
            let plain = crypto::decrypt(&shared, &buf[HEADER_LEN..n]).map_err(|e| e.to_string())?;
            let resp: ResponseBody = decode_response(&plain).map_err(|e| e.to_string())?;
            if let ResponseData::QueryHit { public_key, endpoint, .. } = &resp.data {
                println!(
                    "QUERY ip={ip} -> ok={} public_key={} endpoint={}",
                    resp.ok, public_key, endpoint
                );
                got = true;
                break;
            }
        }
    }
    if !got {
        println!("QUERY ip={ip} -> 未上线或超时");
    }
    Ok(())
}

/// 中继垃圾洪泛：以本机公钥为 src，向指定 dest 发 N 个伪造密文中继帧。
async fn flood_relay(cfg: &ClientConfig, dest_pub_b64: &str, n: usize, size: usize) -> Result<(), String> {
    let server = cfg
        .find_server(&cfg.connections.first().ok_or("无连接")?.server)
        .cloned()
        .ok_or("服务器未配置")?;
    let addr: SocketAddr = server.endpoint.parse::<SocketAddr>().map_err(|e| e.to_string())?;
    let my_pub = cfg.public_key()?;
    let dest = crypto::parse_public_key(dest_pub_b64)?;
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    let junk: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let ct = crypto::encrypt(&[1u8; 32], &junk); // 任意密钥加密，接收端必解密失败
    let frame = frame_relay(&dest, &my_pub, &ct);
    let t0 = Instant::now();
    for _ in 0..n {
        let _ = sock.send_to(&frame, addr).await;
    }
    println!("FLOOD dest={} n={n} size={} elapsed_ms={}", B64.encode(dest), size, t0.elapsed().as_millis());
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = args();
    let config_path = PathBuf::from(arg_val(&args, "--config", "client.json"));
    let mode = arg_val(&args, "--mode", "send");
    let peer_ip = arg_val(&args, "--peer", "10.13.13.2");
    let my_ip = arg_val(&args, "--my-ip", "10.13.13.2");
    let size: usize = arg_val(&args, "--size", "256").parse().unwrap_or(256);
    let count: usize = arg_val(&args, "--count", "20").parse().unwrap_or(20);
    let interval_ms: u64 = arg_val(&args, "--interval-ms", "0").parse().unwrap_or(0);
    let timeout_s: u64 = arg_val(&args, "--timeout-s", "30").parse().unwrap_or(30);
    let log_path = arg_val(&args, "--log", "/tmp/bench.log");

    let mut cfg = match ClientConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("配置加载失败: {e}");
            std::process::exit(1);
        }
    };
    // --no-punch: 禁用打洞，强制走中继
    if arg_flag(&args, "--no-punch") {
        cfg.hole_punch.enabled = false;
        eprintln!("[bench] hole_punch.enabled=false (强制中继)");
    }
    if cfg.identity.is_none() {
        eprintln!("未生成设备身份，请先 --genkey");
        std::process::exit(1);
    }

    let r = match mode.as_str() {
        "send" => {
            let (conn, handle, quit) = match make_conn(&cfg, &log_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("连接初始化失败: {e}");
                    std::process::exit(1);
                }
            };
            let oneway = arg_flag(&args, "--oneway");
            run_send(conn, handle, quit, my_ip, peer_ip, size, count, interval_ms, timeout_s, oneway).await;
            Ok(())
        }
        "recv" => {
            let (conn, _handle, quit) = match make_conn(&cfg, &log_path).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("连接初始化失败: {e}");
                    std::process::exit(1);
                }
            };
            let quiet = arg_flag(&args, "--quiet");
            let no_reply = arg_flag(&args, "--no-reply");
            run_recv(conn, quit, my_ip, timeout_s, quiet, no_reply).await;
            Ok(())
        }
        "decrypt" => {
            let cap = arg_val(&args, "--capture", "");
            offline_decrypt(&cfg, &cap)
        }
        "reg" => {
            let ip = arg_val(&args, "--ip", "");
            reg_ip(&cfg, &ip).await
        }
        "query" => {
            let ip = arg_val(&args, "--ip", "");
            query_ip(&cfg, &ip).await
        }
        "flood" => {
            let dest = arg_val(&args, "--dest", "");
            flood_relay(&cfg, &dest, count, size).await
        }
        other => {
            eprintln!("未知模式 {other} (send|recv|decrypt|reg|query|flood)");
            std::process::exit(1);
        }
    };
    if let Err(e) = r {
        eprintln!("错误: {e}");
        std::process::exit(1);
    }
}
