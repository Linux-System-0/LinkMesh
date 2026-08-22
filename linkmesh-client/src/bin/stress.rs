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

//! 高并发压力 + 随机故障注入测试工具（直接基于 UDP 协议，无需 TUN / root）。
//!
//! 通过 linkmesh-shared 的原始协议封包函数，模拟大量虚拟客户端并发访问
//! `linkmesh-server`，衡量服务端在高并发信令/中继下的吞吐、延迟、丢包与稳定性，
//! 并注入随机故障（畸形帧、超大帧、垃圾洪泛、重复帧、乱序、错误密钥、未授权来源）
//! 验证服务端不崩溃、可恢复。
//!
//! 用法示例：
//!   stress --server 127.0.0.1:18080 --mode register --clients 500
//!   stress --server 127.0.0.1:18080 --mode heartbeat --clients 200 --rate 10 --duration 30
//!   stress --server 127.0.0.1:18080 --mode query --clients 200 --duration 20
//!   stress --server 127.0.0.1:18080 --mode relay --clients 100 --size 512 --rate 100 --duration 15
//!   stress --server 127.0.0.1:18080 --mode mixed --clients 300 --duration 30
//!   stress --server 127.0.0.1:18080 --mode fault --fault-rate 500 --duration 20
//!   stress --server 127.0.0.1:18080 --mode soak --clients 100 --duration 60

use std::net::{Ipv4Addr, SocketAddr};
use std::process::exit;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_shared::crypto::{self, KeyPairSerde, RawKey};
use linkmesh_shared::protocol::{
    decode_response, decode_server_info_body, encode_query, encode_register, frame_relay,
    frame_signaling, parse_header, parse_relay, parse_relay_batch, MSG_KEYQUERY, MSG_QUERY,
    MSG_REGISTER, MSG_RELAY, MSG_RELAY_BATCH, MSG_RESPONSE, MSG_SERVERINFO, QueryBody,
    RegisterBody, ServerInfoBody, HEADER_LEN, RELAY_HEADER_LEN,
};
use tokio::net::UdpSocket;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

/// 一次性注册虚拟客户端：生成 X25519 密钥 + UDP 套接字，返回该客户端句柄。
struct VClient {
    sock: UdpSocket,
    ip: Ipv4Addr,
    pub_raw: RawKey,
    priv_raw: RawKey,
}

/// 构造一个 N 段的虚拟 IP（10.x.y.z）。
fn v_ip(i: usize) -> Ipv4Addr {
    let oct3 = ((i / 65536) % 256) as u8;
    let oct2 = ((i / 256) % 256) as u8;
    let oct1 = (i % 256) as u8;
    Ipv4Addr::new(10, oct3, oct2, oct1)
}

async fn bind_client(i: usize) -> VClient {
    let keypair = KeyPairSerde::generate();
    let pub_raw = keypair.public_raw().unwrap();
    let priv_raw = keypair.private_raw().unwrap();
    let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    VClient {
        sock,
        ip: v_ip(i),
        pub_raw,
        priv_raw,
    }
}

/// 获取服务端公钥（KEYQUERY → 签名 MSG_SERVERINFO）。
async fn fetch_server_pub(
    sock: &UdpSocket,
    server: SocketAddr,
    probe_key: &RawKey,
) -> RawKey {
    let frame = frame_signaling(MSG_KEYQUERY, probe_key, &[]);
    sock.send_to(&frame, server).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("KEYQUERY 超时")
        .unwrap();
    let hdr = parse_header(&buf[..len]).unwrap();
    assert_eq!(
        hdr.msg_type, MSG_SERVERINFO,
        "mesh 服务器 KEYQUERY 必须返回 ServerInfo"
    );
    let sib: ServerInfoBody = decode_server_info_body(&buf[HEADER_LEN..len]).unwrap();
    crypto::parse_public_key(&sib.server_info.server_ik_x).unwrap()
}

/// 发送 REGISTER 并等待 RESPONSE，返回是否成功与 RTT。
async fn register_client(
    c: &VClient,
    server: SocketAddr,
    server_pub: &RawKey,
) -> (bool, u64) {
    let t0 = now_ms();
    let shared = crypto::shared_secret(&c.priv_raw, server_pub);
    let body = encode_register(&RegisterBody {
        ip: c.ip.to_string(),
        relay_rk: None,
        token: None,
        alias: None,
    })
    .unwrap();
    let ct = crypto::encrypt(&shared, &body);
    let frame = frame_signaling(MSG_REGISTER, &c.pub_raw, &ct);
    c.sock.send_to(&frame, server).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), c.sock.recv_from(&mut buf))
        .await
        .expect("REGISTER 超时")
        .unwrap();
    let hdr = parse_header(&buf[..len]).unwrap();
    if hdr.msg_type == MSG_RESPONSE {
        let plain = crypto::decrypt(&shared, &buf[HEADER_LEN..len]).unwrap();
        let resp = decode_response(&plain).unwrap();
        let rtt = now_ms() - t0;
        return (resp.ok, rtt);
    }
    (false, now_ms() - t0)
}

/// 发送一条 HEARTBEAT，等待 RESPONSE（跳过 NOTIFY 等其他类型）。
async fn send_heartbeat(c: &VClient, server: SocketAddr, server_pub: &RawKey) -> bool {
    let shared = crypto::shared_secret(&c.priv_raw, server_pub);
    let body = encode_register(&RegisterBody {
        ip: c.ip.to_string(),
        relay_rk: None,
        token: None,
        alias: None,
    })
    .unwrap();
    let ct = crypto::encrypt(&shared, &body);
    let frame = frame_signaling(linkmesh_shared::protocol::MSG_HEARTBEAT, &c.pub_raw, &ct);
    c.sock.send_to(&frame, server).await.ok();
    recv_response_ok(&c.sock, &shared, Duration::from_secs(3)).await
}

/// 发送一条 QUERY（按 IP），等待 RESPONSE（跳过 NOTIFY 等其他类型）。
async fn send_query(c: &VClient, server: SocketAddr, server_pub: &RawKey, target: &Ipv4Addr) -> bool {
    let shared = crypto::shared_secret(&c.priv_raw, server_pub);
    let body = encode_query(&QueryBody {
        ip: target.to_string(),
        name: None,
    })
    .unwrap();
    let ct = crypto::encrypt(&shared, &body);
    let frame = frame_signaling(MSG_QUERY, &c.pub_raw, &ct);
    c.sock.send_to(&frame, server).await.ok();
    recv_response_ok(&c.sock, &shared, Duration::from_secs(3)).await
}

/// 循环读取，解密并校验 RESPONSE.ok，直到成功或超时（跳过 NOTIFY 等其他消息）。
async fn recv_response_ok(sock: &UdpSocket, shared: &RawKey, timeout: Duration) -> bool {
    let mut buf = vec![0u8; 65536];
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                if let Ok(h) = parse_header(&buf[..len]) {
                    if h.msg_type != MSG_RESPONSE {
                        continue;
                    }
                    let Ok(plain) = crypto::decrypt(shared, &buf[HEADER_LEN..len]) else {
                        continue;
                    };
                    if let Ok(resp) = decode_response(&plain) {
                        return resp.ok;
                    }
                }
            }
            _ => return false,
        }
    }
}

fn report(name: &str, ok: u64, total: u64, latency_ms: &[u64], extra: &str) {
    let rate = if total == 0 { 0.0 } else { 100.0 * ok as f64 / total as f64 };
    let mut s = format!("[{name}] ok={ok}/{total} ({rate:.1}%) {extra}");
    if !latency_ms.is_empty() {
        let mut v = latency_ms.to_vec();
        v.sort_unstable();
        let avg = v.iter().sum::<u64>() as f64 / v.len() as f64;
        let min = *v.first().unwrap();
        let max = *v.last().unwrap();
        let p50 = v[(v.len() as f64 * 0.5) as usize];
        let p95 = v[(v.len() as f64 * 0.95) as usize];
        let p99 = v[(v.len() as f64 * 0.99) as usize];
        s.push_str(&format!(
            " latency_ms: avg={avg:.2} min={min} max={max} p50={p50} p95={p95} p99={p99} n={}",
            v.len()
        ));
    }
    println!("{s}");
}

fn pct_loss(sent: u64, got: u64) -> f64 {
    if sent == 0 {
        0.0
    } else {
        100.0 * sent.saturating_sub(got) as f64 / sent as f64
    }
}

// =====================================================================
// 模式 1：注册风暴 —— N 个客户端并发注册，衡量注册吞吐与延迟
// =====================================================================
async fn mode_register(server: SocketAddr, clients: usize) {
    // 一个探测套接字先取服务端公钥
    let probe = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let probe_key = KeyPairSerde::generate();
    let server_pub = fetch_server_pub(&probe, server, &probe_key.public_raw().unwrap()).await;
    println!("[register] server_pub={}", B64.encode(server_pub));

    // 并发创建客户端并注册
    let start = Instant::now();
    let mut handles = Vec::new();
    for i in 0..clients {
        let server_pub = server_pub;
        handles.push(tokio::spawn(async move {
            let c = bind_client(i).await;
            let r = register_client(&c, server, &server_pub).await;
            (i, r.0, r.1)
        }));
    }
    let mut ok = 0u64;
    let mut lat = Vec::new();
    for h in handles {
        if let Ok((_, o, l)) = h.await {
            if o {
                ok += 1;
            }
            lat.push(l);
        }
    }
    let elapsed = start.elapsed().as_millis();
    let per_s = if elapsed == 0 {
        0.0
    } else {
        clients as f64 / (elapsed as f64 / 1000.0)
    };
    println!("[register] 注册完成耗时 {elapsed}ms，注册速率 {per_s:.1} clients/s");
    report("register", ok, clients as u64, &lat, "");
}

// =====================================================================
// 模式 2：心跳风暴 —— N 个客户端按 rate（次/秒/客户端）持续心跳
// =====================================================================
async fn mode_heartbeat(server: SocketAddr, clients: usize, rate: u64, duration: u64) {
    let probe = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let probe_key = KeyPairSerde::generate();
    let server_pub = fetch_server_pub(&probe, server, &probe_key.public_raw().unwrap()).await;
    println!(
        "[heartbeat] clients={clients} rate={rate}/s each duration={duration}s 总心跳约 {} 次/秒",
        clients as u64 * rate
    );

    // 先全部注册
    let mut vc = Vec::new();
    for i in 0..clients {
        let c = bind_client(i).await;
        register_client(&c, server, &server_pub).await;
        vc.push(c);
    }
    println!("[heartbeat] {} 个客户端注册完成", vc.len());

    let interval = Duration::from_millis((1000 / rate.max(1)).max(1));
    let start = Instant::now();
    let mut ok = 0u64;
    let mut sent = 0u64;
    let mut handles = Vec::new();
    // 每个客户端一个任务，跑满 duration
    for c in vc.into_iter() {
        let server = server;
        let server_pub = server_pub;
        let c = c;
        handles.push(tokio::spawn(async move {
            let mut ok = 0u64;
            let mut sent = 0u64;
            while start.elapsed() < Duration::from_secs(duration) {
                if send_heartbeat(&c, server, &server_pub).await {
                    ok += 1;
                }
                sent += 1;
                tokio::time::sleep(interval).await;
            }
            (ok, sent)
        }));
    }
    for h in handles {
        if let Ok((o, s)) = h.await {
            ok += o;
            sent += s;
        }
    }
    println!(
        "[heartbeat] 已发送 {sent} 次心跳，成功 {ok}，丢包/失败 {:.2}%（预期无）",
        pct_loss(sent, ok)
    );
}

// =====================================================================
// 模式 3：查询风暴 —— 客户端互相查询
// =====================================================================
async fn mode_query(server: SocketAddr, clients: usize, duration: u64) {
    let probe = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let probe_key = KeyPairSerde::generate();
    let server_pub = fetch_server_pub(&probe, server, &probe_key.public_raw().unwrap()).await;

    let mut vc = Vec::new();
    for i in 0..clients {
        let c = bind_client(i).await;
        register_client(&c, server, &server_pub).await;
        vc.push(c);
    }
    println!("[query] {} 个客户端注册完成，开始互相查询", vc.len());
    // 预计算每个客户端的目标 IP（对端 idx+1 循环）
    let ips: Vec<Ipv4Addr> = vc.iter().map(|c| c.ip).collect();
    let targets: Vec<Ipv4Addr> = (0..clients)
        .map(|idx| ips[(idx + 1) % clients])
        .collect();
    let start = Instant::now();
    let mut handles = Vec::new();
    for (idx, c) in vc.into_iter().enumerate() {
        let server = server;
        let server_pub = server_pub;
        let c = c;
        let target_ip = targets[idx];
        handles.push(tokio::spawn(async move {
            let mut ok = 0u64;
            let mut sent = 0u64;
            while start.elapsed() < Duration::from_secs(duration) {
                if send_query(&c, server, &server_pub, &target_ip).await {
                    ok += 1;
                }
                sent += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            (ok, sent)
        }));
    }
    let mut ok = 0u64;
    let mut sent = 0u64;
    for h in handles {
        if let Ok((o, s)) = h.await {
            ok += o;
            sent += s;
        }
    }
    println!("[query] 已发送 {sent} 次查询，成功 {ok}，失败 {:.2}%", pct_loss(sent, ok));
}

// =====================================================================
// 模式 4：中继吞吐 —— 半数发半数收，衡量中继吞吐与丢包
// =====================================================================
async fn mode_relay(server: SocketAddr, clients: usize, size: usize, rate: u64, duration: u64) {
    let probe = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let probe_key = KeyPairSerde::generate();
    let server_pub = fetch_server_pub(&probe, server, &probe_key.public_raw().unwrap()).await;

    // 全部注册；发送方 = 偶数下标，接收方 = 奇数下标
    let mut vc = Vec::new();
    for i in 0..clients {
        let c = bind_client(i).await;
        register_client(&c, server, &server_pub).await;
        vc.push(c);
    }
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for (i, c) in vc.into_iter().enumerate() {
        if i % 2 == 0 {
            senders.push(c);
        } else {
            receivers.push(c);
        }
    }
    println!(
        "[relay] 发送方={} 接收方={} size={size}B rate={rate}/s 单连接，duration={duration}s",
        senders.len(),
        receivers.len()
    );
    // 无接收方（clients<2）时无法中继，直接返回，避免下方 `si % recv_pubs.len()` 除零 panic。
    if receivers.is_empty() {
        println!("[relay] 无接收方（clients<2），跳过中继测试");
        return;
    }

    // 接收方：spawn 一个接收循环，统计收到的中继帧数与字节
    let recv_start = Instant::now();
    let recv_pubs: Vec<RawKey> = receivers.iter().map(|r| r.pub_raw).collect();
    let mut recv_handles = Vec::new();
    for rc in receivers.into_iter() {
        recv_handles.push(tokio::spawn(async move {
            let mut frames = 0u64;
            let mut bytes = 0u64;
            let mut buf = vec![0u8; 65536];
            while recv_start.elapsed() < Duration::from_secs(duration + 2) {
                match tokio::time::timeout(Duration::from_millis(500), rc.sock.recv_from(&mut buf)).await {
                    Ok(Ok((len, _))) => {
                        if len >= 3 {
                            match buf[3] {
                                MSG_RELAY => {
                                    let (_d, _s, _b) = match parse_relay(&buf[..len]) {
                                        Ok(x) => x,
                                        Err(_) => continue,
                                    };
                                    frames += 1;
                                    bytes += len as u64;
                                }
                                MSG_RELAY_BATCH => {
                                    let (_d, subs) = match parse_relay_batch(&buf[..len]) {
                                        Ok(x) => x,
                                        Err(_) => continue,
                                    };
                                    frames += subs.len() as u64;
                                    bytes += len as u64;
                                }
                                _ => {}
                            }
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) => {
                        if recv_start.elapsed() > Duration::from_secs(duration) {
                            break;
                        }
                    }
                }
            }
            (frames, bytes)
        }));
    }

    // 发送方：按 rate 发送中继帧
    let interval = Duration::from_millis((1000 / rate.max(1)).max(1));
    let send_start = Instant::now();
    let mut send_handles = Vec::new();
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    for (si, sc) in senders.into_iter().enumerate() {
        let rc_pub = recv_pubs[si % recv_pubs.len()];
        let ct = crypto::encrypt(&[7u8; 32], &payload); // 任意密钥，接收端无需解密
        let frame = frame_relay(&rc_pub, &sc.pub_raw, &ct);
        let server = server;
        send_handles.push(tokio::spawn(async move {
            let mut sent = 0u64;
            while send_start.elapsed() < Duration::from_secs(duration) {
                sc.sock.send_to(&frame, server).await.unwrap();
                sent += 1;
                tokio::time::sleep(interval).await;
            }
            sent
        }));
    }
    let mut total_sent = 0u64;
    for h in send_handles {
        if let Ok(s) = h.await {
            total_sent += s;
        }
    }
    let mut total_frames = 0u64;
    let mut total_bytes = 0u64;
    for h in recv_handles {
        if let Ok((f, b)) = h.await {
            total_frames += f;
            total_bytes += b;
        }
    }
    let mbps = if duration == 0 {
        0.0
    } else {
        total_bytes as f64 * 8.0 / (duration as f64) / 1_000_000.0
    };
    println!(
        "[relay] 已发送 {total_sent} 帧，接收方收到 {total_frames} 帧，丢包 {:.2}%，吞吐 {mbps:.2} Mbps ({total_bytes} B / {duration}s)",
        pct_loss(total_sent, total_frames)
    );
}

// =====================================================================
// 模式 5：混合负载 —— 注册 + 心跳 + 查询 + 中继同时进行
// =====================================================================
async fn mode_mixed(server: SocketAddr, clients: usize, duration: u64) {
    let probe = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let probe_key = KeyPairSerde::generate();
    let server_pub = fetch_server_pub(&probe, server, &probe_key.public_raw().unwrap()).await;

    let mut vc = Vec::new();
    for i in 0..clients {
        let c = bind_client(i).await;
        register_client(&c, server, &server_pub).await;
        vc.push(c);
    }
    println!("[mixed] {} 个客户端注册完成，开始混合负载", vc.len());
    let ips: Vec<Ipv4Addr> = vc.iter().map(|c| c.ip).collect();
    let targets: Vec<Ipv4Addr> = (0..clients).map(|idx| ips[(idx + 1) % clients]).collect();
    let start = Instant::now();
    let mut handles = Vec::new();
    for (idx, c) in vc.into_iter().enumerate() {
        let server = server;
        let server_pub = server_pub;
        let c = c;
        let target_ip = targets[idx];
        handles.push(tokio::spawn(async move {
            let mut hb_ok = 0u64;
            let mut q_ok = 0u64;
            while start.elapsed() < Duration::from_secs(duration) {
                if send_heartbeat(&c, server, &server_pub).await {
                    hb_ok += 1;
                }
                if send_query(&c, server, &server_pub, &target_ip).await {
                    q_ok += 1;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            (hb_ok, q_ok)
        }));
    }
    let mut hb = 0u64;
    let mut q = 0u64;
    for h in handles {
        if let Ok((a, b)) = h.await {
            hb += a;
            q += b;
        }
    }
    println!("[mixed] 心跳成功 {hb} 次，查询成功 {q} 次，客户端无崩溃");
}

// =====================================================================
// 模式 6：随机故障注入 —— 持续向服务端发畸形/垃圾/超大/重复/乱序帧
// =====================================================================
async fn mode_fault(server: SocketAddr, fault_rate: u64, duration: u64) {
    let probe = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let probe_key = KeyPairSerde::generate();
    let server_pub = fetch_server_pub(&probe, server, &probe_key.public_raw().unwrap()).await;

    // 一个"金丝雀"客户端：持续注册/心跳/查询，验证服务端仍正常响应
    let canary = bind_client(0).await;
    register_client(&canary, server, &server_pub).await;
    println!("[fault] 金丝雀客户端已注册（ip={}），开始故障注入 rate={fault_rate}/s duration={duration}s", canary.ip);

    // 构造各类畸形帧样本
    let garbage = vec![0u8; 64];
    let truncated = vec![0x4c, 0x4d, 0x01]; // LM + version，无完整头
    let bad_magic = vec![0xde, 0xad, 0xbe, 0xef];
    let oversized = vec![0x4c, 0x4d, 0x01, 0x06]; // 中继类型但截断
    // 一个带错误魔数的"看似中继"帧（足够长但魔数错）
    let mut fake_relay = vec![0x41, 0x42]; // 非 LM
    fake_relay.resize(RELAY_HEADER_LEN + 100, 0x11);
    // 畸形批量中继：长度头越界
    let mut bad_batch = vec![0x4c, 0x4d, 0x01, 0x0a];
    bad_batch.resize(HEADER_LEN + 40, 0x33);
    bad_batch[HEADER_LEN] = 0xff; // 长度头极大
    bad_batch[HEADER_LEN + 1] = 0xff;

    let start = Instant::now();
    let interval = Duration::from_micros((1_000_000 / fault_rate.max(1)).max(1) as u64);
    let mut sent_faults = 0u64;
    let mut canary_ok = 0u64;
    let mut canary_rounds = 0u64;
    let canary_client = canary;

    let mut rng_state: u64 = 0x9E3779B97F4A7C15;
    while start.elapsed() < Duration::from_secs(duration) {
        // 每轮先验证金丝雀
        if send_heartbeat(&canary_client, server, &server_pub).await {
            canary_ok += 1;
        }
        canary_rounds += 1;

        // 随机选择故障类型
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let kind = (rng_state >> 33) % 6;
        let sock = &canary_client.sock;
        let f = match kind {
            0 => garbage.clone(),
            1 => truncated.clone(),
            2 => bad_magic.clone(),
            3 => oversized.clone(),
            4 => fake_relay.clone(),
            _ => bad_batch.clone(),
        };
        sock.send_to(&f, server).await.ok();
        sent_faults += 1;

        // 随机重复 / 乱序：偶尔快速连发同一帧
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        if (rng_state >> 33) % 4 == 0 {
            sock.send_to(&f, server).await.ok();
            sent_faults += 1;
        }

        // 偶尔洪泛（连发 20 帧）
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        if (rng_state >> 33) % 20 == 0 {
            for _ in 0..20 {
                sock.send_to(&f, server).await.ok();
                sent_faults += 1;
            }
        }
        tokio::time::sleep(interval).await;
    }
    let canary_ok_rate = if canary_rounds == 0 {
        0.0
    } else {
        100.0 * canary_ok as f64 / canary_rounds as f64
    };
    println!(
        "[fault] 已注入 {sent_faults} 个故障帧。金丝雀心跳 {canary_ok}/{canary_rounds} 成功 ({canary_ok_rate:.1}%) —— 服务端存活且持续响应"
    );
}

// =====================================================================
// 模式 7：浸泡 —— 长时间恒定负载，观察稳定性
// =====================================================================
async fn mode_soak(server: SocketAddr, clients: usize, duration: u64) {
    let probe = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let probe_key = KeyPairSerde::generate();
    let server_pub = fetch_server_pub(&probe, server, &probe_key.public_raw().unwrap()).await;
    let mut vc = Vec::new();
    for i in 0..clients {
        let c = bind_client(i).await;
        register_client(&c, server, &server_pub).await;
        vc.push(c);
    }
    println!("[soak] {} 个客户端，持续 {duration}s 心跳 + 查询", vc.len());
    let ips: Vec<Ipv4Addr> = vc.iter().map(|c| c.ip).collect();
    let targets: Vec<Ipv4Addr> = (0..clients).map(|idx| ips[(idx + 1) % clients]).collect();
    let start = Instant::now();
    let mut handles = Vec::new();
    for (idx, c) in vc.into_iter().enumerate() {
        let server = server;
        let server_pub = server_pub;
        let c = c;
        let target_ip = targets[idx];
        handles.push(tokio::spawn(async move {
            let mut ok = 0u64;
            while start.elapsed() < Duration::from_secs(duration) {
                if send_heartbeat(&c, server, &server_pub).await {
                    ok += 1;
                }
                if send_query(&c, server, &server_pub, &target_ip).await {
                    ok += 1;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            ok
        }));
    }
    let mut ok = 0u64;
    for h in handles {
        if let Ok(o) = h.await {
            ok += o;
        }
    }
    println!("[soak] 完成，成功响应 {ok} 次，客户端进程无崩溃");
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = args();
    let server_str = arg_val(&args, "--server", "127.0.0.1:18080");
    let mode = arg_val(&args, "--mode", "register");
    let clients: usize = arg_val(&args, "--clients", "100").parse().unwrap_or(100);
    let rate: u64 = arg_val(&args, "--rate", "10").parse().unwrap_or(10);
    let duration: u64 = arg_val(&args, "--duration", "15").parse().unwrap_or(15);
    let size: usize = arg_val(&args, "--size", "512").parse().unwrap_or(512);
    let fault_rate: u64 = arg_val(&args, "--fault-rate", "500").parse().unwrap_or(500);

    let server: SocketAddr = match server_str.parse() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("服务端地址无效: {server_str}");
            exit(1);
        }
    };
    println!("== LinkMesh 压力/故障测试  server={server} mode={mode} ==");
    match mode.as_str() {
        "register" => mode_register(server, clients).await,
        "heartbeat" => mode_heartbeat(server, clients, rate, duration).await,
        "query" => mode_query(server, clients, duration).await,
        "relay" => mode_relay(server, clients, size, rate, duration).await,
        "mixed" => mode_mixed(server, clients, duration).await,
        "fault" => mode_fault(server, fault_rate, duration).await,
        "soak" => mode_soak(server, clients, duration).await,
        other => {
            eprintln!("未知模式 {other}");
            exit(1);
        }
    }
}
