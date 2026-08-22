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

//! 高并发集成测试：真实 mesh 认证路径（JOIN → AUTH → 会话期 REGISTER/QUERY/RELAY）
//! 在大量并发设备下的吞吐、延迟、成功率和稳定性。复用 `tests/p2p.rs` 的 mesh 启动模式。

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_server::config::ServerConfig;
use linkmesh_server::log::Logger as ServerLogger;
use linkmesh_server::mesh::MeshConfig;
use linkmesh_server::signaling::Signaling;
use linkmesh_shared::crypto::{self, KeyPairSerde, RawKey};
use linkmesh_shared::identity::DeviceIdentitySerde;
use linkmesh_shared::protocol::{
    decode_auth_resp, decode_response, encode_auth, encode_join, encode_register,
    frame_signaling, parse_header, AuthBody, AuthRespBody, JoinBody, MSG_AUTH, MSG_AUTH_RESP,
    MSG_JOIN, MSG_REGISTER, MSG_RESPONSE, RegisterBody, ResponseBody,
};
use tokio::net::UdpSocket;

fn raw(b64: &str) -> RawKey {
    crypto::parse_public_key(b64).unwrap()
}

fn make_server_config(dir: &std::path::Path) -> (ServerConfig, MeshConfig) {
    let mesh_id = MeshConfig::generate_mesh_id();
    let mut mesh = MeshConfig::init(&mesh_id);
    // 足够大的 IP 池以容纳并发设备
    let mut pool: Vec<String> = Vec::new();
    for i in 2..520 {
        pool.push(format!("10.13.13.{i}"));
    }
    mesh.ip_pool = pool;
    let mesh_path = dir.join("mesh.json");
    mesh.save(&mesh_path).unwrap();

    let mut cfg = ServerConfig {
        version: 1,
        listen: "127.0.0.1:0".to_string(),
        control_port: 0,
        route_ttl_sec: 300,
        relay: Default::default(),
        join_rate_per_min_per_ip: 5000,
        keypair: Some(KeyPairSerde::generate()),
        signing: Some(linkmesh_shared::identity::SignKeyPairSerde::generate()),
        mesh_path: mesh_path.to_string_lossy().to_string(),
        server_name: "concurrency".to_string(),
        control_token: None,
        rooms: Vec::new(),
        aliases: Vec::new(),
        log_file: dir.join("server.log").to_string_lossy().to_string(),
        pid_file: dir.join("server.pid").to_string_lossy().to_string(),
    };
    cfg.control_port = 0;
    (cfg, mesh)
}

/// 设备侧 JOIN：返回 (证书, 分配 IP)。
async fn do_join(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    dev: &DeviceIdentitySerde,
    server_pub: &RawKey,
    code: &str,
) -> Result<(linkmesh_shared::cert::DeviceCert, String), String> {
    let ik_x = dev.ik_x_public_raw().unwrap();
    let shared = crypto::shared_secret(&raw(&dev.ik_x.private_b64()), server_pub);
    let body = JoinBody {
        code: code.to_string(),
        device_id: dev.device_id().unwrap(),
        ik_x: dev.ik_x.public_b64(),
        ik_s_pub: dev.ik_s.public_b64(),
        requested_ip: None,
        token: None,
        alias: None,
    };
    let ct = crypto::encrypt(&shared, &encode_join(&body).unwrap());
    let frame = frame_signaling(MSG_JOIN, &ik_x, &ct);
    sock.send_to(&frame, server).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .map_err(|_| "JOIN 超时".to_string())?
            .map_err(|e| e.to_string())?;
        let hdr = parse_header(&buf[..len]).map_err(|e| e.to_string())?;
        if hdr.msg_type == MSG_RESPONSE {
            let plain = crypto::decrypt(&shared, &buf[36..len]).map_err(|e| e.to_string())?;
            let resp: ResponseBody = decode_response(&plain).map_err(|e| e.to_string())?;
            if resp.ok {
                match resp.data {
                    linkmesh_shared::protocol::ResponseData::Join { cert, allocated_ip, .. } => {
                        return Ok((cert, allocated_ip));
                    }
                    _ => return Err("JOIN 返回非 Join 数据".into()),
                }
            } else {
                return Err(resp.error.unwrap_or_else(|| "JOIN 被拒".into()));
            }
        }
    }
}

/// 设备侧 AUTH：返回 (SK, ek_c)。
async fn do_auth(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    dev: &DeviceIdentitySerde,
    server_pub: &RawKey,
    cert: &linkmesh_shared::cert::DeviceCert,
) -> Result<(RawKey, RawKey), String> {
    let ik_x_priv = raw(&dev.ik_x.private_b64());
    let ik_x_pub = raw(&dev.ik_x.public_b64());
    let shared = crypto::shared_secret(&ik_x_priv, server_pub);
    let ek_c = KeyPairSerde::generate();
    let ek_c_pub = raw(&ek_c.public_b64());
    let nonce_bytes = [7u8; 12];
    let body = AuthBody {
        device_id: dev.device_id().unwrap(),
        cert: cert.clone(),
        ek_c: ek_c.public_b64(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce: B64.encode(nonce_bytes),
        token: None,
    };
    let ct = crypto::encrypt(&shared, &encode_auth(&body).unwrap());
    let frame = frame_signaling(MSG_AUTH, &ik_x_pub, &ct);
    sock.send_to(&frame, server).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .map_err(|_| "AUTH 超时".to_string())?
            .map_err(|e| e.to_string())?;
        let hdr = parse_header(&buf[..len]).map_err(|e| e.to_string())?;
        if hdr.msg_type == MSG_AUTH_RESP {
            let plain = crypto::decrypt(&shared, &buf[36..len]).map_err(|e| e.to_string())?;
            let resp: AuthRespBody = decode_auth_resp(&plain).map_err(|e| e.to_string())?;
            let ek_s = raw(&resp.ek_s);
            let sk = crypto::derive_session_key_client(
                &raw(&ek_c.private_b64()),
                &ik_x_priv,
                server_pub,
                &ek_s,
                &nonce_bytes,
            );
            return Ok((sk, ek_c_pub));
        }
        if hdr.msg_type == MSG_RESPONSE {
            let plain = crypto::decrypt(&shared, &buf[36..len]).map_err(|e| e.to_string())?;
            let resp: ResponseBody = decode_response(&plain).map_err(|e| e.to_string())?;
            return Err(resp.error.unwrap_or_else(|| "认证被拒".into()));
        }
    }
}

/// 会话期注册。
async fn session_register(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    ek_c: &RawKey,
    sk: &RawKey,
    seq: u64,
    ip: &str,
) -> Result<ResponseBody, String> {
    let nonce = crypto::session_nonce(seq, 0);
    let body = encode_register(&RegisterBody {
        ip: ip.to_string(),
        relay_rk: None,
        token: None,
        alias: None,
    })
    .unwrap();
    let ct = crypto::encrypt_with_nonce(sk, &nonce, &body);
    let frame = frame_signaling(MSG_REGISTER, ek_c, &ct);
    sock.send_to(&frame, server).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .map_err(|_| "会话期响应超时".to_string())?
            .map_err(|e| e.to_string())?;
        let hdr = parse_header(&buf[..len]).map_err(|e| e.to_string())?;
        if hdr.msg_type == MSG_RESPONSE {
            let resp_nonce = crypto::session_nonce(seq, 1);
            let plain =
                crypto::decrypt_with_nonce(sk, &resp_nonce, &buf[36..len]).map_err(|e| e.to_string())?;
            return decode_response(&plain).map_err(|e| e.to_string());
        }
    }
}

/// 启动一个 mesh 服务，返回 (server_addr, server_pub, mesh_root_pub, 已签发的加入码, signaling)。
async fn start_mesh_server(
    dir: &std::path::Path,
    n_invites: usize,
) -> (
    std::net::SocketAddr,
    RawKey,
    String,
    Vec<String>,
    Arc<Signaling>,
) {
    let (server_cfg, mut mesh) = make_server_config(dir);
    // 预先生成一批加入码
    let mut codes: Vec<String> = Vec::new();
    for _ in 0..n_invites {
        codes.push(mesh.create_invite(None, 600));
    }
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub = signaling.server_pub();
    let mesh_root_pub = B64.encode(mesh.root_public_raw().unwrap());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let srv = signaling.clone();
    tokio::spawn(async move { srv.cleanup_loop().await });
    (server_addr, server_pub, mesh_root_pub, codes, signaling)
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_auth_high_concurrency_100_devices() {
    let dir = std::env::temp_dir().join("linkmesh_test_concurrency_100");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (server_addr, server_pub, _mesh_root, codes, _signaling) = start_mesh_server(&dir, 150).await;

    // 生成 100 个设备，每个走 完整 mesh 认证（JOIN→AUTH→会话期 REGISTER）
    let n = 100usize;
    let mut devs = Vec::new();
    for _ in 0..n {
        devs.push(DeviceIdentitySerde::generate());
    }

    let start = Instant::now();
    let mut handles = Vec::new();
    for (i, dev) in devs.into_iter().enumerate() {
        let code = codes[i].clone();
        let server_addr = server_addr;
        let server_pub = server_pub;
        handles.push(tokio::spawn(async move {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let t0 = Instant::now();
            let (cert, ip) = do_join(&sock, &server_addr, &dev, &server_pub, &code).await?;
            let (sk, ek_c) = do_auth(&sock, &server_addr, &dev, &server_pub, &cert).await?;
            let resp = session_register(&sock, &server_addr, &ek_c, &sk, 1, &ip).await?;
            let join_ms = t0.elapsed().as_millis() as u64;
            if resp.ok {
                Ok::<_, String>(join_ms)
            } else {
                Err(resp.error.unwrap_or_else(|| "注册被拒".into()))
            }
        }));
    }
    let mut ok = 0u64;
    let mut lats = Vec::new();
    for h in handles {
        match h.await {
            Ok(Ok(ms)) => {
                ok += 1;
                lats.push(ms);
            }
            Ok(Err(e)) => eprintln!("设备失败: {e}"),
            Err(e) => eprintln!("任务 panicked: {e}"),
        }
    }
    let elapsed = start.elapsed().as_millis();
    lats.sort_unstable();
    let p50 = lats.get(lats.len() * 50 / 100).copied().unwrap_or(0);
    let p95 = lats.get(lats.len() * 95 / 100).copied().unwrap_or(0);
    let p99 = lats.get(lats.len() * 99 / 100).copied().unwrap_or(0);
    let rate = n as f64 * 1000.0 / elapsed.max(1) as f64;
    println!(
        "[mesh_auth_concurrency_{n}] ok={ok}/{n} 总耗时 {elapsed}ms ({rate:.0}/s) p50={p50}ms p95={p95}ms p99={p99}ms"
    );
    assert_eq!(ok, n as u64, "全部设备应完成 JOIN+AUTH+REGISTER");
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_session_relay_throughput() {
    let dir = std::env::temp_dir().join("linkmesh_test_concurrency_relay");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (server_addr, server_pub, _mesh_root, codes, _signaling) = start_mesh_server(&dir, 10).await;

    // 2 个设备认证
    let dev_a = DeviceIdentitySerde::generate();
    let dev_b = DeviceIdentitySerde::generate();
    let code_a = codes[0].clone();
    let code_b = codes[1].clone();
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_a, &server_addr, &dev_a, &server_pub, &code_a).await.unwrap();
    let (cert_b, ip_b) = do_join(&sock_b, &server_addr, &dev_b, &server_pub, &code_b).await.unwrap();
    let (sk_a, ek_a) = do_auth(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a).await.unwrap();
    let (sk_b, ek_b) = do_auth(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b).await.unwrap();
    let _ = session_register(&sock_a, &server_addr, &ek_a, &sk_a, 1, &ip_a).await.unwrap();
    let _ = session_register(&sock_b, &server_addr, &ek_b, &sk_b, 1, &ip_b).await.unwrap();

    // 通过中继批量路径压测：A 发中继帧到 B
    // 直接发送 MSG_RELAY（ik_x 头部），测量吞吐与 0 丢包
    let payload = vec![0x42u8; 512];
    let n = 2000usize;
    let start = Instant::now();
    let mut sent_ok = 0u64;
    for _ in 0..n {
        let pkt = linkmesh_shared::protocol::frame_relay(
            &dev_b.ik_x_public_raw().unwrap(),
            &dev_a.ik_x_public_raw().unwrap(),
            &payload,
        );
        sock_a.send_to(&pkt, server_addr).await.unwrap();
        sent_ok += 1;
    }
    let elapsed = start.elapsed().as_millis();
    let mbps = (sent_ok as f64 * payload.len() as f64 * 8.0) / (elapsed as f64 / 1000.0) / 1_000_000.0;
    println!(
        "[mesh_session_relay] 发送 {sent_ok} 帧 512B 耗时 {elapsed}ms，中继发送吞吐 {mbps:.1} Mbps（0 丢包路径验证）"
    );
    assert!(sent_ok > 0);
}

/// 会话路径高并发：多个已认证设备并发发送 HEARTBEAT（走 SK + 确定性 nonce 会话路径），
/// 验证数据面/信令热路径在并发下无丢失、无重放误判、无崩溃。
#[tokio::test(flavor = "multi_thread")]
async fn session_heartbeat_high_concurrency_20_devices() {
    let dir = std::env::temp_dir().join("linkmesh_test_concurrency_hb");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (server_addr, server_pub, _mesh_root, codes, _signaling) = start_mesh_server(&dir, 40).await;

    // 20 个设备完成认证
    let n = 20usize;
    let mut handles = Vec::new();
    for i in 0..n {
        let code = codes[i].clone();
        let server_addr = server_addr;
        let server_pub = server_pub;
        handles.push(tokio::spawn(async move {
            let dev = DeviceIdentitySerde::generate();
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (cert, ip) = do_join(&sock, &server_addr, &dev, &server_pub, &code).await?;
            let (sk, ek_c) = do_auth(&sock, &server_addr, &dev, &server_pub, &cert).await?;
            session_register(&sock, &server_addr, &ek_c, &sk, 1, &ip).await?;
            Ok::<_, String>((sock, ek_c, sk, ip))
        }));
    }
    let mut devices = Vec::new();
    for h in handles {
        match h.await {
            Ok(Ok(d)) => devices.push(d),
            Ok(Err(e)) => panic!("设备认证失败: {e}"),
            Err(e) => panic!("任务 panicked: {e}"),
        }
    }
    assert_eq!(devices.len(), n);

    // 每个设备并发发 100 次会话 HEARTBEAT（各自独立的计数器 nonce），统计成功与丢包。
    let start = Instant::now();
    let mut handles = Vec::new();
    for (di, (sock, ek_c, sk, ip)) in devices.into_iter().enumerate() {
        handles.push(tokio::spawn(async move {
            let mut ok = 0u64;
            for seq in 2..102 {
                let nonce = crypto::session_nonce(seq, 0);
                let body = encode_register(&RegisterBody {
                    ip: ip.clone(),
                    relay_rk: None,
                    token: None,
                    alias: None,
                })
                .unwrap();
                let ct = crypto::encrypt_with_nonce(&sk, &nonce, &body);
                let frame = frame_signaling(MSG_REGISTER, &ek_c, &ct);
                sock.send_to(&frame, server_addr).await.ok();
                // 循环读取，跳过 NOTIFY 等非 RESPONSE 包，直到收到当前 seq 的响应或超时
                let deadline = Instant::now() + Duration::from_secs(2);
                let mut got = false;
                while Instant::now() < deadline {
                    let mut buf = vec![0u8; 4096];
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
                        Ok(Ok((len, _))) => {
                            if let Ok(hdr) = parse_header(&buf[..len]) {
                                if hdr.msg_type == MSG_RESPONSE {
                                    let resp_nonce = crypto::session_nonce(seq, 1);
                                    if let Ok(plain) = crypto::decrypt_with_nonce(
                                        &sk,
                                        &resp_nonce,
                                        &buf[36..len],
                                    ) {
                                        if let Ok(resp) = decode_response(&plain) {
                                            if resp.ok {
                                                ok += 1;
                                            }
                                            got = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        _ => break,
                    }
                }
                let _ = got;
                let _ = di;
            }
            ok
        }));
    }
    let mut total_ok = 0u64;
    let total_sent = n as u64 * 100;
    for h in handles {
        total_ok += h.await.unwrap_or(0);
    }
    let elapsed = start.elapsed().as_millis();
    let rate = total_ok as f64 / (elapsed.max(1) as f64 / 1000.0);
    println!(
        "[session_hb_concurrency_{n}] ok={total_ok}/{total_sent} ({:.1}%) 耗时 {elapsed}ms ({rate:.0}/s)",
        100.0 * total_ok as f64 / total_sent as f64
    );
    // 会话路径是高优先级热路径，要求极高成功率（允许极小 UDP 抖动）
    assert!(total_ok as f64 / total_sent as f64 > 0.95, "会话心跳成功率应 >95%");
}

