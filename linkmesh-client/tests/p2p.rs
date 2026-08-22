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

//! 端到端集成测试：本机起一个信令/中继服务，两个客户端通过 UDP 打洞直连传输数据。
//!
//! 不使用真实 TUN（无需 root）：数据面用注入通道送入、输出通道捕获。

use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_client::connection::Conn;
use linkmesh_client::config::{ClientConfig, ConnectionEntry, ServerEntry, VmNicConfig};
use linkmesh_client::log::Logger as ClientLogger;
use linkmesh_server::log::Logger as ServerLogger;
use linkmesh_server::config::ServerConfig;
use linkmesh_server::mesh::MeshConfig;
use linkmesh_server::signaling::Signaling;
use linkmesh_shared::crypto::{self, KeyPairSerde, RawKey};
use linkmesh_shared::protocol::{
    decode_auth_resp, decode_response, decode_server_info_body, encode_auth, encode_join,
    encode_query, encode_register, frame_relay, frame_signaling, parse_header, parse_relay,
    parse_relay_batch, AuthBody, AuthRespBody, HEADER_LEN, MSG_AUTH, MSG_AUTH_RESP, MSG_JOIN,
    MSG_QUERY, MSG_REGISTER, MSG_RELAY, MSG_RELAY_BATCH, MSG_RESPONSE, MSG_SERVERINFO, QueryBody,
    RegisterBody, ResponseBody, ResponseData, ServerInfoBody,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

fn make_server_config() -> ServerConfig {
    ServerConfig {
        version: 1,
        listen: "127.0.0.1:0".to_string(),
        control_port: 0,
        route_ttl_sec: 300,
        relay: Default::default(),
        join_rate_per_min_per_ip: 200,
        keypair: Some(KeyPairSerde::generate()),
        signing: Some(linkmesh_shared::identity::SignKeyPairSerde::generate()),
        mesh_path: "/tmp/linkmesh_test_mesh.json".to_string(),
        server_name: "test".to_string(),
        control_token: None,
        rooms: Vec::new(),
        aliases: Vec::new(),
        log_file: "/tmp/linkmesh_test_server.log".to_string(),
        pid_file: "/tmp/linkmesh_test_server.pid".to_string(),
    }
}

fn make_client_config(
    dir: &std::path::Path,
    identity: linkmesh_shared::identity::DeviceIdentitySerde,
    ip: &str,
    server_endpoint: &str,
    server_pub: &str,
) -> ClientConfig {
    let mut cfg = ClientConfig {
        version: 1,
        identity: Some(identity),
        vm_nics: vec![VmNicConfig::new("test0".to_string(), ip.to_string())],
        servers: vec![ServerEntry {
            name: "s1".to_string(),
            endpoint: server_endpoint.to_string(),
            public_key: Some(server_pub.to_string()),
            relay: Default::default(),
            mesh_root_pub: None,
            device_cert: None,
            crl_version: None,
            token: None,
        }],
        connections: vec![ConnectionEntry {
            server: "s1".to_string(),
            vm_nic: "test0".to_string(),
        }],
        ..Default::default()
    };
    cfg.log_file = dir.join("client.log").to_string_lossy().to_string();
    cfg.control_port = 0;
    cfg
}

/// 构造一个最小合法 IPv4 包，目的 IP 为 `dst`，载荷为 `payload`。
fn build_ipv4_packet(dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45); // version=4, IHL=5
    pkt.push(0);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0x4000u16.to_be_bytes());
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&[10, 13, 13, 1]);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(payload);
    pkt
}

#[tokio::test(flavor = "multi_thread")]
async fn p2p_direct_transfer_between_two_clients() {
    // 1. 起一个 mesh 模式信令/中继服务（网格强制认证：设备先 JOIN 换取证书）
    let dir = std::env::temp_dir().join("linkmesh_test_p2p");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);

    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let srv = signaling.clone();
    tokio::spawn(async move { srv.cleanup_loop().await });
    let server_pub = raw(&server_pub_b64);
    let mesh_root_pub = B64.encode(mesh.root_public_raw().unwrap());

    // 2. 两台设备 JOIN → 证书 + 分配 IP
    let sock_join_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_join_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let sock_join_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_b, ip_b) = do_join(&sock_join_b, &server_addr, &dev_b, &server_pub, &code_b).await;

    // 3. 两个客户端（mesh：identity + 证书）
    let ep = server_addr.to_string();
    let cfg_a = make_mesh_client_config(&dir, dev_a, &ip_a, &ep, &server_pub_b64, &mesh_root_pub, &cert_a);
    let cfg_b = make_mesh_client_config(&dir, dev_b, &ip_b, &ep, &server_pub_b64, &mesh_root_pub, &cert_b);

    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(64);
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(64);

    let (quit_a, quit_rx_a) = watch::channel(false);
    let (conn_a, handle_a) = Conn::new(
        &cfg_a,
        &cfg_a.connections[0],
        quit_rx_a,
        ClientLogger::new(dir.join("a.log")),
    )
    .await
    .unwrap();
    let mut conn_a = conn_a;
    conn_a.inject_rx = Some(inject_rx);
    let task_a = tokio::spawn(async move { conn_a.run().await });

    let (quit_b, quit_rx_b) = watch::channel(false);
    let (conn_b, handle_b) = Conn::new(
        &cfg_b,
        &cfg_b.connections[0],
        quit_rx_b,
        ClientLogger::new(dir.join("b.log")),
    )
    .await
    .unwrap();
    let mut conn_b = conn_b;
    conn_b.tun_sink = Some(sink_tx);
    let task_b = tokio::spawn(async move { conn_b.run().await });

    // 4. 等待注册完成
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // 5. A 向 B 的虚拟 IP 注入一个包
    let payload = b"hello from A";
    let pkt = build_ipv4_packet([10, 13, 13, 2], payload);
    inject_tx.send(pkt.clone()).await.unwrap();

    // 6. B 应通过 tun_sink 收到解密的 IP 包
    match tokio::time::timeout(Duration::from_secs(6), sink_rx.recv()).await {
        Ok(Some(received)) => {
            assert_eq!(received, pkt, "B 收到的 IP 包应与 A 注入的一致");
        }
        other => {
            eprintln!("A state: {}", handle_a.snapshot().await);
            eprintln!("B state: {}", handle_b.snapshot().await);
            panic!("B 未在超时内收到数据: {other:?}");
        }
    }

    // 7. 清理
    let _ = quit_a.send(true);
    let _ = quit_b.send(true);
    task_a.abort();
    task_b.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn signaling_register_query_relay_flow() {
    let dir = std::env::temp_dir().join("linkmesh_test_reg_query_relay");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);
    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let server_pub = raw(&server_pub_b64);
    let a_pub = dev_a.ik_x_public_raw().unwrap();
    let b_pub = dev_b.ik_x_public_raw().unwrap();

    // 两台设备 JOIN → AUTH → 会话期注册
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let (cert_b, ip_b) = do_join(&sock_b, &server_addr, &dev_b, &server_pub, &code_b).await;
    let (sk_a, ek_c_a, _) = do_auth(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a).await;
    let (sk_b, ek_c_b, _) = do_auth(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b).await;
    assert!(session_register(&sock_a, &server_addr, &ek_c_a, &sk_a, 1, &ip_a).await.ok);
    assert!(session_register(&sock_b, &server_addr, &ek_c_b, &sk_b, 1, &ip_b).await.ok);

    // B 查询 A 的坐标
    let resp = session_query(&sock_b, &server_addr, &ek_c_b, &sk_b, 2, &ip_a).await;
    match resp.data {
        ResponseData::QueryHit { ip, public_key, .. } => {
            assert_eq!(ip, "10.13.13.1");
            assert_eq!(raw(&public_key), a_pub);
        }
        _ => panic!("应返回 QueryHit: {resp:?}"),
    }

    // 中继：A 发给 B 一个中继封包，B 应收到（可能被批量拼接成一个大包）
    let relay_ct = b"encrypted-payload";
    let frame = frame_relay(&b_pub, &a_pub, relay_ct);
    sock_a.send_to(&frame, server_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (len, _) = tokio::time::timeout(remain, sock_b.recv_from(&mut buf))
            .await
            .expect("B 未收到中继转发")
            .unwrap();
        let hdr = parse_header(&buf[..len]).unwrap();
        match hdr.msg_type {
            MSG_RELAY => {
                let (dest, src, body) = parse_relay(&buf[..len]).unwrap();
                assert_eq!(dest, b_pub, "中继目标应为 B");
                assert_eq!(src, a_pub, "中继来源应为 A");
                assert_eq!(body, relay_ct, "中继内容应原样透传");
                break;
            }
            MSG_RELAY_BATCH => {
                let (dest, subframes) = parse_relay_batch(&buf[..len]).unwrap();
                assert_eq!(dest, b_pub, "批量中继目标应为 B");
                assert_eq!(subframes.len(), 1, "批量应恰好包含一个子帧");
                let sf = subframes[0];
                assert!(sf.len() >= 32);
                assert_eq!(&sf[..32], a_pub.as_ref(), "子帧来源应为 A");
                assert_eq!(&sf[32..], relay_ct, "中继内容应原样透传");
                break;
            }
            // 其他帧（如查询触发的 NOTIFY）跳过
            _ => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_fallback_when_hole_punch_disabled() {
    let dir = std::env::temp_dir().join("linkmesh_test_relay");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);
    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let relay_stats = signaling.stats.clone();

    let server_pub = raw(&server_pub_b64);
    let mesh_root_pub = B64.encode(mesh.root_public_raw().unwrap());

    let sock_join_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_join_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let sock_join_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_b, ip_b) = do_join(&sock_join_b, &server_addr, &dev_b, &server_pub, &code_b).await;

    let ep = server_addr.to_string();
    let mut cfg_a = make_mesh_client_config(&dir, dev_a, &ip_a, &ep, &server_pub_b64, &mesh_root_pub, &cert_a);
    cfg_a.hole_punch.enabled = false;
    let mut cfg_b = make_mesh_client_config(&dir, dev_b, &ip_b, &ep, &server_pub_b64, &mesh_root_pub, &cert_b);
    cfg_b.hole_punch.enabled = false;

    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(64);
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(64);

    let (quit_a, quit_rx_a) = watch::channel(false);
    let (conn_a, _h) = Conn::new(
        &cfg_a,
        &cfg_a.connections[0],
        quit_rx_a,
        ClientLogger::new(dir.join("a.log")),
    )
    .await
    .unwrap();
    let mut conn_a = conn_a;
    conn_a.inject_rx = Some(inject_rx);
    let task_a = tokio::spawn(async move { conn_a.run().await });

    let (quit_b, quit_rx_b) = watch::channel(false);
    let (conn_b, _h) = Conn::new(
        &cfg_b,
        &cfg_b.connections[0],
        quit_rx_b,
        ClientLogger::new(dir.join("b.log")),
    )
    .await
    .unwrap();
    let mut conn_b = conn_b;
    conn_b.tun_sink = Some(sink_tx);
    let task_b = tokio::spawn(async move { conn_b.run().await });

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let payload = b"relay payload";
    let pkt = build_ipv4_packet([10, 13, 13, 2], payload);
    inject_tx.send(pkt.clone()).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(6), sink_rx.recv())
        .await
        .expect("B 未在超时内通过中继收到数据")
        .expect("通道关闭");
    assert_eq!(received, pkt);

    // 中继字节应 > 0，证明数据确实经由服务器转发（批量路径异步刷新，轮询等待）
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        {
            if relay_stats.bytes_relayed.load(std::sync::atomic::Ordering::Relaxed) > 0 {
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "中继字节应为正（数据必须经过中继），当前 bytes_relayed={} packets_out={}",
                relay_stats.bytes_relayed.load(std::sync::atomic::Ordering::Relaxed),
                relay_stats.packets_out.load(std::sync::atomic::Ordering::Relaxed)
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let _ = quit_a.send(true);
    let _ = quit_b.send(true);
    task_a.abort();
    task_b.abort();
}

fn raw(b64: &str) -> RawKey {
    crypto::parse_public_key(b64).unwrap()
}

async fn send_register(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    my_pub: &RawKey,
    my_priv: &RawKey,
    server_pub: &RawKey,
    ip: &str,
) {
    let shared = crypto::shared_secret(my_priv, server_pub);
    let body = encode_register(&RegisterBody { ip: ip.to_string(), relay_rk: None, token: None, alias: None }).unwrap();
    let ct = crypto::encrypt(&shared, &body);
    let frame = frame_signaling(MSG_REGISTER, my_pub, &ct);
    sock.send_to(&frame, server).await.unwrap();
}

// 清理辅助

/// 数据面 rk 频繁轮换（PFS）下数据流不得中断：
/// 双方 rekey_every_pkts=3，A 注入 30 个包，B 应全部收到（期间发生多次 epoch 切换）。
#[tokio::test(flavor = "multi_thread")]
async fn p2p_rekey_keeps_flowing() {
    let dir = std::env::temp_dir().join("linkmesh_test_rekey");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);
    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let srv = signaling.clone();
    tokio::spawn(async move { srv.cleanup_loop().await });
    let server_pub = raw(&server_pub_b64);
    let mesh_root_pub = B64.encode(mesh.root_public_raw().unwrap());

    let sock_join_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_join_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let sock_join_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_b, ip_b) = do_join(&sock_join_b, &server_addr, &dev_b, &server_pub, &code_b).await;

    let ep = server_addr.to_string();
    let mut cfg_a = make_mesh_client_config(&dir, dev_a, &ip_a, &ep, &server_pub_b64, &mesh_root_pub, &cert_a);
    let mut cfg_b = make_mesh_client_config(&dir, dev_b, &ip_b, &ep, &server_pub_b64, &mesh_root_pub, &cert_b);
    cfg_a.rekey_every_pkts = 3; // 高频轮换，强制反复走 REKEY 流程
    cfg_b.rekey_every_pkts = 3;
    cfg_a.hole_punch.enabled = false;
    cfg_b.hole_punch.enabled = false;

    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(1024);

    let (quit_a, quit_rx_a) = watch::channel(false);
    let (conn_a, _h) = Conn::new(
        &cfg_a,
        &cfg_a.connections[0],
        quit_rx_a,
        ClientLogger::new(dir.join("a.log")),
    )
    .await
    .unwrap();
    let mut conn_a = conn_a;
    conn_a.inject_rx = Some(inject_rx);
    let task_a = tokio::spawn(async move { conn_a.run().await });

    let (quit_b, quit_rx_b) = watch::channel(false);
    let (conn_b, _h) = Conn::new(
        &cfg_b,
        &cfg_b.connections[0],
        quit_rx_b,
        ClientLogger::new(dir.join("b.log")),
    )
    .await
    .unwrap();
    let mut conn_b = conn_b;
    conn_b.tun_sink = Some(sink_tx);
    let task_b = tokio::spawn(async move { conn_b.run().await });

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let total = 30usize;
    let mut got = 0usize;
    // 先注入一个触发会话建立，再逐个发送，给足 rekey/握手时间
    for i in 0..total {
        let payload = format!("rekey-{i}").into_bytes();
        let pkt = build_ipv4_packet([10, 13, 13, 2], &payload);
        inject_tx.send(pkt).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(50), sink_rx.recv()).await {
            got += 1;
        }
    }
    // 收尾：再集中收一会儿未到的包
    while got < total {
        match tokio::time::timeout(Duration::from_millis(500), sink_rx.recv()).await {
            Ok(Some(_)) => got += 1,
            _ => break,
        }
    }
    let _ = quit_a.send(true);
    let _ = quit_b.send(true);
    task_a.abort();
    task_b.abort();

    assert_eq!(
        got, total,
        "高频 rk 轮换下数据流不应中断: got {got}/{total}"
    );
}

// =====================================================================
// P0-2 完整认证体系（mesh 模式）：JOIN → AUTH → 会话期信令 → 中继会话绑定
// =====================================================================

/// 构造启用 mesh 的服务器配置（独立临时 mesh.json，避免污染其他测试）。
fn make_mesh_server_config(dir: &std::path::Path) -> (ServerConfig, MeshConfig) {
    let mesh_id = MeshConfig::generate_mesh_id();
    let mut mesh = MeshConfig::init(&mesh_id);
    mesh.ip_pool = vec![
        "10.13.13.1".into(),
        "10.13.13.2".into(),
        "10.13.13.3".into(),
        "10.13.13.4".into(),
        "10.13.13.5".into(),
    ];
    let mesh_path = dir.join("mesh.json");
    mesh.save(&mesh_path).unwrap();
    let mut cfg = make_server_config();
    cfg.mesh_path = mesh_path.to_string_lossy().to_string();
    (cfg, mesh)
}

/// 设备侧 JOIN：发送 MSG_JOIN 并等待响应，返回服务端签发的证书与分配 IP。
async fn do_join(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    dev: &linkmesh_shared::identity::DeviceIdentitySerde,
    server_pub: &RawKey,
    code: &str,
) -> (linkmesh_shared::cert::DeviceCert, String) {
    let ik_x = dev.ik_x_public_raw().unwrap();
    let device_id = dev.device_id().unwrap();
    let shared = crypto::shared_secret(&raw(&dev.ik_x.private_b64()), server_pub);
    let body = linkmesh_shared::protocol::JoinBody {
        code: code.to_string(),
        device_id,
        ik_x: dev.ik_x.public_b64(),
        ik_s_pub: dev.ik_s.public_b64(),
        requested_ip: None,
        token: None,
        alias: None,
    };
    let ct = crypto::encrypt(&shared, &encode_join(&body).unwrap());
    let frame = frame_signaling(MSG_JOIN, &ik_x, &ct);
    sock.send_to(&frame, server).await.unwrap();

    let mut buf = vec![0u8; 65536];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("JOIN 响应超时")
            .unwrap();
        let hdr = parse_header(&buf[..len]).unwrap();
        if hdr.msg_type == MSG_RESPONSE {
            let plain = crypto::decrypt(&shared, &buf[HEADER_LEN..len]).unwrap();
            let resp: ResponseBody = decode_response(&plain).unwrap();
            if resp.ok {
                match resp.data {
                    ResponseData::Join { cert, allocated_ip, .. } => {
                        return (cert, allocated_ip);
                    }
                    _ => panic!("expected JOIN data"),
                }
            }
        }
    }
}

/// 设备侧 AUTH：发送 MSG_AUTH，返回 (会话密钥, ek_c, ek_s)。
async fn do_auth(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    dev: &linkmesh_shared::identity::DeviceIdentitySerde,
    server_pub: &RawKey,
    cert: &linkmesh_shared::cert::DeviceCert,
) -> (RawKey, RawKey, RawKey) {
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
    sock.send_to(&frame, server).await.unwrap();

    let mut buf = vec![0u8; 65536];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("AUTH 响应超时")
            .unwrap();
        let hdr = parse_header(&buf[..len]).unwrap();
        if hdr.msg_type == MSG_AUTH_RESP {
            let plain = crypto::decrypt(&shared, &buf[HEADER_LEN..len]).unwrap();
            let resp: AuthRespBody = decode_auth_resp(&plain).unwrap();
            assert_eq!(resp.allocated_ip, cert.allowed_ip);
            let ek_s = raw(&resp.ek_s);
            let sk = crypto::derive_session_key_client(
                &raw(&ek_c.private_b64()),
                &ik_x_priv,
                server_pub,
                &ek_s,
                &nonce_bytes,
            );
            return (sk, ek_c_pub, ek_s);
        }
    }
}

/// 会话期注册：帧头 sender = ek_c，负载用 SK + 计数器 nonce 加密。
async fn session_register(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    ek_c: &RawKey,
    sk: &RawKey,
    seq: u64,
    ip: &str,
) -> ResponseBody {
    session_register_ex(sock, server, ek_c, sk, seq, ip, None).await
}

/// 会话期注册（可携带自报别名）。
async fn session_register_ex(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    ek_c: &RawKey,
    sk: &RawKey,
    seq: u64,
    ip: &str,
    alias: Option<&str>,
) -> ResponseBody {
    let nonce = crypto::session_nonce(seq, 0);
    let body = encode_register(&RegisterBody {
        ip: ip.to_string(),
        relay_rk: None,
        token: None,
        alias: alias.map(|s| s.to_string()),
    })
    .unwrap();
    let ct = crypto::encrypt_with_nonce(sk, &nonce, &body);
    let frame = frame_signaling(MSG_REGISTER, ek_c, &ct);
    sock.send_to(&frame, server).await.unwrap();

    let mut buf = vec![0u8; 4096];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("会话期响应超时")
            .unwrap();
        let hdr = parse_header(&buf[..len]).unwrap();
        if hdr.msg_type == MSG_RESPONSE {
            let resp_nonce = crypto::session_nonce(seq, 1);
            let plain = crypto::decrypt_with_nonce(sk, &resp_nonce, &buf[HEADER_LEN..len]).unwrap();
            return decode_response(&plain).unwrap();
        }
    }
}

/// P0-2 完整认证链路：
/// 1) KEYQUERY 返回 root 签名 ServerInfo（MSG_SERVERINFO），指纹可验证；
/// 2) 未认证设备直接 REGISTER 被拒（mesh 模式拒绝握手期注册）；
/// 3) JOIN（一次性加入码）→ 签发 DeviceCert + 分配 IP；
/// 4) AUTH（证书 + 3-DH）→ 会话建立，AUTH_RESP 携带 CRL/ServerInfo；
/// 5) 会话期 REGISTER 成功（IP 与证书一致），重放同一帧被拒；
/// 6) 中继来源必须是活跃会话（无会话的伪造来源被丢弃）。
#[tokio::test(flavor = "multi_thread")]
async fn mesh_auth_full_chain() {
    let dir = std::env::temp_dir().join("linkmesh_test_mesh_chain");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);

    // 两个设备
    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();

    // 管理员签发两个一次性加入码
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    // 启动服务器（mesh 模式）
    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    {
        let m = signaling.mesh.lock().await;
        assert!(!m.mesh_id.is_empty(), "mesh 模式必须启用");
    }
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });

    let server_pub = raw(&server_pub_b64);
    let ik_a = dev_a.ik_x_public_raw().unwrap();
    let ik_b = dev_b.ik_x_public_raw().unwrap();

    // 1) KEYQUERY → MSG_SERVERINFO（root 签名）
    let sock_probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let frame = frame_signaling(linkmesh_shared::protocol::MSG_KEYQUERY, &ik_a, &[]);
    sock_probe.send_to(&frame, server_addr).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock_probe.recv_from(&mut buf))
        .await
        .expect("ServerInfo 响应超时")
        .unwrap();
    let hdr = parse_header(&buf[..len]).unwrap();
    assert_eq!(hdr.msg_type, MSG_SERVERINFO, "mesh 模式 KEYQUERY 应返回 ServerInfo");
    let sib: ServerInfoBody = decode_server_info_body(&buf[HEADER_LEN..len]).unwrap();
    // 用 mesh root 公钥验证 ServerInfo 签名，并核对服务器公钥（server_ik_x）
    let root_pub = mesh.root_public_raw().unwrap();
    assert_eq!(sib.server_info.mesh_root_pub, B64.encode(root_pub));
    sib.server_info.verify(&root_pub).unwrap();
    assert_eq!(sib.server_info.server_ik_x, server_pub_b64);

    // 2) 未认证设备直接注册 → 被拒（握手期注册不被接受）
    let sock_evil = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send_register(&sock_evil, &server_addr, &ik_a, &raw(&dev_a.ik_x.private_b64()), &server_pub, "10.13.13.1").await;
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock_evil.recv_from(&mut buf))
        .await
        .expect("拒绝响应超时")
        .unwrap();
    let hdr = parse_header(&buf[..len]).unwrap();
    assert_eq!(hdr.msg_type, MSG_RESPONSE);
    let shared_a = crypto::shared_secret(&raw(&dev_a.ik_x.private_b64()), &server_pub);
    let plain = crypto::decrypt(&shared_a, &buf[HEADER_LEN..len]).unwrap();
    let resp: ResponseBody = decode_response(&plain).unwrap();
    assert!(!resp.ok, "mesh 模式未认证注册必须被拒: {resp:?}");

    // 3) A 加入（code_a）→ 证书 + IP
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    assert_eq!(ip_a, "10.13.13.1", "池内第一个空闲 IP");
    cert_a.verify(&root_pub, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).unwrap();

    // B 加入
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_b, ip_b) = do_join(&sock_b, &server_addr, &dev_b, &server_pub, &code_b).await;
    assert_eq!(ip_b, "10.13.13.2");

    // 4) A/B 各自 AUTH → 会话
    let (sk_a, ek_c_a, _) = do_auth(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a).await;
    let (sk_b, ek_c_b, _) = do_auth(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b).await;

    // 5) 会话期注册（IP 与证书一致 → 成功）
    let r1 = session_register(&sock_a, &server_addr, &ek_c_a, &sk_a, 1, "10.13.13.1").await;
    assert!(r1.ok, "会话期注册应成功: {r1:?}");
    let r2 = session_register(&sock_b, &server_addr, &ek_c_b, &sk_b, 1, "10.13.13.2").await;
    assert!(r2.ok, "B 会话期注册应成功: {r2:?}");

    // 重放同一帧（seq=1 再发）→ 计数器/nonce 校验失败，无响应或响应异常
    let nonce = crypto::session_nonce(1, 0);
    let body = encode_register(&RegisterBody { ip: "10.13.13.1".into(), relay_rk: None, token: None, alias: None }).unwrap();
    let ct = crypto::encrypt_with_nonce(&sk_a, &nonce, &body);
    let frame = frame_signaling(MSG_REGISTER, &ek_c_a, &ct);
    sock_a.send_to(&frame, server_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let replayed = tokio::time::timeout(Duration::from_millis(500), sock_a.recv_from(&mut buf))
        .await
        .is_ok();
    assert!(!replayed, "重放会话期帧不应得到成功响应");

    // 6) 中继来源会话绑定：伪造来源（无会话的公钥）的中继帧被丢弃
    let sock_flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let evil_pub = raw(&KeyPairSerde::generate().public_b64());
    let frame = frame_relay(&ik_b, &evil_pub, b"forged");
    sock_flood.send_to(&frame, server_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let got = tokio::time::timeout(Duration::from_millis(500), sock_b.recv_from(&mut buf))
        .await
        .is_ok();
    assert!(!got, "伪造来源的中继帧必须被丢弃");

    // 有会话的来源（A）→ B 可收到
    let frame = frame_relay(&ik_b, &ik_a, b"legit");
    sock_a.send_to(&frame, server_addr).await.unwrap();
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock_b.recv_from(&mut buf))
        .await
        .expect("合法来源中继应被转发")
        .unwrap();
    let hdr = parse_header(&buf[..len]).unwrap();
    match hdr.msg_type {
        MSG_RELAY => {
            let (dest, src, body) = parse_relay(&buf[..len]).unwrap();
            assert_eq!(dest, ik_b);
            assert_eq!(src, ik_a);
            assert_eq!(body, b"legit");
        }
        MSG_RELAY_BATCH => {
            let (_dest, subs) = parse_relay_batch(&buf[..len]).unwrap();
            assert_eq!(subs.len(), 1);
            assert_eq!(&subs[0][..32], ik_a.as_ref());
            assert_eq!(&subs[0][32..], b"legit");
        }
        other => panic!("意外消息类型 {other}"),
    }
}

/// 吊销后立即拒绝：已吊销设备的 AUTH 被拒，且已建会话被踢（中继来源校验失败）。
#[tokio::test(flavor = "multi_thread")]
async fn mesh_revoke_kicks_session() {
    let dir = std::env::temp_dir().join("linkmesh_test_mesh_revoke");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);
    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let code_a = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let server_pub = raw(&server_pub_b64);

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let (sk_a, ek_c_a, _) = do_auth(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a).await;
    let r = session_register(&sock_a, &server_addr, &ek_c_a, &sk_a, 1, &ip_a).await;
    assert!(r.ok);

    // 吊销
    let dev_id = cert_a.device_id.clone();
    let _ = signaling
        .revoke_device(&dev_id, linkmesh_shared::cert::RevokeReason::Compromised)
        .await
        .unwrap();

    // 会话被踢：再次会话期注册（新 seq）得不到成功响应
    let body = encode_register(&RegisterBody { ip: ip_a.clone(), relay_rk: None, token: None, alias: None }).unwrap();
    let nonce = crypto::session_nonce(2, 0);
    let ct = crypto::encrypt_with_nonce(&sk_a, &nonce, &body);
    let frame = frame_signaling(MSG_REGISTER, &ek_c_a, &ct);
    sock_a.send_to(&frame, server_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let got = tokio::time::timeout(Duration::from_millis(500), sock_a.recv_from(&mut buf))
        .await
        .is_ok();
    assert!(!got, "吊销后旧会话必须失效");

    // 重新 AUTH（同证书）→ 拒绝（已吊销），服务端返回 ok=false 的 MSG_RESPONSE
    let sock_a2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ik_x_priv = raw(&dev_a.ik_x.private_b64());
    let ik_x_pub = raw(&dev_a.ik_x.public_b64());
    let shared = crypto::shared_secret(&ik_x_priv, &server_pub);
    let ek_c = KeyPairSerde::generate();
    let body = AuthBody {
        device_id: cert_a.device_id.clone(),
        cert: cert_a.clone(),
        ek_c: ek_c.public_b64(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce: B64.encode([9u8; 12]),
        token: None,
    };
    let ct = crypto::encrypt(&shared, &encode_auth(&body).unwrap());
    let frame = frame_signaling(MSG_AUTH, &ik_x_pub, &ct);
    sock_a2.send_to(&frame, server_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock_a2.recv_from(&mut buf))
        .await
        .expect("吊销后 AUTH 应收到拒绝响应")
        .unwrap();
    let hdr = parse_header(&buf[..len]).unwrap();
    assert_eq!(hdr.msg_type, MSG_RESPONSE, "吊销后 AUTH 应返回错误响应");
    let plain = crypto::decrypt(&shared, &buf[HEADER_LEN..len]).unwrap();
    let resp: ResponseBody = decode_response(&plain).unwrap();
    assert!(!resp.ok, "已吊销设备 AUTH 必须被拒: {resp:?}");

    // 吊销后会话表已清空该设备
    let sessions = signaling.sessions.lock().await;
    assert!(
        sessions.values().all(|s| s.device_id != dev_id),
        "吊销后会话表不应残留该设备"
    );
}

/// 构造 mesh 模式客户端配置：identity + 已加入状态（mesh_root_pub + device_cert）。
fn make_mesh_client_config(
    dir: &std::path::Path,
    identity: linkmesh_shared::identity::DeviceIdentitySerde,
    ip: &str,
    server_endpoint: &str,
    server_pub: &str,
    mesh_root_pub: &str,
    cert: &linkmesh_shared::cert::DeviceCert,
) -> ClientConfig {
    let mut cfg = make_client_config(dir, identity, ip, server_endpoint, server_pub);
    cfg.servers[0].mesh_root_pub = Some(mesh_root_pub.to_string());
    cfg.servers[0].device_cert = Some(cert.clone());
    cfg.servers[0].crl_version = Some(0);
    cfg
}

/// P0-2 完整认证 + 数据面端到端：两个设备 JOIN → AUTH → 会话期注册 → 中继数据面传输。
#[tokio::test(flavor = "multi_thread")]
async fn p2p_mesh_auth_data_transfer() {
    let dir = std::env::temp_dir().join("linkmesh_test_mesh_p2p");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);

    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let srv = signaling.clone();
    tokio::spawn(async move { srv.cleanup_loop().await });
    let server_pub = raw(&server_pub_b64);
    let mesh_root_pub = B64.encode(mesh.root_public_raw().unwrap());

    // 两台设备 JOIN
    let sock_join_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_join_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let sock_join_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_b, ip_b) = do_join(&sock_join_b, &server_addr, &dev_b, &server_pub, &code_b).await;

    let ep = server_addr.to_string();
    let cfg_a = make_mesh_client_config(&dir, dev_a, &ip_a, &ep, &server_pub_b64, &mesh_root_pub, &cert_a);
    let cfg_b = make_mesh_client_config(&dir, dev_b, &ip_b, &ep, &server_pub_b64, &mesh_root_pub, &cert_b);
    let mut cfg_a = cfg_a;
    let mut cfg_b = cfg_b;
    cfg_a.hole_punch.enabled = false;
    cfg_b.hole_punch.enabled = false;

    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(64);
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(64);

    let (quit_a, quit_rx_a) = watch::channel(false);
    let (conn_a, _h) = Conn::new(&cfg_a, &cfg_a.connections[0], quit_rx_a, ClientLogger::new(dir.join("a.log")))
        .await
        .unwrap();
    let mut conn_a = conn_a;
    conn_a.inject_rx = Some(inject_rx);
    let task_a = tokio::spawn(async move { conn_a.run().await });

    let (quit_b, quit_rx_b) = watch::channel(false);
    let (conn_b, _h) = Conn::new(&cfg_b, &cfg_b.connections[0], quit_rx_b, ClientLogger::new(dir.join("b.log")))
        .await
        .unwrap();
    let mut conn_b = conn_b;
    conn_b.tun_sink = Some(sink_tx);
    let task_b = tokio::spawn(async move { conn_b.run().await });

    // 等双方完成 AUTH + 注册 + 会话建立
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let total = 10usize;
    let mut got = 0usize;
    for i in 0..total {
        let payload = format!("mesh-auth-{i}").into_bytes();
        let pkt = build_ipv4_packet([10, 13, 13, 2], &payload);
        inject_tx.send(pkt).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), sink_rx.recv()).await {
            got += 1;
        }
    }
    while got < total {
        match tokio::time::timeout(Duration::from_millis(500), sink_rx.recv()).await {
            Ok(Some(_)) => got += 1,
            _ => break,
        }
    }
    let _ = quit_a.send(true);
    let _ = quit_b.send(true);
    task_a.abort();
    task_b.abort();

    assert_eq!(
        got, total,
        "mesh 认证模式下数据面传输不应丢包: got {got}/{total}"
    );

    // P1-7：中继帧头部必须携带短期 rk 而非长期身份 ik_x（元数据最小化验证）
    // 检查服务器会话：A/B 的路由条目 relay_rk 均非空且不等于各自 ik_x
    let routes = signaling.routes.lock().await;
    let entries = routes.snapshot();
    assert_eq!(entries.len(), 2, "两台设备都应注册");
    for e in &entries {
        let rk = e.relay_rk.as_ref().expect("mesh 模式必须上报中继 rk");
        let ik_x_b64 = B64.encode(e.public_key);
        assert_ne!(rk, &ik_x_b64, "中继 rk 不得等于长期身份 ik_x");
        // rk 可被服务端索引解析回该设备
        assert_eq!(
            routes.get_by_rk(rk).map(|x| x.public_key),
            Some(e.public_key),
            "服务端应能按 rk 解析回设备"
        );
    }
}

/// 已知问题回归：`hole_punch.enabled=false` 必须全程走中继——
/// 即使对端（B）开启打洞并主动发直连包，本机（A）也不得进入直连；
/// 数据必须经由中继到达，且双方传输方式最终均为「中继」。
#[tokio::test(flavor = "multi_thread")]
async fn hole_punch_disabled_stays_relay_even_if_peer_punches() {
    let dir = std::env::temp_dir().join("linkmesh_test_punch_disabled");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);
    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let srv = signaling.clone();
    tokio::spawn(async move { srv.cleanup_loop().await });
    let server_pub = raw(&server_pub_b64);
    let mesh_root_pub = B64.encode(mesh.root_public_raw().unwrap());

    let sock_join_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_join_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let sock_join_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_b, ip_b) = do_join(&sock_join_b, &server_addr, &dev_b, &server_pub, &code_b).await;

    let ep = server_addr.to_string();

    // A：打洞禁用；B：打洞启用（主动打洞方，快速超时便于测试）
    let mut cfg_a = make_mesh_client_config(&dir, dev_a, &ip_a, &ep, &server_pub_b64, &mesh_root_pub, &cert_a);
    cfg_a.hole_punch.enabled = false;
    let mut cfg_b = make_mesh_client_config(&dir, dev_b, &ip_b, &ep, &server_pub_b64, &mesh_root_pub, &cert_b);
    cfg_b.hole_punch.timeout_ms = 800;
    cfg_b.hole_punch.interval_ms = 100;
    cfg_b.hole_punch.max_retries = 3;

    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(64);
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(64);

    let (quit_a, quit_rx_a) = watch::channel(false);
    let (conn_a, handle_a) = Conn::new(
        &cfg_a,
        &cfg_a.connections[0],
        quit_rx_a,
        ClientLogger::new(dir.join("a.log")),
    )
    .await
    .unwrap();
    let mut conn_a = conn_a;
    conn_a.inject_rx = Some(inject_rx);
    let task_a = tokio::spawn(async move { conn_a.run().await });

    let (quit_b, quit_rx_b) = watch::channel(false);
    let (conn_b, handle_b) = Conn::new(
        &cfg_b,
        &cfg_b.connections[0],
        quit_rx_b,
        ClientLogger::new(dir.join("b.log")),
    )
    .await
    .unwrap();
    let mut conn_b = conn_b;
    conn_b.tun_sink = Some(sink_tx);
    let task_b = tokio::spawn(async move { conn_b.run().await });

    // 等注册完成 + B 的打洞超时窗口过去
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // A → B 注入数据，B 必须收到（经中继）
    let payload = b"relay-only";
    let pkt = build_ipv4_packet([10, 13, 13, 2], payload);
    inject_tx.send(pkt.clone()).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(6), sink_rx.recv())
        .await
        .expect("B 未通过中继收到数据")
        .expect("通道关闭");
    assert_eq!(received, pkt);

    // 双方传输方式必须均为「中继」（A 打洞禁用不得直连；B 打洞失败降级中继）
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let sa = handle_a.snapshot().await;
        let sb = handle_b.snapshot().await;
        let all_relay = |v: &serde_json::Value| {
            v["peers"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .all(|p| p["transport"].as_str() == Some("中继"))
                })
                .unwrap_or(true)
        };
        if all_relay(&sa) && all_relay(&sb) {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("传输方式应为中继: A={sa} B={sb}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = quit_a.send(true);
    let _ = quit_b.send(true);
    task_a.abort();
    task_b.abort();
}

/// 对端重启恢复：B 的守护进程重启（全新 Conn、会话表清空、新 relay_rk）后，
/// A（会话保持）继续发包，B 必须能通过「陌生对端经中继来包 → 主动回 HELLO」完成重建，
/// 数据流不得永久中断（修复对端重启后数据静默丢失的死锁）。
#[tokio::test(flavor = "multi_thread")]
async fn peer_restart_recovers_relay_flow() {
    let dir = std::env::temp_dir().join("linkmesh_test_restart");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (server_cfg, mut mesh) = make_mesh_server_config(&dir);
    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let srv = signaling.clone();
    tokio::spawn(async move { srv.cleanup_loop().await });
    let server_pub = raw(&server_pub_b64);
    let mesh_root_pub = B64.encode(mesh.root_public_raw().unwrap());

    let sock_join_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_join_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let sock_join_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_b, ip_b) = do_join(&sock_join_b, &server_addr, &dev_b, &server_pub, &code_b).await;

    let ep = server_addr.to_string();

    let mut cfg_a = make_mesh_client_config(&dir, dev_a, &ip_a, &ep, &server_pub_b64, &mesh_root_pub, &cert_a);
    cfg_a.hole_punch.enabled = false;
    let mut cfg_b = make_mesh_client_config(&dir, dev_b, &ip_b, &ep, &server_pub_b64, &mesh_root_pub, &cert_b);
    cfg_b.hole_punch.enabled = false;

    // 第一代 B
    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(64);
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(64);
    let (quit_a, quit_rx_a) = watch::channel(false);
    let (conn_a, _h) = Conn::new(&cfg_a, &cfg_a.connections[0], quit_rx_a, ClientLogger::new(dir.join("a1.log"))).await.unwrap();
    let mut conn_a = conn_a;
    conn_a.inject_rx = Some(inject_rx);
    let task_a = tokio::spawn(async move { conn_a.run().await });

    let (quit_b, quit_rx_b) = watch::channel(false);
    let (conn_b, _h) = Conn::new(&cfg_b, &cfg_b.connections[0], quit_rx_b, ClientLogger::new(dir.join("b1.log"))).await.unwrap();
    let mut conn_b = conn_b;
    conn_b.tun_sink = Some(sink_tx.clone());
    let task_b = tokio::spawn(async move { conn_b.run().await });

    tokio::time::sleep(Duration::from_millis(1200)).await;
    let payload = b"before-restart";
    inject_tx.send(build_ipv4_packet([10, 13, 13, 2], payload)).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(6), sink_rx.recv()).await;
    assert!(got.is_ok() && got.unwrap().is_some(), "重启前 B 应能收到数据");

    // B「重启」：停掉旧 Conn，用相同身份起全新 Conn（会话表清空、新 rk）
    let _ = quit_b.send(true);
    task_b.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (quit_b2, quit_rx_b2) = watch::channel(false);
    let (conn_b2, _h2) = Conn::new(&cfg_b, &cfg_b.connections[0], quit_rx_b2, ClientLogger::new(dir.join("b2.log"))).await.unwrap();
    let mut conn_b2 = conn_b2;
    conn_b2.tun_sink = Some(sink_tx.clone());
    let task_b2 = tokio::spawn(async move { conn_b2.run().await });
    tokio::time::sleep(Duration::from_millis(800)).await;

    // A 继续发包：B 必须恢复接收（通过主动 HELLO 重建会话）
    let mut recovered = false;
    for i in 0..8u8 {
        let p = format!("after-restart-{i}").into_bytes();
        inject_tx.send(build_ipv4_packet([10, 13, 13, 2], &p)).await.unwrap();
        if let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(600), sink_rx.recv()).await {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let _ = quit_a.send(true);
    let _ = quit_b2.send(true);
    task_a.abort();
    task_b2.abort();
    assert!(recovered, "对端重启后数据流必须恢复（主动 HELLO 重建会话）");
}

// =====================================================================
// 本轮新增：房间令牌隔离 / 别名解析 / 自动重连
// =====================================================================

/// 令牌房间隔离：不同令牌（房间）的设备互相不可见、不可中继；同房间互通。
#[tokio::test(flavor = "multi_thread")]
async fn token_rooms_isolate_peers() {
    let dir = std::env::temp_dir().join("linkmesh_test_rooms");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut server_cfg, mut mesh) = make_mesh_server_config(&dir);
    server_cfg.add_room("office", "tok-office-123456").unwrap();
    server_cfg.add_room("lab", "tok-lab-123456").unwrap();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    let code_c = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let server_pub = raw(&server_pub_b64);

    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // A：房间 office
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // B：房间 lab
    let dev_c = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // C：房间 office

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_c = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1) JOIN 缺令牌被拒
    let resp = do_join_raw(&sock_a, &server_addr, &dev_a, &server_pub, &code_a, None).await;
    assert!(!resp.ok, "JOIN 缺令牌必须被拒: {resp:?}");
    // 2) JOIN 错令牌被拒
    let resp = do_join_raw(&sock_a, &server_addr, &dev_a, &server_pub, &code_a, Some("wrong-token")).await;
    assert!(!resp.ok, "JOIN 错令牌必须被拒: {resp:?}");
    // 3) JOIN + AUTH 正确令牌成功（A/C 同房间 office，B 房间 lab）
    let resp = do_join_raw(&sock_a, &server_addr, &dev_a, &server_pub, &code_a, Some("tok-office-123456")).await;
    assert!(resp.ok, "A JOIN 应成功: {resp:?}");
    let cert_a: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let ip_a = cert_a.allowed_ip.clone();
    let (sk_a, ek_c_a) = do_auth_raw(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a, Some("tok-office-123456"))
        .await
        .expect("A AUTH 应成功");
    assert!(session_register(&sock_a, &server_addr, &ek_c_a, &sk_a, 1, &ip_a).await.ok, "A 注册应成功");

    let resp = do_join_raw(&sock_b, &server_addr, &dev_b, &server_pub, &code_b, Some("tok-lab-123456")).await;
    assert!(resp.ok, "B JOIN 应成功");
    let cert_b: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let ip_b = cert_b.allowed_ip.clone();
    let (sk_b, ek_c_b) = do_auth_raw(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b, Some("tok-lab-123456"))
        .await
        .expect("B AUTH 应成功");
    assert!(session_register(&sock_b, &server_addr, &ek_c_b, &sk_b, 1, &ip_b).await.ok, "B 注册应成功");

    let resp = do_join_raw(&sock_c, &server_addr, &dev_c, &server_pub, &code_c, Some("tok-office-123456")).await;
    assert!(resp.ok, "C JOIN 应成功");
    let cert_c: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let ip_c = cert_c.allowed_ip.clone();
    let (sk_c, ek_c_c) = do_auth_raw(&sock_c, &server_addr, &dev_c, &server_pub, &cert_c, Some("tok-office-123456"))
        .await
        .expect("C AUTH 应成功");
    assert!(session_register(&sock_c, &server_addr, &ek_c_c, &sk_c, 1, &ip_c).await.ok, "C 注册应成功");

    // 4) A(office) 查询 B(lab) → 失败（跨房间不可见，按「未上线」响应）
    let resp = session_query(&sock_a, &server_addr, &ek_c_a, &sk_a, 2, &ip_b).await;
    assert!(!resp.ok, "跨房间查询必须失败: {resp:?}");
    // 5) A 查询 C(office) → 成功
    let resp = session_query(&sock_a, &server_addr, &ek_c_a, &sk_a, 3, &ip_c).await;
    assert!(resp.ok, "同房间查询应成功: {resp:?}");
    match resp.data {
        ResponseData::QueryHit { ip, .. } => assert_eq!(ip, ip_c),
        _ => panic!("expected QueryHit data"),
    }

    // 6) A→B 中继被静默丢弃（B 收不到任何东西）
    let a_pub = dev_a.ik_x_public_raw().unwrap();
    let b_pub = dev_b.ik_x_public_raw().unwrap();
    let c_pub = dev_c.ik_x_public_raw().unwrap();
    let cross = b"cross-room-payload";
    sock_a.send_to(&frame_relay(&b_pub, &a_pub, cross), server_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let got = tokio::time::timeout(Duration::from_millis(500), sock_b.recv_from(&mut buf)).await;
    assert!(got.is_err(), "跨房间中继必须被丢弃");

    // 7) A→C 中继送达（同房间）。注意：步骤 5 的查询会触发服务端向 C 发 NOTIFY，
    // 先排空 C 的 NOTIFY 帧，再断言收到中继帧。
    let same = b"same-room-payload";
    sock_a.send_to(&frame_relay(&c_pub, &a_pub, same), server_addr).await.unwrap();
    let mut buf2 = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut got_relay = false;
    while tokio::time::Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (len, _) = match tokio::time::timeout(remain, sock_c.recv_from(&mut buf2)).await {
            Ok(Ok(v)) => v,
            _ => break,
        };
        let hdr = parse_header(&buf2[..len]).unwrap();
        if matches!(hdr.msg_type, MSG_RELAY | MSG_RELAY_BATCH) {
            got_relay = true;
            break;
        }
        // 其他帧（如 NOTIFY）跳过
    }
    assert!(got_relay, "同房间中继必须送达");
}

/// 别名解析：管理员别名（名称→IP）+ 设备自报别名，均可按名查询；未知别名报错。
#[tokio::test(flavor = "multi_thread")]
async fn alias_resolution_by_name_and_self_alias() {
    let dir = std::env::temp_dir().join("linkmesh_test_alias");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut server_cfg, mut mesh) = make_mesh_server_config(&dir);
    server_cfg.add_alias("gateway", "10.13.13.2").unwrap();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let server_pub = raw(&server_pub_b64);

    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // A：10.13.13.1
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // B：10.13.13.2

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let (cert_b, ip_b) = do_join(&sock_b, &server_addr, &dev_b, &server_pub, &code_b).await;
    let (sk_a, ek_c_a, _) = do_auth(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a).await;
    let (sk_b, ek_c_b, _) = do_auth(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b).await;
    // A 自报别名 computer；B 无自报
    assert!(session_register_ex(&sock_a, &server_addr, &ek_c_a, &sk_a, 1, &ip_a, Some("computer")).await.ok);
    assert!(session_register_ex(&sock_b, &server_addr, &ek_c_b, &sk_b, 1, &ip_b, None).await.ok);

    // 1) 管理员别名 gateway → 10.13.13.2
    let resp = session_query_name(&sock_a, &server_addr, &ek_c_a, &sk_a, 2, "gateway").await;
    assert!(resp.ok, "管理员别名应可解析: {resp:?}");
    match resp.data {
        ResponseData::QueryHit { ip, alias, .. } => {
            assert_eq!(ip, "10.13.13.2");
            assert_eq!(alias, "gateway");
        }
        _ => panic!("expected QueryHit data"),
    }

    // 2) 自报别名 computer → 10.13.13.1
    let resp = session_query_name(&sock_a, &server_addr, &ek_c_a, &sk_a, 3, "computer").await;
    assert!(resp.ok, "自报别名应可解析: {resp:?}");
    match resp.data {
        ResponseData::QueryHit { ip, .. } => assert_eq!(ip, "10.13.13.1"),
        _ => panic!("expected QueryHit data"),
    }

    // 3) 未知别名 → 报错
    let resp = session_query_name(&sock_a, &server_addr, &ek_c_a, &sk_a, 4, "ghost").await;
    assert!(!resp.ok, "未知别名必须失败: {resp:?}");

    // 4) 别名大小写不敏感（服务端规范化）
    let resp = session_query_name(&sock_a, &server_addr, &ek_c_a, &sk_a, 5, "GATEWAY").await;
    assert!(resp.ok, "别名应大小写不敏感: {resp:?}");
}

/// 别名解析尊重房间隔离：跨房间设备即使有别名也解析不到。
#[tokio::test(flavor = "multi_thread")]
async fn alias_resolution_respects_rooms() {
    let dir = std::env::temp_dir().join("linkmesh_test_alias_rooms");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut server_cfg, mut mesh) = make_mesh_server_config(&dir);
    server_cfg.add_room("office", "tok-office-123456").unwrap();
    server_cfg.add_room("lab", "tok-lab-123456").unwrap();
    server_cfg.add_alias("nas", "10.13.13.2").unwrap();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    let code_c = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let server_pub = raw(&server_pub_b64);

    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // A：房间 office
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // B：房间 lab，别名 nas
    let dev_c = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // C：房间 lab

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // A/B/C JOIN + AUTH + 会话期注册（携带房间令牌）
    let resp = do_join_raw(&sock_a, &server_addr, &dev_a, &server_pub, &code_a, Some("tok-office-123456")).await;
    assert!(resp.ok, "A JOIN 应成功: {resp:?}");
    let cert_a: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let (sk_a, ek_c_a) = do_auth_raw(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a, Some("tok-office-123456")).await.expect("A AUTH 应成功");
    assert!(session_register(&sock_a, &server_addr, &ek_c_a, &sk_a, 1, &cert_a.allowed_ip).await.ok);

    let resp = do_join_raw(&sock_b, &server_addr, &dev_b, &server_pub, &code_b, Some("tok-lab-123456")).await;
    assert!(resp.ok, "B JOIN 应成功");
    let cert_b: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let (sk_b, ek_c_b) = do_auth_raw(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b, Some("tok-lab-123456")).await.expect("B AUTH 应成功");
    assert!(session_register(&sock_b, &server_addr, &ek_c_b, &sk_b, 1, &cert_b.allowed_ip).await.ok);

    let resp = do_join_raw(&sock_c, &server_addr, &dev_c, &server_pub, &code_c, Some("tok-lab-123456")).await;
    assert!(resp.ok, "C JOIN 应成功");
    let cert_c: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let (sk_c, ek_c_c) = do_auth_raw(&sock_c, &server_addr, &dev_c, &server_pub, &cert_c, Some("tok-lab-123456")).await.expect("C AUTH 应成功");
    assert!(session_register(&sock_c, &server_addr, &ek_c_c, &sk_c, 1, &cert_c.allowed_ip).await.ok);

    // A(office) 查询 nas（B，lab 房间）→ 失败（跨房间别名不可见）
    let resp = session_query_name(&sock_a, &server_addr, &ek_c_a, &sk_a, 2, "nas").await;
    assert!(!resp.ok, "跨房间别名必须解析失败: {resp:?}");
    // C(lab) 查询 nas → 成功
    let resp = session_query_name(&sock_c, &server_addr, &ek_c_c, &sk_c, 2, "nas").await;
    assert!(resp.ok, "同房间别名应可解析: {resp:?}");
    match resp.data {
        ResponseData::QueryHit { ip, .. } => assert_eq!(ip, "10.13.13.2"),
        _ => panic!("expected QueryHit data"),
    }
}

/// 自动重连：连接异常退出后按 reconnect_secs 重试；reconnect_secs=0 不重连；stop 可中断。
#[tokio::test(flavor = "multi_thread")]
async fn auto_reconnect_manager_retries_until_stop() {
    use linkmesh_client::connection::ConnManager;
    let dir = std::env::temp_dir().join("linkmesh_test_reconnect");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 起一个 mesh 服务器；客户端故意存**错误的**服务器公钥 → 首次 KEYQUERY→SERVERINFO
    // 比对（server_ik_x）即失败（快速失败路径），触发自动重连循环。
    let (server_cfg, _mesh) = make_mesh_server_config(&dir);
    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let wrong_pub = {
        let k = KeyPairSerde::generate();
        k.public_b64()
    };

    let ident = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let mut cfg = make_client_config(&dir, ident, "10.13.13.1", &server_addr.to_string(), &wrong_pub);
    cfg.reconnect_secs = 1;
    let cfg_path = dir.join("client.json");
    cfg.save(&cfg_path).unwrap();

    let mgr = Arc::new(ConnManager::new(cfg_path, ClientLogger::new(dir.join("mgr.log"))));
    mgr.start("s1").await.unwrap();
    // 等第一次失败 + 进入重连等待（reconnect_secs=1）
    tokio::time::sleep(Duration::from_millis(1800)).await;
    assert!(
        mgr.quitters.lock().await.contains_key("s1"),
        "reconnect_secs>0 时重连循环应持续运行（quitters 应保留 s1）"
    );

    // 手动断开：重连循环必须退出并清理
    mgr.stop("s1").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !mgr.quitters.lock().await.contains_key("s1"),
        "stop 后重连循环必须退出"
    );

    // reconnect_secs=0：失败后不再重连，quitters 清理
    let ident0 = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let mut cfg0 = make_client_config(&dir, ident0, "10.13.13.2", &server_addr.to_string(), &wrong_pub);
    cfg0.reconnect_secs = 0;
    let cfg0_path = dir.join("client0.json");
    cfg0.save(&cfg0_path).unwrap();
    let mgr0 = Arc::new(ConnManager::new(cfg0_path, ClientLogger::new(dir.join("mgr0.log"))));
    mgr0.start("s1").await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        !mgr0.quitters.lock().await.contains_key("s1"),
        "reconnect_secs=0 时连接失败后不重连，应清理 quitters"
    );
}

/// mesh 模式令牌：JOIN 缺令牌/错令牌被拒；AUTH 错令牌被拒、正确令牌建立会话并限同房间。
#[tokio::test(flavor = "multi_thread")]
async fn mesh_token_gates_join_and_auth() {
    let dir = std::env::temp_dir().join("linkmesh_test_mesh_rooms");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut server_cfg, mut mesh) = make_mesh_server_config(&dir);
    server_cfg.add_room("office", "tok-office-123456").unwrap();
    server_cfg.add_room("lab", "tok-lab-123456").unwrap();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let server_pub = raw(&server_pub_b64);

    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate();
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate();

    // 1) JOIN 缺令牌 → 被拒
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resp = do_join_raw(&sock_a, &server_addr, &dev_a, &server_pub, &code_a, None).await;
    assert!(!resp.ok, "JOIN 缺令牌必须被拒: {resp:?}");

    // 2) JOIN 错令牌 → 被拒
    let resp = do_join_raw(&sock_a, &server_addr, &dev_a, &server_pub, &code_a, Some("wrong")).await;
    assert!(!resp.ok, "JOIN 错令牌必须被拒: {resp:?}");

    // 3) JOIN 正确令牌 → 成功（A 进 office）
    let resp = do_join_raw(&sock_a, &server_addr, &dev_a, &server_pub, &code_a, Some("tok-office-123456")).await;
    assert!(resp.ok, "JOIN 正确令牌应成功: {resp:?}");
    let cert_a: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let ip_a = cert_a.allowed_ip.clone();

    // 4) AUTH 错令牌 → 被拒（返回 RESPONSE 错误而非 AUTH_RESP）
    let auth_resp = do_auth_raw(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a, Some("wrong")).await;
    assert!(auth_resp.is_err(), "AUTH 错令牌必须被拒");

    // 5) AUTH 正确令牌 → 会话建立
    let (sk_a, ek_c_a) = do_auth_raw(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a, Some("tok-office-123456"))
        .await
        .expect("AUTH 正确令牌应成功");
    let reg = session_register(&sock_a, &server_addr, &ek_c_a, &sk_a, 1, &ip_a).await;
    assert!(reg.ok, "会话期注册应成功: {reg:?}");

    // B 进 lab 房间
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resp = do_join_raw(&sock_b, &server_addr, &dev_b, &server_pub, &code_b, Some("tok-lab-123456")).await;
    assert!(resp.ok, "B JOIN 应成功");
    let cert_b: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let ip_b = cert_b.allowed_ip.clone();
    let (sk_b, ek_c_b) = do_auth_raw(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b, Some("tok-lab-123456"))
        .await
        .expect("B AUTH 应成功");
    let reg = session_register(&sock_b, &server_addr, &ek_c_b, &sk_b, 1, &ip_b).await;
    assert!(reg.ok, "B 会话期注册应成功: {reg:?}");

    // 6) A(office) 会话期查询 B(lab) → 失败（跨房间不可见）
    let resp = session_query(&sock_a, &server_addr, &ek_c_a, &sk_a, 2, &ip_b).await;
    assert!(!resp.ok, "mesh 跨房间查询必须失败: {resp:?}");
}

/// JOIN 原语：携带令牌，返回完整响应。
async fn do_join_raw(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    dev: &linkmesh_shared::identity::DeviceIdentitySerde,
    server_pub: &RawKey,
    code: &str,
    token: Option<&str>,
) -> ResponseBody {
    let ik_x = dev.ik_x_public_raw().unwrap();
    let shared = crypto::shared_secret(&raw(&dev.ik_x.private_b64()), server_pub);
    let body = linkmesh_shared::protocol::JoinBody {
        code: code.to_string(),
        device_id: dev.device_id().unwrap(),
        ik_x: dev.ik_x.public_b64(),
        ik_s_pub: dev.ik_s.public_b64(),
        requested_ip: None,
        token: token.map(|s| s.to_string()),
        alias: None,
    };
    let ct = crypto::encrypt(&shared, &encode_join(&body).unwrap());
    let frame = frame_signaling(MSG_JOIN, &ik_x, &ct);
    sock.send_to(&frame, server).await.unwrap();
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("JOIN 响应超时")
            .unwrap();
        let hdr = parse_header(&buf[..len]).unwrap();
        if hdr.msg_type == MSG_RESPONSE {
            let plain = crypto::decrypt(&shared, &buf[HEADER_LEN..len]).unwrap();
            return decode_response(&plain).unwrap();
        }
    }
}

/// AUTH 原语：携带令牌。成功返回 (SK, ek_c)；失败（RESPONSE 错误）返回 Err。
async fn do_auth_raw(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    dev: &linkmesh_shared::identity::DeviceIdentitySerde,
    server_pub: &RawKey,
    cert: &linkmesh_shared::cert::DeviceCert,
    token: Option<&str>,
) -> Result<(RawKey, RawKey), String> {
    let ik_x_priv = raw(&dev.ik_x.private_b64());
    let ik_x_pub = raw(&dev.ik_x.public_b64());
    let shared = crypto::shared_secret(&ik_x_priv, server_pub);
    let ek_c = KeyPairSerde::generate();
    let ek_c_pub = raw(&ek_c.public_b64());
    let nonce_bytes = [8u8; 12];
    let body = AuthBody {
        device_id: dev.device_id().unwrap(),
        cert: cert.clone(),
        ek_c: ek_c.public_b64(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce: B64.encode(nonce_bytes),
        token: token.map(|s| s.to_string()),
    };
    let ct = crypto::encrypt(&shared, &encode_auth(&body).unwrap());
    let frame = frame_signaling(MSG_AUTH, &ik_x_pub, &ct);
    sock.send_to(&frame, server).await.unwrap();

    let mut buf = vec![0u8; 65536];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .map_err(|_| "AUTH 响应超时".to_string())?
            .map_err(|e| format!("接收失败: {e}"))?;
        let hdr = parse_header(&buf[..len]).unwrap();
        if hdr.msg_type == MSG_AUTH_RESP {
            let plain = crypto::decrypt(&shared, &buf[HEADER_LEN..len]).unwrap();
            let resp: AuthRespBody = decode_auth_resp(&plain).unwrap();
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
            let plain = crypto::decrypt(&shared, &buf[HEADER_LEN..len]).unwrap();
            let resp: ResponseBody = decode_response(&plain).unwrap();
            return Err(resp.error.unwrap_or_else(|| "认证被拒".into()));
        }
    }
}

/// 会话期按 IP 查询（mesh）。
async fn session_query(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    ek_c: &RawKey,
    sk: &RawKey,
    seq: u64,
    ip: &str,
) -> ResponseBody {
    session_query_impl(sock, server, ek_c, sk, seq, ip, None).await
}

/// 会话期按别名查询（mesh）。
async fn session_query_name(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    ek_c: &RawKey,
    sk: &RawKey,
    seq: u64,
    name: &str,
) -> ResponseBody {
    session_query_impl(sock, server, ek_c, sk, seq, "", Some(name)).await
}

async fn session_query_impl(
    sock: &UdpSocket,
    server: &std::net::SocketAddr,
    ek_c: &RawKey,
    sk: &RawKey,
    seq: u64,
    ip: &str,
    name: Option<&str>,
) -> ResponseBody {
    let nonce = crypto::session_nonce(seq, 0);
    let body = encode_query(&QueryBody {
        ip: ip.to_string(),
        name: name.map(|s| s.to_string()),
    })
    .unwrap();
    let ct = crypto::encrypt_with_nonce(sk, &nonce, &body);
    let frame = frame_signaling(MSG_QUERY, ek_c, &ct);
    sock.send_to(&frame, server).await.unwrap();
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .expect("会话期查询超时")
            .unwrap();
        let hdr = parse_header(&buf[..len]).unwrap();
        if hdr.msg_type == MSG_RESPONSE {
            let resp_nonce = crypto::session_nonce(seq, 1);
            let plain = crypto::decrypt_with_nonce(sk, &resp_nonce, &buf[HEADER_LEN..len]).unwrap();
            return decode_response(&plain).unwrap();
        }
    }
}

/// 别名优先级：管理员别名优先于设备自报别名（防设备自报抢占管理员命名）。
#[tokio::test(flavor = "multi_thread")]
async fn admin_alias_takes_precedence_over_self_reported() {
    let dir = std::env::temp_dir().join("linkmesh_test_alias_priority");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut server_cfg, mut mesh) = make_mesh_server_config(&dir);
    // 管理员把 "router" 绑定到 B；A 自报别名 router（试图抢占）
    server_cfg.add_alias("router", "10.13.13.2").unwrap();
    let code_a = mesh.create_invite(None, 600);
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let server_pub = raw(&server_pub_b64);

    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // A：10.13.13.1
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // B：10.13.13.2

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (cert_a, ip_a) = do_join(&sock_a, &server_addr, &dev_a, &server_pub, &code_a).await;
    let (cert_b, ip_b) = do_join(&sock_b, &server_addr, &dev_b, &server_pub, &code_b).await;
    let (sk_a, ek_c_a, _) = do_auth(&sock_a, &server_addr, &dev_a, &server_pub, &cert_a).await;
    let (sk_b, ek_c_b, _) = do_auth(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b).await;
    // A 自报别名 router（试图抢占）；B 无自报
    assert!(session_register_ex(&sock_a, &server_addr, &ek_c_a, &sk_a, 1, &ip_a, Some("router")).await.ok);
    assert!(session_register_ex(&sock_b, &server_addr, &ek_c_b, &sk_b, 1, &ip_b, None).await.ok);

    // 解析 router 必须命中管理员绑定（B，10.13.13.2），而非 A 的自报
    let resp = session_query_name(&sock_a, &server_addr, &ek_c_a, &sk_a, 2, "router").await;
    assert!(resp.ok, "管理员别名应可解析: {resp:?}");
    match resp.data {
        ResponseData::QueryHit { ip, .. } => assert_eq!(ip, "10.13.13.2"),
        _ => panic!("expected QueryHit data"),
    }
}

/// 令牌验证开启时，未注册（无路由条目/无法确定房间）来源的中继帧一律丢弃。
#[tokio::test(flavor = "multi_thread")]
async fn unregistered_relay_sender_dropped_in_rooms_mode() {
    let dir = std::env::temp_dir().join("linkmesh_test_relay_rooms");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (mut server_cfg, mut mesh) = make_mesh_server_config(&dir);
    server_cfg.add_room("lab", "tok-lab-123456").unwrap();
    let code_b = mesh.create_invite(None, 600);
    mesh.save(&dir.join("mesh.json")).unwrap();

    let sock = UdpSocket::bind(&server_cfg.listen).await.unwrap();
    let server_addr = sock.local_addr().unwrap();
    let signaling = Arc::new(
        Signaling::new(sock, &server_cfg, ServerLogger::new(&server_cfg.log_file)).unwrap(),
    );
    let server_pub_b64 = B64.encode(signaling.server_pub());
    let srv = signaling.clone();
    tokio::spawn(async move { srv.run().await });
    let server_pub = raw(&server_pub_b64);

    let dev_a = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // A：10.13.13.1，**不认证不注册**
    let dev_b = linkmesh_shared::identity::DeviceIdentitySerde::generate(); // B：10.13.13.2，注册进 lab 房间

    // B 正常 JOIN + AUTH + 注册（lab 房间）
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resp = do_join_raw(&sock_b, &server_addr, &dev_b, &server_pub, &code_b, Some("tok-lab-123456")).await;
    assert!(resp.ok, "B JOIN 应成功");
    let cert_b: linkmesh_shared::cert::DeviceCert = match resp.data {
        ResponseData::Join { cert, .. } => cert,
        _ => panic!("expected JOIN data"),
    };
    let (sk_b, ek_c_b) = do_auth_raw(&sock_b, &server_addr, &dev_b, &server_pub, &cert_b, Some("tok-lab-123456")).await.expect("B AUTH 应成功");
    assert!(session_register(&sock_b, &server_addr, &ek_c_b, &sk_b, 1, &cert_b.allowed_ip).await.ok);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A 无活跃会话（未认证/未注册）→ 中继帧必须被静默丢弃
    let a_pub = dev_a.ik_x_public_raw().unwrap();
    let b_pub = dev_b.ik_x_public_raw().unwrap();
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_ct = b"unregistered-sender";
    sock_a.send_to(&frame_relay(&b_pub, &a_pub, relay_ct), server_addr).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let got = tokio::time::timeout(Duration::from_millis(500), sock_b.recv_from(&mut buf)).await;
    assert!(got.is_err(), "未注册来源的中继帧必须被丢弃（无活跃会话/无法确定房间）");
}
