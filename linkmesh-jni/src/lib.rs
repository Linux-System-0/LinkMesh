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

//! LinkMesh Android JNI 桥接层。
//!
//! 设计：Android 上不使用 `/dev/net/tun`（无 root、无该设备节点），
//! 而是复用 `linkmesh-client::connection::Conn` 的 `skip_tun` 注入/输出通道：
//!
//! - Kotlin 从 VPNService 提供的 fd 读到 IP 包 → `nativeInject` → Rust 加密发往对端；
//! - Rust 从对端收到并解密的 IP 包 → 输出通道 → `nativeDrain` → Kotlin 写回 fd。
//!
//! 信令/打洞/中继/加密全部复用 `linkmesh-client` 核心逻辑，无需 TUN 设备。

use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jlong, jstring};
use jni::JNIEnv;
use linkmesh_client::config::ClientConfig;
use linkmesh_client::connection::{fetch_server_pubkey, Conn, ConnectionHandle};
use linkmesh_client::log::Logger;
use linkmesh_shared::crypto::{parse_public_key, KeyPairSerde, RawKey};
use tokio::sync::{mpsc, watch};

/// 全局引擎：同一时刻只运行一条连接（Android VPN 单隧道模型）。
static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

struct Engine {
    rt: tokio::runtime::Runtime,
    inject_tx: mpsc::Sender<Vec<u8>>,
    tun_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    quit_tx: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    handle: ConnectionHandle,
}

// ---------- 内部工具 ----------

fn throw_error(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", msg);
}

fn client_config_from_json(json: &str) -> Result<ClientConfig, String> {
    serde_json::from_str::<ClientConfig>(json).map_err(|e| format!("配置解析失败: {e}"))
}

/// 新建一个 current-thread runtime 并 block_on 执行异步闭包。
fn block_on_oneshot<F, T>(f: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("创建 runtime 失败: {e}"))?;
    rt.block_on(f)
}

/// 启动连接引擎。
/// 返回引擎句柄（固定 1；0 表示失败，失败时抛 Java 异常）。
#[no_mangle]
pub extern "system" fn Java_com_linkmesh_client_core_NativeBridge_nativeConnect(
    mut env: JNIEnv,
    _class: JClass,
    config_json: JString,
    log_path: JString,
) -> jlong {
    let cfg_json: String = match env.get_string(&config_json) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_error(&mut env, &format!("读取配置失败: {e}"));
            return 0;
        }
    };
    let log_p: String = match env.get_string(&log_path) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_error(&mut env, &format!("读取日志路径失败: {e}"));
            return 0;
        }
    };

    let cfg = match client_config_from_json(&cfg_json) {
        Ok(c) => c,
        Err(e) => {
            throw_error(&mut env, &e);
            return 0;
        }
    };
    let conn_entry = match cfg.connections.first() {
        Some(c) => c.clone(),
        None => {
            throw_error(&mut env, "配置缺少 connections 条目");
            return 0;
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            throw_error(&mut env, &format!("创建 runtime 失败: {e}"));
            return 0;
        }
    };

    // 注入通道：Kotlin → Rust（本地数据面出口注入）
    let (inject_tx, inject_rx) = mpsc::channel::<Vec<u8>>(256);
    // 输出通道：Rust → Kotlin（对端数据写回 VPN fd）
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(512);
    let (quit_tx, quit_rx) = watch::channel(false);
    let log = Logger::new(&log_p);

    let result = rt.block_on(async {
        let (mut conn, handle) = Conn::new(&cfg, &conn_entry, quit_rx, log).await?;
        conn.skip_tun = true;
        conn.inject_rx = Some(inject_rx);
        conn.tun_sink = Some(tun_tx);
        Ok::<_, String>((conn, handle))
    });

    let (conn, handle) = match result {
        Ok(v) => v,
        Err(e) => {
            throw_error(&mut env, &e);
            return 0;
        }
    };

    let task = rt.spawn(async move {
        conn.run().await;
    });

    let engine = Engine {
        rt,
        inject_tx,
        tun_rx: Mutex::new(Some(tun_rx)),
        quit_tx,
        task: Mutex::new(Some(task)),
        handle,
    };
    *ENGINE.lock().unwrap() = Some(engine);
    1
}

/// 停止连接并释放引擎。
#[no_mangle]
pub extern "system" fn Java_com_linkmesh_client_core_NativeBridge_nativeDisconnect(
    _env: JNIEnv,
    _class: JClass,
    _handle: jlong,
) {
    let mut guard = match ENGINE.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if let Some(engine) = guard.take() {
        let _ = engine.quit_tx.send(true);
        if let Some(task) = engine.task.lock().unwrap().take() {
            // 给 run() 一点时间发送 BYE 并收尾；超时不阻塞。
            let _ = engine.rt.block_on(async {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
            });
        }
        drop(engine);
    }
}

/// 注入一个 IP 包（Kotlin 从 VPN fd 读到 → Rust 加密转发）。成功返回 true。
#[no_mangle]
pub extern "system" fn Java_com_linkmesh_client_core_NativeBridge_nativeInject(
    mut env: JNIEnv,
    _class: JClass,
    _handle: jlong,
    packet: JByteArray,
) -> jboolean {
    let bytes = match env.convert_byte_array(&packet) {
        Ok(b) => b.into_iter().map(|v| v as u8).collect::<Vec<u8>>(),
        Err(e) => {
            throw_error(&mut env, &format!("读取注入包失败: {e}"));
            return 0;
        }
    };
    let guard = match ENGINE.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    match guard.as_ref() {
        Some(engine) => match engine.inject_tx.try_send(bytes) {
            Ok(()) => 1,
            Err(_) => {
                throw_error(&mut env, "注入队列已满");
                0
            }
        },
        None => 0,
    }
}

/// 取走一个 Rust 输出的 IP 包（写回 VPN fd）。无数据时返回 null。
#[no_mangle]
pub extern "system" fn Java_com_linkmesh_client_core_NativeBridge_nativeDrain(
    env: JNIEnv,
    _class: JClass,
    _handle: jlong,
) -> jbyteArray {
    let guard = match ENGINE.lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    let pkt = match guard.as_ref() {
        Some(engine) => engine
            .tun_rx
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|rx| rx.try_recv().ok()),
        None => None,
    };
    match pkt {
        Some(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// 查询连接状态，返回 JSON 字符串。
#[no_mangle]
pub extern "system" fn Java_com_linkmesh_client_core_NativeBridge_nativeStatus(
    env: JNIEnv,
    _class: JClass,
    _handle: jlong,
) -> jstring {
    let guard = match ENGINE.lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    let json = match guard.as_ref() {
        Some(engine) => engine.rt.block_on(engine.handle.snapshot()).to_string(),
        None => "{\"status\":\"未连接\"}".to_string(),
    };
    match env.new_string(&json) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// 生成设备密钥对，返回 `{"public":"...","private":"..."}` JSON。
#[no_mangle]
pub extern "system" fn Java_com_linkmesh_client_core_NativeBridge_nativeGenKeypair(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let kp = KeyPairSerde::generate();
    let json = serde_json::json!({
        "public": kp.public_b64(),
        "private": kp.private_b64(),
    })
    .to_string();
    match env.new_string(&json) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// TOFU：向服务器索取公钥（首次连接信任确认）。
/// 参数：endpoint（"ip:port"）、local_pub_b64。返回 base64 公钥字符串。
#[no_mangle]
pub extern "system" fn Java_com_linkmesh_client_core_NativeBridge_nativeFetchServerPubkey(
    mut env: JNIEnv,
    _class: JClass,
    endpoint: JString,
    local_pub_b64: JString,
) -> jstring {
    let ep: String = match env.get_string(&endpoint) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_error(&mut env, &format!("读取 endpoint 失败: {e}"));
            return std::ptr::null_mut();
        }
    };
    let pub_b64: String = match env.get_string(&local_pub_b64) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_error(&mut env, &format!("读取公钥失败: {e}"));
            return std::ptr::null_mut();
        }
    };
    let server_addr: std::net::SocketAddr = match ep.parse() {
        Ok(a) => a,
        Err(e) => {
            throw_error(&mut env, &format!("服务器地址解析失败: {e}"));
            return std::ptr::null_mut();
        }
    };
    let local_pub: RawKey = match parse_public_key(&pub_b64) {
        Ok(k) => k,
        Err(e) => {
            throw_error(&mut env, &e);
            return std::ptr::null_mut();
        }
    };
    let log = Logger::new("/data/local/tmp/linkmesh_tofu.log");
    let result = block_on_oneshot(async {
        fetch_server_pubkey(server_addr, &local_pub, &log).await
    });
    match result {
        Ok(raw) => {
            let b64 = B64.encode(raw);
            match env.new_string(&b64) {
                Ok(s) => s.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            throw_error(&mut env, &e);
            std::ptr::null_mut()
        }
    }
}
