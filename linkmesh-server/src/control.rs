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

//! 控制通道：本机 CLI 通过 127.0.0.1 的 TCP 端口与后台守护进程通信。
//!
//! 请求/响应均为单行 JSON，换行分隔。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_shared::crypto::{self, RawKey};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};

use crate::config::{RoomEntry, ServerConfig};
use crate::log::Logger;
use crate::signaling::{RouteTable, Stats};

/// 常数时间字符串比较（防时序侧信道）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct CtrlContext {
    pub routes: Arc<Mutex<RouteTable>>,
    pub stats: Arc<Stats>,
    pub server_pub: RawKey,
    pub started: Instant,
    pub control_port: u16,
    pub relay_enabled: bool,
    /// 房间令牌表（运行中可增删并持久化；空 = 单房间开放）。
    pub rooms: Arc<Mutex<Vec<RoomEntry>>>,
    /// 管理员别名表（名称 → 虚拟 IP，运行中可增删并持久化）。
    pub aliases: Arc<Mutex<HashMap<String, String>>>,
    /// 配置路径，运行时变更（房间/别名）持久化。
    pub config_path: PathBuf,
    /// 控制通道鉴权令牌（防本地任意进程控制）。
    pub token: Option<String>,
    pub log: Logger,
}

/// 启动控制通道监听。`shutdown_tx` 被置为 true 时服务退出。
pub async fn serve(
    port: u16,
    ctx: Arc<CtrlContext>,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), String> {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("控制端口 {addr} 绑定失败: {e}"))?;
    ctx.log.info(format!("控制通道监听 {addr}"));

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                ctx.log.warn(format!("控制通道 accept 失败: {e}"));
                continue;
            }
        };
        let ctx = ctx.clone();
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(_e) = handle_conn(stream, ctx, shutdown_tx).await {
                // 连接级错误忽略
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    ctx: Arc<CtrlContext>,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), String> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({ "ok": false, "error": format!("请求解析失败: {e}") });
                let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                continue;
            }
        };
        let cmd = req["cmd"].as_str().unwrap_or("");
        // 控制通道鉴权：配置了 token 时必须匹配（防本地任意进程 stop/routes/status 等）
        if let Some(expected) = &ctx.token {
            let got = req["token"].as_str().unwrap_or("");
            if !constant_time_eq(expected.as_bytes(), got.as_bytes()) {
                ctx.log.warn("控制通道鉴权失败（token 不匹配）");
                let resp = json!({ "ok": false, "error": "鉴权失败：token 不匹配" });
                let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
                continue;
            }
        }
        let resp = match cmd {
            "stop" => {
                let _ = shutdown_tx.send(true);
                json!({ "ok": true, "data": "服务已停止" })
            }
            "routes" => {
                let routes = ctx.routes.lock().await;
                let items: Vec<Value> = routes
                    .snapshot()
                    .iter()
                    .map(|e| {
                        json!({
                            "public_key": B64.encode(e.public_key),
                            "ip": e.ip,
                            "endpoint": e.endpoint,
                            "last_seen": e.last_seen,
                            "room": e.room,
                            "alias": e.alias,
                        })
                    })
                    .collect();
                json!({ "ok": true, "data": { "total": routes.len(), "items": items } })
            }
            "delpeer" => {
                let key = req["key"].as_str().unwrap_or("").to_string();
                match crypto::parse_public_key(&key) {
                    Ok(raw) => {
                        let mut routes = ctx.routes.lock().await;
                        let existed = routes.get(&raw).is_some();
                        routes.remove(&raw);
                        json!({
                            "ok": true,
                            "data": if existed { "已移除" } else { "对端不存在" }
                        })
                    }
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            }
            "status" => {
                let (online, relay) = {
                    let routes = ctx.routes.lock().await;
                    (routes.len(), routes.snapshot().len())
                };
                let stats = &ctx.stats;
                json!({
                    "ok": true,
                    "data": {
                        "online_clients": online,
                        "relay_enabled": ctx.relay_enabled,
                        "control_port": ctx.control_port,
                        "server_public_key": B64.encode(ctx.server_pub),
                        "uptime_secs": ctx.started.elapsed().as_secs(),
                        "stats": {
                            "packets_in": stats.packets_in.load(std::sync::atomic::Ordering::Relaxed),
                            "packets_out": stats.packets_out.load(std::sync::atomic::Ordering::Relaxed),
                            "bytes_relayed": stats.bytes_relayed.load(std::sync::atomic::Ordering::Relaxed),
                        },
                        "routes_snapshot": relay,
                    }
                })
            }
            "add-room" => {
                let name = req["name"].as_str().unwrap_or("").to_string();
                let token = req["token"].as_str().unwrap_or("").to_string();
                let saved: Result<(), String> = async {
                    let mut cfg = ServerConfig::load(&ctx.config_path)?;
                    cfg.add_room(&name, &token)?;
                    let new_rooms = cfg.rooms.clone();
                    *ctx.rooms.lock().await = new_rooms;
                    cfg.save(&ctx.config_path)
                }
                .await;
                match saved {
                    Ok(()) => {
                        ctx.log.info(format!("控制通道新增/更新房间 {name}"));
                        json!({ "ok": true, "data": format!("房间 {name} 已保存（令牌以哈希存储）") })
                    }
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            }
            "remove-room" => {
                let name = req["name"].as_str().unwrap_or("").to_string();
                let removed = {
                    let mut rooms = ctx.rooms.lock().await;
                    let before = rooms.len();
                    rooms.retain(|r| r.name != name);
                    rooms.len() != before
                };
                if !removed {
                    json!({ "ok": false, "error": format!("房间 {name} 不存在") })
                } else {
                    let save_res = match ServerConfig::load(&ctx.config_path) {
                        Ok(mut c) => {
                            c.remove_room(&name);
                            c.save(&ctx.config_path)
                        }
                        Err(e) => Err(e),
                    };
                    match save_res {
                        Ok(()) => json!({ "ok": true, "data": format!("房间 {name} 已删除") }),
                        Err(e) => json!({ "ok": false, "error": format!("已生效但持久化失败: {e}") }),
                    }
                }
            }
            "rooms" => {
                let rooms = ctx.rooms.lock().await;
                let items: Vec<Value> = rooms
                    .iter()
                    .map(|r| {
                        let short = &r.token_hash[..r.token_hash.len().min(12)];
                        json!({
                            "name": r.name,
                            "token_hash": short.to_string() + "…",
                        })
                    })
                    .collect();
                json!({ "ok": true, "data": { "total": items.len(), "items": items } })
            }
            "alias" => {
                let name = req["name"].as_str().unwrap_or("").to_string();
                let ip = req["ip"].as_str().unwrap_or("").to_string();
                let saved: Result<(), String> = async {
                    let mut cfg = ServerConfig::load(&ctx.config_path)?;
                    cfg.add_alias(&name, &ip)?;
                    let new_aliases: HashMap<String, String> =
                        cfg.aliases.iter().map(|a| (a.name.clone(), a.ip.clone())).collect();
                    *ctx.aliases.lock().await = new_aliases;
                    cfg.save(&ctx.config_path)
                }
                .await;
                match saved {
                    Ok(()) => {
                        ctx.log.info(format!("控制通道绑定别名 {name} -> {ip}"));
                        json!({ "ok": true, "data": format!("别名 {name} -> {ip} 已保存") })
                    }
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            }
            "alias-del" => {
                let name = req["name"].as_str().unwrap_or("").to_string();
                let removed = ctx.aliases.lock().await.remove(&name).is_some();
                if !removed {
                    json!({ "ok": false, "error": format!("别名 {name} 不存在") })
                } else {
                    let save_res = match ServerConfig::load(&ctx.config_path) {
                        Ok(mut c) => {
                            c.remove_alias(&name);
                            c.save(&ctx.config_path)
                        }
                        Err(e) => Err(e),
                    };
                    match save_res {
                        Ok(()) => json!({ "ok": true, "data": format!("别名 {name} 已删除") }),
                        Err(e) => json!({ "ok": false, "error": format!("已生效但持久化失败: {e}") }),
                    }
                }
            }
            "alias-list" => {
                let aliases = ctx.aliases.lock().await;
                let mut items: Vec<Value> = aliases
                    .iter()
                    .map(|(name, ip)| json!({ "name": name, "ip": ip }))
                    .collect();
                items.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
                json!({ "ok": true, "data": { "total": items.len(), "items": items } })
            }
            _ => json!({ "ok": false, "error": format!("未知命令 {cmd}") }),
        };
        let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
    }
    Ok(())
}
