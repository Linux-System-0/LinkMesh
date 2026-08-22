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

//! 客户端控制通道：本机 CLI 通过 127.0.0.1 的 TCP 端口与后台守护进程通信。

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::connection::ConnManager;
use crate::log::Logger;

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
    pub manager: Arc<ConnManager>,
    pub shutdown_tx: watch::Sender<bool>,
    /// 控制通道鉴权令牌（防本地任意进程控制）。
    pub token: Option<String>,
    pub log: Logger,
}

pub async fn serve(port: u16, ctx: Arc<CtrlContext>) -> Result<(), String> {
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
        tokio::spawn(async move {
            if let Err(_e) = handle_conn(stream, ctx).await {
                // 连接级错误忽略
            }
        });
    }
}

async fn handle_conn(stream: TcpStream, ctx: Arc<CtrlContext>) -> Result<(), String> {
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
        // 控制通道鉴权：配置了 token 时必须匹配（防本地任意进程 stop/start/status 等）
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
                let _ = ctx.shutdown_tx.send(true);
                json!({ "ok": true, "data": "客户端守护进程已停止" })
            }
            "disconnect" => {
                let name = req["server"].as_str().unwrap_or("").to_string();
                match ctx.manager.stop(&name).await {
                    Ok(_) => json!({ "ok": true, "data": format!("已断开 {name}") }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            }
            "start" => {
                let name = req["server"].as_str().unwrap_or("").to_string();
                match ctx.manager.start(&name).await {
                    Ok(_) => json!({ "ok": true, "data": format!("已启动连接 {name}") }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            }
            "status" => {
                let handles = ctx.manager.handles();
                let handles = handles.lock().await;
                let mut items = Vec::new();
                let mut names: Vec<&String> = handles.keys().collect();
                names.sort();
                for name in names {
                    let h = &handles[name];
                    items.push(h.snapshot().await);
                }
                json!({ "ok": true, "data": { "connections": items } })
            }
            "connections" => {
                let handles = ctx.manager.handles();
                let handles = handles.lock().await;
                let names: Vec<String> = handles.keys().cloned().collect();
                json!({ "ok": true, "data": { "names": names } })
            }
            "resolve" => {
                let name = req["name"].as_str().unwrap_or("").to_string();
                match &ctx.manager.dns {
                    Some(reg) => {
                        let ip = reg.resolve(&name).await;
                        match ip {
                            Some(ip) => json!({ "ok": true, "data": { "name": name, "ip": ip } }),
                            None => json!({ "ok": false, "error": format!("别名 {name} 未解析到任何设备（可能不在同一房间或未上线）") }),
                        }
                    }
                    None => json!({ "ok": false, "error": "内嵌 DNS 未启用（守护进程未配置 dns）" }),
                }
            }
            "dns-cache" => {
                match &ctx.manager.dns {
                    Some(reg) => {
                        let items: Vec<Value> = reg
                            .cached_names()
                            .await
                            .into_iter()
                            .map(|(name, ip)| json!({ "name": name, "ip": ip }))
                            .collect();
                        json!({ "ok": true, "data": { "total": items.len(), "items": items } })
                    }
                    None => json!({ "ok": false, "error": "内嵌 DNS 未启用" }),
                }
            }
            _ => json!({ "ok": false, "error": format!("未知命令 {cmd}") }),
        };
        let _ = writer.write_all(format!("{resp}\n").as_bytes()).await;
    }
    Ok(())
}
