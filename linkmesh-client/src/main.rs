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

//! linkmesh-client：NAT 穿透客户端。
//!
//! 每台设备本地生成密钥对，私钥绝不上传；先尝试 UDP 打洞，失败则走中继。
//! 一切配置集中于 `./client.json`，命令行的操作会改写该文件。

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_client::config::{ClientConfig, ConnectionEntry, ServerEntry, VmNicConfig};
use linkmesh_client::connection::ConnManager;
use linkmesh_client::{control, daemon, log};
use linkmesh_shared::protocol::ResponseBody;
use linkmesh_shared::VERSION;
use serde_json::json;
use tokio::sync::watch;

/// 全局静默开关：`--quiet` 抑制所有非错误输出（info），错误仍输出到 stderr。
static QUIET: AtomicBool = AtomicBool::new(false);

struct Args {
    command: Option<String>,
    positionals: Vec<String>,
    config_path: PathBuf,
    quiet: bool,
    follow: bool,
    ip: Option<String>,
    /// 首次加入（未固定网格根）时的信任策略：Some(true)=-y 默认信任，Some(false)=-n 默认拒绝，None=交互确认。
    trust: Option<bool>,
    /// --join 的加入码。
    code: Option<String>,
    /// 房间令牌（--connect / --join 携带，写入 client.json 的 servers[].token）。
    token: Option<String>,
    /// -d：显示详细内容（面向开发者，所有的都要记录）。
    detail: bool,
}

fn parse_args() -> Args {
    let mut command = None;
    let mut positionals = Vec::new();
    let mut config_path = PathBuf::from("client.json");
    let mut quiet = false;
    let mut follow = false;
    let mut ip = None;
    let mut trust = None;
    let mut code = None;
    let mut token = None;
    let mut detail = false;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => {
                if let Some(v) = it.next() {
                    config_path = PathBuf::from(v);
                }
            }
            "--quiet" => quiet = true,
            "--follow" => follow = true,
            "--ip" => {
                if let Some(v) = it.next() {
                    ip = Some(v);
                }
            }
            "--code" => {
                if let Some(v) = it.next() {
                    code = Some(v);
                }
            }
            "--token" => {
                if let Some(v) = it.next() {
                    token = Some(v);
                }
            }
            "-d" | "--detail" => detail = true,
            "-y" | "--yes" => {
                if trust == Some(false) {
                    err("不能同时指定 -y 与 -n");
                }
                trust = Some(true);
            }
            "-n" | "--no" => {
                if trust == Some(true) {
                    err("不能同时指定 -y 与 -n");
                }
                trust = Some(false);
            }
            _ if arg.starts_with("--") && command.is_none() => {
                command = Some(arg[2..].to_string());
            }
            _ => positionals.push(arg),
        }
    }
    Args {
        command,
        positionals,
        config_path,
        quiet,
        follow,
        ip,
        trust,
        code,
        token,
        detail,
    }
}

/// info 输出：--quiet 时抑制（错误输出走 err，始终可见）。
fn info(msg: &str) {
    if !QUIET.load(AtomicOrdering::Relaxed) {
        println!("{msg}");
    }
}

fn err(msg: &str) -> ! {
    eprintln!("错误: {msg}");
    exit(1);
}

const CMD_LIST: &[(&str, &str)] = &[
    ("genkey", "--genkey：生成本机设备身份（X25519 + Ed25519 双密钥），写入 client.json"),
    ("showpubkey", "--showpubkey：显示本机 X25519 公钥"),
    ("fingerprint", "--fingerprint：显示本机设备指纹（base32，加入/验对端/吊销时比对）"),
    ("join", "--join \"server\" \"vmnic\" --code LMJ-... [--token 房间令牌] [-y|-n]：加入服务器网格（TOFU 根指纹 → 换取设备证书）"),
    ("newvmnic", "--newvmnic \"name\" [--ip x.x.x.x]：新建虚拟网卡（虚拟 IP 由服务端证书绑定，--ip 仅作占位）"),
    ("delvmnic", "--delvmnic \"name\"：删除虚拟网卡（自动断开其上的连接）"),
    ("newserver", "--newserver IP(:Port) \"name\"：新增/修改服务器；name 为空则删除"),
    ("connect", "--connect \"server\" \"vmnic\" [--token 房间令牌] [-d]：连接服务器（默认占用终端并输出日志到控制台，加 -d 则后台运行）"),
    ("disconnect", "--disconnect \"server\"：断开与指定服务器的连接"),
    ("stop", "--stop：停止客户端守护进程并清理 connections[]"),
    ("alias", "--alias \"名称\" \"虚拟IP\"：新增/更新本地别名（如 computer -> 10.13.13.5）；IP 与本机虚拟 IP 一致时会被自报给服务器"),
    ("alias-del", "--alias-del \"名称\"：删除本地别名"),
    ("alias-list", "--alias-list：查看本地别名表"),
    ("resolve", "--resolve \"名称\"：经守护进程解析别名到虚拟 IP（可加 --dns-cache 查看已缓存映射）"),
    ("list", "--list：列出已配置的服务器、虚拟网卡与连接"),
    ("status", "--status [\"server\"]：查看连接实时状态"),
    ("log", "--log [行数] [--follow]：查看运行日志"),
    ("version", "--version：显示版本号"),
    ("help", "--help [命令名]：显示帮助"),
];

fn print_help(cmd: Option<&str>) {
    if let Some(c) = cmd {
        for (name, desc) in CMD_LIST {
            if *name == c {
                println!("{desc}");
                return;
            }
        }
        println!("未知命令 {c}");
        return;
    }
    println!("linkmesh-client {VERSION} — NAT 穿透客户端（UDP 打洞 → 中继）");
    println!();
    println!("用法: linkmesh-client [--config <路径>] [--quiet] <命令> [参数]");
    println!("     --join 支持 [-y|-n]：首次加入确认网格根指纹（TOFU）时默认信任/拒绝，适合 CI 脚本");
    println!();
    for (_, desc) in CMD_LIST {
        println!("    {desc}");
    }
    println!();
    println!("配置文件默认 ./client.json，所有命令都会读写它。");
}

fn load_config(path: &Path) -> ClientConfig {
    match ClientConfig::load(path) {
        Ok(c) => c,
        Err(e) => err(&e),
    }
}

fn save_config(path: &Path, cfg: &ClientConfig) {
    if let Err(e) = cfg.save(path) {
        err(&e);
    }
}

fn main() {
    let args = parse_args();
    QUIET.store(args.quiet, AtomicOrdering::Relaxed);

    let cmd = match args.command.as_deref() {
        None => {
            print_help(None);
            exit(1);
        }
        Some(c) => c,
    };

    match cmd {
        "version" => {
            if !args.quiet {
                println!("linkmesh-client {VERSION}");
            }
        }
        "help" => {
            let c = args.positionals.first().map(String::as_str);
            print_help(c);
        }
        "genkey" => {
            let mut cfg = load_config(&args.config_path);
            if let Err(e) = cfg.genkey() {
                err(&e);
            }
            save_config(&args.config_path, &cfg);
            let pubkey = cfg.public_key().unwrap_or_default();
            let fp = cfg.fingerprint().unwrap_or_default();
            println!(
                "已生成设备身份（X25519 + Ed25519）并写入 {}。公钥: {}",
                args.config_path.display(),
                B64.encode(pubkey)
            );
            println!("设备指纹: {fp}");
        }
        "showpubkey" => {
            let cfg = load_config(&args.config_path);
            match cfg.public_key() {
                Ok(pk) => info(&B64.encode(pk)),
                Err(e) => err(&e),
            }
        }
        "fingerprint" => {
            let cfg = load_config(&args.config_path);
            match cfg.fingerprint() {
                Ok(fp) => info(&fp),
                Err(e) => err(&e),
            }
        }
        "join" => {
            let server = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定服务器名称"));
            let vmnic = args
                .positionals
                .get(1)
                .cloned()
                .unwrap_or_else(|| err("请指定虚拟网卡名称"));
            let code = args
                .code
                .clone()
                .unwrap_or_else(|| err("请用 --code LMJ-... 指定管理员签发的加入码"));
            if cfg_has_vmnic(&args.config_path, &vmnic) {
                // vmnic 已存在则复用
            } else {
                err(&format!("虚拟网卡 {vmnic} 未配置，请先 --newvmnic"));
            }
            let cfg = load_config(&args.config_path);
            if cfg.identity.is_none() {
                err("尚未生成设备身份，请先执行 --genkey");
            }
            if cfg.find_server(&server).is_none() {
                err(&format!("服务器 {server} 未配置"));
            }
            if cfg.find_server(&server).map(|s| s.is_joined()).unwrap_or(false) {
                err(&format!("已加入服务器 {server} 的网格，无需重复加入"));
            }
            let rt = tokio::runtime::Runtime::new().expect("创建运行时失败");
            rt.block_on(run_join(
                &args.config_path,
                &server,
                &vmnic,
                &code,
                args.trust,
                args.token.as_deref(),
            ))
            .unwrap_or_else(|e| err(&e));
        }
        _ => run_command(&args),
    }
}

fn run_command(args: &Args) {
    let cmd = args.command.as_deref().unwrap();
    match cmd {
        "newvmnic" => {
            let name = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定虚拟网卡名称"));
            let mut cfg = load_config(&args.config_path);
            if cfg.find_vmnic(&name).is_some() {
                err(&format!("虚拟网卡 {name} 已存在"));
            }
            // 虚拟 IP 仅作占位：mesh 模式下实际 IP 由服务端证书绑定（JOIN/AUTH 下发）。
            let ip = match &args.ip {
                Some(ip) => ip.clone(),
                None => {
                    let n = cfg.vm_nics.len() + 1;
                    format!("10.13.13.{n}")
                }
            };
            // 条件判定：非空 IP 必须是合法 IP
            if !ip.is_empty() && ip.parse::<IpAddr>().is_err() {
                err(&format!("虚拟 IP {ip} 非法"));
            }
            let nic = VmNicConfig::new(name.clone(), ip.clone());
            cfg.vm_nics.push(nic);
            save_config(&args.config_path, &cfg);
            info(&format!("已创建虚拟网卡 {name}（IP {ip} 占位，认证后以服务端分配为准）"));
        }
        "delvmnic" => {
            let name = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定虚拟网卡名称"));
            let mut cfg = load_config(&args.config_path);
            if cfg.find_vmnic(&name).is_none() {
                err(&format!("虚拟网卡 {name} 不存在"));
            }
            // 先断开引用该网卡的连接
            let affected: Vec<String> = cfg
                .connections
                .iter()
                .filter(|c| c.vm_nic == name)
                .map(|c| c.server.clone())
                .collect();
            if !affected.is_empty() && daemon::already_running(cfg.control_port) {
                for server in &affected {
                    let _ = daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "disconnect", &json!({ "server": server }));
                }
            }
            cfg.connections.retain(|c| c.vm_nic != name);
            cfg.vm_nics.retain(|n| n.name != name);
            save_config(&args.config_path, &cfg);
            info(&format!("已删除虚拟网卡 {name}"));
        }
        "newserver" => {
            let endpoint = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定服务器地址 IP(:Port)"));
            let name = args.positionals.get(1).cloned().unwrap_or_default();
            let mut cfg = load_config(&args.config_path);
            if name.is_empty() {
                // name 为空表示删除：按地址匹配删除
                let existing: Vec<String> = cfg
                    .servers
                    .iter()
                    .filter(|s| s.endpoint == endpoint)
                    .map(|s| s.name.clone())
                    .collect();
                cfg.servers.retain(|s| s.endpoint != endpoint);
                save_config(&args.config_path, &cfg);
                info(&format!("已删除服务器 {}", existing.join(", ")));
                return;
            }
            let full = normalize_endpoint(&endpoint);
            match cfg.find_server_mut(&name) {
                Some(s) => {
                    s.endpoint = full.clone();
                }
                None => {
                    cfg.servers.push(ServerEntry::new(name.clone(), full.clone()));
                }
            }
            save_config(&args.config_path, &cfg);
            info(&format!("已保存服务器 {name} -> {full}"));
        }
        "alias" => {
            let name = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定别名（如 computer）"));
            let ip = args
                .positionals
                .get(1)
                .cloned()
                .unwrap_or_else(|| err("请指定目标虚拟 IP"));
            let name = match linkmesh_client::config::normalize_alias(&name) {
                Ok(n) => n,
                Err(e) => err(&e),
            };
            let ip = ip.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_err() {
                err(&format!("虚拟 IP {ip:?} 非法"));
            }
            let mut cfg = load_config(&args.config_path);
            cfg.aliases.insert(name.clone(), ip.clone());
            save_config(&args.config_path, &cfg);
            info(&format!("已保存本地别名 {name} -> {ip}"));
            info(&format!(
                "提示：若 {ip} 是本机虚拟 IP，该别名会自动自报给服务器，同房间设备可用 {name}:端口 访问本机"
            ));
        }
        "alias-del" => {
            let name = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定别名"));
            let mut cfg = load_config(&args.config_path);
            if cfg.aliases.remove(&name).is_some() {
                save_config(&args.config_path, &cfg);
                info(&format!("已删除本地别名 {name}"));
            } else {
                err(&format!("别名 {name} 不存在"));
            }
        }
        "alias-list" => {
            let cfg = load_config(&args.config_path);
            if cfg.aliases.is_empty() {
                info("本地别名表为空（可用 --alias \"名称\" \"虚拟IP\" 添加）");
                return;
            }
            info(&format!("本地别名表（共 {} 条）:", cfg.aliases.len()));
            for (name, ip) in &cfg.aliases {
                info(&format!("  {name} -> {ip}"));
            }
            info("另可用 --resolve \"名称\" 查看守护进程解析到的完整映射（含服务端别名）");
        }
        "resolve" => {
            let name = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定要解析的别名"));
            let cfg = load_config(&args.config_path);
            match daemon::ctrl_ok(
                cfg.control_port,
                cfg.control_token.as_deref(),
                "resolve",
                &json!({ "name": name }),
            ) {
                Ok(resp) => {
                    info(&format!(
                        "{} -> {}",
                        resp["data"]["name"].as_str().unwrap_or(""),
                        resp["data"]["ip"].as_str().unwrap_or("")
                    ));
                }
                Err(e) => err(&e),
            }
        }
        "connect" => {
            let server = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定服务器名称"));
            let vmnic = args
                .positionals
                .get(1)
                .cloned()
                .unwrap_or_else(|| err("请指定虚拟网卡名称"));
            let mut cfg = load_config(&args.config_path);
            if cfg.find_server(&server).is_none() {
                err(&format!("服务器 {server} 未配置"));
            }
            if cfg.find_vmnic(&vmnic).is_none() {
                err(&format!("虚拟网卡 {vmnic} 未配置"));
            }
            // 网格检查（mesh 强制认证）：必须已 --join（固定 root + 持有设备证书）才能连接。
            // 旧版明文公钥 TOFU 已移除，信任确认统一走 --join 的网格根指纹。
            let entry = cfg.find_server(&server).unwrap();
            if entry.mesh_root_pub.is_none() || entry.device_cert.is_none() {
                err(&format!(
                    "服务器 {server} 尚未加入网格。请先执行 linkmesh-client --join \"{server}\" \"{vmnic}\" --code LMJ-... 加入网格"
                ));
            }
            // 配置结构校验（连接前）
            if let Err(e) = cfg.validate() {
                err(&e);
            }
            // 条件判定：以守护进程运行状态判断是否已连接，而非配置残留的 connections[]
            // （修复 --stop 后 connections[] 残留导致无法重新 --connect 的已知问题）
            if daemon::already_running(cfg.control_port) {
                if let Ok(resp) =
                    daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "status", &json!({}))
                {
                    let running = resp["data"]["connections"]
                        .as_array()
                        .map(|arr| arr.iter().any(|it| it["server"].as_str() == Some(server.as_str())))
                        .unwrap_or(false);
                    if running {
                        err(&format!("已连接到服务器 {server}（连接正在运行）"));
                    }
                }
            }

            if cfg.find_connection(&server).is_none() {
                cfg.connections.push(ConnectionEntry {
                    server: server.clone(),
                    vm_nic: vmnic.clone(),
                });
            }
            // --token：写入该服务器的房间令牌（持久化，之后无需重复指定）
            if let Some(t) = &args.token {
                if !t.trim().is_empty() {
                    if let Some(s) = cfg.find_server_mut(&server) {
                        s.token = Some(t.trim().to_string());
                    }
                }
            }
            save_config(&args.config_path, &cfg);

            if daemon::already_running(cfg.control_port) {
                match daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "start", &json!({ "server": server })) {
                    Ok(resp) => {
                        info(resp["data"].as_str().unwrap_or("已连接"));
                        return;
                    }
                    // 守护进程在停止竞态中刚退出：落回自启路径（spawn 会自检端口占用）
                    Err(_) => {}
                }
            }

            // -d：显示详细内容（面向开发者，所有的都要记录）
            // 默认占用终端并实时输出日志（--log -1 --follow）
            let run_args: Vec<String>;
            if args.detail {
                // 详细模式：后台运行，不占用终端
                // -d 参数下不占用终端，日志仅写入文件
                run_args = vec![
                    "--run".to_string(),
                    "--config".to_string(),
                    args.config_path.to_string_lossy().to_string(),
                ];
            } else {
                // 默认占用终端并实时输出日志：--log -1 --follow --run --config <path>
                run_args = vec![
                    "--log".to_string(),
                    "-1".to_string(),
                    "--follow".to_string(),
                    "--run".to_string(),
                    "--config".to_string(),
                    args.config_path.to_string_lossy().to_string(),
                ];
            }
            let run_refs: Vec<&str> = run_args.iter().map(|s| s.as_str()).collect();
            if let Err(e) = daemon::spawn_daemon(
                &run_refs,
                Path::new(&cfg.log_file),
                Path::new(&cfg.pid_file),
                cfg.control_port,
                args.detail,
            ) {
                err(&e);
            }
            if !daemon::wait_ready(cfg.control_port, Duration::from_secs(5)) {
                err("守护进程启动超时，请查看日志");
            }
            info(&format!("已连接服务器 {server}（虚拟网卡 {vmnic}）"));
        }
        "disconnect" => {
            let server = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定服务器名称"));
            let mut cfg = load_config(&args.config_path);
            if daemon::already_running(cfg.control_port) {
                match daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "disconnect", &json!({ "server": server })) {
                    Ok(resp) => info(resp["data"].as_str().unwrap_or("已断开")),
                    Err(_) => info(&format!("已断开 {server}")),
                }
            } else {
                info(&format!("已断开 {server}"));
            }
            cfg.connections.retain(|c| c.server != server);
            save_config(&args.config_path, &cfg);
        }
        "stop" => {
            let mut cfg = load_config(&args.config_path);
            if daemon::already_running(cfg.control_port) {
                match daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "stop", &json!({})) {
                    Ok(_) => {
                        // 等待守护进程真正退出（控制端口关闭），避免立即 --connect 撞上关闭中的守护进程
                        let deadline = std::time::Instant::now() + Duration::from_secs(3);
                        while daemon::already_running(cfg.control_port)
                            && std::time::Instant::now() < deadline
                        {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        let _ = std::fs::remove_file(&cfg.pid_file);
                        info("客户端守护进程已停止");
                    }
                    Err(e) => err(&e),
                }
            } else {
                let _ = std::fs::remove_file(&cfg.pid_file);
                info("客户端守护进程未在运行");
            }
            // 修复已知问题：--stop 后清理 connections[]，避免残留条目阻塞后续 --connect
            if !cfg.connections.is_empty() {
                cfg.connections.clear();
                save_config(&args.config_path, &cfg);
                info("已清理 connections[]（停止即断开全部连接）");
            }
        }
        "list" => {
            let cfg = load_config(&args.config_path);
            info(&format!("配置文件: {}", args.config_path.display()));
            info("已配置服务器:");
            for s in &cfg.servers {
                let relay = if s.relay.enabled {
                    if s.relay.endpoint.is_empty() {
                        "服务器自身".to_string()
                    } else {
                        s.relay.endpoint.to_string()
                    }
                } else {
                    "关闭".to_string()
                };
                let token = s
                    .token
                    .as_deref()
                    .map(|_| "已配置".to_string())
                    .unwrap_or_else(|| "未配置".to_string());
                info(&format!(
                    "  {} -> {}  (公钥: {})  中继: {}  房间令牌: {token}",
                    s.name,
                    s.endpoint,
                    s.public_key.as_deref().unwrap_or("未获取"),
                    relay
                ));
            }
            info("虚拟网卡:");
            for n in &cfg.vm_nics {
                info(&format!("  {} ({}/{}) MTU {}", n.name, n.ip, n.netmask, n.mtu));
            }
            info("连接:");
            for c in &cfg.connections {
                info(&format!("  {} <-> {}", c.server, c.vm_nic));
            }
            if !cfg.aliases.is_empty() {
                info("本地别名:");
                for (name, ip) in &cfg.aliases {
                    info(&format!("  {name} -> {ip}"));
                }
            }
            info(&format!(
                "自动重连: {}（reconnect_secs={}）",
                if cfg.reconnect_secs > 0 { "开启" } else { "关闭" },
                cfg.reconnect_secs
            ));
            if cfg.dns.enabled {
                info(&format!("内嵌 DNS: udp {}:{}", cfg.dns.bind, cfg.dns.port));
            }
        }
        "status" => {
            let cfg = load_config(&args.config_path);
            let filter = args.positionals.first();
            let resp = match daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "status", &json!({})) {
                Ok(r) => r,
                Err(e) => err(&e),
            };
            let items = resp["data"]["connections"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let mut matched = 0;
            for it in items {
                if let Some(f) = filter {
                    if it["server"].as_str() != Some(f.as_str()) {
                        continue;
                    }
                }
                matched += 1;
                info(&format!(
                    "连接: {} (网卡 {})  状态: {}  收/发: {}/{} 字节",
                    it["server"].as_str().unwrap_or(""),
                    it["vmnic"].as_str().unwrap_or(""),
                    it["status"].as_str().unwrap_or(""),
                    it["rx_bytes"].as_u64().unwrap_or(0),
                    it["tx_bytes"].as_u64().unwrap_or(0)
                ));
                if let Some(e) = it["error"].as_str() {
                    if !e.is_empty() {
                        info(&format!("  错误: {e}"));
                    }
                }
                if let Some(peers) = it["peers"].as_array() {
                    if !peers.is_empty() {
                        info("  对端:");
                        for p in peers {
                            info(&format!(
                                "    IP {}  Endpoint {}  传输: {}",
                                p["ip"].as_str().unwrap_or(""),
                                p["endpoint"].as_str().unwrap_or(""),
                                p["transport"].as_str().unwrap_or("")
                            ));
                        }
                    }
                }
            }
            if matched == 0 {
                info("没有匹配的运行中连接");
            }
        }
        "log" => {
            let cfg = load_config(&args.config_path);
            let n: usize = args
                .positionals
                .first()
                .and_then(|s| s.parse().ok())
                .unwrap_or(50);
            let path = Path::new(&cfg.log_file);
            if !path.exists() {
                info("暂无日志");
                return;
            }
            if args.follow {
                if let Err(e) = log::follow(path, n) {
                    err(&e);
                }
                return;
            }
            for line in log::tail(path, n).unwrap_or_default() {
                println!("{line}");
            }
        }
        "run" => {
            let rt = tokio::runtime::Runtime::new().expect("创建运行时失败");
            if let Err(e) = rt.block_on(run_daemon(&args.config_path)) {
                err(&e);
            }
        }
        other => err(&format!("未知命令 {other}，执行 --help 查看帮助")),
    }
}

// 检查命令行是否包含 --hidden，如果是则不输出到终端

// info 函数已在全局作用域定义（支持 --hidden 参数）

fn cfg_has_vmnic(path: &Path, name: &str) -> bool {
    match ClientConfig::load(path) {
        Ok(c) => c.find_vmnic(name).is_some(),
        Err(_) => false,
    }
}

/// `--join`：向服务器索取 ServerInfo → 校验 root 签名 → TOFU 根指纹 → 发送 JOIN（加入码）
/// → 保存 mesh_root_pub / device_cert / 分配 IP。
async fn run_join(
    config_path: &Path,
    server: &str,
    vmnic: &str,
    code: &str,
    trust: Option<bool>,
    token: Option<&str>,
) -> Result<(), String> {
    let mut cfg = ClientConfig::load(config_path)?;
    if cfg.identity.is_none() {
        return Err("尚未生成设备身份，请先执行 --genkey".into());
    }
    let entry = cfg
        .find_server(server)
        .cloned()
        .ok_or_else(|| format!("服务器 {server} 未配置"))?;
    // 令牌：--token 优先；否则用配置中已保存的令牌
    let token = match token {
        Some(t) if !t.trim().is_empty() => Some(t.trim().to_string()),
        _ => entry.token.clone(),
    };
    let endpoint: SocketAddr = entry
        .endpoint
        .parse()
        .map_err(|e| format!("服务器地址 {} 解析失败: {e}", entry.endpoint))?;
    let local_pub = cfg.public_key()?;
    let log = log::Logger::new(&cfg.log_file);

    // 1) 索取 ServerInfo（P1-6 TOFU 升级）
    let server_info = linkmesh_client::connection::fetch_server_info(endpoint, &local_pub, &log)
        .await
        .map_err(|e| format!("获取服务器信息失败: {e}"))?;

    // 2) 校验 root 签名（ServerInfo 自含 mesh_root_pub，签名用它验证）
    let mesh_root_b64 = server_info.mesh_root_pub.clone();
    let root_pub = linkmesh_shared::identity::parse_sig_public(&mesh_root_b64)?;
    server_info
        .verify(&root_pub)
        .map_err(|e| format!("服务器信息签名无效（可能被篡改或非本网格）: {e}"))?;

    // 3) TOFU 网格根指纹
    let fp = linkmesh_shared::identity::fingerprint_from_device_id(&root_pub);
    let trusted = match trust {
        Some(true) => true,
        Some(false) => false,
        None => confirm_root_fingerprint(server, &fp),
    };
    if !trusted {
        return Err(format!("已拒绝信任网格 {server} 的根指纹，未加入"));
    }
    if cfg
        .find_server(server)
        .and_then(|s| s.mesh_root_pub.as_ref())
        .is_some()
    {
        // 已固定过根：比对一致性
        let stored = cfg.find_server(server).unwrap().mesh_root_pub.clone().unwrap();
        if stored != mesh_root_b64 {
            return Err("服务器出示的网格根与本地已固定的根不一致（可能换了网格或存在中间人）".into());
        }
    }

    // 4) 发送 JOIN
    let device_id = cfg.device_id()?;
    let ik_s_pub = cfg
        .signing_public_b64()
        .ok_or("缺少设备签名公钥")?;
    // 自报别名：本地别名表中 IP 与本机虚拟 IP 一致的那条（可选）
    let nic_ip = cfg
        .find_vmnic(vmnic)
        .map(|n| n.ip.clone())
        .unwrap_or_default();
    let self_alias = cfg
        .aliases
        .iter()
        .find(|(_, ip)| **ip == nic_ip)
        .map(|(name, _)| name.clone());
    let shared = linkmesh_shared::crypto::shared_secret(&cfg.private_key()?, &server_info.server_ik_x_raw()?);
    let body = linkmesh_shared::protocol::JoinBody {
        code: code.to_string(),
        device_id,
        ik_x: B64.encode(local_pub),
        ik_s_pub,
        requested_ip: None,
        token: token.clone(),
        alias: self_alias,
    };
    let ct = linkmesh_shared::crypto::encrypt(
        &shared,
        &linkmesh_shared::protocol::encode_join(&body).map_err(|e| e.to_string())?,
    );
    let frame = linkmesh_shared::protocol::frame_signaling(
        linkmesh_shared::protocol::MSG_JOIN,
        &local_pub,
        &ct,
    );
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    sock.send_to(&frame, endpoint).await.map_err(|e| format!("发送 JOIN 失败: {e}"))?;
    let mut buf = vec![0u8; 65536];
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let (allocated_ip, cert) = loop {
        let remain = deadline.saturating_duration_since(std::time::Instant::now());
        let (len, src) = tokio::time::timeout(remain, sock.recv_from(&mut buf))
            .await
            .map_err(|_| "等待 JOIN 响应超时".to_string())?
            .map_err(|e| format!("接收失败: {e}"))?;
        if src != endpoint {
            continue;
        }
        let hdr = linkmesh_shared::protocol::parse_header(&buf[..len])?;
        if hdr.msg_type != linkmesh_shared::protocol::MSG_RESPONSE {
            continue;
        }
        let plain = linkmesh_shared::crypto::decrypt(&shared, &buf[36..len])?;
        let resp: ResponseBody =
            linkmesh_shared::protocol::decode_response(&plain).map_err(|e| format!("解析失败: {e}"))?;
        if !resp.ok {
            return Err(resp.error.unwrap_or_else(|| "加入失败".into()));
        }
        let (cert, ip) = match resp.data {
            linkmesh_shared::protocol::ResponseData::Join {
                cert, allocated_ip, ..
            } => (cert, allocated_ip),
            _ => return Err("加入响应缺少证书".into()),
        };
        break (ip, cert);
    };

    // 5) 保存到 ServerEntry
    if let Some(s) = cfg.find_server_mut(server) {
        s.mesh_root_pub = Some(mesh_root_b64);
        s.device_cert = Some(cert.clone());
        s.public_key = Some(server_info.server_ik_x.clone());
        s.crl_version = Some(server_info.crl_version);
        if let Some(t) = &token {
            s.token = Some(t.clone());
        }
    }
    // 若分配的 IP 与虚拟网卡配置不一致，更新网卡 IP
    if let Some(n) = cfg.vm_nics.iter_mut().find(|n| n.name == vmnic) {
        n.ip = allocated_ip.clone();
    }
    ClientConfig::save(&cfg, config_path)?;
    info(&format!(
        "已加入服务器 {server} 的网格（mesh_root 已固定）"
    ));
    info(&format!("分配虚拟 IP: {allocated_ip}"));
    info(&format!(
        "证书有效期至 {}（设备 {}）",
        cert.not_after, cert.device_id
    ));
    info(&format!(
        "设备指纹: {}",
        linkmesh_shared::identity::fingerprint_from_device_id(&{
            let ik_s = linkmesh_shared::identity::parse_sig_public(&cert.ik_s_pub)?;
            let ik_x = linkmesh_shared::crypto::parse_public_key(&cert.ik_x)?;
            linkmesh_shared::identity::device_id(&ik_x, &ik_s)
        })
    ));
    info("下一步：--connect 完成 AUTH 握手并建立连接");
    Ok(())
}

/// 交互式确认网格根指纹。无输入默认拒绝。
fn confirm_root_fingerprint(server: &str, fp: &str) -> bool {
    loop {
        eprint!(
            "服务器 {server} 所属网格的根指纹:\n  {fp}\n是否信任并加入？[y/N] "
        );
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => return false,
            Ok(_) => match line.trim().to_lowercase().as_str() {
                "y" | "yes" => return true,
                "n" | "no" | "" => return false,
                _ => {}
            },
        }
    }
}

fn normalize_endpoint(ep: &str) -> String {
    if ep.contains(':') {
        ep.to_string()
    } else {
        format!("{ep}:8080")
    }
}

async fn run_daemon(config_path: &Path) -> Result<(), String> {
    let cfg = ClientConfig::load(config_path)?;
    if cfg.identity.is_none() {
        return Err("尚未生成设备身份（identity），请先执行 --genkey".into());
    }
    // 配置结构校验（守护进程启动前）
    cfg.validate()?;
    let logger = log::Logger::new(&cfg.log_file);
    logger.info("客户端守护进程启动");

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    // 内嵌 DNS 应答器：解析网格别名（computer -> 10.13.13.x），供应用直接使用 computer:8080
    let dns_registry = if cfg.dns.enabled {
        let reg = Arc::new(linkmesh_client::dns::DnsRegistry::new());
        // 本地别名直接登记
        for (name, ip) in &cfg.aliases {
            reg.insert(name, ip).await;
        }
        let bind = cfg.dns.bind.clone();
        let port = cfg.dns.port;
        let reg2 = reg.clone();
        let log2 = logger.clone();
        let quit_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            if let Err(e) = linkmesh_client::dns::serve(reg2, &bind, port, quit_rx, log2).await {
                eprintln!("DNS 应答器错误: {e}");
            }
        });
        Some(reg)
    } else {
        logger.warn("内嵌 DNS 应答器已禁用（dns.enabled=false），别名无法通过 DNS 解析");
        None
    };

    let mut manager = ConnManager::new(config_path.to_path_buf(), logger.clone());
    if let Some(reg) = &dns_registry {
        manager.dns = Some(reg.clone());
    }
    let manager = Arc::new(manager);
    let ctx = Arc::new(control::CtrlContext {
        manager: manager.clone(),
        shutdown_tx: shutdown_tx.clone(),
        token: cfg.control_token.clone(),
        log: logger.clone(),
    });
    tokio::spawn(control::serve(cfg.control_port, ctx));

    manager.start_all().await;

    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
    // 优雅停止全部连接（发送 MSG_BYE，服务端及时清理路由表），再退出
    manager.shutdown_all().await;
    logger.info("客户端守护进程退出");
    Ok(())
}
