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

//! linkmesh-server：中心化信令 + 中继服务。
//!
//! 一切配置集中于 `./server.json`，命令行的操作会改写该文件。

use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_server::config::ServerConfig;
use linkmesh_server::control;
use linkmesh_server::daemon;
use linkmesh_server::log::{self, Logger};
use linkmesh_server::mesh::MeshConfig;
use linkmesh_server::signaling::{relay_loop, RelayBatcher, Signaling};
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
    reason: Option<String>,
    /// -d：显示详细内容（面向开发者，所有的都要记录）。
    detail: bool,
}

fn parse_args() -> Args {
    let mut command = None;
    let mut positionals = Vec::new();
    let mut config_path = PathBuf::from("server.json");
    let mut quiet = false;
    let mut follow = false;
    let mut ip = None;
    let mut reason = None;
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
            "--reason" => {
                if let Some(v) = it.next() {
                    reason = Some(v);
                }
            }
            "-d" | "--detail" => detail = true,
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
        reason,
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
    ("start", "--start \"PORT\" [-d]：启动信令服务并监听指定端口（默认占用终端并输出日志到控制台，加 -d 则后台运行）"),
    ("stop", "--stop：停止信令服务"),
    ("genkey", "--genkey：生成服务端密钥对（已存在则报错），写入 server.json"),
    ("showpubkey", "--showpubkey：显示服务端公钥"),
    ("add-room", "--add-room \"房间名\" \"令牌\"：新增/更新房间令牌（分房间隔离；令牌只存哈希）"),
    ("remove-room", "--remove-room \"房间名\"：删除房间令牌（删除后该房间设备无法再接入）"),
    ("rooms", "--rooms：查看房间令牌列表（名称 + 哈希前缀）"),
    ("alias", "--alias \"别名\" \"虚拟IP\"：绑定别名（如 computer -> 10.13.13.5，客户端可用 computer:8080 访问）"),
    ("alias-del", "--alias-del \"别名\"：删除别名绑定"),
    ("alias-list", "--alias-list：查看别名表"),
    ("mesh-init", "--mesh-init：初始化网格根（生成 mesh.json，显示根指纹）"),
    ("invite", "--invite [--ip x.x.x.x]：生成一次性加入码（10 分钟有效，可预绑定虚拟 IP）"),
    ("issue", "--issue \"ik_x公钥\" \"ik_s公钥\" [--ip x.x.x.x]：离线签发设备证书（类似 authorized_keys 工作流）"),
    ("revoke", "--revoke <device_id|ik_x> [--reason compromised|leaked|rotated|admin|discontinued]：吊销设备并强制下线"),
    ("crl", "--crl：查看当前吊销列表"),
    ("show-fingerprint", "--show-fingerprint：显示网格根指纹（加入时带外比对）"),
    ("list", "--list：查看路由表（在线客户端公钥 / 虚拟 IP / Endpoint）"),
    ("delpeer", "--delpeer \"public key\"：强制下线指定公钥的客户端"),
    ("status", "--status：查看服务实时运行状态"),
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
    println!("linkmesh-server {VERSION} — 中心化信令 + 中继服务");
    println!();
    println!("用法: linkmesh-server [--config <路径>] [--quiet] <命令> [参数]");
    println!();
    for (_, desc) in CMD_LIST {
        println!("    {desc}");
    }
    println!();
    println!("配置文件默认 ./server.json，所有命令都会读写它。");
}

fn load_config(path: &Path) -> ServerConfig {
    match ServerConfig::load(path) {
        Ok(c) => c,
        Err(e) => err(&e),
    }
}

fn save_config(path: &Path, cfg: &ServerConfig) {
    if let Err(e) = cfg.save(path) {
        err(&e);
    }
}

/// 加载 mesh.json；未初始化则报错。
fn load_mesh(path: &Path) -> MeshConfig {
    match MeshConfig::load(path) {
        Ok(Some(m)) => m,
        Ok(None) => err(&format!("{} 不存在，请先执行 --mesh-init 初始化网格", path.display())),
        Err(e) => err(&e),
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
                println!("linkmesh-server {VERSION}");
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
            println!(
                "已生成密钥对并写入 {}。公钥: {}",
                args.config_path.display(),
                B64.encode(pubkey)
            );
        }
        "showpubkey" => {
            let cfg = load_config(&args.config_path);
            match cfg.public_key() {
                Ok(pk) => info(&B64.encode(pk)),
                Err(e) => err(&e),
            }
        }
        "add-room" => {
            let name = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定房间名"));
            let token = args
                .positionals
                .get(1)
                .cloned()
                .unwrap_or_else(|| err("请指定房间令牌"));
            let mut cfg = load_config(&args.config_path);
            if let Err(e) = cfg.add_room(&name, &token) {
                err(&e);
            }
            save_config(&args.config_path, &cfg);
            info(&format!("房间 {name} 已保存（令牌以 SHA-256 哈希存储，不落明文）"));
            info("运行中的守护进程请用控制通道 add-room 即时生效，或重启服务端");
        }
        "remove-room" => {
            let name = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定房间名"));
            let mut cfg = load_config(&args.config_path);
            if cfg.remove_room(&name) {
                save_config(&args.config_path, &cfg);
                info(&format!("房间 {name} 已删除（该房间设备此后无法通过令牌验证）"));
            } else {
                err(&format!("房间 {name} 不存在"));
            }
        }
        "rooms" => {
            let cfg = load_config(&args.config_path);
            if cfg.rooms.is_empty() {
                info("未配置房间令牌（rooms 为空）：单房间开放模式，所有设备同处一个房间，无令牌验证");
                return;
            }
            info(&format!("共 {} 个房间（令牌以哈希存储）:", cfg.rooms.len()));
            for r in &cfg.rooms {
                let short = &r.token_hash[..r.token_hash.len().min(12)];
                info(&format!("  {}  token_hash: {}…", r.name, short));
            }
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
            let mut cfg = load_config(&args.config_path);
            if let Err(e) = cfg.add_alias(&name, &ip) {
                err(&e);
            }
            save_config(&args.config_path, &cfg);
            info(&format!("已绑定别名 {name} -> {ip}"));
            info("运行中的守护进程请用控制通道 alias 即时生效，或重启服务端");
        }
        "alias-del" => {
            let name = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定别名"));
            let mut cfg = load_config(&args.config_path);
            if cfg.remove_alias(&name) {
                save_config(&args.config_path, &cfg);
                info(&format!("已删除别名 {name}"));
            } else {
                err(&format!("别名 {name} 不存在"));
            }
        }
        "alias-list" => {
            let cfg = load_config(&args.config_path);
            if cfg.aliases.is_empty() {
                info("别名表为空");
                return;
            }
            info(&format!("共 {} 个别名:", cfg.aliases.len()));
            for a in &cfg.aliases {
                info(&format!("  {} -> {}", a.name, a.ip));
            }
        }
        "mesh-init" => {
            let cfg = load_config(&args.config_path);
            if cfg.keypair.is_none() {
                err("尚未生成服务端密钥对，请先执行 --genkey");
            }
            let mesh_path = Path::new(&cfg.mesh_path);
            if mesh_path.exists() {
                err(&format!("{} 已存在（网格已初始化，如需重建请删除该文件）", cfg.mesh_path));
            }
            let mesh = MeshConfig::init(&MeshConfig::generate_mesh_id());
            if let Err(e) = mesh.save(mesh_path) {
                err(&e);
            }
            let fp = mesh.root_fingerprint().unwrap_or_default();
            info(&format!("网格已初始化，写入 {}", cfg.mesh_path));
            info(&format!("网格 ID: {}", mesh.mesh_id));
            info(&format!("网格根指纹: {fp}"));
            info("请离线妥善备份 mesh.json（含 root 私钥，chmod 600）");
            info("下一步：linkmesh-server --invite [--ip x.x.x.x] 生成加入码");
        }
        "invite" => {
            let cfg = load_config(&args.config_path);
            let mesh_path = Path::new(&cfg.mesh_path);
            let mut mesh = load_mesh(mesh_path);
            let ip = args.ip.clone();
            if let Some(ip) = &ip {
                if mesh.allocate_ip(Some(ip)).is_err() {
                    // 预绑定 IP 校验失败（格式非法等）
                    err(&format!("虚拟 IP {ip} 不可用"));
                }
            }
            let code = mesh.create_invite(ip.as_deref(), linkmesh_server::mesh::INVITE_TTL_SECS);
            if let Err(e) = mesh.save(mesh_path) {
                err(&e);
            }
            info(&format!("加入码（10 分钟有效，单次使用）: {code}"));
            if let Some(ip) = &ip {
                info(&format!("已预绑定虚拟 IP: {ip}"));
            }
        }
        "issue" => {
            let cfg = load_config(&args.config_path);
            let ik_x = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定设备 X25519 公钥（ik_x，来自 --showpubkey）"));
            let ik_s = args
                .positionals
                .get(1)
                .cloned()
                .unwrap_or_else(|| err("请指定设备 Ed25519 签名公钥（ik_s）"));
            let mesh_path = Path::new(&cfg.mesh_path);
            let mut mesh = load_mesh(mesh_path);
            let ip = args.ip.clone().unwrap_or_default();
            match mesh.issue_cert(&ik_x, &ik_s, &ip, None) {
                Ok(cert) => {
                    if let Err(e) = mesh.save(mesh_path) {
                        err(&e);
                    }
                    info(&format!(
                        "已签发设备证书: device_id={} allowed_ip={} valid_until={}",
                        cert.device_id, cert.allowed_ip, cert.not_after
                    ));
                    info("设备侧执行 linkmesh-client --join 完成绑定（或把证书写入其 client.json）");
                }
                Err(e) => err(&e),
            }
        }
        "revoke" => {
            let cfg = load_config(&args.config_path);
            let target = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定 device_id 或 X25519 公钥"));
            let reason = match args.reason.as_deref() {
                None | Some("compromised") => linkmesh_shared::cert::RevokeReason::Compromised,
                Some("leaked") => linkmesh_shared::cert::RevokeReason::Leaked,
                Some("rotated") => linkmesh_shared::cert::RevokeReason::Rotated,
                Some("admin") => linkmesh_shared::cert::RevokeReason::Admin,
                Some("discontinued") => linkmesh_shared::cert::RevokeReason::Discontinued,
                Some(other) => err(&format!("未知吊销原因 {other}")),
            };
            let mesh_path = Path::new(&cfg.mesh_path);
            let mut mesh = load_mesh(mesh_path);
            let device_id = {
                // 支持按 device_id 或按 ik_x 公钥定位
                let by_id = mesh.find_member(&target).map(|m| m.device_id.clone());
                let by_key = mesh.find_by_ik_x(&target).map(|m| m.device_id.clone());
                by_id.or(by_key).unwrap_or_else(|| err("未找到该设备（不在成员表或已吊销）"))
            };
            match mesh.revoke(&device_id, reason) {
                Ok(crl) => {
                    if let Err(e) = mesh.save(mesh_path) {
                        err(&e);
                    }
                    info(&format!("已吊销设备 {device_id}，CRL 版本 -> {}", crl.version));
                    info("运行中的守护进程将按 CRL 拒绝其接入；如需立即踢下线请用控制通道 revoke");
                }
                Err(e) => err(&e),
            }
        }
        "crl" => {
            let cfg = load_config(&args.config_path);
            let mesh_path = Path::new(&cfg.mesh_path);
            let mesh = load_mesh(mesh_path);
            if mesh.crl.entries.is_empty() {
                info(&format!("吊销列表为空（CRL v{}）", mesh.crl.version));
                return;
            }
            info(&format!("吊销列表（CRL v{}，共 {} 条）:", mesh.crl.version, mesh.crl.entries.len()));
            for e in &mesh.crl.entries {
                info(&format!(
                    "  device_id={} reason={} revoked_at={}",
                    e.device_id,
                    e.reason.as_str(),
                    e.revoked_at
                ));
            }
        }
        "show-fingerprint" => {
            let cfg = load_config(&args.config_path);
            let mesh_path = Path::new(&cfg.mesh_path);
            let mesh = load_mesh(mesh_path);
            match mesh.root_fingerprint() {
                Ok(fp) => info(&fp),
                Err(e) => err(&e),
            }
        }
        _ => run_command(&args),
    }
}

fn run_command(args: &Args) {
    let cmd = args.command.as_deref().unwrap();
    match cmd {
        "start" => {
            let port = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| "8080".to_string());
            let port: u16 = match port.parse() {
                Ok(p) => p,
                Err(_) => err("端口必须为 1-65535 的整数"),
            };
            let mut cfg = load_config(&args.config_path);
            if cfg.keypair.is_none() {
                err("尚未生成密钥对，请先执行 --genkey");
            }
            cfg.listen = format!("0.0.0.0:{port}");
            save_config(&args.config_path, &cfg);

            let run_args = ["--run".to_string(),
                "--config".to_string(),
                args.config_path.to_string_lossy().to_string()];
            let run_refs: Vec<&str> = run_args.iter().map(|s| s.as_str()).collect();
            // -d：显示详细内容（面向开发者，所有的都要记录）
            // 默认占用终端并实时输出日志（--log -1 --follow）
            if args.detail {
                // 详细模式：后台运行，不占用终端
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
                info(&format!(
                    "信令服务已启动，监听端口 {port}（中继默认同端口）"
                ));
            } else {
                // 默认占用终端并实时输出日志：--log -1 --follow --run --config <path>
                let run_args_with_log = [
                    "--log".to_string(),
                    "-1".to_string(),
                    "--follow".to_string(),
                    "--run".to_string(),
                    "--config".to_string(),
                    args.config_path.to_string_lossy().to_string(),
                ];
                let run_refs_with_log: Vec<&str> = run_args_with_log.iter().map(|s| s.as_str()).collect();
                if let Err(e) = daemon::spawn_daemon(
                    &run_refs_with_log,
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
                info(&format!(
                    "信令服务已启动，监听端口 {port}（中继默认同端口）"
                ));
            }
        }
        "stop" => {
            let cfg = load_config(&args.config_path);
            match daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "stop", &json!({})) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&cfg.pid_file);
                    info("服务已停止");
                }
                Err(e) => err(&e),
            }
        }
        "list" => {
            let cfg = load_config(&args.config_path);
            let resp = match daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "routes", &json!({})) {
                Ok(r) => r,
                Err(e) => err(&e),
            };
            let items = resp["data"]["items"].as_array().cloned().unwrap_or_default();
            if items.is_empty() {
                info("路由表为空，暂无在线客户端");
                return;
            }
            info(&format!("共 {} 个在线客户端:", items.len()));
            for it in items {
                let room = it["room"].as_str().unwrap_or("default");
                let alias = it["alias"].as_str().unwrap_or("");
                let alias_s = if alias.is_empty() {
                    String::new()
                } else {
                    format!("  别名: {alias}")
                };
                info(&format!(
                    "  公钥: {}  虚拟IP: {}  Endpoint: {}  房间: {}{alias_s}",
                    it["public_key"].as_str().unwrap_or(""),
                    it["ip"].as_str().unwrap_or(""),
                    it["endpoint"].as_str().unwrap_or(""),
                    room
                ));
            }
        }
        "delpeer" => {
            let key = args
                .positionals
                .first()
                .cloned()
                .unwrap_or_else(|| err("请指定要删除的公钥"));
            let cfg = load_config(&args.config_path);
            match daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "delpeer", &json!({ "key": key })) {
                Ok(resp) => info(resp["data"].as_str().unwrap_or("已执行")),
                Err(e) => err(&e),
            }
        }
        "status" => {
            let cfg = load_config(&args.config_path);
            let resp = match daemon::ctrl_ok(cfg.control_port, cfg.control_token.as_deref(), "status", &json!({})) {
                Ok(r) => r,
                Err(e) => err(&e),
            };
            let d = &resp["data"];
            info(&format!(
                "在线客户端: {}",
                d["online_clients"].as_u64().unwrap_or(0)
            ));
            info(&format!(
                "中继: {}",
                if d["relay_enabled"].as_bool().unwrap_or(false) {
                    "启用"
                } else {
                    "关闭"
                }
            ));
            info(&format!(
                "服务端公钥: {}",
                d["server_public_key"].as_str().unwrap_or("")
            ));
            info(&format!(
                "收/发包: {}/{}，中继字节: {}",
                d["stats"]["packets_in"].as_u64().unwrap_or(0),
                d["stats"]["packets_out"].as_u64().unwrap_or(0),
                d["stats"]["bytes_relayed"].as_u64().unwrap_or(0)
            ));
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

/// 加大 UDP 套接字收发缓冲（Linux 默认 212KB / Windows 默认 ~8KB，突发批量转发时易丢包）。
fn enlarge_udp_buffers(sock: &std::net::UdpSocket, size: usize) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        unsafe {
            let v = size as libc::c_int;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &v as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &v as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        let s = sock.as_raw_socket();
        // WinSock 常量（libc crate 未导出）：SOL_SOCKET=0xffff, SO_RCVBUF=0x1002, SO_SNDBUF=0x1001
        const SOL_SOCKET: libc::c_int = 0xffff;
        const SO_RCVBUF: libc::c_int = 0x1002;
        const SO_SNDBUF: libc::c_int = 0x1001;
        unsafe {
            let v = size as libc::c_int;
            let sock = s as libc::SOCKET;
            libc::setsockopt(
                sock,
                SOL_SOCKET,
                SO_RCVBUF,
                &v as *const _ as *const libc::c_char,
                std::mem::size_of::<libc::c_int>() as libc::c_int,
            );
            libc::setsockopt(
                sock,
                SOL_SOCKET,
                SO_SNDBUF,
                &v as *const _ as *const libc::c_char,
                std::mem::size_of::<libc::c_int>() as libc::c_int,
            );
        }
    }
}

async fn run_daemon(config_path: &Path) -> Result<(), String> {
    let cfg = ServerConfig::load(config_path)?;
    let logger = Logger::new(&cfg.log_file);

    let std_sock = std::net::UdpSocket::bind(&cfg.listen)
        .map_err(|e| format!("监听 {} 失败: {e}", cfg.listen))?;
    enlarge_udp_buffers(&std_sock, 16 * 1024 * 1024);
    std_sock
        .set_nonblocking(true)
        .map_err(|e| format!("设置非阻塞失败: {e}"))?;
    let sock = tokio::net::UdpSocket::from_std(std_sock).map_err(|e| format!("转换失败: {e}"))?;
    let local = sock.local_addr().map_err(|e| e.to_string())?;
    logger.info(format!("UDP 信令/中继监听 {local}"));

    let signaling = Arc::new(Signaling::new(sock, &cfg, logger.clone())?);
    tokio::spawn(signaling.clone().run());
    tokio::spawn(signaling.clone().cleanup_loop());

    // 独立中继端口（可选）
    if cfg.relay.enabled && cfg.relay.port != 0 {
        let relay_addr = format!("0.0.0.0:{}", cfg.relay.port);
        let rstd_sock = std::net::UdpSocket::bind(&relay_addr)
            .map_err(|e| format!("中继监听 {relay_addr} 失败: {e}"))?;
        enlarge_udp_buffers(&rstd_sock, 16 * 1024 * 1024);
        rstd_sock
            .set_nonblocking(true)
            .map_err(|e| format!("设置非阻塞失败: {e}"))?;
        let rsock = Arc::new(
            tokio::net::UdpSocket::from_std(rstd_sock).map_err(|e| format!("转换失败: {e}"))?,
        );
        let routes = signaling.routes.clone();
        let stats = signaling.stats.clone();
        let batcher = RelayBatcher::spawn(&cfg.relay.batch, rsock.clone(), stats.clone());
        if batcher.is_some() {
            logger.info(format!(
                "中继批量转发已启用（窗口 {}ms / 上限 {}B）",
                cfg.relay.batch.window_ms, cfg.relay.batch.max_bytes
            ));
        }
        let active_ik_x = signaling.active_ik_x.clone();
        let rooms = signaling.rooms.clone();
        tokio::spawn(relay_loop(rsock, routes, stats, batcher, active_ik_x, rooms));
        logger.info(format!("独立中继端口 {relay_addr}"));
    }

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let ctx = Arc::new(control::CtrlContext {
        routes: signaling.routes.clone(),
        stats: signaling.stats.clone(),
        server_pub: signaling.server_pub(),
        started: std::time::Instant::now(),
        control_port: cfg.control_port,
        relay_enabled: cfg.relay.enabled,
        rooms: signaling.rooms.clone(),
        aliases: signaling.aliases.clone(),
        config_path: config_path.to_path_buf(),
        token: cfg.control_token.clone(),
        log: logger.clone(),
    });
    tokio::spawn(control::serve(cfg.control_port, ctx, shutdown_tx.clone()));

    logger.info("服务启动完成");
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
    logger.info("服务停止");
    Ok(())
}
