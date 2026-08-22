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

//! 后台运行：把 `--run` 模式的守护进程脱离终端启动，并与之通信。

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

/// 通过控制端口探测守护进程是否在运行。
pub fn already_running(control_port: u16) -> bool {
    std::net::TcpStream::connect(("127.0.0.1", control_port)).is_ok()
}

/// 向控制端口发送一条 JSON 请求并等待一行 JSON 响应。
/// `token` 非空时随请求携带鉴权令牌（守护进程校验，防本地任意进程控制）。
pub fn ctrl_request(port: u16, token: Option<&str>, req: &Value) -> Result<Value, String> {
    let mut req = req.clone();
    if let Some(t) = token {
        if !t.is_empty() {
            req.as_object_mut()
                .expect("json object")
                .insert("token".to_string(), json!(t));
        }
    }
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .map_err(|e| format!("无法连接控制端口 {port}（守护进程未运行？）: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("设置超时失败: {e}"))?;
    let line = format!("{}\n", serde_json::to_string(&req).map_err(|e| e.to_string())?);
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("发送控制请求失败: {e}"))?;
    let mut buf = String::new();
    BufReader::new(&stream)
        .read_line(&mut buf)
        .map_err(|e| format!("读取控制响应失败: {e}"))?;
    let v: Value = serde_json::from_str(&buf).map_err(|e| format!("响应解析失败: {e}"))?;
    Ok(v)
}

/// 发起控制请求并检查 ok 字段；失败时返回 error 信息。
pub fn ctrl_ok(port: u16, token: Option<&str>, cmd: &str, extra: &Value) -> Result<Value, String> {
    let mut req = json!({ "cmd": cmd });
    if let Some(obj) = extra.as_object() {
        let req_obj = req.as_object_mut().expect("json object");
        for (k, v) in obj {
            req_obj.insert(k.clone(), v.clone());
        }
    }
    let resp = ctrl_request(port, token, &req)?;
    if resp["ok"].as_bool().unwrap_or(false) {
        Ok(resp)
    } else {
        Err(resp["error"].as_str().unwrap_or("未知错误").to_string())
    }
}

/// 把守护进程以脱离终端的方式启动，输出追加写入日志文件。
pub fn spawn_daemon(
    run_args: &[&str],
    log_path: &Path,
    pid_path: &Path,
    control_port: u16,
) -> Result<(), String> {
    if already_running(control_port) {
        return Err(format!("守护进程已在运行（控制端口 {control_port}）"));
    }
    let exe = std::env::current_exe().map_err(|e| format!("获取自身路径失败: {e}"))?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("打开日志 {} 失败: {e}", log_path.display()))?;
    let log_dup = log.try_clone().map_err(|e| format!("复制日志句柄失败: {e}"))?;

    let mut cmd = Command::new(&exe);
    cmd.args(run_args);
    cmd.stdin(Stdio::null());
    cmd.stdout(log_dup);
    cmd.stderr(log);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let child = cmd.spawn().map_err(|e| format!("启动守护进程失败: {e}"))?;
    std::fs::write(pid_path, child.id().to_string())
        .map_err(|e| format!("写入 PID 文件失败: {e}"))?;
    Ok(())
}

/// 轮询控制端口直到就绪，或超时。
pub fn wait_ready(control_port: u16, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if already_running(control_port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}
