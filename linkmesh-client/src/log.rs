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

//! 简单的文件日志与尾部读取。

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 转义日志消息中的控制字符（换行/回车/ESC 等），防止日志注入。
/// 保留可读的常规字符；`\n`/`\r`/`\t`/`\x1b` 及其余 C0/C1 控制字符转义为可见形式。
fn escape_log(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len() + 8);
    for c in msg.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x1b' => out.push_str("\\x1b"),
            c if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

#[derive(Clone)]
pub struct Logger {
    path: PathBuf,
}

impl Logger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Logger { path: path.into() }
    }

    pub fn info(&self, msg: impl AsRef<str>) {
        Self::write(&self.path, "INFO", msg.as_ref());
    }

    pub fn warn(&self, msg: impl AsRef<str>) {
        Self::write(&self.path, "WARN", msg.as_ref());
    }

    pub fn debug(&self, msg: impl AsRef<str>) {
        Self::write(&self.path, "DEBUG", msg.as_ref());
    }

    pub fn error(&self, msg: impl AsRef<str>) {
        Self::write(&self.path, "ERROR", msg.as_ref());
    }

    fn write(path: &Path, level: &str, msg: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // 转义控制字符/换行/ANSI，防止服务器可控字符串（resp.error、别名等）注入日志行
        // 或伪造日志（安全审计 item E）。
        let escaped = escape_log(msg);
        let line = format!("[{ts}] [{level}] {escaped}\n");
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// 读取日志文件末尾 `n` 行。
pub fn tail(path: &Path, n: usize) -> Result<Vec<String>, String> {
    let mut f = OpenOptions::new().read(true).open(path)
        .map_err(|e| format!("打开日志 {} 失败: {e}", path.display()))?;
    let size = f.metadata().map_err(|e| e.to_string())?.len();
    let read_size = size.min(64 * 1024) as usize;
    f.seek(SeekFrom::End(-(read_size as i64)))
        .map_err(|e| format!("定位日志失败: {e}"))?;
    let mut buf = vec![0u8; read_size];
    f.read_exact(&mut buf).map_err(|e| format!("读取日志失败: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    if n >= lines.len() {
        Ok(lines)
    } else {
        Ok(lines[lines.len() - n..].to_vec())
    }
}

/// 先输出末尾 `n` 行，随后持续追踪新增行（`--follow`）。按 Ctrl-C 退出。
pub fn follow(path: &Path, n: usize) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| format!("打开日志 {} 失败: {e}", path.display()))?;
    let size = f.metadata().map_err(|e| e.to_string())?.len();
    let read_size = size.min(64 * 1024) as usize;
    f.seek(SeekFrom::End(-(read_size as i64)))
        .map_err(|e| format!("定位日志失败: {e}"))?;
    let mut buf = vec![0u8; read_size];
    f.read_exact(&mut buf).map_err(|e| format!("读取日志失败: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    let start = lines.len().saturating_sub(n);
    for line in lines.drain(start..) {
        println!("{line}");
    }
    let mut offset = f.stream_position().map_err(|e| e.to_string())?;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let new_size = f.metadata().map_err(|e| e.to_string())?.len();
        if new_size > offset {
            f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
            let mut chunk = String::new();
            f.read_to_string(&mut chunk).map_err(|e| e.to_string())?;
            for line in chunk.lines() {
                println!("{line}");
            }
            offset = f.stream_position().map_err(|e| e.to_string())?;
        } else if new_size < offset {
            f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            offset = 0;
        }
    }
}
