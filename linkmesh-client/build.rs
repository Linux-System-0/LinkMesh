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

//! Windows 构建脚本：将 wintun.dll 内嵌进可执行文件，实现「内置 Wintun」。
//!
//! - 优先使用 `wintun/wintun.dll`（随仓库分发）。
//! - 非 Windows 目标不执行任何操作。

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wintun/wintun.dll");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dll_src = manifest.join("wintun").join("wintun.dll");
    if !dll_src.exists() {
        panic!(
            "缺少 wintun.dll（预期位置 {}）。请从 https://www.wintun.net/ 下载并放置于此。",
            dll_src.display()
        );
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dll_out = out_dir.join("wintun.dll");
    fs::copy(&dll_src, &dll_out).expect("复制 wintun.dll 失败");

    // 生成内嵌模块：`WINTUN_DLL` 为字节数组。
    let embed = out_dir.join("wintun_embedded.rs");
    fs::write(
        &embed,
        "pub static WINTUN_DLL: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/wintun.dll\"));\n",
    )
    .expect("生成内嵌模块失败");
}
