#!/usr/bin/env bash
# LinkMesh - 可以在多个操作系统上运行的内网穿透工具
# Copyright (C) 2026 Linux-System-0(Github) / 一架在Linux上起飞的A320(Bilibili) <ls0_1@qq.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# 交叉编译 Windows 版 linkmesh-client / linkmesh-server。
# 需要：rustup target add x86_64-pc-windows-gnu，以及 mingw-w64 链接器。
set -euo pipefail

cd "$(dirname "$0")/.."

rustup target add x86_64-pc-windows-gnu

cargo build --release --target x86_64-pc-windows-gnu -p linkmesh-client -p linkmesh-server

OUT=target/x86_64-pc-windows-gnu/release
echo
echo "产物："
ls -lh "$OUT"/linkmesh-client.exe "$OUT"/linkmesh-server.exe
echo
echo "说明：wintun.dll 已内嵌进 linkmesh-client.exe，运行时自动释放到可执行文件同目录，无需额外拷贝。"
