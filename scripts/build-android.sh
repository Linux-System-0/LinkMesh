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

# 交叉编译 Android 版 Rust 核心库（.so，供 Kotlin/Java 通过 JNI 调用）。
#
# 环境要求（已在本机配置好）：
#   - ANDROID_HOME 指向 Android SDK（默认 ~/Android/Sdk）
#   - NDK：sdkmanager "ndk;29.0.14206865"（本机已装 r29）
#   - Rust Android 目标：rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
#   - cargo install cargo-ndk
#
# 用法：
#   CRATE=linkmesh-jni ./scripts/build-android.sh
#   默认 CRATE=linkmesh-jni（cdylib，产出 4 ABI 的 liblinkmesh_jni.so）。
set -euo pipefail

cd "$(dirname "$0")/.."

CRATE="${CRATE:-linkmesh-jni}"
OUT_DIR="${OUT_DIR:-android/app/src/main/jniLibs}"

: "${ANDROID_HOME:?请先 export ANDROID_HOME（如 ~/Android/Sdk）}"
NDK_DIR=$(ls -d "$ANDROID_HOME"/ndk/*/ 2>/dev/null | sort -V | tail -1 | sed 's:/$::')
[ -n "$NDK_DIR" ] || { echo "未找到 NDK，请先安装: sdkmanager \"ndk;29.0.14206865\""; exit 1; }
export ANDROID_NDK_HOME="$NDK_DIR"

echo "NDK: $NDK_DIR"
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

cargo ndk -t arm64-v8a -t armeabi-v7a -t x86 -t x86_64 -o "$OUT_DIR" build --release -p "$CRATE"

echo
echo "产物："
find "$OUT_DIR" -name "*.so" -exec ls -lh {} \; 2>/dev/null || true
echo
echo "说明：要让 Rust 代码产出 .so，JNI 包装 crate 需声明 crate-type = [\"cdylib\"]，"
echo "      并通过 #[no_mangle] pub extern \"C\" 导出 JNI 函数（jni crate 可简化）。"
