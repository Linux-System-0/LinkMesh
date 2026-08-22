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

package com.linkmesh.client.core

import org.json.JSONObject

/**
 * Rust 核心（liblinkmesh_jni.so）的 JNI 桥接。
 *
 * 数据流：
 * - VPN fd 读到 IP 包 → [inject] → Rust 加密发往对端
 * - Rust 解密输出 → [drain] → 写回 VPN fd
 *
 * 所有 native 方法都与 linkmesh-jni/src/lib.rs 中的导出符号一一对应。
 */
object NativeBridge {

    init {
        System.loadLibrary("linkmesh_jni")
    }

    private const val HANDLE = 1L

    /**
     * 启动连接引擎。
     * @param configJson 完整 client.json（含 keypair / servers / connections / vm_nics）
     * @param logPath 日志文件绝对路径（App 私有目录）
     */
    fun connect(configJson: String, logPath: String) {
        val h = nativeConnect(configJson, logPath)
        if (h == 0L) throw RuntimeException("连接启动失败，请查看日志")
    }

    fun disconnect() = nativeDisconnect(HANDLE)

    /** 注入一个 IP 包（Kotlin 从 VPN fd 读到 → Rust）。成功返回 true。 */
    fun inject(packet: ByteArray): Boolean = nativeInject(HANDLE, packet) != 0.toByte()

    /** 取走一个 Rust 输出的 IP 包（写回 VPN fd）；无数据返回 null。 */
    fun drain(): ByteArray? = nativeDrain(HANDLE)

    /** 连接状态 JSON。 */
    fun status(): JSONObject {
        val s = nativeStatus(HANDLE) ?: return JSONObject("{\"status\":\"未连接\"}")
        return JSONObject(s)
    }

    /** 生成设备密钥对，返回 {"public":..., "private":...}。 */
    fun genKeypair(): JSONObject = JSONObject(nativeGenKeypair()!!)

    /** TOFU：向服务器索取公钥，返回 base64 公钥。 */
    fun fetchServerPubkey(endpoint: String, localPubB64: String): String =
        nativeFetchServerPubkey(endpoint, localPubB64) ?: throw RuntimeException("获取服务器公钥失败")

    /** DHCP 预取：向服务器索取本机分配虚拟 IP（建 TUN 前调用）；未分配返回空串。 */
    fun fetchAllocatedIp(endpoint: String, localPubB64: String): String =
        nativeFetchAllocatedIp(endpoint, localPubB64) ?: throw RuntimeException("获取分配 IP 失败")

    private external fun nativeConnect(configJson: String, logPath: String): Long
    private external fun nativeDisconnect(handle: Long)
    private external fun nativeInject(handle: Long, packet: ByteArray): Byte
    private external fun nativeDrain(handle: Long): ByteArray?
    private external fun nativeStatus(handle: Long): String?
    private external fun nativeGenKeypair(): String?
    private external fun nativeFetchServerPubkey(endpoint: String, localPubB64: String): String?
    private external fun nativeFetchAllocatedIp(endpoint: String, localPubB64: String): String?
}
