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

package com.linkmesh.client.data

import org.json.JSONArray
import org.json.JSONObject

/**
 * 服务器配置（对应 client.json 的 ServerEntry）。
 */
data class ServerConfig(
    val name: String,
    val endpoint: String,
    val publicKey: String? = null,
    val relayEnabled: Boolean = true,
    val relayEndpoint: String = "",
    /** 房间令牌（server.json rooms 令牌；服务器启用令牌验证时必填，与 Linux `--token` 对齐）。 */
    val token: String = "",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("endpoint", endpoint)
        publicKey?.let { put("public_key", it) }
        if (token.isNotBlank()) put("token", token)
        // 中继地址为空时仍保留 enabled 标志，但 endpoint 留空让 Rust 侧走服务器自身
        put("relay", JSONObject().apply {
            put("enabled", relayEnabled)
            put("endpoint", relayEndpoint)
        })
    }

    companion object {
        fun fromJson(o: JSONObject): ServerConfig = ServerConfig(
            name = o.getString("name"),
            endpoint = o.getString("endpoint"),
            publicKey = o.optString("public_key", null),
            relayEnabled = o.optJSONObject("relay")?.optBoolean("enabled", true) ?: true,
            relayEndpoint = o.optJSONObject("relay")?.optString("endpoint", "") ?: "",
            token = o.optString("token", ""),
        )
    }
}

/**
 * 虚拟网卡 IP 获取模式。
 * @see <a href="https://github.com/Linux-System-0/LinkMesh">linkmesh-client VmNicConfig.mode</a>
 */
enum class VmIpMode(val json: String) {
    /** 本机静态配置虚拟 IP（默认）。 */
    STATIC("static"),
    /** DHCP：虚拟 IP 由服务端从 IP 池分配（证书绑定），本机不配置。 */
    DHCP("dhcp");

    companion object {
        fun fromJson(v: String?): VmIpMode = when (v?.lowercase()) {
            "dhcp" -> DHCP
            else -> STATIC
        }
    }
}

/**
 * 本地设备配置（密钥对 + 虚拟网卡 + 服务器列表 + 运行选项）。
 */
data class DeviceConfig(
    val publicKey: String? = null,
    val privateKey: String? = null,
    val vmIp: String = "10.13.13.2",
    val vmNetmask: String = "255.255.255.0",
    val vmMtu: Int = 1280,
    /** 虚拟 IP 获取模式：静态 / DHCP（服务端分配）。 */
    val vmMode: VmIpMode = VmIpMode.STATIC,
    val servers: List<ServerConfig> = emptyList(),
    val autoReconnect: Boolean = true,
    /** 本机自报别名（如 "myphone"）；服务器据此登记，供同房间设备按名解析（与 Linux `--alias` 对齐）。 */
    val selfAlias: String = "",
    /** 开机自启总开关（默认关）。 */
    val bootEnabled: Boolean = false,
    /** 开机自启时仅连接这些服务器名（空 = 连接第一个配置的服务器）。 */
    val bootServers: Set<String> = emptySet(),
) {
    /**
     * 构建 Rust 侧要求的 client.json 完整结构。
     * @param serverName 仅连接该服务器；null 则包含所有服务器（Rust 侧取第一个）。
     */
    fun toClientConfigJson(serverName: String? = null): String {
        val vmNics = JSONArray().put(JSONObject().apply {
            put("name", "linkmesh0")
            put("ip", vmIp)
            put("netmask", vmNetmask)
            put("mtu", vmMtu)
            put("mode", vmMode.json)
        })
        val targetServers = if (serverName != null) {
            servers.filter { it.name == serverName }
        } else servers
        val serverArr = JSONArray()
        targetServers.forEach { serverArr.put(it.toJson()) }
        val connArr = JSONArray()
        targetServers.forEach { s ->
            connArr.put(JSONObject().apply {
                put("server", s.name)
                put("vm_nic", "linkmesh0")
            })
        }
        val cfg = JSONObject().apply {
            put("version", 1)
            if (publicKey != null && privateKey != null) {
                put("keypair", JSONObject().apply {
                    put("public", publicKey)
                    put("private", privateKey)
                })
            }
            put("vm_nics", vmNics)
            put("servers", serverArr)
            put("connections", connArr)
            // 本地别名表：把 selfAlias → 本机虚拟 IP 写进 aliases，使 Rust 自报别名
            // （self_alias() 取 IP 与本机虚拟 IP 一致的那条）。DHCP 模式实际 IP 由服务端分配，
            // 静态映射无法预先匹配，故 DHCP 下不自报（与 Linux 静态 --alias 行为一致）。
            if (selfAlias.isNotBlank()) {
                put("aliases", JSONObject().apply { put(selfAlias, vmIp) })
            }
            put("hole_punch", JSONObject().apply {
                put("enabled", true)
                put("timeout_ms", 5000)
                put("max_retries", 3)
                put("interval_ms", 250)
                put("max_errors", 3)
            })
            put("heartbeat_sec", 20)
            put("rekey_every_pkts", 65536)
            put("rekey_every_secs", 300)
            // 自动重连与 Rust 端 reconnect_secs 对齐：关闭时置 0，避免 Rust 在 App 关闭开关后仍重连
            put("reconnect_secs", if (autoReconnect) 5 else 0)
            put("control_token", null)
            put("control_port", 0)
            put("log_file", "")
            put("pid_file", "")
        }
        return cfg.toString()
    }

    /** 当前选中的首个服务器（App 单隧道模型连接第一个）。 */
    fun primaryServer(): ServerConfig? = servers.firstOrNull()
}
