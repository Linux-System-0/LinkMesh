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

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.dataStore by preferencesDataStore(name = "linkmesh_config")

/**
 * 配置持久化（DataStore）。
 */
class ConfigRepository(private val context: Context) {

    private object Keys {
        val PUBLIC_KEY = stringPreferencesKey("public_key")
        val PRIVATE_KEY = stringPreferencesKey("private_key")
        val VM_IP = stringPreferencesKey("vm_ip")
        val VM_NETMASK = stringPreferencesKey("vm_netmask")
        val VM_MTU = stringPreferencesKey("vm_mtu")
        val VM_MODE = stringPreferencesKey("vm_mode")
        val SERVERS = stringPreferencesKey("servers")
        val AUTO_RECONNECT = booleanPreferencesKey("auto_reconnect")
        val SELF_ALIAS = stringPreferencesKey("self_alias")
        val BOOT_ENABLED = booleanPreferencesKey("boot_enabled")
        val BOOT_SERVERS = stringPreferencesKey("boot_servers")
    }

    val config: Flow<DeviceConfig> = context.dataStore.data.map { prefs ->
        val serversJson = prefs[Keys.SERVERS] ?: "[]"
        val arr = JSONArray(serversJson)
        val servers = (0 until arr.length()).map { ServerConfig.fromJson(arr.getJSONObject(it)) }
        val bootList = prefs[Keys.BOOT_SERVERS]?.let { raw ->
            val a = JSONArray(raw)
            (0 until a.length()).map { a.getString(it) }.toSet()
        } ?: emptySet()
        DeviceConfig(
            publicKey = prefs[Keys.PUBLIC_KEY],
            privateKey = prefs[Keys.PRIVATE_KEY],
            vmIp = prefs[Keys.VM_IP] ?: "10.13.13.2",
            vmNetmask = prefs[Keys.VM_NETMASK] ?: "255.255.255.0",
            vmMtu = prefs[Keys.VM_MTU]?.toIntOrNull() ?: 1280,
            vmMode = VmIpMode.fromJson(prefs[Keys.VM_MODE]),
            servers = servers,
            autoReconnect = prefs[Keys.AUTO_RECONNECT] ?: true,
            selfAlias = prefs[Keys.SELF_ALIAS] ?: "",
            bootEnabled = prefs[Keys.BOOT_ENABLED] ?: false,
            bootServers = bootList,
        )
    }

    suspend fun saveServers(servers: List<ServerConfig>) {
        val arr = JSONArray()
        servers.forEach { arr.put(it.toJson()) }
        context.dataStore.edit { prefs -> prefs[Keys.SERVERS] = arr.toString() }
    }

    suspend fun saveKeypair(publicKey: String, privateKey: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.PUBLIC_KEY] = publicKey
            prefs[Keys.PRIVATE_KEY] = privateKey
        }
    }

    suspend fun saveVm(ip: String, netmask: String, mtu: Int) {
        context.dataStore.edit { prefs ->
            prefs[Keys.VM_IP] = ip
            prefs[Keys.VM_NETMASK] = netmask
            prefs[Keys.VM_MTU] = mtu.toString()
        }
    }

    suspend fun saveVmMode(mode: VmIpMode) {
        context.dataStore.edit { prefs -> prefs[Keys.VM_MODE] = mode.json }
    }

    suspend fun setAutoReconnect(enabled: Boolean) {
        context.dataStore.edit { prefs -> prefs[Keys.AUTO_RECONNECT] = enabled }
    }

    suspend fun saveSelfAlias(alias: String) {
        context.dataStore.edit { prefs -> prefs[Keys.SELF_ALIAS] = alias.trim() }
    }

    suspend fun setBootEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs -> prefs[Keys.BOOT_ENABLED] = enabled }
    }

    suspend fun setBootServers(names: Set<String>) {
        val arr = JSONArray()
        names.forEach { arr.put(it) }
        context.dataStore.edit { prefs -> prefs[Keys.BOOT_SERVERS] = arr.toString() }
    }
}
