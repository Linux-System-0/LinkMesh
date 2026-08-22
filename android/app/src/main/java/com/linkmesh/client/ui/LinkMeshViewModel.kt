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

package com.linkmesh.client.ui

import android.app.Application
import android.util.Base64
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.linkmesh.client.core.NativeBridge
import com.linkmesh.client.data.ConfigRepository
import com.linkmesh.client.data.DeviceConfig
import com.linkmesh.client.data.ServerConfig
import com.linkmesh.client.data.VmIpMode
import com.linkmesh.client.vpn.LinkMeshVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/**
 * TOFU（Trust On First Use）确认请求：服务器首次出示公钥，等待用户信任/拒绝。
 */
data class TofuRequest(
    val server: ServerConfig,
    /** 服务器实际出示的公钥（base64）。 */
    val pubkey: String,
    /** 展示用指纹（SHA-256，便于人工比对）。 */
    val fingerprint: String,
)

/**
 * 一个对端设备摘要（来自 Rust status() 的 peers[]）。
 */
data class PeerInfo(
    /** 对端虚拟 IP。 */
    val ip: String,
    /** 对端实际地址（直连/中继 endpoint），可能为空。 */
    val endpoint: String,
    /** 传输方式：直连 / 中继 / 打洞中。 */
    val transport: String,
)

/**
 * 主界面状态与逻辑。
 */
class LinkMeshViewModel(application: Application) : AndroidViewModel(application) {

    val repo = ConfigRepository(application)

    private val _config = mutableStateOf(DeviceConfig())
    val config: State<DeviceConfig> = _config

    private val _status = mutableStateOf(LinkMeshVpnService.currentStatus)
    val status: State<String> = _status

    /** 在线对端设备列表（每条 = 一台对端设备）。 */
    private val _peers = mutableStateOf<List<PeerInfo>>(emptyList())
    val peers: State<List<PeerInfo>> = _peers

    /** 连接级累计上行/下行字节（用于对端列表页眉展示）。 */
    private val _txBytes = mutableStateOf(0L)
    val txBytes: State<Long> = _txBytes

    private val _rxBytes = mutableStateOf(0L)
    val rxBytes: State<Long> = _rxBytes

    private val _connected = mutableStateOf(LinkMeshVpnService.running)
    val connected: State<Boolean> = _connected

    private val _logLines = mutableStateOf<List<String>>(emptyList())
    val logLines: State<List<String>> = _logLines

    private val _busy = mutableStateOf(false)
    val busy: State<Boolean> = _busy

    private val _toast = mutableStateOf<String?>(null)
    val toast: State<String?> = _toast

    /** 待确认的 TOFU 请求；非空时 UI 弹出服务器公钥确认框。 */
    private val _tofu = mutableStateOf<TofuRequest?>(null)
    val tofu: State<TofuRequest?> = _tofu

    /** TOFU 拉取公钥进行中（避免重复点击）。 */
    private val _tofuBusy = mutableStateOf(false)
    val tofuBusy: State<Boolean> = _tofuBusy

    /** TOFU 确认成功后要继续执行的连接动作（来自“连接 VPN”按钮）。 */
    private var pendingVpnRequest: (() -> Unit)? = null

    /** 当前连接的服务器名（最近一次启动 VPN 时选择的）。 */
    val connectedServerName: String?
        get() = _connectedServerName

    private var _connectedServerName: String? = null

    private var pollJob: Job? = null

    init {
        refreshConfig()
        startPolling()
    }

    private fun refreshConfig() {
        viewModelScope.launch {
            _config.value = repo.config.first()
        }
    }

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            while (isActive) {
                _connected.value = LinkMeshVpnService.running
                _status.value = LinkMeshVpnService.currentStatus
                if (LinkMeshVpnService.running) {
                    // JNI status() 内部 block_on Rust runtime，放 IO 线程避免卡死主线程
                    val st: JSONObject? = withContext(Dispatchers.IO) {
                        try {
                            NativeBridge.status()
                        } catch (_: Exception) {
                            null
                        }
                    }
                    if (st != null) {
                        val status = st.optString("status", "")
                        val error = st.optString("error", "")
                        val display = if (error.isNotEmpty() && error != "null") "$status：$error" else status
                        if (display.isNotEmpty() && display != _status.value) {
                            _status.value = display
                        }
                        val peers = st.optJSONArray("peers")
                        _peers.value = if (peers != null && peers.length() > 0) {
                            buildList {
                                for (i in 0 until peers.length()) {
                                    val p = peers.getJSONObject(i)
                                    add(
                                        PeerInfo(
                                            ip = p.optString("ip", "?"),
                                            endpoint = p.optString("endpoint", ""),
                                            transport = p.optString("transport", "?"),
                                        )
                                    )
                                }
                            }
                        } else emptyList()
                        _txBytes.value = st.optLong("tx_bytes", 0L)
                        _rxBytes.value = st.optLong("rx_bytes", 0L)
                    }
                }
                refreshLogs()
                delay(2000)
            }
        }
    }

    private fun refreshLogs() {
        try {
            val f = File(getApplication<Application>().filesDir, "linkmesh.log")
            if (!f.exists()) {
                _logLines.value = emptyList()
                return
            }
            val lines = f.readLines().takeLast(200)
            _logLines.value = lines
        } catch (_: Exception) {
        }
    }

    /** 首次使用：生成密钥对。 */
    fun ensureKeypair(onDone: (Boolean) -> Unit) {
        if (_config.value.privateKey != null) {
            onDone(true)
            return
        }
        _busy.value = true
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val kp = NativeBridge.genKeypair()
                repo.saveKeypair(kp.getString("public"), kp.getString("private"))
                refreshConfig()
                onDone(true)
            } catch (e: Exception) {
                _toast.value = "生成密钥失败: ${e.message}"
                onDone(false)
            } finally {
                _busy.value = false
            }
        }
    }

    fun addServer(name: String, endpoint: String, relayEnabled: Boolean, relayEndpoint: String, token: String) {
        viewModelScope.launch {
            val existing = _config.value.servers.toMutableList()
            if (existing.any { it.name == name }) {
                _toast.value = "服务器名已存在：$name"
                return@launch
            }
            existing.add(
                ServerConfig(
                    name = name,
                    endpoint = endpoint,
                    relayEnabled = relayEnabled,
                    relayEndpoint = relayEndpoint,
                    token = token.trim()
                )
            )
            repo.saveServers(existing)
            refreshConfig()
            _toast.value = "已添加服务器 $name"
        }
    }

    fun updateServer(s: ServerConfig) {
        viewModelScope.launch {
            val list = _config.value.servers.map {
                if (it.name == s.name) s else it
            }
            repo.saveServers(list)
            refreshConfig()
        }
    }

    fun removeServer(name: String) {
        viewModelScope.launch {
            repo.saveServers(_config.value.servers.filter { it.name != name })
            refreshConfig()
        }
    }

    fun saveVmSettings(ip: String, netmask: String, mtu: Int, mode: VmIpMode = VmIpMode.STATIC) {
        viewModelScope.launch {
            repo.saveVm(ip, netmask, mtu)
            repo.saveVmMode(mode)
            refreshConfig()
            _toast.value = "网络设置已保存"
        }
    }

    fun setAutoReconnect(enabled: Boolean) {
        viewModelScope.launch {
            repo.setAutoReconnect(enabled)
            refreshConfig()
        }
    }

    fun setSelfAlias(alias: String) {
        viewModelScope.launch {
            repo.saveSelfAlias(alias)
            refreshConfig()
        }
    }

    fun setBootEnabled(enabled: Boolean) {
        viewModelScope.launch {
            repo.setBootEnabled(enabled)
            refreshConfig()
        }
    }

    fun setBootServers(names: Set<String>) {
        viewModelScope.launch {
            repo.setBootServers(names)
            refreshConfig()
        }
    }

    /**
     * 发起连接。
     * 若目标服务器公钥尚未确认（TOFU 待完成），先弹出公钥确认框，
     * 用户点“信任”后自动继续 [onVpnRequest]；已确认则直接继续。
     */
    fun connect(server: ServerConfig?, onVpnRequest: () -> Unit) {
        val target = server ?: run {
            _toast.value = "请先添加服务器"
            return
        }
        if (target.publicKey == null) {
            startTofu(target, proceed = onVpnRequest)
            return
        }
        if (_config.value.privateKey == null) {
            ensureKeypair { ok -> if (ok) onVpnRequest() }
        } else {
            onVpnRequest()
        }
    }

    /**
     * 开始 TOFU 验证：向服务器索取公钥 → 弹出确认框。
     * [proceed] 在用户点“信任”后执行（连接流程用）。
     */
    fun startTofu(server: ServerConfig, proceed: (() -> Unit)? = null) {
        if (_tofuBusy.value) return
        pendingVpnRequest = proceed
        if (_config.value.privateKey == null) {
            ensureKeypair { ok ->
                if (ok) fetchServerPubkey(server) else {
                    pendingVpnRequest = null
                }
            }
        } else {
            fetchServerPubkey(server)
        }
    }

    private fun fetchServerPubkey(server: ServerConfig) {
        _tofuBusy.value = true
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val localPub = _config.value.publicKey
                    ?: throw RuntimeException("缺少本机公钥，请重试")
                val key = NativeBridge.fetchServerPubkey(server.endpoint, localPub)
                val req = TofuRequest(
                    server = server,
                    pubkey = key,
                    fingerprint = fingerprintOf(key),
                )
                withContext(Dispatchers.Main) { _tofu.value = req }
            } catch (e: Exception) {
                _toast.value = "获取服务器公钥失败: ${e.message}"
                pendingVpnRequest = null
            } finally {
                _tofuBusy.value = false
            }
        }
    }

    /** 用户选择“信任”：保存公钥，然后继续挂起的连接动作。 */
    fun confirmTofu() {
        val req = _tofu.value ?: return
        viewModelScope.launch {
            val updated = _config.value.servers.map {
                if (it.name == req.server.name) it.copy(publicKey = req.pubkey) else it
            }
            repo.saveServers(updated)
            refreshConfig()
            _tofu.value = null
            val next = pendingVpnRequest
            pendingVpnRequest = null
            next?.invoke()
            _toast.value = "已信任服务器 ${req.server.name}，公钥已保存"
        }
    }

    /** 用户选择“拒绝”：放弃本次连接，不保存公钥。 */
    fun rejectTofu() {
        _tofu.value = null
        pendingVpnRequest = null
    }

    /** 服务器公钥指纹（SHA-256，前 16 字节，4 位一组，便于人工比对）。 */
    private fun fingerprintOf(pubB64: String): String = try {
        val raw = Base64.decode(pubB64, Base64.NO_WRAP)
        val digest = MessageDigest.getInstance("SHA-256").digest(raw)
        digest.take(16).joinToString("") { "%02X".format(it) }.chunked(4).joinToString(" ")
    } catch (_: Exception) {
        pubB64.take(24)
    }

    fun disconnect() {
        LinkMeshVpnService.stop(getApplication())
    }

    /** UI 手动刷新日志。 */
    fun refreshLogsForUi() = refreshLogs()

    fun showToastOnce() {
        _toast.value?.let {
            _toast.value = null
        }
    }
}
