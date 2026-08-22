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

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Article
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.linkmesh.client.data.ServerConfig
import com.linkmesh.client.data.VmIpMode
import kotlinx.coroutines.launch

/**
 * LinkMesh 主界面。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LinkMeshRoot(
    onConnect: () -> Unit,
    notificationGranted: Boolean = true,
    vm: LinkMeshViewModel = viewModel(),
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var tab by remember { mutableStateOf(0) }

    LaunchedEffect(vm.toast.value) {
        vm.toast.value?.let {
            snackbarHostState.showSnackbar(it)
            vm.showToastOnce()
        }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("LinkMesh") }) },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
        ) {
            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("连接") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("服务器") })
                Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text("日志") })
                Tab(selected = tab == 3, onClick = { tab = 3 }, text = { Text("设置") })
            }
            when (tab) {
                0 -> ConnectionTab(vm, onConnect, notificationGranted, snackbarHostState, scope)
                1 -> ServersTab(vm)
                2 -> LogsTab(vm)
                3 -> SettingsTab(vm)
            }
        }
    }

    // TOFU：服务器公钥首次确认框（任意页签都可弹出）
    TofuDialog(vm)
}

// ---------------- TOFU 公钥确认框 ----------------

@Composable
private fun TofuDialog(vm: LinkMeshViewModel) {
    val req = vm.tofu.value ?: return
    AlertDialog(
        onDismissRequest = { if (!vm.tofuBusy.value) vm.rejectTofu() },
        title = { Text("首次连接确认（TOFU）") },
        text = {
            Column {
                Text("服务器 ${req.server.name}（${req.server.endpoint}）首次出示的公钥：")
                Spacer(Modifier.height(8.dp))
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(12.dp)) {
                        Text("SHA-256 指纹", style = MaterialTheme.typography.labelMedium)
                        Text(
                            req.fingerprint,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(Modifier.height(6.dp))
                        Text("公钥", style = MaterialTheme.typography.labelMedium)
                        Text(
                            req.pubkey,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "请与服务器管理员提供的指纹比对。确认一致后点“信任”，此公钥将被保存并在以后每次连接时校验。",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { vm.confirmTofu() },
                enabled = !vm.tofuBusy.value
            ) { Text("信任") }
        },
        dismissButton = {
            OutlinedButton(
                onClick = { vm.rejectTofu() },
                enabled = !vm.tofuBusy.value
            ) { Text("拒绝") }
        }
    )
}

// ---------------- 连接页 ----------------

@Composable
private fun ConnectionTab(
    vm: LinkMeshViewModel,
    onConnect: () -> Unit,
    notificationGranted: Boolean,
    snackbarHostState: SnackbarHostState,
    scope: kotlinx.coroutines.CoroutineScope,
) {
    val cfg = vm.config.value
    val connected = vm.connected.value
    val status = vm.status.value
    val peers = vm.peers.value

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(24.dp))
        // 状态指示圆
        val color = when {
            connected -> Color(0xFF2E7D32)
            else -> Color(0xFF9E9E9E)
        }
        Box(
            modifier = Modifier
                .width(120.dp)
                .height(120.dp),
            contentAlignment = Alignment.Center
        ) {
            androidx.compose.foundation.Canvas(Modifier.fillMaxSize()) {
                drawCircle(color = color, radius = size.minDimension / 2)
            }
            Icon(
                Icons.Filled.PowerSettingsNew,
                contentDescription = null,
                tint = Color.White,
                modifier = Modifier.width(48.dp).height(48.dp)
            )
        }
        Spacer(Modifier.height(16.dp))
        Text(status, style = MaterialTheme.typography.headlineSmall)

        // 对端设备列表（连接后展示每台在线设备的虚拟 IP / 传输方式 / 地址）
        if (connected && peers.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "对端设备（${peers.size}）",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    "↑ ${formatBytes(vm.txBytes.value)}  ↓ ${formatBytes(vm.rxBytes.value)}",
                    style = MaterialTheme.typography.labelSmall
                )
            }
            Spacer(Modifier.height(4.dp))
            peers.forEach { p ->
                Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(p.ip, style = MaterialTheme.typography.titleSmall)
                            if (p.endpoint.isNotEmpty()) {
                                Text(
                                    p.endpoint,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                        Text(
                            p.transport,
                            style = MaterialTheme.typography.labelMedium,
                            color = when (p.transport) {
                                "直连" -> Color(0xFF2E7D32)
                                "中继" -> Color(0xFFB26A00)
                                else -> MaterialTheme.colorScheme.outline
                            }
                        )
                    }
                }
            }
        } else if (connected) {
            Spacer(Modifier.height(8.dp))
            Text(
                "暂无对端设备",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(24.dp))

        val server = cfg.servers.firstOrNull { it.name == vm.connectedServerName } ?: cfg.primaryServer()
        if (server != null) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("服务器: ${server.name}", style = MaterialTheme.typography.titleMedium)
                    Text(server.endpoint, style = MaterialTheme.typography.bodyMedium)
                    cfg.publicKey?.let {
                        Text("本机公钥: $it", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        } else {
            Card(modifier = Modifier.fillMaxWidth()) {
                Text(
                    "尚未配置服务器，请先在“服务器”页添加。",
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
        Spacer(Modifier.height(24.dp))

        if (!connected) {
            Button(
                onClick = {
                    if (server == null) {
                        scope.launch { snackbarHostState.showSnackbar("请先添加服务器") }
                    } else {
                        vm.connect(server, onVpnRequest = onConnect)
                    }
                },
                modifier = Modifier.fillMaxWidth().height(52.dp)
            ) {
                Text("连接 VPN")
            }
        } else {
            OutlinedButton(
                onClick = { vm.disconnect() },
                modifier = Modifier.fillMaxWidth().height(52.dp)
            ) {
                Text("断开 VPN")
            }
        }
    }
}

// ---------------- 服务器页 ----------------

@Composable
private fun ServersTab(vm: LinkMeshViewModel) {
    val cfg = vm.config.value
    var showAdd by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<ServerConfig?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("服务器列表", style = MaterialTheme.typography.titleMedium)
            Button(onClick = { showAdd = true }) {
                Icon(Icons.Filled.Add, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text("添加")
            }
        }
        Spacer(Modifier.height(8.dp))
        if (cfg.servers.isEmpty()) {
            Text("暂无服务器。添加后即可连接。", style = MaterialTheme.typography.bodyMedium)
        }
        cfg.servers.forEach { s ->
            Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Row(
                    modifier = Modifier.padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(s.name, style = MaterialTheme.typography.titleSmall)
                        Text(s.endpoint, style = MaterialTheme.typography.bodySmall)
                        if (s.publicKey != null) {
                            Text("公钥已确认", style = MaterialTheme.typography.labelSmall)
                        } else {
                            Text(
                                "公钥未确认（TOFU 待完成）",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                        if (s.token.isNotBlank()) {
                            Text("房间令牌已配置", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    if (s.publicKey == null) {
                        OutlinedButton(
                            onClick = { vm.startTofu(s) },
                            enabled = !vm.tofuBusy.value
                        ) { Text("验证") }
                    }
                    IconButton(onClick = { editing = s }) {
                        Icon(Icons.Filled.Settings, contentDescription = "编辑")
                    }
                    IconButton(onClick = { vm.removeServer(s.name) }) {
                        Icon(Icons.Filled.Delete, contentDescription = "删除")
                    }
                }
            }
        }
    }

    if (showAdd) {
        ServerEditDialog(
            initial = null,
            onDismiss = { showAdd = false },
            onSave = { name, endpoint, relayEnabled, relayEndpoint, token ->
                vm.addServer(name, endpoint, relayEnabled, relayEndpoint, token)
                showAdd = false
            }
        )
    }
    editing?.let { s ->
        ServerEditDialog(
            initial = s,
            onDismiss = { editing = null },
            onSave = { name, endpoint, relayEnabled, relayEndpoint, token ->
                vm.updateServer(
                    ServerConfig(
                        name = name,
                        endpoint = endpoint,
                        relayEnabled = relayEnabled,
                        relayEndpoint = relayEndpoint,
                        publicKey = s.publicKey,
                        token = token
                    )
                )
                editing = null
            }
        )
    }
}

@Composable
private fun ServerEditDialog(
    initial: ServerConfig?,
    onDismiss: () -> Unit,
    onSave: (String, String, Boolean, String, String) -> Unit,
) {
    var name by remember { mutableStateOf(initial?.name ?: "") }
    var endpoint by remember { mutableStateOf(initial?.endpoint ?: "") }
    var relayEnabled by remember { mutableStateOf(initial?.relayEnabled ?: true) }
    var relayEndpoint by remember { mutableStateOf(initial?.relayEndpoint ?: "") }
    var token by remember { mutableStateOf(initial?.token ?: "") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (initial == null) "添加服务器" else "编辑服务器") },
        text = {
            Column {
                OutlinedTextField(
                    value = name, onValueChange = { name = it },
                    label = { Text("名称") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = endpoint, onValueChange = { endpoint = it },
                    label = { Text("地址 (ip:port)") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = token, onValueChange = { token = it },
                    label = { Text("房间令牌（可选）") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("启用中继")
                    Spacer(Modifier.width(8.dp))
                    Switch(checked = relayEnabled, onCheckedChange = { relayEnabled = it })
                }
                if (relayEnabled) {
                    OutlinedTextField(
                        value = relayEndpoint, onValueChange = { relayEndpoint = it },
                        label = { Text("中继地址（留空=服务器自身）") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                if (name.isNotBlank() && endpoint.isNotBlank()) {
                    onSave(name.trim(), endpoint.trim(), relayEnabled, relayEndpoint.trim(), token.trim())
                }
            }) { Text("保存") }
        },
        dismissButton = {
            OutlinedButton(onClick = onDismiss) { Text("取消") }
        }
    )
}

// ---------------- 日志页 ----------------

@Composable
private fun LogsTab(vm: LinkMeshViewModel) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("运行日志", style = MaterialTheme.typography.titleMedium)
            IconButton(onClick = { vm.refreshLogsForUi() }) {
                Icon(Icons.Filled.Refresh, contentDescription = "刷新")
            }
        }
        Divider()
        Spacer(Modifier.height(8.dp))
        val lines = vm.logLines.value
        if (lines.isEmpty()) {
            Text("暂无日志", style = MaterialTheme.typography.bodyMedium)
        } else {
            Text(
                lines.joinToString("\n"),
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.verticalScroll(rememberScrollState())
            )
        }
    }
}

// ---------------- 设置页 ----------------

@Composable
private fun SettingsTab(vm: LinkMeshViewModel) {
    val cfg = vm.config.value
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Text("网络设置", style = MaterialTheme.typography.titleMedium)
        var vmMode by remember { mutableStateOf(cfg.vmMode) }
        var vmIp by remember { mutableStateOf(cfg.vmIp) }
        var netmask by remember { mutableStateOf(cfg.vmNetmask) }
        var mtu by remember { mutableStateOf(cfg.vmMtu.toString()) }
        // IP 获取模式：静态 / DHCP
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("IP 获取模式", style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.width(12.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(
                    selected = vmMode == VmIpMode.STATIC,
                    onClick = { vmMode = VmIpMode.STATIC }
                )
                Text("静态")
            }
            Spacer(Modifier.width(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(
                    selected = vmMode == VmIpMode.DHCP,
                    onClick = { vmMode = VmIpMode.DHCP }
                )
                Text("DHCP")
            }
        }
        if (vmMode == VmIpMode.DHCP) {
            Spacer(Modifier.height(4.dp))
            Text(
                "DHCP 模式：虚拟 IP 由服务器从 IP 池自动分配（无需手动配置）。",
                style = MaterialTheme.typography.bodySmall
            )
        }
        Spacer(Modifier.height(8.dp))
        if (vmMode == VmIpMode.STATIC) {
            OutlinedTextField(
                value = vmIp, onValueChange = { vmIp = it },
                label = { Text("虚拟 IP") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = netmask, onValueChange = { netmask = it },
                label = { Text("子网掩码") }, singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
        }
        OutlinedTextField(
            value = mtu, onValueChange = { mtu = it },
            label = { Text("MTU") }, singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = {
            vm.saveVmSettings(
                vmIp.trim(), netmask.trim(), mtu.toIntOrNull() ?: 1280, vmMode
            )
        }) { Text("保存网络设置") }

        Spacer(Modifier.height(24.dp))
        Text("运行选项", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = cfg.selfAlias, onValueChange = { vm.setSelfAlias(it) },
            label = { Text("本机别名（同房间设备按名解析用，如 myphone）") }, singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("自动重连")
            Switch(checked = cfg.autoReconnect, onCheckedChange = { vm.setAutoReconnect(it) })
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("开机自启动")
            Switch(checked = cfg.bootEnabled, onCheckedChange = { vm.setBootEnabled(it) })
        }
        if (cfg.bootEnabled) {
            Text(
                "勾选开机后要自动连接的服务器（不勾选=连接第一个）：",
                style = MaterialTheme.typography.bodySmall
            )
            cfg.servers.forEach { s ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = s.name in cfg.bootServers,
                        onCheckedChange = { checked ->
                            val newSet = cfg.bootServers.toMutableSet()
                            if (checked) newSet.add(s.name) else newSet.remove(s.name)
                            vm.setBootServers(newSet)
                        }
                    )
                    Text(s.name)
                }
            }
        }
    }
}

/** 字节数人性化显示（B / KB / MB / GB）。 */
private fun formatBytes(b: Long): String = when {
    b >= 1L shl 30 -> "%.1f GB".format(b.toDouble() / (1L shl 30))
    b >= 1L shl 20 -> "%.1f MB".format(b.toDouble() / (1L shl 20))
    b >= 1L shl 10 -> "%.1f KB".format(b.toDouble() / (1L shl 10))
    else -> "$b B"
}
