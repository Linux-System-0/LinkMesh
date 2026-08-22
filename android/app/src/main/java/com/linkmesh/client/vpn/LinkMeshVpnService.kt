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

package com.linkmesh.client.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.linkmesh.client.MainActivity
import com.linkmesh.client.R
import com.linkmesh.client.core.NativeBridge
import com.linkmesh.client.data.ConfigRepository
import com.linkmesh.client.data.DeviceConfig
import com.linkmesh.client.data.VmIpMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * LinkMesh VPN 服务。
 *
 * 架构：
 * - VPNService 建立 tun 接口（fd）并保护 Rust 信令/UDP 流量不走隧道；
 * - 读线程：fd 读 IP 包 → [NativeBridge.inject] → Rust 加密发往对端；
 * - 写线程：Rust 输出 → [NativeBridge.drain] → 写回 fd；
 * - 常驻前台服务（通知栏）；断线自动重连。
 */
class LinkMeshVpnService : VpnService() {

    companion object {
        const val CHANNEL_ID = "linkmesh_vpn"
        const val NOTIFICATION_ID = 1
        const val ACTION_STOP = "com.linkmesh.client.STOP"
        const val EXTRA_SERVER = "extra_server"

        @Volatile
        var running = false
            private set

        @Volatile
        var currentStatus: String = "未连接"
            private set

        /** 启动 VPN。@param serverName 指定连接某个服务器；null = 连接第一个配置的服务器。 */
        fun start(context: Context, serverName: String? = null) {
            val i = Intent(context, LinkMeshVpnService::class.java)
            if (serverName != null) i.putExtra(EXTRA_SERVER, serverName)
            context.startForegroundService(i)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, LinkMeshVpnService::class.java))
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnThread: Job? = null
    private var reconnectJob: Job? = null
    private var tunnelFd: ParcelFileDescriptor? = null
    private var config: DeviceConfig? = null

    private lateinit var repo: ConfigRepository
    private lateinit var logFile: File
    private var lastConnectedServer: String? = null
    private var stoppedByUser = false
    private var requestedServer: String? = null

    override fun onCreate() {
        super.onCreate()
        repo = ConfigRepository(this)
        createNotificationChannel()
        // 前台服务类型：Android 14 的 FOREGROUND_SERVICE_TYPE_VPN(0x4000) 在 Android 15 (API 35)
        // SDK 中已被移除，官方推荐 VPN 应用改用 systemExempted(1024) 以满足长时运行要求。
        startForeground(NOTIFICATION_ID, buildNotification("正在启动…"), 1024)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stoppedByUser = true
            stopVpn()
            return START_NOT_STICKY
        }
        // 已在运行则复用
        if (running) return START_STICKY
        stoppedByUser = false
        requestedServer = intent?.getStringExtra(EXTRA_SERVER)

        scope.launch {
            val cfg = repo.config.first()
            if (cfg.privateKey == null || cfg.servers.isEmpty()) {
                currentStatus = "配置不完整"
                updateNotification("配置不完整：请先在应用内生成密钥并添加服务器")
                stopSelf()
                return@launch
            }
            config = cfg
            startVpn(cfg)
        }
        return START_STICKY
    }

    private fun startVpn(cfg: DeviceConfig) {
        // 支持指定服务器（开机自启只连某些）：requestedServer 优先，否则第一个
        val server = cfg.servers.firstOrNull { it.name == requestedServer }
            ?: cfg.primaryServer()
            ?: run {
                currentStatus = "没有可用服务器"
                stopSelf()
                return
            }
        val builder = Builder()
        builder.setSession("LinkMesh → ${server.name}")
        builder.setMtu(cfg.vmMtu)

        // 虚拟 IP：静态用配置值；DHCP 先向服务器预取分配 IP，保证 TUN 地址与网格身份一致
        var tunIp = cfg.vmIp
        if (cfg.vmMode == VmIpMode.DHCP) {
            val pk = cfg.publicKey
            if (pk != null) {
                try {
                    val allocated = NativeBridge.fetchAllocatedIp(server.endpoint, pk)
                    if (allocated.isNotBlank()) tunIp = allocated
                } catch (e: Throwable) {
                    // 捕获 Throwable：若 JNI 导出缺失（UnsatisfiedLinkError，属 Error 而非 Exception）
                    // 或服务器不可达，均回退静态 IP，避免 DHCP 模式直接闪退（安全审计 F2）。
                    appendLog("DHCP 预取分配 IP 失败（回退 ${cfg.vmIp}）: ${e.message}")
                }
            }
        }
        val (netAddr, prefix) = networkAddress(tunIp, cfg.vmNetmask)
        builder.addAddress(tunIp, prefix)
        // 仅路由虚拟子网；公网流量走系统默认网络（LinkMesh 是点对点网格，无公网出口）
        builder.addRoute(netAddr, prefix)

        // 保护本 App 自身的 UDP 信令/隧道流量：不让它们被路由进 VPN 隧道
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
        }
        // 安全收紧（审计 F4）：隧道只对本 App 可用，禁止设备上其他应用借手机身份
        // 访问网格（网格按设备级认证，不区分 socket 来源；暴露虚拟子网会让恶意本地
        // App 借手机身份扫描/访问/注入对端服务）。
        try {
            builder.addAllowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
        }

        val fd: ParcelFileDescriptor = try {
            builder.establish() ?: run {
                currentStatus = "VPN 建立失败"
                stopSelf()
                return
            }
        } catch (e: Exception) {
            currentStatus = "VPN 建立异常: ${e.message}"
            stopSelf()
            return
        }
        tunnelFd = fd

        // 准备日志文件
        logFile = File(filesDir, "linkmesh.log")
        logFile.delete()

        // 启动 Rust 引擎
        try {
            NativeBridge.connect(cfg.toClientConfigJson(server.name), logFile.absolutePath)
        } catch (e: Exception) {
            currentStatus = "核心启动失败: ${e.message}"
            appendLog("核心启动失败: ${e.message}")
            stopVpn()
            return
        }

        running = true
        currentStatus = "连接中…"
        lastConnectedServer = server.name
        appendLog("VPN 已建立，服务器=${server.name} 地址=${server.endpoint} IP=$tunIp")
        updateNotification("连接中：${server.name}")

        // 数据泵：注入读 + 排空写 双协程。
        // 条件判定（修复回包饿死）：排空循环独立于注入读——若只在「读到新包」后顺带排空，
        // 对端回包到达时注入读正阻塞在 fd 上，回包会一直积压在 Rust 输出通道而无法写回 fd
        // （表现为 tun0 只发不收、ping 全丢）。排空循环独立轮询即可保证双向畅通。
        vpnThread = scope.launch {
            val input = FileInputStream(fd.fileDescriptor)
            val output = FileOutputStream(fd.fileDescriptor)
            val buf = ByteArray(32768)
            var unexpected = false
            val injectJob = launch {
                try {
                    while (isActive) {
                        val n = input.read(buf)
                        if (n > 0) {
                            val pkt = buf.copyOf(n)
                            NativeBridge.inject(pkt)
                        } else if (n < 0) {
                            break
                        }
                    }
                } catch (_: Exception) {
                    unexpected = true
                }
            }
            val drainJob = launch {
                try {
                    while (isActive) {
                        val out = NativeBridge.drain()
                        if (out != null) {
                            output.write(out)
                        } else {
                            delay(5)
                        }
                    }
                } catch (_: Exception) {
                    unexpected = true
                }
            }
            // 注入侧退出（fd 关闭/异常）即整体收尾
            injectJob.join()
            drainJob.cancel()
            appendLog("VPN 数据通道关闭")
            running = false
            currentStatus = "已断开"
            updateNotification("已断开")
            // 意外断开（fd 失效/异常）且非用户主动停止 → 触发自动重连（仅当用户开启自动重连）
            if (unexpected && !stoppedByUser && config?.autoReconnect == true) {
                reconnectJob?.cancel()
                reconnectJob = scope.launch {
                    delay(2000)
                    if (!stoppedByUser && !running) {
                        appendLog("检测到断开，尝试自动重连…")
                        currentStatus = "重连中…"
                        updateNotification("重连中…")
                        stopVpnInternal()
                        delay(1500)
                        if (!stoppedByUser) config?.let { startVpn(it) }
                    }
                }
            }
        }

        // 连接状态监视（仅更新通知与日志）
        reconnectJob = scope.launch {
            while (isActive && running) {
                delay(3000)
                if (running) refreshStatus()
            }
        }
    }

    private fun refreshStatus() {
        try {
            val st = NativeBridge.status()
            val status = st.optString("status", "未知")
            val error = st.optString("error", "").takeIf { it.isNotEmpty() && it != "null" } ?: ""
            val peers = st.optJSONArray("peers")
            val peerInfo = if (peers != null && peers.length() > 0) {
                buildString {
                    for (i in 0 until peers.length()) {
                        val p = peers.getJSONObject(i)
                        append(p.optString("ip", "?")).append(" [")
                            .append(p.optString("transport", "?")).append("] ")
                    }
                }.trim()
            } else ""
            currentStatus = status
            val server = lastConnectedServer ?: ""
            val text = buildString {
                append("服务器：").append(server)
                if (peerInfo.isNotEmpty()) append("\n对端：").append(peerInfo)
                if (error.isNotEmpty()) append("\n错误：").append(error)
            }
            updateNotification(text.ifEmpty { status })
            appendLog(
                "状态: $status 收/发: ${st.optLong("rx_bytes")}/${st.optLong("tx_bytes")} " +
                    if (peerInfo.isNotEmpty()) "对端[$peerInfo]" else ""
            )
        } catch (_: Exception) {
        }
    }

    private fun stopVpn() {
        running = false
        stopVpnInternal()
        stopSelf()
    }

    private fun stopVpnInternal() {
        reconnectJob?.cancel()
        vpnThread?.cancel()
        try {
            NativeBridge.disconnect()
        } catch (_: Exception) {
        }
        tunnelFd?.close()
        tunnelFd = null
        currentStatus = "已断开"
    }

    override fun onDestroy() {
        stopVpnInternal()
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpnInternal()
        stopSelf()
    }

    // ---------- 通知 ----------

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID, "LinkMesh VPN", NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "VPN 连接状态"
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, LinkMeshVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("LinkMesh")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .addAction(0, "断开", stopIntent)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    // ---------- 日志 ----------

    private fun appendLog(line: String) {
        try {
            logFile?.appendText("${System.currentTimeMillis() / 1000} $line\n")
        } catch (_: Exception) {
        }
    }

    /** 由 IP + 点分十进制掩码计算网络地址与前缀长度（如 10.13.13.5/255.255.255.0 → 10.13.13.0, 24）。 */
    private fun networkAddress(ip: String, netmask: String): Pair<String, Int> {
        val ipB = ip.split('.').map { it.toInt().and(0xFF) }
        val mB = netmask.split('.').map { it.toInt().and(0xFF) }
        val netB = ipB.zip(mB) { a, m -> a and m }
        val prefix = mB.sumOf { Integer.bitCount(it) }
        return netB.joinToString(".") to prefix
    }
}
