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

package com.linkmesh.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.linkmesh.client.data.ConfigRepository
import com.linkmesh.client.vpn.LinkMeshVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * 开机自启（仅在用户开启"开机自启动"总开关后才工作）。
 *
 * 行为：
 * - 总开关关闭 → 不自动连接（默认）；
 * - 总开关开启：
 *   - 勾选了服务器 → 只连接勾选列表中的第一个；
 *   - 未勾选 → 连接第一个配置的服务器。
 */
class BootReceiver : BroadcastReceiver() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        scope.launch {
            val repo = ConfigRepository(context)
            val cfg = repo.config.first()
            if (!cfg.bootEnabled) return@launch
            if (cfg.privateKey == null || cfg.servers.isEmpty()) return@launch
            val target = if (cfg.bootServers.isNotEmpty()) {
                cfg.servers.firstOrNull { it.name in cfg.bootServers } ?: return@launch
            } else {
                cfg.servers.first()
            }
            LinkMeshVpnService.start(context, target.name)
        }
    }
}
