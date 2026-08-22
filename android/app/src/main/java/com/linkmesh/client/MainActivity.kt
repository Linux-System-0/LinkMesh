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

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import com.linkmesh.client.core.NativeBridge
import com.linkmesh.client.ui.LinkMeshRoot
import com.linkmesh.client.vpn.LinkMeshVpnService

class MainActivity : ComponentActivity() {

    /** VPN 授权结果（用户勾选"我信任此应用"后回调）。 */
    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                LinkMeshVpnService.start(this)
            }
        }

    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> notificationGranted = granted }

    /** 通知权限状态（延迟到 onCreate 初始化，避免 context 未 attach）。 */
    private var notificationGranted by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        notificationGranted =
            Build.VERSION.SDK_INT < 33 ||
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        requestNotificationPermissionIfNeeded()
        // JNI 探针（仅 debug）：验证 Rust 核心可被调用（生成密钥对，不保存）
        if (BuildConfig.DEBUG) {
            try {
                val kp = NativeBridge.genKeypair()
                android.util.Log.i(
                    "LinkMeshJni", "JNI OK: pub=${kp.optString("public")}"
                )
            } catch (e: Throwable) {
                android.util.Log.e("LinkMeshJni", "JNI FAIL: ${e.message}", e)
            }
        }
        setContent {
            LinkMeshRoot(
                onConnect = { requestVpnAndConnect() },
                notificationGranted = notificationGranted
            )
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun requestVpnAndConnect() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermission.launch(intent)
        } else {
            LinkMeshVpnService.start(this)
        }
    }
}
