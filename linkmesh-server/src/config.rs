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

//! 服务端配置（`./server.json`）。
//!
//! 一切运行参数都收敛在这一个 JSON 文件里，命令行操作会读写它。

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_shared::crypto::{KeyPairSerde, RawKey};
use linkmesh_shared::identity::SignKeyPairSerde;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
pub const DEFAULT_CONTROL_PORT: u16 = 12778;
pub const DEFAULT_ROUTE_TTL_SEC: u64 = 300;
pub const DEFAULT_LOG_FILE: &str = "server.log";
pub const DEFAULT_PID_FILE: &str = "server.pid";
pub const DEFAULT_MESH_FILE: &str = "mesh.json";
pub const DEFAULT_SERVER_NAME: &str = "linkmesh";

/// 别名（管理员绑定）：名称 → 虚拟 IP，供客户端按名解析（如 `computer:8080`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasEntry {
    /// 别名（小写，`[a-z0-9_-]`，最长 32）。
    pub name: String,
    /// 目标虚拟 IP。
    pub ip: String,
}

/// 房间令牌：`name` → 令牌的 SHA-256 hex（不存明文）。
///
/// `rooms` 为空 = 单房间开放（不做令牌验证），此时服务启动/日志/无令牌配置均给出警告。
/// rooms 非空时，客户端 JOIN/AUTH/REGISTER 必须携带其中一个有效令牌；
/// 令牌决定设备所属房间，不同房间互相隔离（查询/中继/NOTIFY 均限同房间）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    /// 房间名（如 "office"）。
    pub name: String,
    /// 令牌的 SHA-256 hex（hex 64 字符）。
    pub token_hash: String,
}

/// 校验并规范化一个别名（小写；`[a-z0-9_-]`；1..=32 字符）。
pub fn validate_alias(raw: &str) -> Result<String, String> {
    let name = raw.trim().to_lowercase();
    if name.is_empty() {
        return Err("别名不能为空".into());
    }
    if name.len() > 32 {
        return Err("别名最长 32 个字符".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(format!(
            "别名 {name:?} 非法：只能包含小写字母、数字、- 与 _"
        ));
    }
    Ok(name)
}

fn default_true() -> bool {
    true
}

fn default_mesh_path() -> String {
    DEFAULT_MESH_FILE.to_string()
}

fn default_server_name() -> String {
    DEFAULT_SERVER_NAME.to_string()
}

fn default_batch_window_ms() -> u64 {
    5
}

fn default_batch_max_bytes() -> usize {
    1200
}

/// JOIN/AUTH 每源 IP 每分钟默认上限。
fn default_join_rate() -> usize {
    60
}

/// 中继批量转发参数：把短时间内到达的多个小中继帧拼成一个大 UDP 载荷再发出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayBatchConfig {
    /// 是否启用批量拼接。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 聚合时间窗（毫秒）：窗口内的多个小帧会拼成一个批量载荷。
    #[serde(default = "default_batch_window_ms")]
    pub window_ms: u64,
    /// 聚合后单个 UDP 载荷的最大字节数，超过则立即触发发送。
    #[serde(default = "default_batch_max_bytes")]
    pub max_bytes: usize,
}

impl Default for RelayBatchConfig {
    fn default() -> Self {
        RelayBatchConfig {
            enabled: true,
            window_ms: default_batch_window_ms(),
            max_bytes: default_batch_max_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 中继监听端口；0 表示与信令共用同一 UDP 端口。
    #[serde(default)]
    pub port: u16,
    /// 批量拼接参数。
    #[serde(default)]
    pub batch: RelayBatchConfig,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            enabled: true,
            port: 0,
            batch: RelayBatchConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub version: u32,
    pub listen: String,
    pub control_port: u16,
    pub route_ttl_sec: u64,
    pub relay: RelayConfig,
    /// JOIN/AUTH 每源 IP 每分钟上限（防枚举与刷码）。0 = 不限速。
    /// 默认 60：允许单个 NAT IP 后的批量入网，同时保留反枚举兜底。
    #[serde(default = "default_join_rate")]
    pub join_rate_per_min_per_ip: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keypair: Option<KeyPairSerde>,
    /// 服务端 Ed25519 签名密钥（ik_s_s，ServerInfo / 会话 Rekey 签名用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<SignKeyPairSerde>,
    /// mesh.json 路径（网格根所在）。
    #[serde(default = "default_mesh_path")]
    pub mesh_path: String,
    /// 服务器显示名称（ServerInfo 用）。
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// 控制通道鉴权令牌（`--genkey` 自动生成）。空/缺失 = 不鉴权（仅本机）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_token: Option<String>,
    /// 房间令牌列表。空 = 单房间开放（启动时给出警告）。
    #[serde(default)]
    pub rooms: Vec<RoomEntry>,
    /// 管理员绑定的别名表（名称 → 虚拟 IP）。
    #[serde(default)]
    pub aliases: Vec<AliasEntry>,
    pub log_file: String,
    pub pid_file: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            version: 1,
            listen: DEFAULT_LISTEN.to_string(),
            control_port: DEFAULT_CONTROL_PORT,
            route_ttl_sec: DEFAULT_ROUTE_TTL_SEC,
            relay: RelayConfig::default(),
            join_rate_per_min_per_ip: default_join_rate(),
            keypair: None,
            signing: None,
            mesh_path: DEFAULT_MESH_FILE.to_string(),
            server_name: DEFAULT_SERVER_NAME.to_string(),
            control_token: None,
            rooms: Vec::new(),
            aliases: Vec::new(),
            log_file: DEFAULT_LOG_FILE.to_string(),
            pid_file: DEFAULT_PID_FILE.to_string(),
        }
    }
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            let cfg = ServerConfig::default();
            cfg.save(path)?;
            return Ok(cfg);
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
        let cfg: ServerConfig =
            serde_json::from_str(&text).map_err(|e| format!("解析 {} 失败: {e}", path.display()))?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| format!("序列化配置失败: {e}"))?;
        // 原子写：先写临时文件再 rename，避免写配置中途崩溃留下半截文件
        // （配置文件含私钥与 mesh 相关敏感数据，安全审计 item E）。
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("写入 {} 失败: {e}", tmp.display()))?;
        // 配置文件含私钥，收紧为仅属主可读写（P0 修复）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("原子替换 {} 失败: {e}", path.display()))?;
        Ok(())
    }

    /// 生成密钥对。若配置中已存在密钥对则报错（每台机器只允许一套密钥）。
    pub fn genkey(&mut self) -> Result<(), String> {
        if self.keypair.is_some() {
            return Err("本机已存在密钥对（server.json 已配置），不再重复生成".into());
        }
        self.keypair = Some(KeyPairSerde::generate());
        // 服务端签名密钥（Ed25519）一并生成
        self.signing = Some(SignKeyPairSerde::generate());
        // 控制通道鉴权令牌
        self.control_token = Some(crate::token::generate());
        Ok(())
    }

    pub fn public_key(&self) -> Result<RawKey, String> {
        self.keypair
            .as_ref()
            .ok_or_else(|| "尚未生成密钥对，请先执行 --genkey".to_string())
            .and_then(|k| k.public_raw())
    }

    pub fn private_key(&self) -> Result<RawKey, String> {
        self.keypair
            .as_ref()
            .ok_or_else(|| "尚未生成密钥对，请先执行 --genkey".to_string())
            .and_then(|k| k.private_raw())
    }

    /// 服务端 Ed25519 签名公钥（ServerInfo 的 server_ik_s_pub）。
    pub fn signing_public_b64(&self) -> Result<String, String> {
        self.signing
            .as_ref()
            .ok_or_else(|| "服务端尚未生成签名密钥，请先执行 --genkey".to_string())
            .map(|s| s.public_b64())
    }

    /// 服务端 Ed25519 签名私钥种子。
    pub fn signing_seed(&self) -> Result<linkmesh_shared::identity::RawSigPriv, String> {
        let bytes = B64
            .decode(
                self.signing
                    .as_ref()
                    .ok_or_else(|| "服务端尚未生成签名密钥，请先执行 --genkey".to_string())?
                    .private
                    .trim(),
            )
            .map_err(|e| format!("签名私钥 base64 解析失败: {e}"))?;
        bytes
            .try_into()
            .map_err(|_| "签名私钥长度错误，应为 32 字节".to_string())
    }

    // ---------- 房间令牌 ----------

    /// 是否启用了令牌验证（rooms 非空）。
    pub fn token_required(&self) -> bool {
        !self.rooms.is_empty()
    }

    /// 新增/更新房间。令牌以 SHA-256 存储，不落明文。
    pub fn add_room(&mut self, name: &str, token: &str) -> Result<(), String> {
        let name = validate_alias(name)?;
        if token.trim().len() < 6 {
            return Err("房间令牌至少 6 个字符".into());
        }
        let hash = Self::hash_token(token);
        if let Some(r) = self.rooms.iter_mut().find(|r| r.name == name) {
            r.token_hash = hash;
        } else {
            self.rooms.push(RoomEntry { name, token_hash: hash });
        }
        Ok(())
    }

    /// 删除房间。返回是否真的存在。
    pub fn remove_room(&mut self, name: &str) -> bool {
        let before = self.rooms.len();
        self.rooms.retain(|r| r.name != name);
        self.rooms.len() != before
    }

    /// 令牌的 SHA-256 hex。
    pub fn hash_token(token: &str) -> String {
        let mut h = Sha256::new();
        h.update(token.trim().as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 校验令牌并返回所属房间名（无效/未配置返回 None）。
    pub fn room_by_token(&self, token: &str) -> Option<String> {
        let hash = Self::hash_token(token);
        self.rooms
            .iter()
            .find(|r| r.token_hash == hash)
            .map(|r| r.name.clone())
    }

    // ---------- 别名表 ----------

    /// 新增/更新管理员别名（名称 → 虚拟 IP）。
    pub fn add_alias(&mut self, name: &str, ip: &str) -> Result<(), String> {
        let name = validate_alias(name)?;
        let ip = ip.trim();
        if ip.is_empty() || ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("别名 {name} 的目标 IP {ip:?} 非法（必须为合法 IP）"));
        }
        if let Some(a) = self.aliases.iter_mut().find(|a| a.name == name) {
            a.ip = ip.to_string();
        } else {
            self.aliases.push(AliasEntry {
                name,
                ip: ip.to_string(),
            });
        }
        Ok(())
    }

    /// 删除别名。返回是否真的存在。
    pub fn remove_alias(&mut self, name: &str) -> bool {
        let before = self.aliases.len();
        self.aliases.retain(|a| a.name != name);
        self.aliases.len() != before
    }

    /// 按名称查管理员别名（未绑定返回 None）。
    pub fn alias_ip(&self, name: &str) -> Option<String> {
        self.aliases
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.ip.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genkey_twice_errors() {
        let mut cfg = ServerConfig::default();
        assert!(cfg.keypair.is_none());
        assert!(cfg.genkey().is_ok());
        assert!(cfg.keypair.is_some());
        assert!(cfg.genkey().is_err(), "已有密钥对再次生成必须报错");
        let pub1 = cfg.public_key().unwrap();
        let pub2 = cfg.public_key().unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn legacy_config_with_authorized_field_still_loads() {
        // 旧版 server.json 可能携带已移除的 "authorized" 授权表字段。
        // serde 默认忽略未知字段，旧配置仍可正常反序列化（字段被丢弃）。
        let json = r#"{
            "version": 1,
            "listen": "0.0.0.0:8080",
            "control_port": 12778,
            "route_ttl_sec": 300,
            "relay": { "enabled": true, "port": 0, "batch": { "enabled": true, "window_ms": 5, "max_bytes": 1200 } },
            "auth_required": true,
            "authorized": [ { "public_key": "dGVzdA==", "ip": "10.13.13.50", "note": "legacy" } ],
            "mesh_path": "mesh.json",
            "server_name": "linkmesh",
            "log_file": "server.log",
            "pid_file": "server.pid"
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.mesh_path, "mesh.json");
        assert_eq!(cfg.listen, "0.0.0.0:8080");
        // 反序列化后不残留 authorized / auth_required 历史字段
        assert!(!serde_json::to_string(&cfg).unwrap().contains("authorized"));
        assert!(!serde_json::to_string(&cfg).unwrap().contains("auth_required"));
    }

    #[test]
    fn config_roundtrip() {
        let path = std::env::temp_dir().join("linkmesh_test_server_config.json");
        let _ = std::fs::remove_file(&path);
        {
            let mut cfg = ServerConfig::default();
            cfg.genkey().unwrap();
            cfg.listen = "0.0.0.0:9999".to_string();
            cfg.save(&path).unwrap();
        }
        let loaded = ServerConfig::load(&path).unwrap();
        assert_eq!(loaded.listen, "0.0.0.0:9999");
        assert!(loaded.keypair.is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn room_token_hash_roundtrip() {
        let mut cfg = ServerConfig::default();
        assert!(!cfg.token_required());
        assert!(cfg.add_room("office", "secret-token-1").is_ok());
        assert!(cfg.token_required());
        // 明文不落盘：配置中只应有 hash
        assert!(!serde_json::to_string(&cfg).unwrap().contains("secret-token-1"));
        // 有效令牌解析到房间
        assert_eq!(cfg.room_by_token("secret-token-1").as_deref(), Some("office"));
        // 错误令牌/空白令牌无效
        assert!(cfg.room_by_token("wrong").is_none());
        assert!(cfg.room_by_token("").is_none());
        // 更新同名校验（换令牌）
        cfg.add_room("office", "new-token-2").unwrap();
        assert!(cfg.room_by_token("secret-token-1").is_none());
        assert_eq!(cfg.room_by_token("new-token-2").as_deref(), Some("office"));
        // 非法名/过短令牌拒绝
        assert!(cfg.add_room("Bad Name!", "xyz123456").is_err());
        assert!(cfg.add_room("ok-room", "ab").is_err());
        // 删除
        assert!(cfg.remove_room("office"));
        assert!(!cfg.token_required());
        assert!(!cfg.remove_room("office"));
    }

    #[test]
    fn alias_table_validation() {
        let mut cfg = ServerConfig::default();
        assert!(cfg.add_alias("Computer", "10.13.13.5").is_ok());
        // 规范化小写
        assert_eq!(cfg.alias_ip("computer").as_deref(), Some("10.13.13.5"));
        // 更新
        cfg.add_alias("computer", "10.13.13.6").unwrap();
        assert_eq!(cfg.alias_ip("computer").as_deref(), Some("10.13.13.6"));
        // 非法
        assert!(cfg.add_alias("bad name", "10.13.13.5").is_err());
        assert!(cfg.add_alias("ok", "not-an-ip").is_err());
        assert!(cfg.remove_alias("computer"));
        assert!(cfg.alias_ip("computer").is_none());
    }
}
