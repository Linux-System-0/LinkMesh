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

//! 客户端配置（`./client.json`）。
//!
//! 一切运行参数都收敛在这一个 JSON 文件里，命令行操作会读写它。
//! 私钥只保存在本机此配置中，绝不发送给服务端。

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_shared::crypto::RawKey;
use linkmesh_shared::identity::{DeviceIdentitySerde, SignKeyPairSerde};
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONTROL_PORT: u16 = 12779;
pub const DEFAULT_LOG_FILE: &str = "client.log";
pub const DEFAULT_PID_FILE: &str = "client.pid";
pub const DEFAULT_NETMASK: &str = "255.255.255.0";
pub const DEFAULT_MTU: usize = 1280;
pub const DEFAULT_HEARTBEAT_SEC: u64 = 20;

fn default_true() -> bool {
    true
}
fn default_netmask() -> String {
    DEFAULT_NETMASK.to_string()
}
fn default_mtu() -> usize {
    DEFAULT_MTU
}
fn default_timeout_ms() -> u64 {
    5000
}
fn default_max_retries() -> u32 {
    3
}
fn default_interval_ms() -> u64 {
    250
}
fn default_max_errors() -> u32 {
    3
}

/// 虚拟网卡（内核态 TUN，Windows 上为内置 Wintun）。
///
/// mesh 模式下虚拟 IP 一律由服务端证书绑定（JOIN/AUTH 下发），本机配置的
/// `ip` 仅作占位，认证握手后自动以证书绑定 IP 为准（不再区分 Static/DHCP）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmNicConfig {
    pub name: String,
    /// 虚拟 IP 占位（mesh 模式下由服务端证书绑定 IP 覆盖，认证后自动更新）。
    pub ip: String,
    #[serde(default = "default_netmask")]
    pub netmask: String,
    #[serde(default = "default_mtu")]
    pub mtu: usize,
}

impl VmNicConfig {
    pub fn new(name: String, ip: String) -> Self {
        VmNicConfig {
            name,
            ip,
            netmask: default_netmask(),
            mtu: default_mtu(),
        }
    }
}

/// 中继目标。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTarget {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 中继端点；为空表示默认使用服务器自身。
    #[serde(default)]
    pub endpoint: String,
}

impl Default for RelayTarget {
    fn default() -> Self {
        RelayTarget {
            enabled: true,
            endpoint: String::new(),
        }
    }
}

/// 已配置的服务器。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub name: String,
    pub endpoint: String,
    /// 服务器公钥。首次连接时经 `--connect`（可加 -y/-n）确认信任后保存（trust on first use），
    /// 之后每次连接都会与服务器实际出示的公钥比对，不一致则拒绝连接。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default)]
    pub relay: RelayTarget,
    /// 网格根公钥（P0-2 认证）：`--join` 时 TOFU 根指纹并固定，此后凭 root 签名验证一切。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_root_pub: Option<String>,
    /// 本设备在该服务器的证书（`--join` 签发后保存）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_cert: Option<linkmesh_shared::cert::DeviceCert>,
    /// 已缓存的 CRL 版本（仅接受更新版本，防回退降级）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_version: Option<u64>,
    /// 房间令牌（服务器启用令牌验证时必填；`--connect/--join --token` 写入）。
    /// 令牌决定本设备所属房间，不同令牌（房间）的设备互相隔离。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl ServerEntry {
    pub fn new(name: String, endpoint: String) -> Self {
        ServerEntry {
            name,
            endpoint,
            public_key: None,
            relay: RelayTarget::default(),
            mesh_root_pub: None,
            device_cert: None,
            crl_version: None,
            token: None,
        }
    }

    /// 本设备是否已加入该服务器网格（有证书即已加入）。
    pub fn is_joined(&self) -> bool {
        self.device_cert.is_some()
    }
}

/// 一条连接：服务器 + 虚拟网卡。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEntry {
    pub server: String,
    pub vm_nic: String,
}

/// UDP 打洞参数。打洞失败（超时 / 错误次数超限）后降级为中继。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HolePunchConfig {
    /// 是否启用 UDP 打洞；false 表示直接走中继。
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_max_errors")]
    pub max_errors: u32,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        HolePunchConfig {
            enabled: true,
            timeout_ms: default_timeout_ms(),
            max_retries: default_max_retries(),
            interval_ms: default_interval_ms(),
            max_errors: default_max_errors(),
        }
    }
}

fn dns_enabled_default() -> bool {
    true
}
fn dns_bind_default() -> String {
    "127.0.0.1".to_string()
}
fn dns_port_default() -> u16 {
    5353
}

/// 内嵌 DNS 应答器配置：把网格内别名（如 computer）解析为虚拟 IP，
/// 使系统应用可以直接使用 `computer:8080` 这类地址访问对端。
///
/// 仅回答本网格内已知的别名（本地 aliases + 服务端别名表/设备自报别名），
/// 不向任何上游 DNS 转发（杜绝开放解析器滥用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// 是否启用内嵌 DNS 应答器。
    #[serde(default = "dns_enabled_default")]
    pub enabled: bool,
    /// 监听地址（默认 127.0.0.1，仅本机可用；可改为 0.0.0.0 供同机容器/同网段使用）。
    #[serde(default = "dns_bind_default")]
    pub bind: String,
    /// 监听 UDP 端口（默认 5353，避免与系统 53 冲突）。
    #[serde(default = "dns_port_default")]
    pub port: u16,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            enabled: dns_enabled_default(),
            bind: dns_bind_default(),
            port: dns_port_default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub version: u32,
    /// 设备身份（P0-2 强制）：ik_x（X25519）+ ik_s（Ed25519）双长期密钥。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<DeviceIdentitySerde>,
    pub vm_nics: Vec<VmNicConfig>,
    pub servers: Vec<ServerEntry>,
    pub connections: Vec<ConnectionEntry>,
    #[serde(default)]
    pub hole_punch: HolePunchConfig,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_sec: u64,
    /// 数据面路由密钥按发送包数自动轮换（0 = 仅按时间轮换）。
    #[serde(default = "default_rekey_pkts")]
    pub rekey_every_pkts: u64,
    /// 数据面路由密钥按秒自动轮换（0 = 仅按包数轮换）。
    #[serde(default = "default_rekey_secs")]
    pub rekey_every_secs: u64,
    /// 控制通道鉴权令牌（`--genkey` 自动生成）。空/缺失 = 不鉴权（仅本机）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_token: Option<String>,
    /// 自动重连间隔（秒）：连接异常退出后按该间隔自动重连；0 = 不自动重连（与 Android 的
    /// 「断线自动重连」对齐，可在配置中关闭）。
    #[serde(default = "default_reconnect_secs")]
    pub reconnect_secs: u64,
    /// 本地别名表（名称 → 虚拟 IP，本地覆盖；与服务端别名表叠加，本地优先）。
    #[serde(default)]
    pub aliases: std::collections::BTreeMap<String, String>,
    /// 内嵌 DNS 应答器配置。
    #[serde(default)]
    pub dns: DnsConfig,
    pub control_port: u16,
    pub log_file: String,
    pub pid_file: String,
}

fn default_heartbeat() -> u64 {
    DEFAULT_HEARTBEAT_SEC
}

fn default_reconnect_secs() -> u64 {
    5
}

/// 校验并规范化一个别名（小写；`[a-z0-9_-]`；1..=32 字符）。与服务端规则一致。
pub fn normalize_alias(raw: &str) -> Result<String, String> {
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
        return Err(format!("别名 {name:?} 非法：只能包含小写字母、数字、- 与 _"));
    }
    Ok(name)
}

fn default_rekey_pkts() -> u64 {
    65536
}

fn default_rekey_secs() -> u64 {
    300
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            version: 1,
            identity: None,
            vm_nics: Vec::new(),
            servers: Vec::new(),
            connections: Vec::new(),
            hole_punch: HolePunchConfig::default(),
            heartbeat_sec: DEFAULT_HEARTBEAT_SEC,
            rekey_every_pkts: default_rekey_pkts(),
            rekey_every_secs: default_rekey_secs(),
            control_token: None,
            reconnect_secs: default_reconnect_secs(),
            aliases: std::collections::BTreeMap::new(),
            dns: DnsConfig::default(),
            control_port: DEFAULT_CONTROL_PORT,
            log_file: DEFAULT_LOG_FILE.to_string(),
            pid_file: DEFAULT_PID_FILE.to_string(),
        }
    }
}

/// 生成控制通道鉴权令牌（32 字节随机，base64）。
fn client_token() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    B64.encode(buf)
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            let cfg = ClientConfig::default();
            cfg.save(path)?;
            return Ok(cfg);
        }
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
        let cfg: ClientConfig =
            serde_json::from_str(&text).map_err(|e| format!("解析 {} 失败: {e}", path.display()))?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| format!("序列化配置失败: {e}"))?;
        // 原子写：先写临时文件再 rename，避免进程崩溃/断电在写配置中途留下半截文件
        // （配置文件含私钥，损坏即丢失设备身份，安全审计 item E）。
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

    /// 生成设备身份（双长期密钥 ik_x + ik_s）。若已存在则报错（每台设备只允许一套身份）。
    pub fn genkey(&mut self) -> Result<(), String> {
        if self.identity.is_some() {
            return Err("本机已存在设备身份（client.json 已配置），不再重复生成".into());
        }
        let identity = DeviceIdentitySerde::generate();
        self.identity = Some(identity);
        // 控制通道鉴权令牌
        self.control_token = Some(client_token());
        Ok(())
    }

    /// 设备 X25519 公钥（ik_x）。
    pub fn public_key(&self) -> Result<RawKey, String> {
        match &self.identity {
            Some(id) => id.ik_x_public_raw(),
            None => Err("尚未生成设备身份（identity），请先执行 --genkey".into()),
        }
    }

    /// 设备 X25519 私钥。
    pub fn private_key(&self) -> Result<RawKey, String> {
        match &self.identity {
            Some(id) => id.ik_x.private_raw(),
            None => Err("尚未生成设备身份（identity），请先执行 --genkey".into()),
        }
    }

    /// 设备 Ed25519 签名密钥对（`identity.ik_s`）。
    pub fn signing_keypair(&self) -> Option<&SignKeyPairSerde> {
        self.identity.as_ref().map(|id| &id.ik_s)
    }

    /// 设备签名公钥（base64）。
    pub fn signing_public_b64(&self) -> Option<String> {
        self.identity.as_ref().map(|id| id.ik_s.public_b64())
    }

    /// 设备 ID（由 ik_x + ik_s 推导）。
    pub fn device_id(&self) -> Result<String, String> {
        match &self.identity {
            Some(id) => id.device_id(),
            None => Err("尚未生成设备身份（identity），请先执行 --genkey".into()),
        }
    }

    /// 设备指纹（base32，加入网格 / 验对端 / 吊销时人工比对）。
    pub fn fingerprint(&self) -> Result<String, String> {
        match &self.identity {
            Some(id) => Ok(linkmesh_shared::identity::fingerprint(
                &id.ik_x_public_raw()?,
                &id.ik_s_public_raw()?,
            )),
            None => Err("尚未生成设备身份（identity），请先执行 --genkey".into()),
        }
    }

    pub fn find_server(&self, name: &str) -> Option<&ServerEntry> {
        self.servers.iter().find(|s| s.name == name)
    }

    pub fn find_server_mut(&mut self, name: &str) -> Option<&mut ServerEntry> {
        self.servers.iter_mut().find(|s| s.name == name)
    }

    pub fn find_vmnic(&self, name: &str) -> Option<&VmNicConfig> {
        self.vm_nics.iter().find(|n| n.name == name)
    }

    pub fn find_connection(&self, server: &str) -> Option<&ConnectionEntry> {
        self.connections.iter().find(|c| c.server == server)
    }

    /// 配置结构校验（连接/守护进程启动前调用，返回首个错误）。
    /// 条件判定：虚拟 IP 非空时必须合法（mesh 模式为空占位也可，认证后以服务端为准）；
    /// 连接引用必须存在；打洞参数必须 > 0；公钥格式必须合法。
    pub fn validate(&self) -> Result<(), String> {
        let mut names = std::collections::HashSet::new();
        for n in &self.vm_nics {
            if n.name.is_empty() {
                return Err("虚拟网卡名称不能为空".into());
            }
            if !names.insert(n.name.clone()) {
                return Err(format!("虚拟网卡名称重复: {}", n.name));
            }
            if !(68..=65535).contains(&n.mtu) {
                return Err(format!("网卡 {} 的 MTU 越界: {}", n.name, n.mtu));
            }
            if !n.ip.is_empty() && n.ip.parse::<std::net::IpAddr>().is_err() {
                return Err(format!(
                    "网卡 {} 的 IP {:?} 非法（非空时必须为合法 IP）",
                    n.name, n.ip
                ));
            }
        }
        for s in &self.servers {
            if s.name.is_empty() {
                return Err("服务器名称不能为空".into());
            }
            if s.endpoint.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!("服务器 {} 的地址 {:?} 非法", s.name, s.endpoint));
            }
            if let Some(pk) = &s.public_key {
                if linkmesh_shared::crypto::parse_public_key(pk).is_err() {
                    return Err(format!("服务器 {} 的公钥格式非法", s.name));
                }
            }
        }
        for (name, ip) in &self.aliases {
            if normalize_alias(name).is_err() {
                return Err(format!(
                    "别名 {name:?} 非法：只能包含小写字母、数字、- 与 _（最长 32 字符）"
                ));
            }
            if ip.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("别名 {name} 的目标 IP {ip:?} 非法"));
            }
        }
        if self.dns.port == 0 {
            return Err("dns.port 必须为 1-65535（0 表示未启用应设 dns.enabled=false）".into());
        }
        for c in &self.connections {
            if self.find_server(&c.server).is_none() {
                return Err(format!("连接引用了不存在的服务器 {}", c.server));
            }
            if self.find_vmnic(&c.vm_nic).is_none() {
                return Err(format!("连接引用了不存在的虚拟网卡 {}", c.vm_nic));
            }
        }
        if self.hole_punch.timeout_ms == 0 {
            return Err("hole_punch.timeout_ms 必须大于 0".into());
        }
        if self.hole_punch.interval_ms == 0 {
            return Err("hole_punch.interval_ms 必须大于 0".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genkey_twice_errors() {
        let mut cfg = ClientConfig::default();
        assert!(cfg.identity.is_none());
        assert!(cfg.genkey().is_ok());
        assert!(cfg.identity.is_some());
        assert!(cfg.genkey().is_err(), "已有身份再次生成必须报错");
    }

    #[test]
    fn default_values() {
        let cfg = ClientConfig::default();
        assert_eq!(cfg.control_port, DEFAULT_CONTROL_PORT);
        assert!(cfg.hole_punch.timeout_ms > 0);
        assert!(cfg.vm_nics.is_empty());
        assert!(cfg.servers.is_empty());
        assert!(cfg.connections.is_empty());
    }

    #[test]
    fn add_and_find() {
        let mut cfg = ClientConfig::default();
        cfg.vm_nics.push(VmNicConfig::new("linkmesh0".into(), "10.13.13.1".into()));
        cfg.servers.push(ServerEntry::new("s".into(), "1.2.3.4:8080".into()));
        cfg.connections.push(ConnectionEntry { server: "s".into(), vm_nic: "linkmesh0".into() });
        assert!(cfg.find_vmnic("linkmesh0").is_some());
        assert!(cfg.find_vmnic("nope").is_none());
        assert!(cfg.find_server("s").is_some());
        assert!(cfg.find_connection("s").is_some());
    }

    #[test]
    fn validate_rejects_bad_ip() {
        let mut cfg = ClientConfig::default();
        let nic = VmNicConfig::new("linkmesh0".into(), "not-an-ip".into());
        cfg.vm_nics.push(nic);
        cfg.servers.push(ServerEntry::new("s".into(), "1.2.3.4:8080".into()));
        assert!(cfg.validate().is_err(), "非法 IP 必须报错");
    }

    #[test]
    fn validate_accepts_empty_ip_placeholder() {
        let mut cfg = ClientConfig::default();
        let nic = VmNicConfig::new("linkmesh0".into(), String::new());
        cfg.vm_nics.push(nic);
        cfg.servers.push(ServerEntry::new("s".into(), "1.2.3.4:8080".into()));
        assert!(cfg.validate().is_ok(), "空 IP 占位应合法（mesh 认证后由服务端下发）");
    }

    #[test]
    fn validate_rejects_duplicate_names_and_dangling_refs() {
        let mut cfg = ClientConfig::default();
        cfg.vm_nics.push(VmNicConfig::new("a".into(), "10.13.13.2".into()));
        cfg.vm_nics.push(VmNicConfig::new("a".into(), "10.13.13.3".into()));
        assert!(cfg.validate().is_err(), "重复网卡名必须报错");

        let mut cfg2 = ClientConfig::default();
        cfg2.vm_nics.push(VmNicConfig::new("a".into(), "10.13.13.2".into()));
        cfg2.servers.push(ServerEntry::new("s".into(), "1.2.3.4:8080".into()));
        cfg2.connections.push(ConnectionEntry { server: "ghost".into(), vm_nic: "a".into() });
        assert!(cfg2.validate().is_err(), "悬空连接引用必须报错");
    }

    #[test]
    fn new_fields_defaults_and_roundtrip() {
        let cfg = ClientConfig::default();
        // 自动重连默认开启（5 秒），可配置 0 关闭
        assert_eq!(cfg.reconnect_secs, 5);
        assert!(cfg.aliases.is_empty());
        assert!(cfg.dns.enabled);
        assert_eq!(cfg.dns.port, 5353);
        // 旧配置缺字段也能解析（serde default）
        let old = r#"{"version":1,"vm_nics":[],"servers":[],"connections":[],"control_port":0,"log_file":"","pid_file":""}"#;
        let parsed: ClientConfig = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.reconnect_secs, 5);
        assert_eq!(parsed.dns.port, 5353);
        // 新字段往返
        let mut cfg2 = ClientConfig::default();
        cfg2.reconnect_secs = 0;
        cfg2.aliases.insert("computer".to_string(), "10.13.13.5".to_string());
        cfg2.servers.push(ServerEntry::new("s".into(), "1.2.3.4:8080".into()));
        cfg2.servers[0].token = Some("tok-1".into());
        let text = serde_json::to_string(&cfg2).unwrap();
        let back: ClientConfig = serde_json::from_str(&text).unwrap();
        assert_eq!(back.reconnect_secs, 0);
        assert_eq!(back.aliases.get("computer").map(String::as_str), Some("10.13.13.5"));
        assert_eq!(back.servers[0].token.as_deref(), Some("tok-1"));
    }

    #[test]
    fn alias_normalization() {
        assert_eq!(normalize_alias("Computer").unwrap(), "computer");
        assert_eq!(normalize_alias("my-nas_2").unwrap(), "my-nas_2");
        assert!(normalize_alias("bad name").is_err());
        assert!(normalize_alias("").is_err());
        assert!(normalize_alias(&"x".repeat(40)).is_err());
    }
}
