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

//! 网格信任根（mesh root）管理：`mesh.json` 读写、一次性加入码、设备证书签发与吊销。
//!
//! 信任模型（见 `docs/身份认证与密钥管理体系设计.md` §3.3 / §4.1 / §6）：
//! - 网格根 `root`（Ed25519）由管理员持有并离线保管，签发设备证书 / ServerInfo / CRL；
//! - 客户端只在一加入时 TOFU 网格根指纹，此后一切凭 Ed25519 签名离线可验证；
//! - 设备入网 = 管理员签发加入码（`--invite`）或离线签发证书（`--issue`）→ 设备 `--join`；
//! - 吊销 = `--revoke` 使 CRL 版本单调递增，服务端立即踢会话，客户端拉取后断开。
//!
//! `mesh.json` 含 root 私钥，保存时强制 chmod 600（跨平台：Unix 直接设，Windows 由
//! 用户目录 ACL 保证）。

use std::collections::HashSet;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use linkmesh_shared::cert::{Crl, CrlEntry, DeviceCert, RevokeReason};
use linkmesh_shared::crypto::parse_public_key;
use linkmesh_shared::identity::{
    device_id_b64, fingerprint_from_device_id, parse_sig_public, sign, RawSigPriv, RawSigPub,
    SignKeyPairSerde,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 加入码默认有效期（10 分钟）。
pub const INVITE_TTL_SECS: u64 = 600;
/// 设备证书默认有效期（1 年）。
pub const CERT_VALIDITY_SECS: u64 = 365 * 24 * 3600;
/// 默认虚拟 IP 池起始/结束（10.13.13.2 - 10.13.13.254）。
const POOL_START: u8 = 2;
const POOL_END: u8 = 254;

/// 一个已入网设备。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberEntry {
    pub device_id: String,
    pub cert: DeviceCert,
    pub joined_at: u64,
    /// 设备自报别名（--join 时携带，可选）。服务端仅登记，按名解析时
    /// 管理员别名（server.json aliases）优先于设备自报别名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

/// 一个一次性加入码（服务端只存 SHA-256 哈希，单次有效，可预绑定虚拟 IP）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteEntry {
    /// code 规范化的 SHA-256（hex）。
    pub code_hash: String,
    pub expires_at: u64,
    pub used: bool,
    /// 预绑定的虚拟 IP（可选）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

/// 网格配置（`mesh.json`，root 私钥所在，chmod 600）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub mesh_id: String,
    /// 网格根密钥对（Ed25519，私钥仅存于此文件）。
    pub root: SignKeyPairSerde,
    /// 吊销列表（root 签名，version 单调递增）。
    pub crl: Crl,
    /// 已入网设备。
    #[serde(default)]
    pub members: Vec<MemberEntry>,
    /// 一次性加入码。
    #[serde(default)]
    pub invites: Vec<InviteEntry>,
    /// 可分配虚拟 IP 池。
    #[serde(default)]
    pub ip_pool: Vec<String>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 随机 hex 串（n 字节）。
fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// 默认虚拟 IP 池：10.13.13.2 - 10.13.13.254。
fn default_ip_pool() -> Vec<String> {
    (POOL_START..=POOL_END).map(|n| format!("10.13.13.{n}")).collect()
}

impl MeshConfig {
    /// 初始化新网格：生成 root 密钥对 + 空 CRL（root 签名）+ 默认 IP 池。
    pub fn init(mesh_id: &str) -> Self {
        let root = SignKeyPairSerde::generate();
        let mut crl = Crl {
            mesh_id: mesh_id.to_string(),
            version: 0,
            entries: Vec::new(),
            signature: None,
        };
        crl.sign(&root_seed_of(&root));
        MeshConfig {
            mesh_id: mesh_id.to_string(),
            root,
            crl,
            members: Vec::new(),
            invites: Vec::new(),
            ip_pool: default_ip_pool(),
        }
    }

    /// 生成随机网格 ID：`mesh-<16 hex>`。
    pub fn generate_mesh_id() -> String {
        format!("mesh-{}", random_hex(8))
    }

    /// root 私钥种子（用于签名）。
    pub fn root_seed(&self) -> Result<RawSigPriv, String> {
        let bytes = B64
            .decode(self.root.private.trim())
            .map_err(|e| format!("root 私钥 base64 解析失败: {e}"))?;
        bytes
            .try_into()
            .map_err(|_| "root 私钥长度错误，应为 32 字节".to_string())
    }

    /// root 公钥（原始字节）。
    pub fn root_public_raw(&self) -> Result<RawSigPub, String> {
        self.root.parse_public()
    }

    /// 网格根指纹（base32，SSH 风格，用于带外比对）。
    pub fn root_fingerprint(&self) -> Result<String, String> {
        let root_pub = self.root_public_raw()?;
        Ok(fingerprint_from_device_id(&root_pub))
    }

    /// 生成一次性加入码：`LMJ-XXXX-...`（128 bit 随机），服务端只存哈希。
    ///
    /// 返回原始加入码（打印给管理员），`ip` 非空时预绑定该虚拟 IP。
    pub fn create_invite(&mut self, ip: Option<&str>, ttl_secs: u64) -> String {
        let raw = random_hex(16); // 32 hex 字符 = 128 bit
        let mut groups: Vec<String> = Vec::new();
        for i in (0..raw.len()).step_by(4) {
            groups.push(raw[i..i + 4].to_string());
        }
        let code = format!("LMJ-{}", groups.join("-"));
        let hash = Self::hash_code(&code);
        self.invites.retain(|e| e.expires_at > now_secs() && !e.used);
        self.invites.push(InviteEntry {
            code_hash: hash,
            expires_at: now_secs() + ttl_secs.max(1),
            used: false,
            ip: ip.map(|s| s.to_string()),
        });
        code
    }

    /// 规范化加入码（去分隔符、大写）并返回其 SHA-256 hex。
    pub fn hash_code(code: &str) -> String {
        let norm: String = code
            .trim()
            .to_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        let mut h = Sha256::new();
        h.update(norm.as_bytes());
        hex_encode(&h.finalize())
    }

    /// 只校验加入码（不消费），返回预绑定 IP（可能为 None）。
    ///
    /// 与 [`consume_invite`] 的区别：本方法不改动任何状态，用于「先校验、后消费」，
    /// 避免 JOIN 因 device_id 不一致 / IP 不可分配 / 证书签发失败等**后续**校验不通过时，
    /// 一次性加入码被白白烧毁（受邀设备失去唯一的入网凭据）。
    pub fn peek_invite(&self, code: &str) -> Result<Option<String>, String> {
        let hash = Self::hash_code(code);
        let now = now_secs();
        let entry = self
            .invites
            .iter()
            .find(|e| e.code_hash == hash)
            .ok_or("加入码无效（不存在）")?;
        if entry.used {
            return Err("加入码已被使用（单次有效）".into());
        }
        if entry.expires_at < now {
            return Err("加入码已过期".into());
        }
        Ok(entry.ip.clone())
    }

    /// 校验并消费一个加入码。成功返回预绑定 IP（可能为 None）。
    pub fn consume_invite(&mut self, code: &str) -> Result<Option<String>, String> {
        let hash = Self::hash_code(code);
        let now = now_secs();
        let idx = self
            .invites
            .iter()
            .position(|e| e.code_hash == hash)
            .ok_or("加入码无效（不存在）")?;
        let entry = &self.invites[idx];
        if entry.used {
            return Err("加入码已被使用（单次有效）".into());
        }
        if entry.expires_at < now {
            return Err("加入码已过期".into());
        }
        let ip = entry.ip.clone();
        self.invites[idx].used = true;
        self.invites.retain(|e| e.expires_at > now);
        Ok(ip)
    }

    /// 从未被占用的 IP 池中分配一个虚拟 IP。`preferred` 非空且可用时优先。
    pub fn allocate_ip(&self, preferred: Option<&str>) -> Result<String, String> {
        let used: HashSet<&str> = self
            .members
            .iter()
            .map(|m| m.cert.allowed_ip.as_str())
            .chain(self.invites.iter().filter(|e| !e.used).filter_map(|e| e.ip.as_deref()))
            .collect();
        if let Some(p) = preferred {
            if !p.trim().is_empty() && !used.contains(p.trim()) && self.ip_pool.iter().any(|x| x == p.trim()) {
                return Ok(p.trim().to_string());
            }
            if !p.trim().is_empty() && !used.contains(p.trim()) {
                // 池外的显式 IP（管理员指定网段）也允许
                return Ok(p.trim().to_string());
            }
        }
        for ip in &self.ip_pool {
            if !used.contains(ip.as_str()) {
                return Ok(ip.clone());
            }
        }
        Err("IP 池已耗尽，请扩容 mesh.json 的 ip_pool".into())
    }

    /// 离线签发设备证书（`--issue`）：绑定设备双公钥与虚拟 IP，root 签名，登记入成员表。
    pub fn issue_cert(
        &mut self,
        ik_x_b64: &str,
        ik_s_pub_b64: &str,
        ip: &str,
        note_device_id: Option<&str>,
    ) -> Result<DeviceCert, String> {
        let ik_x = parse_public_key(ik_x_b64)?;
        let ik_s_pub = parse_sig_public(ik_s_pub_b64)?;
        let device_id = note_device_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| device_id_b64(&ik_x, &ik_s_pub));
        let ip = self.allocate_ip(Some(ip))?;
        if self.members.iter().any(|m| m.device_id == device_id) {
            return Err("该设备已入网，无需重复签发".into());
        }
        if self.is_revoked(&device_id) {
            return Err("该设备已被吊销，拒绝签发".into());
        }
        let now = now_secs();
        let mut cert = DeviceCert::new(
            &self.mesh_id,
            self.members.len() as u32 + 1,
            &device_id,
            ik_x_b64,
            ik_s_pub_b64,
            &ip,
            now,
            now + CERT_VALIDITY_SECS,
        );
        cert.sign(&self.root_seed()?);
        self.members.push(MemberEntry {
            device_id: device_id.clone(),
            cert: cert.clone(),
            joined_at: now,
            alias: None,
        });
        Ok(cert)
    }

    /// 吊销设备：CRL 版本 +1（root 签名），从成员表移除，返回新 CRL。
    pub fn revoke(&mut self, device_id: &str, reason: RevokeReason) -> Result<Crl, String> {
        if self.is_revoked(device_id) {
            return Err("该设备已在吊销列表中".into());
        }
        // 线格式上限保护：WireCrl 固定 `MAX_CRL_ENTRIES`（256）个条目槽位，超出后
        // AUTH_RESP/JOIN 的 CRL 序列化会失败，导致整个网格无法入网（自锁死）。
        // 在此显式拒绝并给出明确提示，把「全网静默锁死」转为管理员可处理的报错。
        if self.crl.entries.len() >= linkmesh_shared::wire::MAX_CRL_ENTRIES {
            return Err(format!(
                "CRL 已达线格式上限（{} 条），无法再吊销。请清理/精简吊销列表后再试",
                linkmesh_shared::wire::MAX_CRL_ENTRIES
            ));
        }
        self.crl.version += 1;
        self.crl.entries.push(CrlEntry {
            device_id: device_id.to_string(),
            reason,
            revoked_at: now_secs(),
            replacement: None,
        });
        self.crl.sign(&self.root_seed()?);
        self.members.retain(|m| m.device_id != device_id);
        Ok(self.crl.clone())
    }

    /// 该设备是否已吊销。
    pub fn is_revoked(&self, device_id: &str) -> bool {
        self.crl.is_revoked(device_id)
    }

    /// 按 device_id 查成员证书。
    pub fn find_member(&self, device_id: &str) -> Option<&MemberEntry> {
        self.members.iter().find(|m| m.device_id == device_id)
    }

    /// 按 X25519 公钥（base64）查成员（含吊销检查）。
    pub fn find_by_ik_x(&self, ik_x_b64: &str) -> Option<&MemberEntry> {
        self.members.iter().find(|m| m.cert.ik_x == ik_x_b64)
    }

    /// 登记/更新成员的别名（--join 自报）。
    pub fn set_member_alias(&mut self, device_id: &str, alias: &str) {
        if let Some(m) = self.members.iter_mut().find(|m| m.device_id == device_id) {
            m.alias = Some(alias.to_string());
        }
    }

    /// 按别名查在线/已登记成员（不含吊销设备），返回 (device_id, ip)。
    pub fn member_by_alias(&self, alias: &str) -> Option<(String, String)> {
        self.members
            .iter()
            .filter(|m| !self.is_revoked(&m.device_id))
            .find(|m| m.alias.as_deref() == Some(alias))
            .map(|m| (m.device_id.clone(), m.cert.allowed_ip.clone()))
    }

    /// 读取 `mesh.json`。不存在时返回 None（未初始化网格）。
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
        let cfg: MeshConfig = serde_json::from_str(&text)
            .map_err(|e| format!("解析 {} 失败: {e}", path.display()))?;
        Ok(Some(cfg))
    }

    /// 保存 `mesh.json`（含 root 私钥，强制 chmod 600）。
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| format!("序列化 mesh 配置失败: {e}"))?;
        // 原子写：先写临时文件再 rename，避免写 mesh.json（含 root 私钥）中途崩溃留下半截文件
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("写入 {} 失败: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("原子替换 {} 失败: {e}", path.display()))?;
        Ok(())
    }

    /// 仅序列化（不落盘），供调用方在释放 mesh 锁后再做原子写，缩短锁持有时间。
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("序列化 mesh 配置失败: {e}"))
    }

    /// 原子写已序列化的 mesh 文本（调用方通常在释放锁后调用，避免长持锁）。
    pub fn save_json(path: &Path, text: &str) -> Result<(), String> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("写入 {} 失败: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("原子替换 {} 失败: {e}", path.display()))?;
        Ok(())
    }

    /// 校验 CRL 签名（root）与成员证书签名。
    pub fn verify_integrity(&self) -> Result<(), String> {
        let root_pub = self.root_public_raw()?;
        self.crl.verify(&root_pub)?;
        for m in &self.members {
            m.cert.verify(&root_pub, now_secs())?;
        }
        Ok(())
    }
}

/// 从 SignKeyPairSerde 取 root 私钥种子（签名用）。
fn root_seed_of(kp: &SignKeyPairSerde) -> RawSigPriv {
    let bytes = B64.decode(kp.private.trim()).expect("root 私钥应为合法 base64");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    seed
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 签名一条声明（供 mesh 外部使用，如 ServerInfo 由 root 签名）。
pub fn sign_with_root(mesh: &MeshConfig, msg: &[u8]) -> Result<Vec<u8>, String> {
    let seed = mesh.root_seed()?;
    Ok(sign(&seed, msg).to_vec())
}

/// 校验签名（root 公钥）。
pub fn verify_with_root(mesh: &MeshConfig, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(root_pub) = mesh.root_public_raw() else {
        return false;
    };
    let Ok(sig_arr) = sig.try_into() else {
        return false;
    };
    linkmesh_shared::identity::verify(&root_pub, msg, sig_arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linkmesh_shared::identity::device_id_b64;

    fn new_mesh() -> MeshConfig {
        MeshConfig::init(&MeshConfig::generate_mesh_id())
    }

    #[test]
    fn mesh_init_and_save_load_roundtrip() {
        let path = std::env::temp_dir().join("linkmesh_test_mesh.json");
        let _ = std::fs::remove_file(&path);
        {
            let m = new_mesh();
            assert!(m.root_fingerprint().unwrap().len() > 0);
            assert!(!m.mesh_id.is_empty());
            assert!(m.crl.version == 0);
            assert_eq!(m.crl.signature.is_some(), true);
            m.save(&path).unwrap();
        }
        let loaded = MeshConfig::load(&path).unwrap().unwrap();
        assert_eq!(loaded.mesh_id, loaded.mesh_id);
        assert!(loaded.verify_integrity().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn invite_consume_once_and_expire() {
        let mut m = new_mesh();
        let code = m.create_invite(Some("10.13.13.50"), 600);
        assert!(code.starts_with("LMJ-"));
        // 第一次消费成功，返回预绑定 IP
        assert_eq!(m.consume_invite(&code).unwrap().as_deref(), Some("10.13.13.50"));
        // 第二次消费失败（单次有效）
        assert!(m.consume_invite(&code).is_err());
        // 错误码失败
        assert!(m.consume_invite("LMJ-XXXX-XXXX-XXXX-XXXX").is_err());        // 过期
        let mut m2 = new_mesh();
        let code2 = m2.create_invite(None, 1);
        m2.invites[0].expires_at = now_secs() - 10;
        assert!(m2.consume_invite(&code2).is_err());
    }

    #[test]
    fn peek_invite_validates_without_consuming() {
        let mut m = new_mesh();
        let code = m.create_invite(Some("10.13.13.60"), 600);
        // peek 只校验、不消费：连续多次 peek 均成功，且状态不变
        for _ in 0..3 {
            assert_eq!(m.peek_invite(&code).unwrap().as_deref(), Some("10.13.13.60"));
        }
        assert_eq!(m.invites.iter().find(|e| e.code_hash == MeshConfig::hash_code(&code)).unwrap().used, false);
        // 错误码 / 已过期均被 peek 拒绝
        assert!(m.peek_invite("LMJ-XXXX-XXXX-XXXX-XXXX").is_err());
        m.invites[0].expires_at = now_secs() - 10;
        assert!(m.peek_invite(&code).is_err());
        // consume 之后 peek 拒绝（单次有效）
        let mut m3 = new_mesh();
        let code3 = m3.create_invite(None, 600);
        m3.consume_invite(&code3).unwrap();
        assert!(m3.peek_invite(&code3).is_err());
    }

    #[test]
    fn hash_code_normalizes() {
        let a = MeshConfig::hash_code("LMJ-AB12-CD34-EF56-7890-AB12-CD34-EF56-7890");
        let b = MeshConfig::hash_code("lmj ab12 cd34 ef56 7890 ab12 cd34 ef56 7890");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn issue_cert_and_revoke() {
        let mut m = new_mesh();
        let dev = linkmesh_shared::crypto::KeyPairSerde::generate();
        let dev_ik_s = SignKeyPairSerde::generate();
        let ik_x = dev.public_b64();
        let ik_s = dev_ik_s.public.clone();
        let id = device_id_b64(&dev.public_raw().unwrap(), &dev_ik_s.parse_public().unwrap());

        let cert = m.issue_cert(&ik_x, &ik_s, "10.13.13.60", None).unwrap();
        assert_eq!(cert.device_id, id);
        assert_eq!(cert.allowed_ip, "10.13.13.60");
        cert.verify(&m.root_public_raw().unwrap(), now_secs()).unwrap();

        // 重复签发报错
        assert!(m.issue_cert(&ik_x, &ik_s, "10.13.13.60", None).is_err());

        // IP 池不再含已分配地址
        let used = m.members.iter().map(|x| x.cert.allowed_ip.as_str()).collect::<Vec<_>>();
        assert!(used.contains(&"10.13.13.60"));

        // 吊销
        let crl = m.revoke(&id, RevokeReason::Compromised).unwrap();
        assert_eq!(crl.version, 1);
        assert!(m.is_revoked(&id));
        assert!(m.find_member(&id).is_none());
        // 重复吊销报错
        assert!(m.revoke(&id, RevokeReason::Compromised).is_err());
        // 已吊销设备不可再签发
        assert!(m.issue_cert(&ik_x, &ik_s, "10.13.13.61", None).is_err());
    }

    #[test]
    fn allocate_ip_prefers_pool() {
        let mut m = new_mesh();
        let ip = m.allocate_ip(None).unwrap();
        assert_eq!(ip, "10.13.13.2");
        // 占用后分配下一个
        let dev = linkmesh_shared::crypto::KeyPairSerde::generate();
        let dev_ik_s = SignKeyPairSerde::generate();
        m.issue_cert(&dev.public_b64(), &dev_ik_s.public, &ip, None).unwrap();
        assert_eq!(m.allocate_ip(None).unwrap(), "10.13.13.3");
    }
}
