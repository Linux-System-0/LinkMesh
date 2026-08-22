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

//! 网格信任根（mesh root，Ed25519）签发的各类声明。
//!
//! - `DeviceCert`：设备证书，把「设备身份（ik_x + ik_s）→ 虚拟 IP + 有效期」绑定，
//!   由 root 签名，客户端/服务端均可离线验证；
//! - `ServerInfo`：服务器信息（含网格根公钥、协议版本、CRL 版本），由 root 签名，
//!   客户端加入时一次性 TOFU 根指纹后，此后全部凭签名验证；
//! - `Crl`：吊销列表，root 签名，`version` 单调递增（防回退降级）；
//! - `RotationStatement`：设备长期密钥轮换声明（旧 ik_s 签名证明持有权 + root 签名登记）；
//! - `ServerKeyStatement`：服务端密钥轮换声明（root 签名）。
//!
//! 所有签名输入都使用 `canonical()` 生成确定字节：`k=v` 一行一个，不依赖 serde 字段序，
//! 杜绝跨实现签名不匹配。设计见 `docs/身份认证与密钥管理体系设计.md` 第 3、6 章。

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::crypto::RawKey;
use crate::identity::{self, RawSig, RawSigPriv, RawSigPub};

/// 将字段列表拼成确定的待签名字节。`prefix` 是声明类型与版本，`fields` 必须固定顺序。
pub fn canonical(prefix: &str, fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = format!("{prefix}\n").into_bytes();
    for (k, v) in fields {
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
        out.push(b'\n');
    }
    out
}

fn b64_to<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let bytes = B64.decode(s.trim()).map_err(|e| format!("{what} base64 解析失败: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{what} 长度错误，应为 {N} 字节"))
}

/// 设备证书：root 签名的「设备身份 → 虚拟 IP + 有效期」绑定。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCert {
    pub mesh_id: String,
    pub version: u32,
    /// base64 编码的 device_id（见 identity::device_id_b64）。
    pub device_id: String,
    /// base64 编码的 X25519 公钥。
    pub ik_x: String,
    /// base64 编码的 Ed25519 公钥。
    pub ik_s_pub: String,
    /// 证书允许的虚拟 IP（服务端分配，防 IP 抢占）。
    pub allowed_ip: String,
    pub valid_from: u64,
    pub not_after: u64,
    /// root 的 Ed25519 签名（base64）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl DeviceCert {
    pub fn new(
        mesh_id: &str,
        version: u32,
        device_id: &str,
        ik_x: &str,
        ik_s_pub: &str,
        allowed_ip: &str,
        valid_from: u64,
        not_after: u64,
    ) -> Self {
        DeviceCert {
            mesh_id: mesh_id.to_string(),
            version,
            device_id: device_id.to_string(),
            ik_x: ik_x.to_string(),
            ik_s_pub: ik_s_pub.to_string(),
            allowed_ip: allowed_ip.to_string(),
            valid_from,
            not_after,
            signature: None,
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        canonical(
            "linkmesh-device-cert-v1",
            &[
                ("mesh_id", &self.mesh_id),
                ("version", &self.version.to_string()),
                ("device_id", &self.device_id),
                ("ik_x", &self.ik_x),
                ("ik_s_pub", &self.ik_s_pub),
                ("allowed_ip", &self.allowed_ip),
                ("valid_from", &self.valid_from.to_string()),
                ("not_after", &self.not_after.to_string()),
            ],
        )
    }

    /// 用 root 私钥种子签发（就地写入 signature）。
    pub fn sign(&mut self, root_seed: &RawSigPriv) {
        let sig = identity::sign(root_seed, &self.canonical_bytes());
        self.signature = Some(B64.encode(sig));
    }

    /// 校验签名与有效期。`now_secs` 为当前 Unix 时间。
    pub fn verify(&self, root_pub: &RawSigPub, now_secs: u64) -> Result<(), String> {
        let sig_b64 = self.signature.as_ref().ok_or("设备证书缺少签名")?;
        let sig: RawSig = b64_to(sig_b64, "设备证书签名")?;
        if !identity::verify(root_pub, &self.canonical_bytes(), &sig) {
            return Err("设备证书签名无效（root 不匹配或内容被篡改）".into());
        }
        if now_secs < self.valid_from || now_secs > self.not_after {
            return Err("设备证书已过期或尚未生效".into());
        }
        Ok(())
    }

    /// 校验证书绑定的密钥与设备实际出示的双公钥一致。
    pub fn matches_keys(&self, ik_x: &RawKey, ik_s_pub: &RawSigPub) -> Result<(), String> {
        let cert_ik_x = crate::crypto::parse_public_key(&self.ik_x)?;
        let cert_ik_s: RawSigPub = b64_to(&self.ik_s_pub, "证书 ik_s_pub")?;
        if cert_ik_x != *ik_x || cert_ik_s != *ik_s_pub {
            return Err("证书与设备出示的公钥不匹配".into());
        }
        Ok(())
    }
}

/// 服务器信息：root 签名的「网格根公钥 + 当前服务器公钥 + 协议/CRL 版本」。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub mesh_id: String,
    pub server_name: String,
    /// base64 编码的网格根公钥（客户端 TOFU 并固定）。
    pub mesh_root_pub: String,
    /// base64 编码的服务器 X25519 公钥。
    pub server_ik_x: String,
    /// base64 编码的服务器 Ed25519 公钥。
    pub server_ik_s_pub: String,
    /// 协议能力版本（当前为 2：强制认证）。
    pub protocol_ver: u32,
    /// 当前 CRL 版本（客户端据此判断是否需要拉取）。
    pub crl_version: u64,
    /// 是否强制认证（旧版 v1 客户端会被明确拒绝）。
    pub auth_required: bool,
    /// root 的 Ed25519 签名（base64）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ServerInfo {
    fn canonical_bytes(&self) -> Vec<u8> {
        canonical(
            "linkmesh-server-info-v1",
            &[
                ("mesh_id", &self.mesh_id),
                ("server_name", &self.server_name),
                ("mesh_root_pub", &self.mesh_root_pub),
                ("server_ik_x", &self.server_ik_x),
                ("server_ik_s_pub", &self.server_ik_s_pub),
                ("protocol_ver", &self.protocol_ver.to_string()),
                ("crl_version", &self.crl_version.to_string()),
                ("auth_required", &self.auth_required.to_string()),
            ],
        )
    }

    pub fn sign(&mut self, root_seed: &RawSigPriv) {
        let sig = identity::sign(root_seed, &self.canonical_bytes());
        self.signature = Some(B64.encode(sig));
    }

    pub fn verify(&self, root_pub: &RawSigPub) -> Result<(), String> {
        let sig_b64 = self.signature.as_ref().ok_or("服务器信息缺少签名")?;
        let sig: RawSig = b64_to(sig_b64, "服务器信息签名")?;
        if !identity::verify(root_pub, &self.canonical_bytes(), &sig) {
            return Err("服务器信息签名无效".into());
        }
        Ok(())
    }

    /// 服务器 X25519 公钥（原始字节）。
    pub fn server_ik_x_raw(&self) -> Result<RawKey, String> {
        crate::crypto::parse_public_key(&self.server_ik_x)
    }
}

/// 吊销原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevokeReason {
    /// 私钥疑似泄露（最常见：设备失窃、配置外泄）。
    Compromised,
    /// 私钥已泄露。
    Leaked,
    /// 因密钥轮换被替换（replacement 指向新设备 ID）。
    Rotated,
    /// 管理员主动吊销（不再允许入网）。
    Admin,
    /// 设备退役。
    Discontinued,
}

impl RevokeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevokeReason::Compromised => "compromised",
            RevokeReason::Leaked => "leaked",
            RevokeReason::Rotated => "rotated",
            RevokeReason::Admin => "admin",
            RevokeReason::Discontinued => "discontinued",
        }
    }
}

/// 吊销列表中的一条。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlEntry {
    pub device_id: String,
    pub reason: RevokeReason,
    pub revoked_at: u64,
    /// 仅 reason=Rotated 时指向新设备 ID。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

/// 吊销列表（CRL）：root 签名，`version` 单调递增。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Crl {
    pub mesh_id: String,
    pub version: u64,
    pub entries: Vec<CrlEntry>,
    /// root 的 Ed25519 签名（base64）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Crl {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut fields = vec![
            ("mesh_id".to_string(), self.mesh_id.clone()),
            ("version".to_string(), self.version.to_string()),
        ];
        let mut entries: Vec<&CrlEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        for e in entries {
            fields.push((
                "revoke".to_string(),
                format!(
                    "{}:{}:{}",
                    e.device_id,
                    e.reason.as_str(),
                    e.revoked_at
                ),
            ));
        }
        let refs: Vec<(&str, &str)> = fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        canonical("linkmesh-crl-v1", &refs)
    }

    pub fn sign(&mut self, root_seed: &RawSigPriv) {
        let sig = identity::sign(root_seed, &self.canonical_bytes());
        self.signature = Some(B64.encode(sig));
    }

    pub fn verify(&self, root_pub: &RawSigPub) -> Result<(), String> {
        let sig_b64 = self.signature.as_ref().ok_or("CRL 缺少签名")?;
        let sig: RawSig = b64_to(sig_b64, "CRL 签名")?;
        if !identity::verify(root_pub, &self.canonical_bytes(), &sig) {
            return Err("CRL 签名无效".into());
        }
        Ok(())
    }

    pub fn is_revoked(&self, device_id: &str) -> bool {
        self.entries.iter().any(|e| e.device_id == device_id)
    }

    /// 校验另一份 CRL 是否可作为本 CRL 的更新：签名有效、属于同一网格、版本更高。
    pub fn is_newer_than(&self, other: &Crl) -> bool {
        self.mesh_id == other.mesh_id && self.version > other.version
    }
}

/// 设备密钥轮换声明：root 签名登记新设备身份（撤销旧身份、签发新证书）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStatement {
    pub mesh_id: String,
    pub new_device_id: String,
    /// base64 编码的新 X25519 公钥。
    pub new_ik_x: String,
    /// base64 编码的新 Ed25519 公钥。
    pub new_ik_s_pub: String,
    pub timestamp: u64,
    /// 由 root 私钥签名（base64）：登记为新证书依据。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_signature: Option<String>,
}

impl RotationStatement {
    fn canonical_bytes(&self) -> Vec<u8> {
        canonical(
            "linkmesh-rotation-v2",
            &[
                ("mesh_id", &self.mesh_id),
                ("new_device_id", &self.new_device_id),
                ("new_ik_x", &self.new_ik_x),
                ("new_ik_s_pub", &self.new_ik_s_pub),
                ("timestamp", &self.timestamp.to_string()),
            ],
        )
    }

    /// 用 root 私钥签名（服务端登记背书）。
    pub fn sign_with_root(&mut self, root_seed: &RawSigPriv) {
        let sig = identity::sign(root_seed, &self.canonical_bytes());
        self.root_signature = Some(B64.encode(sig));
    }

    /// 校验 root 签名。
    pub fn verify(&self, root_pub: &RawSigPub) -> Result<(), String> {
        let root_sig_b64 = self.root_signature.as_ref().ok_or("轮换声明缺少 root 签名")?;
        let root_sig: RawSig = b64_to(root_sig_b64, "root 签名")?;
        if !identity::verify(root_pub, &self.canonical_bytes(), &root_sig) {
            return Err("轮换声明的 root 签名无效".into());
        }
        Ok(())
    }
}

/// 服务端密钥轮换声明：root 签名，客户端据此自动更新固定的服务器公钥。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerKeyStatement {
    pub mesh_id: String,
    /// 被替换的旧服务器 X25519 公钥（base64），客户端必须匹配本地固定值才接受。
    pub old_server_ik_x: String,
    /// base64 编码的新服务器 X25519 公钥。
    pub new_ik_x: String,
    /// base64 编码的新服务器 Ed25519 公钥。
    pub new_ik_s_pub: String,
    pub timestamp: u64,
    /// root 的 Ed25519 签名（base64）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_signature: Option<String>,
}

impl ServerKeyStatement {
    fn canonical_bytes(&self) -> Vec<u8> {
        canonical(
            "linkmesh-server-key-v1",
            &[
                ("mesh_id", &self.mesh_id),
                ("old_server_ik_x", &self.old_server_ik_x),
                ("new_ik_x", &self.new_ik_x),
                ("new_ik_s_pub", &self.new_ik_s_pub),
                ("timestamp", &self.timestamp.to_string()),
            ],
        )
    }

    pub fn sign_with_root(&mut self, root_seed: &RawSigPriv) {
        let sig = identity::sign(root_seed, &self.canonical_bytes());
        self.root_signature = Some(B64.encode(sig));
    }

    pub fn verify(&self, root_pub: &RawSigPub) -> Result<(), String> {
        let sig_b64 = self.root_signature.as_ref().ok_or("服务器密钥声明缺少签名")?;
        let sig: RawSig = b64_to(sig_b64, "服务器密钥声明签名")?;
        if !identity::verify(root_pub, &self.canonical_bytes(), &sig) {
            return Err("服务器密钥声明签名无效".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use crate::identity::{device_id_b64, SignKeyPairSerde};

    fn root_keypair() -> SignKeyPairSerde {
        SignKeyPairSerde::generate()
    }

    fn root_seed(kp: &SignKeyPairSerde) -> RawSigPriv {
        let bytes = B64.decode(kp.private.trim()).unwrap();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        seed
    }

    #[test]
    fn device_cert_sign_verify_roundtrip() {
        let root = root_keypair();
        let root_pub = root.parse_public().unwrap();
        let dev_ik = generate_keypair();
        let dev_ik_s = SignKeyPairSerde::generate();
        let dev_ik_s_pub = dev_ik_s.parse_public().unwrap();
        let id = device_id_b64(&dev_ik.public, &dev_ik_s_pub);

        let mut cert = DeviceCert::new(
            "mesh-test",
            1,
            &id,
            &B64.encode(dev_ik.public),
            &dev_ik_s.public,
            "10.13.13.50",
            1_000_000,
            9_000_000_000,
        );
        cert.sign(&root_seed(&root));
        assert!(cert.verify(&root_pub, 5_000_000).is_ok());
        assert!(cert.matches_keys(&dev_ik.public, &dev_ik_s_pub).is_ok());

        // 篡改必失败
        let mut tampered = cert.clone();
        tampered.allowed_ip = "10.13.13.66".to_string();
        assert!(tampered.verify(&root_pub, 5_000_000).is_err());

        // 过期 / 未生效
        assert!(cert.verify(&root_pub, 500).is_err());
        assert!(cert.verify(&root_pub, 9_000_000_001).is_err());

        // 错误 root / 密钥不匹配
        let other_root = root_keypair();
        assert!(cert.verify(&other_root.parse_public().unwrap(), 5_000_000).is_err());
        let other_dev = generate_keypair();
        assert!(cert.matches_keys(&other_dev.public, &dev_ik_s_pub).is_err());
    }

    #[test]
    fn server_info_sign_verify() {
        let root = root_keypair();
        let root_pub = root.parse_public().unwrap();
        let server_ik = generate_keypair();
        let mut info = ServerInfo {
            mesh_id: "mesh-test".into(),
            server_name: "s1".into(),
            mesh_root_pub: B64.encode(root_pub),
            server_ik_x: B64.encode(server_ik.public),
            server_ik_s_pub: B64.encode([9u8; 32]),
            protocol_ver: 2,
            crl_version: 3,
            auth_required: true,
            signature: None,
        };
        info.sign(&root_seed(&root));
        assert!(info.verify(&root_pub).is_ok());
        let mut tampered = info.clone();
        tampered.crl_version = 2;
        assert!(tampered.verify(&root_pub).is_err());
    }

    #[test]
    fn crl_sign_verify_and_monotonic() {
        let root = root_keypair();
        let root_pub = root.parse_public().unwrap();
        let mut crl = Crl {
            mesh_id: "mesh-test".into(),
            version: 1,
            entries: vec![
                CrlEntry {
                    device_id: "dev-a".into(),
                    reason: RevokeReason::Compromised,
                    revoked_at: 1_000_000,
                    replacement: None,
                },
                CrlEntry {
                    device_id: "dev-b".into(),
                    reason: RevokeReason::Rotated,
                    revoked_at: 1_000_001,
                    replacement: Some("dev-c".into()),
                },
            ],
            signature: None,
        };
        crl.sign(&root_seed(&root));
        assert!(crl.verify(&root_pub).is_ok());
        assert!(crl.is_revoked("dev-a"));
        assert!(crl.is_revoked("dev-b"));
        assert!(!crl.is_revoked("dev-c"));

        let mut tampered = crl.clone();
        tampered.entries.push(CrlEntry {
            device_id: "dev-x".into(),
            reason: RevokeReason::Admin,
            revoked_at: 1_000_002,
            replacement: None,
        });
        assert!(tampered.verify(&root_pub).is_err());

        let mut v2 = crl.clone();
        v2.version = 2;
        v2.sign(&root_seed(&root));
        assert!(v2.is_newer_than(&crl));
        assert!(!crl.is_newer_than(&v2));

        // 跨网格 CRL 不能互相更新
        let mut foreign = crl.clone();
        foreign.mesh_id = "mesh-other".into();
        foreign.version = 99;
        assert!(!foreign.is_newer_than(&crl));
    }

    #[test]
    fn rotation_statement_verify_chain() {
        let root = root_keypair();
        let root_pub = root.parse_public().unwrap();

        let new_ik = generate_keypair();
        let new_ik_s = SignKeyPairSerde::generate();
        let new_pub = new_ik_s.parse_public().unwrap();
        let new_id = device_id_b64(&new_ik.public, &new_pub);

        let mut stmt = RotationStatement {
            mesh_id: "mesh-test".into(),
            new_device_id: new_id,
            new_ik_x: B64.encode(new_ik.public),
            new_ik_s_pub: new_ik_s.public.clone(),
            timestamp: 1_000_000,
            root_signature: None,
        };
        stmt.sign_with_root(&root_seed(&root));
        assert!(stmt.verify(&root_pub).is_ok());

        // 新密钥被替换必失败
        let mut forged = stmt.clone();
        forged.new_ik_x = B64.encode(generate_keypair().public);
        assert!(forged.verify(&root_pub).is_err());
    }

    #[test]
    fn server_key_statement_verify() {
        let root = root_keypair();
        let root_pub = root.parse_public().unwrap();
        let new_server = generate_keypair();
        let mut stmt = ServerKeyStatement {
            mesh_id: "mesh-test".into(),
            old_server_ik_x: B64.encode([1u8; 32]),
            new_ik_x: B64.encode(new_server.public),
            new_ik_s_pub: B64.encode([2u8; 32]),
            timestamp: 1_000_000,
            root_signature: None,
        };
        stmt.sign_with_root(&root_seed(&root));
        assert!(stmt.verify(&root_pub).is_ok());
        let mut tampered = stmt.clone();
        tampered.new_ik_x = B64.encode([3u8; 32]);
        assert!(tampered.verify(&root_pub).is_err());
    }
}
