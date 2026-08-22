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

//! 设备身份：长期加密密钥（X25519）与长期签名密钥（Ed25519）共同构成设备身份。
//!
//! - `ik_x`：X25519 静态密钥，用于 ECDH（与现有 wire 格式完全兼容）。
//! - `ik_s`：Ed25519 签名密钥（X25519 无法签名，故引入），用于对设备证书、密钥轮换、
//!   吊销等声明签名。
//! - `device_id`：由 ik_x 与 ik_s 公钥共同推导的稳定标识，用于目录、证书与吊销列表。
//! - `fingerprint`：取 device_id 前 20 字节做 base32，4 字符一组展示（SSH 风格），
//!   用于加入网格、验对端、吊销时的人工比对。
//!
//! 设计见 `docs/身份认证与密钥管理体系设计.md` 第 3 章。

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::RawKey;

pub const SIG_PRIV_LEN: usize = 32;
pub const SIG_PUB_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const DEVICE_ID_LEN: usize = 32;

/// Ed25519 私钥种子（32 字节）。
pub type RawSigPriv = [u8; SIG_PRIV_LEN];
/// Ed25519 公钥（32 字节）。
pub type RawSigPub = [u8; SIG_PUB_LEN];
/// Ed25519 签名（64 字节）。
pub type RawSig = [u8; SIG_LEN];

/// base64 序列化的 Ed25519 密钥对（私钥只保存在本机配置，绝不上传）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignKeyPairSerde {
    pub public: String,
    pub private: String,
}

impl SignKeyPairSerde {
    pub fn generate() -> Self {
        let mut seed = [0u8; SIG_PRIV_LEN];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        SignKeyPairSerde {
            public: B64.encode(sk.verifying_key().to_bytes()),
            private: B64.encode(seed),
        }
    }

    pub fn public_b64(&self) -> String {
        self.public.clone()
    }

    pub fn parse_public(&self) -> Result<RawSigPub, String> {
        parse_sig_public(&self.public)
    }

    pub fn parse_private(&self) -> Result<SigningKey, String> {
        let bytes = B64
            .decode(self.private.trim())
            .map_err(|e| format!("签名私钥 base64 解析失败: {e}"))?;
        let seed: RawSigPriv = bytes
            .try_into()
            .map_err(|_| format!("签名私钥长度错误，应为 {} 字节", SIG_PRIV_LEN))?;
        Ok(SigningKey::from_bytes(&seed))
    }
}

/// 设备身份：X25519 加密密钥 + Ed25519 签名密钥。
///
/// P1 起写入 client.json（`identity` 字段）；P0 阶段仅作为共享库原语提供。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentitySerde {
    pub ik_x: crate::crypto::KeyPairSerde,
    pub ik_s: SignKeyPairSerde,
}

impl DeviceIdentitySerde {
    pub fn generate() -> Self {
        DeviceIdentitySerde {
            ik_x: crate::crypto::KeyPairSerde::generate(),
            ik_s: SignKeyPairSerde::generate(),
        }
    }

    pub fn ik_x_public_raw(&self) -> Result<RawKey, String> {
        self.ik_x.public_raw()
    }

    pub fn ik_s_public_raw(&self) -> Result<RawSigPub, String> {
        self.ik_s.parse_public()
    }

    /// 由双公钥推导稳定设备 ID（base64）。
    pub fn device_id(&self) -> Result<String, String> {
        Ok(device_id_b64(
            &self.ik_x_public_raw()?,
            &self.ik_s_public_raw()?,
        ))
    }
}

/// 设备 ID：`SHA-256("linkmesh-device-v1" ‖ ik_x_pub ‖ ik_s_pub)` 的前 32 字节。
pub fn device_id(ik_x_pub: &RawKey, ik_s_pub: &RawSigPub) -> [u8; DEVICE_ID_LEN] {
    let mut h = Sha256::new();
    h.update(b"linkmesh-device-v1");
    h.update(ik_x_pub);
    h.update(ik_s_pub);
    let out = h.finalize();
    let mut id = [0u8; DEVICE_ID_LEN];
    id.copy_from_slice(&out[..DEVICE_ID_LEN]);
    id
}

pub fn device_id_b64(ik_x_pub: &RawKey, ik_s_pub: &RawSigPub) -> String {
    B64.encode(device_id(ik_x_pub, ik_s_pub))
}

/// 解析 base64 编码的 Ed25519 公钥。
pub fn parse_sig_public(b64: &str) -> Result<RawSigPub, String> {
    let bytes = B64
        .decode(b64.trim())
        .map_err(|e| format!("签名公钥 base64 解析失败: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("签名公钥长度错误，应为 {} 字节", SIG_PUB_LEN))
}

/// 用 32 字节种子（私钥）对消息签名，返回 64 字节签名。
pub fn sign(seed: &RawSigPriv, msg: &[u8]) -> RawSig {
    let sk = SigningKey::from_bytes(seed);
    sk.sign(msg).to_bytes()
}

/// 验签。签名无效或公钥非法时返回 false。
pub fn verify(pub_bytes: &RawSigPub, msg: &[u8], sig: &RawSig) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pub_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(sig);
    vk.verify(msg, &sig).is_ok()
}

/// 设备指纹：取 device_id 前 20 字节，base32 编码为 32 字符，4 字符一组展示。
///
/// 例：`ABCD EFGH IJKL MNOP QRST UVWX YZAB CDEF`
pub fn fingerprint(ik_x_pub: &RawKey, ik_s_pub: &RawSigPub) -> String {
    fingerprint_from_device_id(&device_id(ik_x_pub, ik_s_pub))
}

pub fn fingerprint_from_device_id(id: &[u8; DEVICE_ID_LEN]) -> String {
    let b32 = base32_encode(&id[..20]);
    let mut out = String::with_capacity(39);
    for (i, ch) in b32.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

/// RFC 4648 base32 编码（无填充）。
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = SignKeyPairSerde::generate();
        let pub_bytes = kp.parse_public().unwrap();
        let seed = B64.decode(kp.private.trim()).unwrap();
        let mut seed_arr = [0u8; SIG_PRIV_LEN];
        seed_arr.copy_from_slice(&seed);
        let msg = b"linkmesh statement";
        let sig = sign(&seed_arr, msg);
        assert!(verify(&pub_bytes, msg, &sig));
        assert!(!verify(&pub_bytes, b"tampered", &sig));
        let other = SignKeyPairSerde::generate();
        assert!(!verify(&other.parse_public().unwrap(), msg, &sig));
    }

    #[test]
    fn device_id_deterministic_and_unique() {
        let a = DeviceIdentitySerde::generate();
        let b = DeviceIdentitySerde::generate();
        let ik_a = a.ik_x_public_raw().unwrap();
        let iks_a = a.ik_s_public_raw().unwrap();
        let ik_b = b.ik_x_public_raw().unwrap();
        let iks_b = b.ik_s_public_raw().unwrap();
        assert_eq!(device_id_b64(&ik_a, &iks_a), device_id_b64(&ik_a, &iks_a));
        assert_ne!(device_id_b64(&ik_a, &iks_a), device_id_b64(&ik_b, &iks_b));
        // 仅更换签名密钥也会改变设备 ID
        assert_ne!(device_id_b64(&ik_a, &iks_a), device_id_b64(&ik_a, &iks_b));
    }

    #[test]
    fn fingerprint_format() {
        let a = DeviceIdentitySerde::generate();
        let fp = fingerprint(&a.ik_x_public_raw().unwrap(), &a.ik_s_public_raw().unwrap());
        let groups: Vec<&str> = fp.split(' ').collect();
        assert_eq!(groups.len(), 8);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(fp.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ' '));
    }

    #[test]
    fn base32_known_vector() {
        // RFC 4648: "foobar" -> "MZXW6YTBOI"
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        // 20 字节 -> 32 字符（无填充余数）
        assert_eq!(base32_encode(&[0u8; 20]).len(), 32);
    }

    #[test]
    fn signing_key_serde_roundtrip() {
        let kp = SignKeyPairSerde::generate();
        let json = serde_json::to_string(&kp).unwrap();
        let back: SignKeyPairSerde = serde_json::from_str(&json).unwrap();
        assert_eq!(back.public, kp.public);
        assert_eq!(back.private, kp.private);
        assert_eq!(back.parse_public().unwrap(), kp.parse_public().unwrap());
    }

    #[test]
    fn parse_sig_public_rejects_bad() {
        assert!(parse_sig_public("not-base64!!").is_err());
        assert!(parse_sig_public(&B64.encode([0u8; 8])).is_err());
    }
}
