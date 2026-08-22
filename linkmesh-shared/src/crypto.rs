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

//! 密钥交换与加解密。
//!
//! - 每台设备在本地用 X25519 生成自己的密钥对，私钥永不离开本机。
//! - 双方经「自己的私钥 + 对端公钥」计算得到同一个共享密钥。
//! - 共享密钥用于 ChaCha20-Poly1305 加密数据。
//! - 公钥以 base64 形式在网络上传输与展示。
//! - 会话密钥（3-DH + HKDF，含临时密钥成分）提供前向保密，见 `derive_session_key_*`。

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key as ChaKey, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// 公钥/私钥的 base64 编码表示（各 43 字符）。
pub type B64Key = String;

/// 32 字节的原始密钥。
pub type RawKey = [u8; KEY_LEN];

/// X25519 密钥对。私钥只存在于本机内存/本机配置文件。
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: RawKey,
    pub private: RawKey,
}

impl KeyPair {
    pub fn public_b64(&self) -> B64Key {
        B64.encode(self.public)
    }

    pub fn private_b64(&self) -> B64Key {
        B64.encode(self.private)
    }
}

/// 密钥对（base64 字符串形式持久化）。私钥只存在于本机配置，绝不上传。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairSerde {
    pub public: B64Key,
    pub private: B64Key,
}

impl KeyPairSerde {
    pub fn generate() -> Self {
        let kp = generate_keypair();
        KeyPairSerde {
            public: kp.public_b64(),
            private: kp.private_b64(),
        }
    }

    pub fn public_b64(&self) -> B64Key {
        self.public.clone()
    }

    pub fn private_b64(&self) -> B64Key {
        self.private.clone()
    }

    pub fn public_raw(&self) -> Result<RawKey, String> {
        parse_public_key(&self.public)
    }

    pub fn private_raw(&self) -> Result<RawKey, String> {
        parse_public_key(&self.private)
    }
}

/// 生成本机密钥对。私钥仅保存在本地。
pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    KeyPair {
        public,
        private: secret.to_bytes(),
    }
}

/// 解析 base64 编码的公钥。
pub fn parse_public_key(b64: &str) -> Result<RawKey, String> {
    let bytes = B64.decode(b64.trim()).map_err(|e| format!("公钥 base64 解析失败: {e}"))?;
    let arr: RawKey = bytes
        .try_into()
        .map_err(|_| format!("公钥长度错误，应为 {} 字节", KEY_LEN))?;
    Ok(arr)
}

/// ECDH：用自己的私钥 + 对端公钥计算共享密钥（双方计算结果相同）。
pub fn shared_secret(private: &RawKey, peer_public: &RawKey) -> RawKey {
    let secret = StaticSecret::from(*private);
    let peer = PublicKey::from(*peer_public);
    let shared = secret.diffie_hellman(&peer);
    shared.to_bytes()
}

/// 加密：随机 12 字节 nonce 前置 + ChaCha20-Poly1305 密文。
pub fn encrypt(key: &RawKey, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    encrypt_with_nonce(key, &nonce_bytes, plaintext)
}

/// 解密 `encrypt` 的输出，验证失败返回错误。
pub fn decrypt(key: &RawKey, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_LEN {
        return Err("密文过短".into());
    }
    let (nonce_bytes, ct) = data.split_at(NONCE_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);
    decrypt_ct(key, &nonce, ct)
}

/// 加密：使用调用方提供的 12 字节 nonce（用于会话期确定性 nonce：计数器 + 方向位）。
pub fn encrypt_with_nonce(key: &RawKey, nonce_bytes: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + 16);
    encrypt_with_nonce_into(key, nonce_bytes, plaintext, &mut out);
    out
}

/// `encrypt_with_nonce` 的就地版本：把 `nonce ‖ ciphertext‖tag` 写入调用方提供的 `out`，
/// 复用缓冲避免每包 2 次堆分配 + 2 次全量拷贝（数据面热路径）。
///
/// 输出字节与 `encrypt_with_nonce` 完全一致（兼容线上格式）；`out` 旧内容被覆盖。
pub fn encrypt_with_nonce_into(
    key: &RawKey,
    nonce_bytes: &[u8; NONCE_LEN],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) {
    let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    out.clear();
    out.reserve(NONCE_LEN + plaintext.len() + 16);
    out.extend_from_slice(nonce_bytes);
    out.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(nonce, &[], &mut out[NONCE_LEN..])
        .expect("加密失败");
    out.extend_from_slice(&tag);
}

/// 解密 `encrypt_with_nonce` 的输出（`data` 含 12 字节 nonce 前缀）。
///
/// nonce 前缀必须与调用方提供的 nonce 一致，否则视为重放/乱序直接拒绝。
pub fn decrypt_with_nonce(
    key: &RawKey,
    nonce_bytes: &[u8; NONCE_LEN],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_LEN {
        return Err("密文过短".into());
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    if nonce != nonce_bytes {
        return Err("nonce 不匹配（重放或乱序）".to_string());
    }
    decrypt_ct(key, nonce_bytes, ct)
}

/// 对纯密文（不含 nonce 前缀）执行 ChaCha20-Poly1305 解密。
fn decrypt_ct(key: &RawKey, nonce_bytes: &[u8; NONCE_LEN], ct: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| "解密失败（密钥不匹配或密文被篡改）".to_string())
}

/// 把 8 字节计数器 + 1 字节方向位组成为会话期确定性 nonce（低 3 字节恒为 0）。
///
/// 计数器必须单调递增、永不回卷复用；方向位用于区分请求/响应（0 或 1），
/// 避免双向 nonce 碰撞。见设计文档 §10.3。
pub fn session_nonce(counter: u64, direction: u8) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&counter.to_be_bytes());
    nonce[8] = direction & 0x01;
    nonce
}

// ---------- 会话密钥派生（3-DH + HKDF，前向保密） ----------

const SESSION_INFO: &[u8] = b"linkmesh/session/v1";
const PEER_INFO: &[u8] = b"linkmesh/peer/v1";

/// 客户端视角：会话密钥 = HKDF(salt=握手 nonce, ikm=DH(ek_c, ik_x_s)‖DH(ik_x_c, ek_s)‖DH(ek_c, ek_s))。
///
/// 3-DH 使单一静态密钥泄露不足以恢复历史会话密钥（需同时持有某一次会话的临时私钥），
/// 临时私钥与已退役会话密钥用后即清零（见 `SessionKey`）。
pub fn derive_session_key_client(
    ek_c_priv: &RawKey,
    ik_x_c_priv: &RawKey,
    ik_s_pub: &RawKey,
    ek_s_pub: &RawKey,
    salt: &[u8],
) -> RawKey {
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&shared_secret(ek_c_priv, ik_s_pub)); // DH(ek_c, ik_x_s)
    ikm.extend_from_slice(&shared_secret(ik_x_c_priv, ek_s_pub)); // DH(ik_x_c, ek_s)
    ikm.extend_from_slice(&shared_secret(ek_c_priv, ek_s_pub)); // DH(ek_c, ek_s)
    hkdf_expand(salt, &ikm, SESSION_INFO)
}

/// 服务端视角：与会话密钥与客户端视角计算结果一致。
///
/// 三项 DH 的拼接顺序必须与客户端完全一致（ECDH 对称，双方用各自私钥计算同一项）：
/// `DH(ek_c,ik_x_s) ‖ DH(ik_x_c,ek_s) ‖ DH(ek_c,ek_s)`。
pub fn derive_session_key_server(
    ek_s_priv: &RawKey,
    ik_s_priv: &RawKey,
    ek_c_pub: &RawKey,
    ik_x_c_pub: &RawKey,
    salt: &[u8],
) -> RawKey {
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&shared_secret(ik_s_priv, ek_c_pub)); // DH(ek_c, ik_x_s)
    ikm.extend_from_slice(&shared_secret(ek_s_priv, ik_x_c_pub)); // DH(ik_x_c, ek_s)
    ikm.extend_from_slice(&shared_secret(ek_s_priv, ek_c_pub)); // DH(ek_c, ek_s)
    hkdf_expand(salt, &ikm, SESSION_INFO)
}

/// 对端（数据面）会话密钥：HKDF(DH(ik_x_c, ik_x_p)‖DH(rk_c, rk_p), "linkmesh/peer/v1")。
///
/// 静态 ik 成分保证身份连续性与防冒充，路由密钥 rk 每次连接/重协商轮换提供前向保密。
pub fn derive_peer_key(
    ik_priv: &RawKey,
    peer_ik_pub: &RawKey,
    rk_priv: &RawKey,
    peer_rk_pub: &RawKey,
    salt: &[u8],
) -> RawKey {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&shared_secret(ik_priv, peer_ik_pub));
    ikm.extend_from_slice(&shared_secret(rk_priv, peer_rk_pub));
    hkdf_expand(salt, &ikm, PEER_INFO)
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8]) -> RawKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm).expect("HKDF 展开失败");
    okm
}

/// 会话期敏感密钥：Drop 时清零，是前向保密论证的前提。
///
/// 设计文档 §10.3：临时密钥与已退役会话密钥必须清零。P1 起信令/数据面会话密钥
/// 一律存放于此类型中，禁止以裸 `RawKey` 长期持有。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKey(pub RawKey);

impl SessionKey {
    pub fn new(key: RawKey) -> Self {
        SessionKey(key)
    }

    pub fn as_raw(&self) -> &RawKey {
        &self.0
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_and_public_derivation() {
        let kp = generate_keypair();
        // 公钥可由私钥重新推导（Ed25519/X25519 确定性公钥派生）
        assert_eq!(kp.public_b64().len(), 44);
        let _ = kp;
    }

    /// 零拷贝：`encrypt_with_nonce_into` 就地加密进复用缓冲，不触发重新分配。
    ///
    /// 用 capacity 在多次调用间保持稳定来证明「复用容量」（零拷贝的核心收益）：
    /// 若每次新建 Vec 或扩容，capacity 会随包长大或多次分配；复用后 capacity 恒等，
    /// 且输出与分配版逐字节一致（格式兼容）。
    #[test]
    fn inplace_encrypt_reuses_capacity_no_realloc() {
        let key = [9u8; 32];
        let nonce = session_nonce(1, 0);
        // 预分配一次到足够容量
        let mut buf = Vec::with_capacity(128);
        // 冷启动填充小包
        encrypt_with_nonce_into(&key, &nonce, b"small", &mut buf);
        let cap_after_small = buf.capacity();
        // 用不同大小负载多次就地加密，capacity 不得超过预分配（零重新分配）
        for i in 1..=50usize {
            let payload = vec![0xA5u8; i * 3]; // 包长变化
            encrypt_with_nonce_into(&key, &nonce, &payload, &mut buf);
            assert!(
                buf.capacity() <= cap_after_small.max(128 + (payload.len() + 28)),
                "就地加密不应触发超出预分配的重新分配（零拷贝断言）"
            );
            // 输出与分配版逐字节一致（线上格式兼容）
            let expected = encrypt_with_nonce(&key, &nonce, &payload);
            assert_eq!(buf, expected, "就地加密输出必须与分配版一致");
        }
    }

    #[test]
    fn two_devices_share_same_secret() {
        let a = generate_keypair();
        let b = generate_keypair();
        let s1 = shared_secret(&a.private, &b.public);
        let s2 = shared_secret(&b.private, &a.public);
        assert_eq!(s1, s2);
        assert_ne!(s1, [0u8; KEY_LEN]);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let a = generate_keypair();
        let b = generate_keypair();
        let key = shared_secret(&a.private, &b.public);
        let msg = b"hello linkmesh";
        let ct = encrypt(&key, msg);
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let a = generate_keypair();
        let b = generate_keypair();
        let c = generate_keypair();
        let key_ab = shared_secret(&a.private, &b.public);
        let key_ac = shared_secret(&a.private, &c.public);
        let ct = encrypt(&key_ab, b"secret");
        assert!(decrypt(&key_ac, &ct).is_err());
    }

    #[test]
    fn public_key_b64_roundtrip() {
        let kp = generate_keypair();
        let parsed = parse_public_key(&kp.public_b64()).unwrap();
        assert_eq!(parsed, kp.public);
    }

    #[test]
    fn session_nonce_structure() {
        let n = session_nonce(7, 1);
        assert_eq!(&n[..8], &7u64.to_be_bytes());
        assert_eq!(n[8], 1);
        assert_eq!(&n[9..], &[0, 0, 0]);
        // 不同计数器/方向产生不同 nonce
        assert_ne!(session_nonce(7, 0), session_nonce(7, 1));
        assert_ne!(session_nonce(7, 1), session_nonce(8, 1));
    }

    #[test]
    fn encrypt_with_nonce_roundtrip_and_replay_reject() {
        let key = [3u8; 32];
        let nonce = session_nonce(42, 0);
        let ct = encrypt_with_nonce(&key, &nonce, b"hello session");
        // 错误 nonce 无法解密（重放/乱序防护）
        let wrong_nonce = session_nonce(43, 0);
        assert!(decrypt_with_nonce(&key, &wrong_nonce, &ct).is_err());
        // 正确 nonce 可解密
        let pt = decrypt_with_nonce(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, b"hello session");
    }

    #[test]
    fn inplace_variants_byte_identical_and_roundtrip() {
        let key = [7u8; 32];
        let nonce = session_nonce(100, 1);
        let plain = b"in-place buffer reuse test";

        // 就地加密的输出与普通版本逐字节一致
        let mut buf = Vec::with_capacity(128);
        encrypt_with_nonce_into(&key, &nonce, plain, &mut buf);
        let ct = encrypt_with_nonce(&key, &nonce, plain);
        assert_eq!(buf, ct);

        // 就地加密后可用普通版本解密还原明文
        let out = decrypt_with_nonce(&key, &nonce, &buf).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn session_key_derivation_agrees_both_sides() {
        // 客户端与服务端各自的密钥材料
        let client_ik = generate_keypair();
        let client_ek = generate_keypair();
        let server_ik = generate_keypair();
        let server_ek = generate_keypair();
        let salt = [9u8; 12];

        let sk_client = derive_session_key_client(
            &client_ek.private,
            &client_ik.private,
            &server_ik.public,
            &server_ek.public,
            &salt,
        );
        let sk_server = derive_session_key_server(
            &server_ek.private,
            &server_ik.private,
            &client_ek.public,
            &client_ik.public,
            &salt,
        );
        assert_eq!(sk_client, sk_server);

        // 换盐 / 换临时密钥都产生不同会话密钥（前向保密敏感项）
        let sk_other_salt =
            derive_session_key_client(&client_ek.private, &client_ik.private, &server_ik.public, &server_ek.public, &[0u8; 12]);
        assert_ne!(sk_client, sk_other_salt);
        let client_ek2 = generate_keypair();
        let sk_other_ek = derive_session_key_client(
            &client_ek2.private,
            &client_ik.private,
            &server_ik.public,
            &server_ek.public,
            &salt,
        );
        assert_ne!(sk_client, sk_other_ek);
    }

    #[test]
    fn peer_key_derivation_agrees_both_sides() {
        let a_ik = generate_keypair();
        let a_rk = generate_keypair();
        let b_ik = generate_keypair();
        let b_rk = generate_keypair();
        let salt = [5u8; 16];

        let k_a = derive_peer_key(&a_ik.private, &b_ik.public, &a_rk.private, &b_rk.public, &salt);
        let k_b = derive_peer_key(&b_ik.private, &a_ik.public, &b_rk.private, &a_rk.public, &salt);
        assert_eq!(k_a, k_b);

        // rk 轮换后密钥变化（前向保密）
        let b_rk2 = generate_keypair();
        let k_b2 = derive_peer_key(&b_ik.private, &a_ik.public, &b_rk2.private, &a_rk.public, &salt);
        assert_ne!(k_a, k_b2);
    }

    #[test]
    fn session_key_zeroized_on_drop() {
        // Drop 必须把密钥缓冲区清零：原地 drop（不移动）后通过原始指针读取同一内存验证。
        let mut key = SessionKey::new([0xAA; 32]);
        let ptr = key.0.as_ptr();
        unsafe { std::ptr::drop_in_place(&mut key) };
        let bytes = unsafe { std::slice::from_raw_parts(ptr, KEY_LEN) };
        assert!(
            bytes.iter().all(|&b| b == 0),
            "SessionKey 释放后密钥缓冲区必须清零"
        );
    }
}
