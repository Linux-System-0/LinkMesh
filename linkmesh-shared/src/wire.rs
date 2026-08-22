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

//! 信令负载的固定布局二进制编解码（替代旧版 `serde_json`）。
//!
//! 所有 AEAD 密文内的负载均编码为固定大小结构体（zerocopy v0.8：
//! `#[repr(C)]` + `FromBytes/IntoBytes/Unaligned/Immutable`）。文本字段用定长缓冲
//! [`WireStr`]，密钥/签名/设备 ID 用原始字节数组。数值字段固定小端（所有受支持
//! 目标平台 x86_64/aarch64/arm/i686 均为小端）。
//!
//! 编码方向（`encode_*`）：域类型（`protocol` 模块的字符串形式）→ 定长结构体字节；
//! 解码方向（`decode_*`）：字节 → 域类型，并对长度/魔数/UTF-8/枚举取值做严格校验，
//! 畸形输入一律返回错误而非 panic 或接受（安全优先）。
//!
//! 证书/CRL/ServerInfo 同时承载「域类型（持久化，`cert.rs` serde）」与「线格式」
//! 两种表示，本模块提供双向转换（密钥 base64 ↔ 原始字节，往返无损，保证签名校验一致）。

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use zerocopy::byteorder::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::cert::{Crl, CrlEntry, DeviceCert, RevokeReason, ServerInfo};
use crate::protocol::{
    AuthBody, AuthRespBody, JoinBody, NotifyBody, PeerInfo, QueryBody, RegisterBody, ResponseBody,
    ResponseData, ServerInfoBody,
};

// ---------- 定长尺寸常量 ----------
/// IPv4/IPv6 文本最大长度。
pub const IP_LEN: usize = 48;
/// `ip:port` 文本最大长度。
pub const ENDPOINT_LEN: usize = 64;
/// 名称类字段（mesh_id / server_name / 别名 / 房间名 / 查询键）。
pub const NAME_LEN: usize = 64;
/// 房间令牌。
pub const TOKEN_LEN: usize = 64;
/// 一次性加入码。
pub const CODE_LEN: usize = 64;
/// 错误信息。
pub const ERR_LEN: usize = 256;
/// CRL 单帧容纳的最大吊销条目数。
pub const MAX_CRL_ENTRIES: usize = 256;

/// 响应类型标签（`ResponseBody` 的定长判别）。
pub const RESP_OK: u8 = 1;
pub const RESP_ERR: u8 = 2;
pub const RESP_QUERY_HIT: u8 = 3;
pub const RESP_QUERY_MISS: u8 = 4;
pub const RESP_JOIN: u8 = 5;

// ---------- 通用辅助 ----------

/// 定长文本缓冲：`NUL` 结尾 + 零填充。`set` 拒绝含 `NUL` 的输入与超长输入；
/// `to_str` 在首个 `NUL` 处截断并校验 UTF-8（安全：不信任对端字节）。
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
pub struct WireStr<const N: usize> {
    buf: [u8; N],
}

impl<const N: usize> Default for WireStr<N> {
    fn default() -> Self {
        WireStr { buf: [0; N] }
    }
}

impl<const N: usize> WireStr<N> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        let mut w = Self::empty();
        w.set(s)?;
        Ok(w)
    }

    pub fn set(&mut self, s: &str) -> Result<(), String> {
        if s.as_bytes().contains(&0) {
            return Err("字符串含 NUL 字节".into());
        }
        let b = s.as_bytes();
        if b.len() > N {
            return Err(format!("字段超长（{} > {} 字节）", b.len(), N));
        }
        self.buf[..b.len()].copy_from_slice(b);
        for x in &mut self.buf[b.len()..] {
            *x = 0;
        }
        Ok(())
    }

    /// 首 `NUL` 处截断，校验 UTF-8。
    pub fn to_str(&self) -> Result<&str, String> {
        let end = self.buf.iter().position(|&b| b == 0).unwrap_or(self.buf.len());
        std::str::from_utf8(&self.buf[..end]).map_err(|_| "字段含非法 UTF-8".into())
    }

    pub fn to_string(&self) -> Result<String, String> {
        Ok(self.to_str()?.to_string())
    }
}

/// 从定长缓冲区填充（`Some` 时设置）。
fn put_opt_str<const N: usize>(dst: &mut WireStr<N>, s: &Option<String>) -> Result<bool, String> {
    match s {
        Some(v) => {
            dst.set(v)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

fn b64_key(s: &str) -> Result<[u8; 32], String> {
    let b = B64.decode(s.trim()).map_err(|e| format!("公钥 base64 解析失败: {e}"))?;
    b.try_into().map_err(|_| "公钥长度错误，应为 32 字节".into())
}

fn key_b64(k: &[u8; 32]) -> String {
    B64.encode(k)
}

fn b64_sig(s: &str) -> Result<[u8; 64], String> {
    let b = B64.decode(s.trim()).map_err(|e| format!("签名 base64 解析失败: {e}"))?;
    b.try_into().map_err(|_| "签名长度错误，应为 64 字节".into())
}

fn sig_b64(sig: &[u8; 64]) -> String {
    B64.encode(sig)
}

fn b64_12(s: &str, what: &str) -> Result<[u8; 12], String> {
    let b = B64.decode(s.trim()).map_err(|e| format!("{what} base64 解析失败: {e}"))?;
    b.try_into().map_err(|_| format!("{what} 长度错误，应为 12 字节"))
}

fn b64_12_enc(k: &[u8; 12]) -> String {
    B64.encode(k)
}

/// 16 字节 base64（session_id）。
fn b64_sig_to_16(s: &str) -> Result<[u8; 16], String> {
    let b = B64.decode(s.trim()).map_err(|e| format!("session_id base64 解析失败: {e}"))?;
    b.try_into().map_err(|_| "session_id 长度错误，应为 16 字节".into())
}

fn key_b64_16(k: &[u8; 16]) -> String {
    B64.encode(k)
}

/// 构造一个定长结构体的字节表示。
fn encode_impl<T>(
    fill: impl FnOnce(&mut T) -> Result<(), String>,
) -> Result<Vec<u8>, String>
where
    T: FromBytes + IntoBytes + Unaligned + Immutable + KnownLayout,
{
    let size = std::mem::size_of::<T>();
    let mut buf = vec![0u8; size];
    let (view, _) = T::mut_from_prefix(&mut buf).map_err(|_| "编码失败：结构体尺寸错误".to_string())?;
    fill(view)?;
    Ok(buf)
}

/// 解码一个定长结构体，要求字节数恰好匹配且无尾部多余数据。
fn decode_impl<T>(bytes: &[u8], what: &str) -> Result<T, String>
where
    T: FromBytes + IntoBytes + Unaligned + Immutable + KnownLayout + Copy,
{
    let (t, rest) = T::ref_from_prefix(bytes).map_err(|_| format!("{what} 长度错误"))?;
    if !rest.is_empty() {
        return Err(format!("{what} 尾部存在多余数据"));
    }
    Ok(*t)
}

// ---------- 帧负载定长结构体 ----------

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireRegister {
    ip: WireStr<IP_LEN>,
    has_relay_rk: u8,
    relay_rk: [u8; 32],
    has_token: u8,
    token: WireStr<TOKEN_LEN>,
    has_alias: u8,
    alias: WireStr<NAME_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireQuery {
    ip: WireStr<IP_LEN>,
    has_name: u8,
    name: WireStr<NAME_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WirePeerInfo {
    public_key: [u8; 32],
    endpoint: WireStr<ENDPOINT_LEN>,
    has_relay_rk: u8,
    relay_rk: [u8; 32],
    has_alias: u8,
    alias: WireStr<NAME_LEN>,
    has_ip: u8,
    ip: WireStr<IP_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireNotify {
    peer: WirePeerInfo,
}

// ---- 响应（kind 判别前缀 + 定长变体） ----

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireRespErr {
    error: WireStr<ERR_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireRespQueryHit {
    req: WireStr<NAME_LEN>,
    ip: WireStr<IP_LEN>,
    public_key: [u8; 32],
    endpoint: WireStr<ENDPOINT_LEN>,
    has_relay_rk: u8,
    relay_rk: [u8; 32],
    has_alias: u8,
    alias: WireStr<NAME_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireRespQueryMiss {
    req: WireStr<NAME_LEN>,
    error: WireStr<ERR_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireRespJoin {
    device_id: [u8; 32],
    allocated_ip: WireStr<IP_LEN>,
    cert: WireDeviceCert,
    server_info: WireServerInfo,
    crl: WireCrl,
}

// ---- 认证 / ServerInfo / 证书 ----

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireJoin {
    code: WireStr<CODE_LEN>,
    device_id: [u8; 32],
    ik_x: [u8; 32],
    ik_s_pub: [u8; 32],
    has_requested_ip: u8,
    requested_ip: WireStr<IP_LEN>,
    has_token: u8,
    token: WireStr<TOKEN_LEN>,
    has_alias: u8,
    alias: WireStr<NAME_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireAuth {
    device_id: [u8; 32],
    cert: WireDeviceCert,
    ek_c: [u8; 32],
    timestamp: U64,
    nonce: [u8; 12],
    has_token: u8,
    token: WireStr<TOKEN_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireAuthResp {
    ek_s: [u8; 32],
    session_id: [u8; 16],
    crl: WireCrl,
    server_info: WireServerInfo,
    allocated_ip: WireStr<IP_LEN>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
struct WireServerInfoBody {
    server_info: WireServerInfo,
}

// ---------- 证书 / 服务器信息 / CRL（线格式，转换自 cert.rs 域类型） ----------

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
pub struct WireDeviceCert {
    mesh_id: WireStr<NAME_LEN>,
    version: U32,
    device_id: [u8; 32],
    ik_x: [u8; 32],
    ik_s_pub: [u8; 32],
    allowed_ip: WireStr<IP_LEN>,
    valid_from: U64,
    not_after: U64,
    has_signature: u8,
    signature: [u8; 64],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
pub struct WireServerInfo {
    mesh_id: WireStr<NAME_LEN>,
    server_name: WireStr<NAME_LEN>,
    mesh_root_pub: [u8; 32],
    server_ik_x: [u8; 32],
    server_ik_s_pub: [u8; 32],
    protocol_ver: U32,
    crl_version: U64,
    auth_required: u8,
    has_signature: u8,
    signature: [u8; 64],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
pub struct WireCrlEntry {
    device_id: [u8; 32],
    reason: u8,
    revoked_at: U64,
    has_replacement: u8,
    replacement: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Unaligned, Immutable, KnownLayout)]
pub struct WireCrl {
    mesh_id: WireStr<NAME_LEN>,
    version: U64,
    count: U16,
    entries: [WireCrlEntry; MAX_CRL_ENTRIES],
    has_signature: u8,
    signature: [u8; 64],
}

// ---------- 吊销原因映射 ----------
impl RevokeReason {
    pub fn to_u8(&self) -> u8 {
        match self {
            RevokeReason::Compromised => 0,
            RevokeReason::Leaked => 1,
            RevokeReason::Rotated => 2,
            RevokeReason::Admin => 3,
            RevokeReason::Discontinued => 4,
        }
    }

    pub fn from_u8(v: u8) -> Option<RevokeReason> {
        match v {
            0 => Some(RevokeReason::Compromised),
            1 => Some(RevokeReason::Leaked),
            2 => Some(RevokeReason::Rotated),
            3 => Some(RevokeReason::Admin),
            4 => Some(RevokeReason::Discontinued),
            _ => None,
        }
    }
}

// ---------- 证书 / CRL / ServerInfo 双向转换 ----------

impl WireDeviceCert {
    pub fn to_domain(&self) -> Result<DeviceCert, String> {
        let signature = if self.has_signature == 1 {
            Some(sig_b64(&self.signature))
        } else {
            None
        };
        Ok(DeviceCert {
            mesh_id: self.mesh_id.to_string()?,
            version: self.version.get(),
            device_id: key_b64(&self.device_id),
            ik_x: key_b64(&self.ik_x),
            ik_s_pub: key_b64(&self.ik_s_pub),
            allowed_ip: self.allowed_ip.to_string()?,
            valid_from: self.valid_from.get(),
            not_after: self.not_after.get(),
            signature,
        })
    }

    pub fn from_domain(c: &DeviceCert) -> Result<Self, String> {
        let mut w = WireDeviceCert {
            mesh_id: WireStr::empty(),
            version: U32::new(c.version),
            device_id: [0u8; 32],
            ik_x: [0u8; 32],
            ik_s_pub: [0u8; 32],
            allowed_ip: WireStr::empty(),
            valid_from: U64::new(c.valid_from),
            not_after: U64::new(c.not_after),
            has_signature: 0,
            signature: [0u8; 64],
        };
        w.mesh_id.set(&c.mesh_id)?;
        w.device_id = b64_key(&c.device_id)?;
        w.ik_x = b64_key(&c.ik_x)?;
        w.ik_s_pub = b64_key(&c.ik_s_pub)?;
        w.allowed_ip.set(&c.allowed_ip)?;
        if let Some(sig) = &c.signature {
            w.has_signature = 1;
            w.signature = b64_sig(sig)?;
        }
        Ok(w)
    }
}

impl WireServerInfo {
    pub fn to_domain(&self) -> Result<ServerInfo, String> {
        let signature = if self.has_signature == 1 {
            Some(sig_b64(&self.signature))
        } else {
            None
        };
        Ok(ServerInfo {
            mesh_id: self.mesh_id.to_string()?,
            server_name: self.server_name.to_string()?,
            mesh_root_pub: key_b64(&self.mesh_root_pub),
            server_ik_x: key_b64(&self.server_ik_x),
            server_ik_s_pub: key_b64(&self.server_ik_s_pub),
            protocol_ver: self.protocol_ver.get(),
            crl_version: self.crl_version.get(),
            auth_required: self.auth_required != 0,
            signature,
        })
    }

    pub fn from_domain(s: &ServerInfo) -> Result<Self, String> {
        let mut w = WireServerInfo {
            mesh_id: WireStr::empty(),
            server_name: WireStr::empty(),
            mesh_root_pub: [0u8; 32],
            server_ik_x: [0u8; 32],
            server_ik_s_pub: [0u8; 32],
            protocol_ver: U32::new(s.protocol_ver),
            crl_version: U64::new(s.crl_version),
            auth_required: s.auth_required as u8,
            has_signature: 0,
            signature: [0u8; 64],
        };
        w.mesh_id.set(&s.mesh_id)?;
        w.server_name.set(&s.server_name)?;
        w.mesh_root_pub = b64_key(&s.mesh_root_pub)?;
        w.server_ik_x = b64_key(&s.server_ik_x)?;
        w.server_ik_s_pub = b64_key(&s.server_ik_s_pub)?;
        if let Some(sig) = &s.signature {
            w.has_signature = 1;
            w.signature = b64_sig(sig)?;
        }
        Ok(w)
    }
}

impl WireCrlEntry {
    fn to_domain(&self) -> Result<CrlEntry, String> {
        let reason = RevokeReason::from_u8(self.reason)
            .ok_or_else(|| format!("非法吊销原因取值 {}", self.reason))?;
        let replacement = if self.has_replacement == 1 {
            Some(key_b64(&self.replacement))
        } else {
            None
        };
        Ok(CrlEntry {
            device_id: key_b64(&self.device_id),
            reason,
            revoked_at: self.revoked_at.get(),
            replacement,
        })
    }

    fn from_domain(e: &CrlEntry) -> Result<Self, String> {
        let mut w = WireCrlEntry {
            device_id: [0u8; 32],
            reason: e.reason.to_u8(),
            revoked_at: U64::new(e.revoked_at),
            has_replacement: 0,
            replacement: [0u8; 32],
        };
        w.device_id = b64_key(&e.device_id)?;
        if let Some(r) = &e.replacement {
            w.has_replacement = 1;
            w.replacement = b64_key(r)?;
        }
        Ok(w)
    }
}

impl WireCrl {
    pub fn to_domain(&self) -> Result<Crl, String> {
        let count = self.count.get() as usize;
        if count > MAX_CRL_ENTRIES {
            return Err(format!("CRL 条目数越界（{count} > {MAX_CRL_ENTRIES}）"));
        }
        let mut entries = Vec::with_capacity(count);
        for e in &self.entries[..count] {
            entries.push(e.to_domain()?);
        }
        let signature = if self.has_signature == 1 {
            Some(sig_b64(&self.signature))
        } else {
            None
        };
        Ok(Crl {
            mesh_id: self.mesh_id.to_string()?,
            version: self.version.get(),
            entries,
            signature,
        })
    }

    pub fn from_domain(c: &Crl) -> Result<Self, String> {
        if c.entries.len() > MAX_CRL_ENTRIES {
            return Err(format!("CRL 条目数超上限（{} > {MAX_CRL_ENTRIES}）", c.entries.len()));
        }
        let mut w = WireCrl {
            mesh_id: WireStr::empty(),
            version: U64::new(c.version),
            count: U16::new(c.entries.len() as u16),
            entries: [WireCrlEntry {
                device_id: [0u8; 32],
                reason: 0,
                revoked_at: U64::new(0),
                has_replacement: 0,
                replacement: [0u8; 32],
            }; MAX_CRL_ENTRIES],
            has_signature: 0,
            signature: [0u8; 64],
        };
        w.mesh_id.set(&c.mesh_id)?;
        for (i, e) in c.entries.iter().enumerate() {
            w.entries[i] = WireCrlEntry::from_domain(e)?;
        }
        if let Some(sig) = &c.signature {
            w.has_signature = 1;
            w.signature = b64_sig(sig)?;
        }
        Ok(w)
    }
}

// ---------- 各消息的 encode / decode ----------

pub fn encode_register(b: &RegisterBody) -> Result<Vec<u8>, String> {
    encode_impl::<WireRegister>(|w| {
        w.ip.set(&b.ip)?;
        if let Some(rk) = &b.relay_rk {
            w.has_relay_rk = 1;
            w.relay_rk = b64_key(rk)?;
        }
        w.has_token = put_opt_str(&mut w.token, &b.token)? as u8;
        w.has_alias = put_opt_str(&mut w.alias, &b.alias)? as u8;
        Ok(())
    })
}

pub fn decode_register(bytes: &[u8]) -> Result<RegisterBody, String> {
    let w = decode_impl::<WireRegister>(bytes, "RegisterBody")?;
    let mut b = RegisterBody {
        ip: w.ip.to_string()?,
        relay_rk: None,
        token: None,
        alias: None,
    };
    if w.has_relay_rk == 1 {
        b.relay_rk = Some(key_b64(&w.relay_rk));
    }
    if w.has_token == 1 {
        b.token = Some(w.token.to_string()?);
    }
    if w.has_alias == 1 {
        b.alias = Some(w.alias.to_string()?);
    }
    Ok(b)
}

pub fn encode_query(b: &QueryBody) -> Result<Vec<u8>, String> {
    encode_impl::<WireQuery>(|w| {
        w.ip.set(&b.ip)?;
        w.has_name = put_opt_str(&mut w.name, &b.name)? as u8;
        Ok(())
    })
}

pub fn decode_query(bytes: &[u8]) -> Result<QueryBody, String> {
    let w = decode_impl::<WireQuery>(bytes, "QueryBody")?;
    let mut b = QueryBody {
        ip: w.ip.to_string()?,
        name: None,
    };
    if w.has_name == 1 {
        b.name = Some(w.name.to_string()?);
    }
    Ok(b)
}

fn fill_peer_info(w: &mut WirePeerInfo, p: &PeerInfo) -> Result<(), String> {
    w.public_key = b64_key(&p.public_key)?;
    w.endpoint.set(&p.endpoint)?;
    if let Some(rk) = &p.relay_rk {
        w.has_relay_rk = 1;
        w.relay_rk = b64_key(rk)?;
    }
    w.has_alias = put_opt_str(&mut w.alias, &p.alias)? as u8;
    w.has_ip = put_opt_str(&mut w.ip, &p.ip)? as u8;
    Ok(())
}

fn peer_info_from_wire(p: &WirePeerInfo) -> Result<PeerInfo, String> {
    let mut pi = PeerInfo {
        public_key: key_b64(&p.public_key),
        endpoint: p.endpoint.to_string()?,
        relay_rk: None,
        alias: None,
        ip: None,
    };
    if p.has_relay_rk == 1 {
        pi.relay_rk = Some(key_b64(&p.relay_rk));
    }
    if p.has_alias == 1 {
        pi.alias = Some(p.alias.to_string()?);
    }
    if p.has_ip == 1 {
        pi.ip = Some(p.ip.to_string()?);
    }
    Ok(pi)
}

pub fn encode_notify(b: &NotifyBody) -> Result<Vec<u8>, String> {
    encode_impl::<WireNotify>(|w| fill_peer_info(&mut w.peer, &b.peer))
}

pub fn decode_notify(bytes: &[u8]) -> Result<NotifyBody, String> {
    let w = decode_impl::<WireNotify>(bytes, "NotifyBody")?;
    Ok(NotifyBody {
        peer: peer_info_from_wire(&w.peer)?,
    })
}

pub fn encode_response(r: &ResponseBody) -> Result<Vec<u8>, String> {
    match &r.data {
        ResponseData::None => {
            if r.ok {
                Ok(vec![RESP_OK])
            } else {
                let err = r.error.clone().unwrap_or_default();
                let body = encode_impl::<WireRespErr>(|w| w.error.set(&err))?;
                let mut out = Vec::with_capacity(1 + body.len());
                out.push(RESP_ERR);
                out.extend_from_slice(&body);
                Ok(out)
            }
        }
        ResponseData::QueryHit {
            req,
            ip,
            public_key,
            endpoint,
            relay_rk,
            alias,
        } => {
            let body = encode_impl::<WireRespQueryHit>(|w| {
                w.req.set(req)?;
                w.ip.set(ip)?;
                w.public_key = b64_key(public_key)?;
                w.endpoint.set(endpoint)?;
                if let Some(rk) = relay_rk {
                    w.has_relay_rk = 1;
                    w.relay_rk = b64_key(rk)?;
                }
                w.alias.set(alias)?;
                Ok(())
            })?;
            let mut out = Vec::with_capacity(1 + body.len());
            out.push(RESP_QUERY_HIT);
            out.extend_from_slice(&body);
            Ok(out)
        }
        ResponseData::QueryMiss { req, error } => {
            let body = encode_impl::<WireRespQueryMiss>(|w| {
                w.req.set(req)?;
                w.error.set(error)?;
                Ok(())
            })?;
            let mut out = Vec::with_capacity(1 + body.len());
            out.push(RESP_QUERY_MISS);
            out.extend_from_slice(&body);
            Ok(out)
        }
        ResponseData::Join {
            device_id,
            allocated_ip,
            cert,
            server_info,
            crl,
        } => {
            let body = encode_impl::<WireRespJoin>(|w| {
                w.device_id = b64_key(device_id)?;
                w.allocated_ip.set(allocated_ip)?;
                w.cert = WireDeviceCert::from_domain(cert)?;
                w.server_info = WireServerInfo::from_domain(server_info)?;
                w.crl = WireCrl::from_domain(crl)?;
                Ok(())
            })?;
            let mut out = Vec::with_capacity(1 + body.len());
            out.push(RESP_JOIN);
            out.extend_from_slice(&body);
            Ok(out)
        }
    }
}

pub fn decode_response(bytes: &[u8]) -> Result<ResponseBody, String> {
    if bytes.is_empty() {
        return Err("响应为空".into());
    }
    let kind = bytes[0];
    let rest = &bytes[1..];
    match kind {
        RESP_OK => Ok(ResponseBody::ok()),
        RESP_ERR => {
            let w = decode_impl::<WireRespErr>(rest, "RespErr")?;
            Ok(ResponseBody::err(w.error.to_string()?))
        }
        RESP_QUERY_HIT => {
            let w = decode_impl::<WireRespQueryHit>(rest, "RespQueryHit")?;
            Ok(ResponseBody::ok_with_data(ResponseData::QueryHit {
                req: w.req.to_string()?,
                ip: w.ip.to_string()?,
                public_key: key_b64(&w.public_key),
                endpoint: w.endpoint.to_string()?,
                relay_rk: if w.has_relay_rk == 1 {
                    Some(key_b64(&w.relay_rk))
                } else {
                    None
                },
                alias: w.alias.to_string()?,
            }))
        }
        RESP_QUERY_MISS => {
            let w = decode_impl::<WireRespQueryMiss>(rest, "RespQueryMiss")?;
            Ok(ResponseBody {
                ok: false,
                data: ResponseData::QueryMiss {
                    req: w.req.to_string()?,
                    error: w.error.to_string()?,
                },
                error: Some(w.error.to_string()?),
            })
        }
        RESP_JOIN => {
            let w = decode_impl::<WireRespJoin>(rest, "RespJoin")?;
            Ok(ResponseBody::ok_with_data(ResponseData::Join {
                device_id: key_b64(&w.device_id),
                allocated_ip: w.allocated_ip.to_string()?,
                cert: w.cert.to_domain()?,
                server_info: w.server_info.to_domain()?,
                crl: w.crl.to_domain()?,
            }))
        }
        _ => Err(format!("未知响应类型 {kind}")),
    }
}

pub fn encode_join(b: &JoinBody) -> Result<Vec<u8>, String> {
    encode_impl::<WireJoin>(|w| {
        w.code.set(&b.code)?;
        w.device_id = b64_key(&b.device_id)?;
        w.ik_x = b64_key(&b.ik_x)?;
        w.ik_s_pub = b64_key(&b.ik_s_pub)?;
        w.has_requested_ip = put_opt_str(&mut w.requested_ip, &b.requested_ip)? as u8;
        w.has_token = put_opt_str(&mut w.token, &b.token)? as u8;
        w.has_alias = put_opt_str(&mut w.alias, &b.alias)? as u8;
        Ok(())
    })
}

pub fn decode_join(bytes: &[u8]) -> Result<JoinBody, String> {
    let w = decode_impl::<WireJoin>(bytes, "JoinBody")?;
    let mut b = JoinBody {
        code: w.code.to_string()?,
        device_id: key_b64(&w.device_id),
        ik_x: key_b64(&w.ik_x),
        ik_s_pub: key_b64(&w.ik_s_pub),
        requested_ip: None,
        token: None,
        alias: None,
    };
    if w.has_requested_ip == 1 {
        b.requested_ip = Some(w.requested_ip.to_string()?);
    }
    if w.has_token == 1 {
        b.token = Some(w.token.to_string()?);
    }
    if w.has_alias == 1 {
        b.alias = Some(w.alias.to_string()?);
    }
    Ok(b)
}

pub fn encode_auth(b: &AuthBody) -> Result<Vec<u8>, String> {
    encode_impl::<WireAuth>(|w| {
        w.device_id = b64_key(&b.device_id)?;
        w.cert = WireDeviceCert::from_domain(&b.cert)?;
        w.ek_c = b64_key(&b.ek_c)?;
        w.timestamp = U64::new(b.timestamp);
        w.nonce = b64_12(&b.nonce, "nonce")?;
        w.has_token = put_opt_str(&mut w.token, &b.token)? as u8;
        Ok(())
    })
}

pub fn decode_auth(bytes: &[u8]) -> Result<AuthBody, String> {
    let w = decode_impl::<WireAuth>(bytes, "AuthBody")?;
    let mut b = AuthBody {
        device_id: key_b64(&w.device_id),
        cert: w.cert.to_domain()?,
        ek_c: key_b64(&w.ek_c),
        timestamp: w.timestamp.get(),
        nonce: b64_12_enc(&w.nonce),
        token: None,
    };
    if w.has_token == 1 {
        b.token = Some(w.token.to_string()?);
    }
    Ok(b)
}

pub fn encode_auth_resp(b: &AuthRespBody) -> Result<Vec<u8>, String> {
    encode_impl::<WireAuthResp>(|w| {
        w.ek_s = b64_key(&b.ek_s)?;
        w.session_id = b64_sig_to_16(&b.session_id)?;
        w.crl = WireCrl::from_domain(&b.crl)?;
        w.server_info = WireServerInfo::from_domain(&b.server_info)?;
        w.allocated_ip.set(&b.allocated_ip)?;
        Ok(())
    })
}

pub fn decode_auth_resp(bytes: &[u8]) -> Result<AuthRespBody, String> {
    let w = decode_impl::<WireAuthResp>(bytes, "AuthRespBody")?;
    Ok(AuthRespBody {
        ek_s: key_b64(&w.ek_s),
        session_id: key_b64_16(&w.session_id),
        crl: w.crl.to_domain()?,
        server_info: w.server_info.to_domain()?,
        allocated_ip: w.allocated_ip.to_string()?,
    })
}

pub fn encode_server_info_body(b: &ServerInfoBody) -> Result<Vec<u8>, String> {
    encode_impl::<WireServerInfoBody>(|w| {
        w.server_info = WireServerInfo::from_domain(&b.server_info)?;
        Ok(())
    })
}

pub fn decode_server_info_body(bytes: &[u8]) -> Result<ServerInfoBody, String> {
    let w = decode_impl::<WireServerInfoBody>(bytes, "ServerInfoBody")?;
    Ok(ServerInfoBody {
        server_info: w.server_info.to_domain()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{RevokeReason};
    use crate::crypto::generate_keypair;
    use crate::identity::device_id_b64;

    fn sample_cert() -> DeviceCert {
        let dev_ik = generate_keypair();
        let dev_ik_s = crate::identity::SignKeyPairSerde::generate();
        let dev_ik_s_pub = dev_ik_s.parse_public().unwrap();
        let id = device_id_b64(&dev_ik.public, &dev_ik_s_pub);
        DeviceCert {
            mesh_id: "mesh-test".into(),
            version: 3,
            device_id: id,
            ik_x: B64.encode(dev_ik.public),
            ik_s_pub: dev_ik_s.public.clone(),
            allowed_ip: "10.13.13.50".into(),
            valid_from: 1_000_000,
            not_after: 9_000_000_000,
            signature: Some(B64.encode([0xAA; 64])),
        }
    }

    fn sample_server_info() -> ServerInfo {
        ServerInfo {
            mesh_id: "mesh-test".into(),
            server_name: "s1".into(),
            mesh_root_pub: B64.encode([1u8; 32]),
            server_ik_x: B64.encode([2u8; 32]),
            server_ik_s_pub: B64.encode([3u8; 32]),
            protocol_ver: 2,
            crl_version: 3,
            auth_required: true,
            signature: Some(B64.encode([0xBB; 64])),
        }
    }

    fn sample_crl() -> Crl {
        Crl {
            mesh_id: "mesh-test".into(),
            version: 1,
            entries: vec![
                CrlEntry {
                    device_id: B64.encode([7u8; 32]),
                    reason: RevokeReason::Compromised,
                    revoked_at: 1_000_000,
                    replacement: None,
                },
                CrlEntry {
                    device_id: B64.encode([8u8; 32]),
                    reason: RevokeReason::Rotated,
                    revoked_at: 1_000_001,
                    replacement: Some(B64.encode([9u8; 32])),
                },
            ],
            signature: Some(B64.encode([0xCC; 64])),
        }
    }

    #[test]
    fn register_roundtrip() {
        let b = RegisterBody {
            ip: "10.13.13.2".into(),
            relay_rk: Some(B64.encode([1u8; 32])),
            token: Some("tok-123".into()),
            alias: Some("computer".into()),
        };
        let enc = encode_register(&b).unwrap();
        let dec = decode_register(&enc).unwrap();
        assert_eq!(dec.ip, b.ip);
        assert_eq!(dec.relay_rk, b.relay_rk);
        assert_eq!(dec.token, b.token);
        assert_eq!(dec.alias, b.alias);
        // 无可选字段
        let bare = RegisterBody { ip: "10.0.0.1".into(), relay_rk: None, token: None, alias: None };
        let dec2 = decode_register(&encode_register(&bare).unwrap()).unwrap();
        assert!(dec2.relay_rk.is_none());
        assert_eq!(dec2.ip, "10.0.0.1");
    }

    #[test]
    fn query_roundtrip() {
        let b = QueryBody { ip: "10.13.13.9".into(), name: None };
        let dec = decode_query(&encode_query(&b).unwrap()).unwrap();
        assert_eq!(dec.ip, b.ip);
        assert!(dec.name.is_none());

        let b2 = QueryBody { ip: String::new(), name: Some("printer".into()) };
        let dec2 = decode_query(&encode_query(&b2).unwrap()).unwrap();
        assert_eq!(dec2.name.as_deref(), Some("printer"));
    }

    #[test]
    fn peer_info_and_notify_roundtrip() {
        let p = PeerInfo {
            public_key: B64.encode([5u8; 32]),
            endpoint: "1.2.3.4:51820".into(),
            relay_rk: Some(B64.encode([6u8; 32])),
            alias: Some("nas".into()),
            ip: Some("10.13.13.9".into()),
        };
        // PeerInfo 往返经 Notify 编解码验证（PeerInfo 本身不再单独暴露 encode/decode）。
        let n = NotifyBody { peer: p };
        let dn = decode_notify(&encode_notify(&n).unwrap()).unwrap();
        assert_eq!(dn.peer.endpoint, n.peer.endpoint);
        assert_eq!(dn.peer.alias, n.peer.alias);
        assert_eq!(dn.peer.relay_rk, n.peer.relay_rk);
        assert_eq!(dn.peer.ip, n.peer.ip);
        assert_eq!(dn.peer.public_key, n.peer.public_key);
    }

    #[test]
    fn response_all_variants_roundtrip() {
        // Ok
        let ok = ResponseBody::ok();
        let d = decode_response(&encode_response(&ok).unwrap()).unwrap();
        assert!(d.ok);

        // Err
        let err = ResponseBody::err("目标未上线");
        let d = decode_response(&encode_response(&err).unwrap()).unwrap();
        assert!(!d.ok);
        assert_eq!(d.error.as_deref(), Some("目标未上线"));

        // QueryHit
        let hit = ResponseBody::ok_with_data(ResponseData::QueryHit {
            req: "10.13.13.9".into(),
            ip: "10.13.13.9".into(),
            public_key: B64.encode([1u8; 32]),
            endpoint: "9.9.9.9:1".into(),
            relay_rk: Some(B64.encode([2u8; 32])),
            alias: "nas".into(),
        });
        let d = decode_response(&encode_response(&hit).unwrap()).unwrap();
        match d.data {
            ResponseData::QueryHit { req, ip, public_key: _, endpoint, relay_rk, alias } => {
                assert_eq!(req, "10.13.13.9");
                assert_eq!(ip, "10.13.13.9");
                assert_eq!(endpoint, "9.9.9.9:1");
                assert_eq!(relay_rk, Some(B64.encode([2u8; 32])));
                assert_eq!(alias, "nas");
            }
            _ => panic!("应为 QueryHit"),
        }

        // QueryMiss
        let miss = ResponseBody {
            ok: false,
            data: ResponseData::QueryMiss { req: "printer".into(), error: "目标 printer 未上线".into() },
            error: Some("目标 printer 未上线".into()),
        };
        let d = decode_response(&encode_response(&miss).unwrap()).unwrap();
        assert!(!d.ok);
        match d.data {
            ResponseData::QueryMiss { req, error } => {
                assert_eq!(req, "printer");
                assert!(error.contains("printer"));
            }
            _ => panic!("应为 QueryMiss"),
        }

        // Join
        let join = ResponseBody::ok_with_data(ResponseData::Join {
            device_id: B64.encode([3u8; 32]),
            allocated_ip: "10.13.13.50".into(),
            cert: sample_cert(),
            server_info: sample_server_info(),
            crl: sample_crl(),
        });
        let d = decode_response(&encode_response(&join).unwrap()).unwrap();
        match d.data {
            ResponseData::Join { device_id: _, allocated_ip, cert, server_info, crl } => {
                assert_eq!(allocated_ip, "10.13.13.50");
                assert_eq!(cert.mesh_id, "mesh-test");
                assert_eq!(cert.version, 3);
                assert_eq!(cert.allowed_ip, "10.13.13.50");
                assert_eq!(cert.signature.as_deref(), Some(B64.encode([0xAA; 64]).as_str()));
                assert_eq!(server_info.protocol_ver, 2);
                assert_eq!(server_info.crl_version, 3);
                assert_eq!(crl.entries.len(), 2);
                assert_eq!(crl.entries[1].reason, RevokeReason::Rotated);
                assert_eq!(crl.entries[1].replacement.as_deref(), Some(B64.encode([9u8; 32]).as_str()));
            }
            _ => panic!("应为 Join"),
        }
    }

    #[test]
    fn join_roundtrip() {
        let b = JoinBody {
            code: "LMJ-ABCD".into(),
            device_id: B64.encode([1u8; 32]),
            ik_x: B64.encode([2u8; 32]),
            ik_s_pub: B64.encode([3u8; 32]),
            requested_ip: Some("10.13.13.60".into()),
            token: Some("tok".into()),
            alias: Some("pc".into()),
        };
        let d = decode_join(&encode_join(&b).unwrap()).unwrap();
        assert_eq!(d.code, b.code);
        assert_eq!(d.device_id, b.device_id);
        assert_eq!(d.ik_x, b.ik_x);
        assert_eq!(d.ik_s_pub, b.ik_s_pub);
        assert_eq!(d.requested_ip.as_deref(), Some("10.13.13.60"));
        assert_eq!(d.token.as_deref(), Some("tok"));
        assert_eq!(d.alias.as_deref(), Some("pc"));
    }

    #[test]
    fn auth_and_auth_resp_roundtrip() {
        let ab = AuthBody {
            device_id: B64.encode([1u8; 32]),
            cert: sample_cert(),
            ek_c: B64.encode([2u8; 32]),
            timestamp: 1_700_000_000,
            nonce: B64.encode([3u8; 12]),
            token: Some("tok".into()),
        };
        let d = decode_auth(&encode_auth(&ab).unwrap()).unwrap();
        assert_eq!(d.device_id, ab.device_id);
        assert_eq!(d.ek_c, ab.ek_c);
        assert_eq!(d.timestamp, ab.timestamp);
        assert_eq!(d.nonce, ab.nonce);
        assert_eq!(d.token.as_deref(), Some("tok"));
        assert_eq!(d.cert.mesh_id, "mesh-test");
        assert_eq!(d.cert.version, 3);

        let ar = AuthRespBody {
            ek_s: B64.encode([4u8; 32]),
            session_id: B64.encode([5u8; 16]),
            crl: sample_crl(),
            server_info: sample_server_info(),
            allocated_ip: "10.13.13.50".into(),
        };
        let d = decode_auth_resp(&encode_auth_resp(&ar).unwrap()).unwrap();
        assert_eq!(d.ek_s, ar.ek_s);
        assert_eq!(d.session_id, ar.session_id);
        assert_eq!(d.allocated_ip, "10.13.13.50");
        assert_eq!(d.crl.entries.len(), 2);
        assert_eq!(d.server_info.crl_version, 3);
    }

    #[test]
    fn server_info_body_roundtrip() {
        let b = ServerInfoBody {
            server_info: sample_server_info(),
        };
        let d = decode_server_info_body(&encode_server_info_body(&b).unwrap()).unwrap();
        assert_eq!(d.server_info.server_name, "s1");
        assert_eq!(d.server_info.mesh_root_pub, B64.encode([1u8; 32]));
    }

    #[test]
    fn cert_wire_conversion_is_lossless() {
        let c = sample_cert();
        let w = WireDeviceCert::from_domain(&c).unwrap();
        let back = w.to_domain().unwrap();
        assert_eq!(back.mesh_id, c.mesh_id);
        assert_eq!(back.version, c.version);
        assert_eq!(back.device_id, c.device_id);
        assert_eq!(back.ik_x, c.ik_x);
        assert_eq!(back.ik_s_pub, c.ik_s_pub);
        assert_eq!(back.allowed_ip, c.allowed_ip);
        assert_eq!(back.valid_from, c.valid_from);
        assert_eq!(back.not_after, c.not_after);
        assert_eq!(back.signature, c.signature);

        let si = sample_server_info();
        let back = WireServerInfo::from_domain(&si).unwrap().to_domain().unwrap();
        assert_eq!(back.mesh_id, si.mesh_id);
        assert_eq!(back.server_ik_s_pub, si.server_ik_s_pub);
        assert_eq!(back.signature, si.signature);
        assert_eq!(back.auth_required, si.auth_required);

        let crl = sample_crl();
        let back = WireCrl::from_domain(&crl).unwrap().to_domain().unwrap();
        assert_eq!(back.mesh_id, crl.mesh_id);
        assert_eq!(back.version, crl.version);
        assert_eq!(back.entries.len(), 2);
        assert_eq!(back.entries[1].replacement, crl.entries[1].replacement);
        assert_eq!(back.signature, crl.signature);
    }

    #[test]
    fn malformed_inputs_rejected() {
        // 空字节 / 截断
        assert!(decode_register(&[]).is_err());
        assert!(decode_query(&[0u8; 5]).is_err());
        assert!(decode_response(&[]).is_err());
        // 未知响应类型
        assert!(decode_response(&[0xFF, 0, 0]).is_err());
        // 尾部多余数据
        let enc = encode_register(&RegisterBody {
            ip: "10.0.0.1".into(), relay_rk: None, token: None, alias: None,
        }).unwrap();
        let mut padded = enc.clone();
        padded.push(0);
        assert!(decode_register(&padded).is_err());
        // 非法 base64 字段（密钥）编码失败
        let bad = RegisterBody { ip: "10.0.0.1".into(), relay_rk: Some("!!bad!!".into()), token: None, alias: None };
        assert!(encode_register(&bad).is_err());
        // 超长文本字段编码失败
        let too_long = RegisterBody { ip: "x".repeat(1000), relay_rk: None, token: None, alias: None };
        assert!(encode_register(&too_long).is_err());
    }
}
