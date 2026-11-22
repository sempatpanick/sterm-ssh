use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, CryptoResult};

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;

const VAULT_KEY_INFO: &[u8] = b"sterm-vault-key-v1";
const AUTH_KEY_INFO: &[u8] = b"sterm-auth-key-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 65_536, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    /// Fast parameters strictly for unit tests.
    pub fn fast_for_tests() -> Self {
        Self {
            m_cost_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_LEN,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

pub struct DerivedKeys {
    /// Never leaves the local device; wraps/unwraps the random Vault DEK.
    pub vault_key: SecretKey,
    /// Sent to the optional sync server during login/register (re-hashed server-side).
    pub auth_key: SecretKey,
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derives a master secret via Argon2id, then domain-separates `vault_key` and `auth_key`
/// using HKDF-SHA256 so server authentication credentials can never decrypt vault records.
pub fn derive_keys(
    master_password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> CryptoResult<DerivedKeys> {
    let argon_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut master_secret = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut master_secret)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let hk = Hkdf::<Sha256>::new(Some(salt), &master_secret);
    let mut vault_bytes = [0u8; KEY_LEN];
    let mut auth_bytes = [0u8; KEY_LEN];

    hk.expand(VAULT_KEY_INFO, &mut vault_bytes)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    hk.expand(AUTH_KEY_INFO, &mut auth_bytes)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    master_secret.zeroize();

    Ok(DerivedKeys {
        vault_key: SecretKey(vault_bytes),
        auth_key: SecretKey(auth_bytes),
    })
}
