use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use keyring::Entry;

use crate::{kdf::SecretKey, CryptoError, CryptoResult};

const SERVICE_NAME: &str = "app.sterm.ssh";
const VAULT_KEY_USER: &str = "local-vault-key";
const SYNC_TOKEN_USER: &str = "sync-refresh-token";

pub fn store_vault_key_in_os_keychain(key: &SecretKey) -> CryptoResult<()> {
    let entry = Entry::new(SERVICE_NAME, VAULT_KEY_USER)
        .map_err(|e| CryptoError::Keychain(e.to_string()))?;
    let encoded = B64.encode(key.as_bytes());
    entry
        .set_password(&encoded)
        .map_err(|e| CryptoError::Keychain(e.to_string()))
}

pub fn load_vault_key_from_os_keychain() -> CryptoResult<Option<SecretKey>> {
    let entry = Entry::new(SERVICE_NAME, VAULT_KEY_USER)
        .map_err(|e| CryptoError::Keychain(e.to_string()))?;
    match entry.get_password() {
        Ok(encoded) => {
            let bytes = B64
                .decode(encoded.trim())
                .map_err(|e| CryptoError::Keychain(e.to_string()))?;
            Ok(Some(SecretKey::from_slice(&bytes)?))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(CryptoError::Keychain(e.to_string())),
    }
}

pub fn clear_vault_key_from_os_keychain() -> CryptoResult<()> {
    let entry = Entry::new(SERVICE_NAME, VAULT_KEY_USER)
        .map_err(|e| CryptoError::Keychain(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(CryptoError::Keychain(e.to_string())),
    }
}

pub fn store_sync_secret(value: &str) -> CryptoResult<()> {
    let entry = Entry::new(SERVICE_NAME, SYNC_TOKEN_USER)
        .map_err(|e| CryptoError::Keychain(e.to_string()))?;
    entry
        .set_password(value)
        .map_err(|e| CryptoError::Keychain(e.to_string()))
}

pub fn load_sync_secret() -> CryptoResult<Option<String>> {
    let entry = Entry::new(SERVICE_NAME, SYNC_TOKEN_USER)
        .map_err(|e| CryptoError::Keychain(e.to_string()))?;
    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(CryptoError::Keychain(e.to_string())),
    }
}

pub fn clear_sync_secret() -> CryptoResult<()> {
    let entry = Entry::new(SERVICE_NAME, SYNC_TOKEN_USER)
        .map_err(|e| CryptoError::Keychain(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(CryptoError::Keychain(e.to_string())),
    }
}
