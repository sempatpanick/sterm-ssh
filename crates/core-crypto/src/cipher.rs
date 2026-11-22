use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{kdf::SecretKey, CryptoError, CryptoResult};

pub const NONCE_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Builds structured Associated Data (AAD) binding ciphertext to its record identity.
pub fn build_record_aad(entity_id: &str, entity_type: &str, schema_version: u32) -> Vec<u8> {
    format!("sterm:v{schema_version}:{entity_type}:{entity_id}").into_bytes()
}

pub fn encrypt_aead(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> CryptoResult<EncryptedBlob> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Encrypt)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(EncryptedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt_aead(
    key: &SecretKey,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    if nonce_bytes.len() != NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength(nonce_bytes.len()));
    }
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(Zeroizing::new(plaintext))
}

/// Wraps a 32-byte DEK with the master-password-derived Vault Key.
pub fn wrap_dek(vault_key: &SecretKey, dek: &SecretKey) -> CryptoResult<Vec<u8>> {
    let blob = encrypt_aead(vault_key, dek.as_bytes(), b"sterm-wrapped-dek-v1")?;
    let mut out = Vec::with_capacity(NONCE_LEN + blob.ciphertext.len());
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.ciphertext);
    Ok(out)
}

/// Unwraps a 32-byte DEK using the master-password-derived Vault Key.
pub fn unwrap_dek(vault_key: &SecretKey, wrapped: &[u8]) -> CryptoResult<SecretKey> {
    if wrapped.len() <= NONCE_LEN {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ciphertext) = wrapped.split_at(NONCE_LEN);
    let plain = decrypt_aead(vault_key, nonce, ciphertext, b"sterm-wrapped-dek-v1")?;
    SecretKey::from_slice(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_keys, generate_salt, KdfParams};

    #[test]
    fn roundtrip_and_tamper_detection() {
        let key = SecretKey::generate();
        let aad = build_record_aad("01900000-0000-7000-8000-000000000001", "host", 1);
        let msg = b"{\"hostname\":\"prod.example.com\",\"port\":22}";

        let blob = encrypt_aead(&key, msg, &aad).expect("encrypt");
        let plain = decrypt_aead(&key, &blob.nonce, &blob.ciphertext, &aad).expect("decrypt");
        assert_eq!(plain.as_slice(), msg);

        // Tamper with AAD -> must fail
        let wrong_aad = build_record_aad("01900000-0000-7000-8000-000000000002", "host", 1);
        assert!(decrypt_aead(&key, &blob.nonce, &blob.ciphertext, &wrong_aad).is_err());

        // Tamper with ciphertext -> must fail
        let mut tampered = blob.ciphertext.clone();
        tampered[0] ^= 0xff;
        assert!(decrypt_aead(&key, &blob.nonce, &tampered, &aad).is_err());
    }

    #[test]
    fn dek_wrap_and_domain_separation() {
        let salt = generate_salt();
        let ephemeral_input = format!("kdf-fixture-{salt:02x?}");
        let derived = derive_keys(&ephemeral_input, &salt, &KdfParams::fast_for_tests())
            .expect("kdf");

        assert_ne!(derived.vault_key.as_bytes(), derived.auth_key.as_bytes());

        let dek = SecretKey::generate();
        let wrapped = wrap_dek(&derived.vault_key, &dek).expect("wrap");

        // Auth key must NOT unwrap the DEK
        assert!(unwrap_dek(&derived.auth_key, &wrapped).is_err());

        let unwrapped = unwrap_dek(&derived.vault_key, &wrapped).expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }
}
