use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, Certificate, HashAlg, LineEnding, PrivateKey};

use crate::{CryptoError, CryptoResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedKeypair {
    pub algorithm: String,
    pub private_key_openssh: String,
    pub public_key_openssh: String,
    pub fingerprint_sha256: String,
}

/// Generates a new Ed25519 SSH keypair in OpenSSH format, optionally encrypted with a passphrase.
pub fn generate_ed25519_keypair(
    comment: &str,
    passphrase: Option<&str>,
) -> CryptoResult<GeneratedKeypair> {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| CryptoError::SshKey(e.to_string()))?;
    key.set_comment(comment);

    let public_key_openssh = key
        .public_key()
        .to_openssh()
        .map_err(|e| CryptoError::SshKey(e.to_string()))?;

    let fingerprint_sha256 = key.public_key().fingerprint(HashAlg::Sha256).to_string();

    let encoded_private = match passphrase {
        Some(pass) if !pass.is_empty() => key
            .encrypt(&mut OsRng, pass)
            .map_err(|e| CryptoError::SshKey(e.to_string()))?
            .to_openssh(LineEnding::LF)
            .map_err(|e| CryptoError::SshKey(e.to_string()))?,
        _ => key
            .to_openssh(LineEnding::LF)
            .map_err(|e| CryptoError::SshKey(e.to_string()))?,
    };

    Ok(GeneratedKeypair {
        algorithm: "ssh-ed25519".to_string(),
        private_key_openssh: encoded_private.to_string(),
        public_key_openssh,
        fingerprint_sha256,
    })
}

/// Inspects an existing OpenSSH private key (encrypted or unencrypted) and extracts
/// its public key and SHA-256 fingerprint.
pub fn inspect_private_key(
    private_key_pem: &str,
    passphrase: Option<&str>,
) -> CryptoResult<(String, String)> {
    let parsed = PrivateKey::from_openssh(private_key_pem)
        .map_err(|e| CryptoError::SshKey(e.to_string()))?;

    let unlocked = if parsed.is_encrypted() {
        let pass = passphrase.ok_or_else(|| {
            CryptoError::SshKey("private key is encrypted; passphrase required".into())
        })?;
        parsed
            .decrypt(pass)
            .map_err(|e| CryptoError::SshKey(format!("invalid passphrase: {e}")))?
    } else {
        parsed
    };

    let pub_key = unlocked
        .public_key()
        .to_openssh()
        .map_err(|e| CryptoError::SshKey(e.to_string()))?;
    let fp = unlocked
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    Ok((pub_key, fp))
}

/// Validates an OpenSSH user certificate (`*-cert-v01@openssh.com ...`) and returns its SHA-256 fingerprint.
pub fn inspect_openssh_certificate(certificate_openssh: &str) -> CryptoResult<String> {
    let trimmed = certificate_openssh.trim();
    if trimmed.is_empty() {
        return Err(CryptoError::SshKey(
            "OpenSSH certificate is empty".into(),
        ));
    }
    let cert = Certificate::from_openssh(trimmed)
        .map_err(|e| CryptoError::SshKey(format!("invalid OpenSSH certificate: {e}")))?;
    Ok(cert.public_key().fingerprint(HashAlg::Sha256).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_inspects_ed25519_keypair() {
        let kp = generate_ed25519_keypair("test@sterm", Some("pass123")).expect("keygen");
        assert!(kp.public_key_openssh.starts_with("ssh-ed25519 "));
        assert!(kp.fingerprint_sha256.starts_with("SHA256:"));

        let (pub_k, fp) =
            inspect_private_key(&kp.private_key_openssh, Some("pass123")).expect("inspect");
        assert_eq!(pub_k, kp.public_key_openssh);
        assert_eq!(fp, kp.fingerprint_sha256);

        assert!(inspect_private_key(&kp.private_key_openssh, Some("wrong")).is_err());
    }
}
