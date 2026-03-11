use crate::error::{PbringError, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

const KEYCHAIN_SERVICE: &str = "com.pbring.encryption-key";
const KEYCHAIN_ACCOUNT: &str = "pbring";
const NONCE_SIZE: usize = 12;

pub struct EncryptionKey {
    key: Zeroizing<[u8; 32]>,
}

impl EncryptionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(bytes),
        }
    }

    pub fn load_or_create() -> Result<Self> {
        match Self::load_from_keychain() {
            Ok(key) => Ok(key),
            Err(PbringError::KeychainLocked) => Err(PbringError::KeychainLocked),
            Err(_) => {
                let key = Self::generate();
                key.save_to_keychain()?;
                Ok(key)
            }
        }
    }

    fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self {
            key: Zeroizing::new(bytes),
        }
    }

    fn load_from_keychain() -> Result<Self> {
        use std::process::Command;

        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                KEYCHAIN_ACCOUNT,
                "-w",
            ])
            .output()
            .map_err(|e| PbringError::Keychain(format!("failed to run security command: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("could not be found") || stderr.contains("SecKeychainSearchCopyNext") {
                return Err(PbringError::Keychain("key not found in keychain".into()));
            }
            if stderr.contains("User interaction is not allowed")
                || stderr.contains("errSecInteractionNotAllowed")
            {
                return Err(PbringError::KeychainLocked);
            }
            return Err(PbringError::Keychain(format!(
                "security command failed: {stderr}"
            )));
        }

        let b64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
        use base64_decode;
        let decoded = base64_decode(&b64)?;

        if decoded.len() != 32 {
            return Err(PbringError::Keychain(format!(
                "invalid key length: {} (expected 32)",
                decoded.len()
            )));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        // Zeroize the decoded vec
        let mut decoded = decoded;
        zeroize::Zeroize::zeroize(&mut decoded[..]);

        Ok(Self {
            key: Zeroizing::new(bytes),
        })
    }

    fn save_to_keychain(&self) -> Result<()> {
        use std::process::Command;

        let b64 = base64_encode(&self.key[..]);

        // Try to delete existing entry first (ignore errors)
        let _ = Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                KEYCHAIN_ACCOUNT,
            ])
            .output();

        let output = Command::new("security")
            .args([
                "add-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                KEYCHAIN_ACCOUNT,
                "-w",
                &b64,
            ])
            .output()
            .map_err(|e| PbringError::Keychain(format!("failed to run security command: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PbringError::Keychain(format!(
                "failed to save key to keychain: {stderr}"
            )));
        }

        Ok(())
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new_from_slice(&self.key[..])
            .map_err(|e| PbringError::Crypto(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| PbringError::Crypto(e.to_string()))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key[..])
            .map_err(|e| PbringError::Crypto(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| PbringError::Crypto(e.to_string()))?;

        Ok(Zeroizing::new(plaintext))
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    fn char_to_val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let input = input.trim();
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut result = Vec::new();

    for chunk in bytes.chunks(4) {
        let vals: Vec<u8> = chunk
            .iter()
            .filter_map(|&b| char_to_val(b))
            .collect();

        if vals.is_empty() {
            continue;
        }

        match vals.len() {
            4 => {
                result.push((vals[0] << 2) | (vals[1] >> 4));
                result.push((vals[1] << 4) | (vals[2] >> 2));
                result.push((vals[2] << 6) | vals[3]);
            }
            3 => {
                result.push((vals[0] << 2) | (vals[1] >> 4));
                result.push((vals[1] << 4) | (vals[2] >> 2));
            }
            2 => {
                result.push((vals[0] << 2) | (vals[1] >> 4));
            }
            _ => {
                return Err(PbringError::Crypto(format!(
                    "invalid base64 chunk length: {}",
                    vals.len()
                )));
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = EncryptionKey::from_bytes([42u8; 32]);
        let plaintext = b"Hello, clipboard!";

        let (ciphertext, nonce) = key.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = key.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let key = EncryptionKey::from_bytes([42u8; 32]);
        let plaintext = b"same data";

        let (ct1, n1) = key.encrypt(plaintext).unwrap();
        let (ct2, n2) = key.encrypt(plaintext).unwrap();

        assert_ne!(n1, n2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = EncryptionKey::from_bytes([1u8; 32]);
        let key2 = EncryptionKey::from_bytes([2u8; 32]);

        let (ciphertext, nonce) = key1.encrypt(b"secret").unwrap();
        let result = key2.decrypt(&ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World! 123";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_empty() {
        let encoded = base64_encode(b"");
        let decoded = base64_decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_encrypt_empty() {
        let key = EncryptionKey::from_bytes([42u8; 32]);
        let (ct, nonce) = key.encrypt(b"").unwrap();
        let decrypted = key.decrypt(&ct, &nonce).unwrap();
        assert!(decrypted.is_empty());
    }
}
