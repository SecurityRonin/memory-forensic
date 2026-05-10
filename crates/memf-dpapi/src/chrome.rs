use crate::DpapiError;

/// How a Chrome/Chromium cookie value is encoded in heap memory.
#[derive(Debug, PartialEq)]
pub enum ChromeCookieEncoding {
    /// Plaintext — no encryption prefix detected.
    Raw,
    /// Classic DPAPI blob (prefix `DPAPI`, 5 bytes). Windows 7 / no App-Bound.
    DpapiBlob(Vec<u8>),
    /// AES-256-GCM v10: `v10` + 12-byte nonce + ciphertext + 16-byte tag.
    V10 { nonce: [u8; 12], ciphertext: Vec<u8> },
    /// AES-256-GCM v20 (Chrome 127+): same wire format as v10.
    V20 { nonce: [u8; 12], ciphertext: Vec<u8> },
}

/// Detect the encoding of a raw `encrypted_value` blob from Chrome's Cookies DB.
pub fn detect_chrome_cookie_encoding(data: &[u8]) -> ChromeCookieEncoding {
    todo!()
}

/// Decrypt a v10/v20 AES-256-GCM cookie value.
/// `key` is the 32-byte AES key from Chrome's `Local State` (already decrypted).
pub fn decrypt_v10_cookie(
    nonce: &[u8; 12],
    ciphertext: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, DpapiError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_v10_prefix() {
        let mut data = vec![0u8; 20];
        data[0..3].copy_from_slice(b"v10");
        let enc = detect_chrome_cookie_encoding(&data);
        assert!(matches!(enc, ChromeCookieEncoding::V10 { .. }));
    }

    #[test]
    fn detect_v20_prefix() {
        let mut data = vec![0u8; 20];
        data[0..3].copy_from_slice(b"v20");
        let enc = detect_chrome_cookie_encoding(&data);
        assert!(matches!(enc, ChromeCookieEncoding::V20 { .. }));
    }

    #[test]
    fn detect_dpapi_prefix() {
        let data = b"DPAPI\x00\x01\x02\x03".to_vec();
        let enc = detect_chrome_cookie_encoding(&data);
        assert!(matches!(enc, ChromeCookieEncoding::DpapiBlob(_)));
    }

    #[test]
    fn detect_plaintext_is_raw() {
        let enc = detect_chrome_cookie_encoding(b"plaintext_value");
        assert_eq!(enc, ChromeCookieEncoding::Raw);
    }

    #[test]
    fn decrypt_v10_roundtrip() {
        use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Nonce}};
        let key = [0x42u8; 32];
        let nonce_bytes = [0x11u8; 12];
        let plaintext = b"session_token_value";
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let recovered = decrypt_v10_cookie(&nonce_bytes, &ciphertext, &key).expect("ok");
        assert_eq!(recovered, plaintext);
    }
}
