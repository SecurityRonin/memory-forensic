use crate::DpapiError;

/// Decrypt an AES-256-CBC ciphertext.
pub fn decrypt_aes256_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    todo!()
}

/// Verify HMAC-SHA1 over `data` using `key`; return Err if mismatch.
pub fn verify_hmac_sha1(key: &[u8], data: &[u8], expected: &[u8]) -> Result<(), DpapiError> {
    todo!()
}

/// Decrypt a DPAPI blob using the provided master key bytes.
/// Verifies HMAC before decrypting.
pub fn decrypt_dpapi_blob(
    blob: &crate::dpapi_blob::DpapiBlob,
    master_key: &[u8],
) -> Result<Vec<u8>, DpapiError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes256;
    use cbc::Encryptor;
    use cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

    fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let enc = Encryptor::<Aes256>::new_from_slices(key, iv).unwrap();
        let mut buf = plaintext.to_vec();
        // pad to 16-byte boundary
        let pad_len = 16 - (buf.len() % 16);
        buf.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        enc.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
           .unwrap()
           .to_vec()
    }

    #[test]
    fn decrypt_aes256_cbc_roundtrip() {
        let key = [0x42u8; 32];
        let iv  = [0x11u8; 16];
        let plaintext = b"hello DPAPI world!";
        let ciphertext = aes256_cbc_encrypt(&key, &iv, plaintext);
        let recovered = decrypt_aes256_cbc(&key, &iv, &ciphertext).expect("decrypt ok");
        assert_eq!(&recovered[..plaintext.len()], plaintext);
    }

    #[test]
    fn verify_hmac_sha1_correct_passes() {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let key = b"secretkey";
        let data = b"some data to mac";
        let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
        mac.update(data);
        let expected = mac.finalize().into_bytes();
        assert!(verify_hmac_sha1(key, data, &expected).is_ok());
    }

    #[test]
    fn verify_hmac_sha1_wrong_key_fails() {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let data = b"data";
        let mut mac = Hmac::<Sha1>::new_from_slice(b"key1").unwrap();
        mac.update(data);
        let expected = mac.finalize().into_bytes();
        assert!(verify_hmac_sha1(b"key2", data, &expected).is_err());
    }
}
