use aes::Aes256;
use cbc::Decryptor;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::dpapi::DpapiError;

/// Decrypt an AES-256-CBC ciphertext.
pub fn decrypt_aes256_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let mut buf = ciphertext.to_vec();
    let decryptor =
        Decryptor::<Aes256>::new_from_slices(key, iv).map_err(|_| DpapiError::InvalidKeyLength)?;
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| DpapiError::DecryptionFailed)?;
    Ok(plaintext.to_vec())
}

/// Verify HMAC-SHA1 over `data` using `key`; return Err if mismatch.
pub fn verify_hmac_sha1(key: &[u8], data: &[u8], expected: &[u8]) -> Result<(), DpapiError> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| DpapiError::InvalidKeyLength)?;
    mac.update(data);
    mac.verify_slice(expected)
        .map_err(|_| DpapiError::HmacMismatch)
}

/// Decrypt a DPAPI blob using the provided master key bytes.
/// Derives session key via HMAC-SHA1(master_key, blob.hmac_key), expands it,
/// then decrypts with AES-256-CBC or 3DES-CBC depending on alg_id_encrypt.
pub fn decrypt_dpapi_blob(
    blob: &crate::dpapi::dpapi_blob::DpapiBlob,
    master_key: &[u8],
    _entropy: Option<&[u8]>,
) -> Result<Vec<u8>, DpapiError> {
    // Derive session key: HMAC-SHA1(master_key, hmac_key_from_blob)
    let mut mac =
        Hmac::<Sha1>::new_from_slice(master_key).map_err(|_| DpapiError::InvalidKeyLength)?;
    mac.update(&blob.hmac_key);
    let session_key = mac.finalize().into_bytes();

    match blob.alg_id_encrypt {
        0x6610 => {
            // AES-256-CBC: needs 32-byte key + 16-byte IV
            let key_material = expand_key(&session_key, 48);
            decrypt_aes256_cbc(&key_material[..32], &key_material[32..48], &blob.ciphertext)
        }
        0x6603 => {
            // 3DES-CBC: 24-byte key + 8-byte IV
            decrypt_3des_cbc(&session_key, &blob.ciphertext)
        }
        id => Err(DpapiError::UnsupportedAlgId(id)),
    }
}

/// SHA1-based counter-mode key expansion (NIST SP800-108 simplified).
fn expand_key(seed: &[u8], needed: usize) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    let mut out = Vec::new();
    let mut counter = 1u32;
    while out.len() < needed {
        let mut h = Sha1::new();
        h.update(counter.to_le_bytes());
        h.update(seed);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(needed);
    out
}

fn decrypt_3des_cbc(key_material: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    use cbc::Decryptor as CbcDec;
    use cipher::block_padding::NoPadding;
    use des::TdesEde3;

    // Expand seed to 32 bytes (24 key + 8 IV)
    let expanded = expand_key(key_material, 32);
    let key = &expanded[..24];
    let iv = &expanded[24..32];
    let mut buf = ciphertext.to_vec();
    let dec =
        CbcDec::<TdesEde3>::new_from_slices(key, iv).map_err(|_| DpapiError::InvalidKeyLength)?;
    let out = dec
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| DpapiError::DecryptionFailed)?;
    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes256;
    use cbc::Encryptor;
    use cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

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
        let iv = [0x11u8; 16];
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

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Tier-1 vector: blob minted on Windows, master key recovered with mimikatz,
    // plaintext authored & confirmed by impacket 0.12.0 (DPAPI_BLOB.decrypt).
    // hashAlgo=0x800e (SHA512), cryptAlgo=0x6610 (AES-256-CBC), no entropy.
    const MASTER_KEY_HEX: &str = "9828d9873735439e823dbd216205ff88266d28ad685a413970c640d5ee943154bbade31fada673d542c72d707a163bb3d1bceb0c50465b359ae06998481b0ce3";
    const VECTOR1_BLOB_HEX: &str = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc6000000000200000000001066000000010000200000000d1af96e5e102266fd36d96ac7d1595552e5a4e972463f77e6e227f22d5fc8df000000000e8000000002000020000000834f3c5710c8a7474f7dbcea8ba28ab8e4d4443f50a0c63ff4eba1cce485295f20000000b61d7576c0c6caf3690edb247bde3f7edaa59580e3b4be1265ea78e8c1b8a61d400000001c03ab807147742649b6bdfd1c1344d178bb163842d70abacfd51233af909cb81a677ec05d8db996f587ef5ac410dc189beda756eb0d1b6ee376823e80968538";

    #[test]
    fn decrypt_sha512_aes256_blob_no_entropy() {
        let blob =
            crate::dpapi::dpapi_blob::parse_dpapi_blob(&hex(VECTOR1_BLOB_HEX)).expect("parse");
        let mk = hex(MASTER_KEY_HEX);
        let pt = decrypt_dpapi_blob(&blob, &mk, None).expect("decrypt");
        assert_eq!(pt, b"Some test string");
    }
}
