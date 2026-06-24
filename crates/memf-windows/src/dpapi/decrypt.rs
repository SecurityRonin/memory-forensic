use aes::Aes256;
use cbc::Decryptor;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha512;

use crate::dpapi::dpapi_blob::{hash_alg, HashAlg};
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

/// Cipher (encryption algorithm) parameters from the blob's `alg_id_encrypt`.
///
/// `key_len`/`iv_len` are the cipher's key and IV sizes. The IV is always zeros
/// (impacket: `iv=b'\x00'*IVLen`).
struct CryptAlg {
    key_len: usize,
    iv_len: usize,
    block_len: usize,
    is_aes256: bool,
}

fn crypt_alg(alg_id_encrypt: u32) -> Option<CryptAlg> {
    match alg_id_encrypt {
        0x6610 => Some(CryptAlg {
            key_len: 32,
            iv_len: 16,
            block_len: 16,
            is_aes256: true,
        }),
        0x6603 => Some(CryptAlg {
            key_len: 24,
            iv_len: 8,
            block_len: 8,
            is_aes256: false,
        }),
        _ => None,
    }
}

/// Keyed HMAC over `msg` selecting SHA1 or SHA512 by `alg`.
fn hmac_hash(alg: HashAlg, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, DpapiError> {
    if alg.is_sha512 {
        let mut mac =
            Hmac::<Sha512>::new_from_slice(key).map_err(|_| DpapiError::InvalidKeyLength)?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    } else {
        let mut mac =
            Hmac::<Sha1>::new_from_slice(key).map_err(|_| DpapiError::InvalidKeyLength)?;
        mac.update(msg);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

/// Plain (unkeyed) hash digest selecting SHA1 or SHA512 by `alg`.
fn plain_hash(alg: HashAlg, msg: &[u8]) -> Vec<u8> {
    if alg.is_sha512 {
        Sha512::digest(msg).to_vec()
    } else {
        Sha1::digest(msg).to_vec()
    }
}

/// impacket `DPAPI_BLOB.deriveKey`: derive the cipher key from the session key.
///
/// When the session key is longer than the hash's derive block, it is re-MACed;
/// when the resulting key is shorter than the cipher key length, it is expanded
/// via the ipad/opad construction (with DES parity fix-up applied to the bytes).
fn derive_key(alg: HashAlg, session_key: &[u8], cipher_key_len: usize) -> Vec<u8> {
    let mut derived = if session_key.len() > alg.derive_block_len {
        // HMAC with an empty message, keyed by the session key.
        hmac_hash(alg, session_key, &[]).unwrap_or_default()
    } else {
        session_key.to_vec()
    };

    if derived.len() < cipher_key_len {
        let mut padded = derived.clone();
        padded.resize(alg.derive_block_len, 0);
        let ipad: Vec<u8> = padded
            .iter()
            .take(alg.derive_block_len)
            .map(|b| b ^ 0x36)
            .collect();
        let opad: Vec<u8> = padded
            .iter()
            .take(alg.derive_block_len)
            .map(|b| b ^ 0x5c)
            .collect();
        let mut out = plain_hash(alg, &ipad);
        out.extend_from_slice(&plain_hash(alg, &opad));
        fixparity(&mut out);
        derived = out;
    }

    derived
}

/// DES odd-parity fix-up: set each byte's low bit so the byte has odd parity,
/// matching impacket's `fixparity`.
fn fixparity(key: &mut [u8]) {
    for b in key.iter_mut() {
        let high7 = *b >> 1;
        let ones = high7.count_ones();
        *b = (high7 << 1) | u8::from(ones % 2 == 0);
    }
}

/// Decrypt a DPAPI blob with the provided master-key bytes (and optional entropy).
///
/// Implements impacket's `DPAPI_BLOB.decrypt`:
/// `keyHash = SHA1(master_key)`; `sessionKey = HMAC_H(keyHash, salt[||entropy])`
/// where `H` is SHA1 for `algId` 0x8004 and SHA512 for 0x8009/0x800e;
/// the cipher key is `deriveKey(sessionKey)`; the IV is all zeros. The trailing
/// `Sign` HMAC is verified (either impacket integrity formula) before returning.
pub fn decrypt_dpapi_blob(
    blob: &crate::dpapi::dpapi_blob::DpapiBlob,
    master_key: &[u8],
    entropy: Option<&[u8]>,
) -> Result<Vec<u8>, DpapiError> {
    let alg = hash_alg(blob.alg_id_hash);
    let cipher =
        crypt_alg(blob.alg_id_encrypt).ok_or(DpapiError::UnsupportedAlgId(blob.alg_id_encrypt))?;

    // keyHash = SHA1(master_key) — always SHA1, even for SHA512 blobs.
    let key_hash = Sha1::digest(master_key).to_vec();

    // sessionKey = HMAC_H(keyHash, salt [|| entropy])
    let mut salt_msg = blob.salt.clone();
    if let Some(e) = entropy {
        salt_msg.extend_from_slice(e);
    }
    let session_key = hmac_hash(alg, &key_hash, &salt_msg)?;

    let derived = derive_key(alg, &session_key, cipher.key_len);
    if derived.len() < cipher.key_len {
        return Err(DpapiError::InvalidKeyLength);
    }
    let iv = vec![0u8; cipher.iv_len];

    let cleartext = if cipher.is_aes256 {
        decrypt_aes256_cbc(&derived[..cipher.key_len], &iv, &blob.ciphertext)?
    } else {
        decrypt_3des_cbc(&derived[..cipher.key_len], &iv, &blob.ciphertext)?
    };

    verify_blob_signature(&alg, &key_hash, blob, entropy)?;
    let _ = cipher.block_len;
    Ok(cleartext)
}

/// Verify the blob's trailing `Sign` HMAC against impacket's two accepted forms.
fn verify_blob_signature(
    alg: &HashAlg,
    key_hash: &[u8],
    blob: &crate::dpapi::dpapi_blob::DpapiBlob,
    entropy: Option<&[u8]>,
) -> Result<(), DpapiError> {
    // Form 1: manual ipad/opad over keyHash padded to the hash block size.
    let mut key_hash2 = key_hash.to_vec();
    key_hash2.resize(key_hash.len() + alg.hash_block_len, 0);
    let ipad: Vec<u8> = key_hash2
        .iter()
        .take(alg.hash_block_len)
        .map(|b| b ^ 0x36)
        .collect();
    let opad: Vec<u8> = key_hash2
        .iter()
        .take(alg.hash_block_len)
        .map(|b| b ^ 0x5c)
        .collect();

    let mut inner = ipad;
    inner.extend_from_slice(&blob.hmac);
    let inner_digest = plain_hash(*alg, &inner);

    let mut outer = opad;
    outer.extend_from_slice(&inner_digest);
    if let Some(e) = entropy {
        outer.extend_from_slice(e);
    }
    outer.extend_from_slice(&blob.to_sign);
    let calc1 = plain_hash(*alg, &outer);

    // Form 2: standard HMAC_H(keyHash, HMac [|| entropy] || toSign).
    let mut msg2 = blob.hmac.clone();
    if let Some(e) = entropy {
        msg2.extend_from_slice(e);
    }
    msg2.extend_from_slice(&blob.to_sign);
    let calc2 = hmac_hash(*alg, key_hash, &msg2)?;

    if calc1 == blob.sign || calc2 == blob.sign {
        Ok(())
    } else {
        Err(DpapiError::HmacMismatch)
    }
}

fn decrypt_3des_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    use cbc::Decryptor as CbcDec;
    use cipher::block_padding::NoPadding;
    use des::TdesEde3;

    let mut buf = ciphertext.to_vec();
    let dec =
        CbcDec::<TdesEde3>::new_from_slices(key, iv).map_err(|_| DpapiError::InvalidKeyLength)?;
    let out = dec
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| DpapiError::DecryptionFailed)?;

    // impacket unpads with the cipher block size; mirror that here.
    let unpadded = pkcs_unpad(out, 8)?;
    Ok(unpadded)
}

/// PKCS#7-style unpad for a given block size (impacket's `unpad`).
fn pkcs_unpad(data: &[u8], block_len: usize) -> Result<Vec<u8>, DpapiError> {
    let pad = *data.last().ok_or(DpapiError::DecryptionFailed)? as usize;
    if pad == 0 || pad > block_len || pad > data.len() {
        return Err(DpapiError::DecryptionFailed);
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(DpapiError::DecryptionFailed);
    }
    Ok(data[..data.len() - pad].to_vec())
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

    // Vector 2: same key, hashAlgo=0x800e/AES-256, WITH entropy b"Some entropy".
    const VECTOR2_BLOB_HEX: &str = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc600000000020000000000106600000001000020000000f239c0018e71b33bef9a6299675c7e209eef1f6447bd578d19c7973548737545000000000e80000000020000200000009d9ef33e15ffb1b310a13ecec39b1c02adc39e8d40a7162f9f9bb3170c699a812000000040e820259332c47af42e5f9de629e109d1504641aad853f3818c40ac311cf24a4000000010f01a84a5cc0393d3ea44cc3a8ff00ca4d02fcabc7c353a6823c53e4e719c9b398282a06b8878250205160ed79fef8b026093ad5a467594953d6de28d71f8c9";

    #[test]
    fn decrypt_sha512_aes256_blob_no_entropy() {
        let blob =
            crate::dpapi::dpapi_blob::parse_dpapi_blob(&hex(VECTOR1_BLOB_HEX)).expect("parse");
        let mk = hex(MASTER_KEY_HEX);
        let pt = decrypt_dpapi_blob(&blob, &mk, None).expect("decrypt");
        assert_eq!(pt, b"Some test string");
    }

    #[test]
    fn decrypt_sha512_aes256_blob_with_entropy() {
        let blob =
            crate::dpapi::dpapi_blob::parse_dpapi_blob(&hex(VECTOR2_BLOB_HEX)).expect("parse");
        let mk = hex(MASTER_KEY_HEX);
        let pt = decrypt_dpapi_blob(&blob, &mk, Some(b"Some entropy")).expect("decrypt");
        assert_eq!(pt, b"Some test string");
    }

    #[test]
    fn decrypt_sha512_blob_wrong_entropy_fails_integrity() {
        let blob =
            crate::dpapi::dpapi_blob::parse_dpapi_blob(&hex(VECTOR2_BLOB_HEX)).expect("parse");
        let mk = hex(MASTER_KEY_HEX);
        // Wrong/missing entropy must not silently return garbage: the Sign HMAC
        // check rejects it.
        assert!(decrypt_dpapi_blob(&blob, &mk, None).is_err());
    }
}
