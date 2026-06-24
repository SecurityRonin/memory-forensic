use crate::dpapi::DpapiError;

/// Properties of a DPAPI hash algorithm, mirroring impacket's `ALGORITHMS_DATA`.
///
/// Two distinct block sizes are in play and must not be conflated:
/// * `derive_block_len` is the table's salt/block field used by `deriveKey`
///   (impacket index `[4]`): 64 for SHA1 and `CALG_HMAC` (0x8009), 128 for
///   `CALG_SHA_512` (0x800e).
/// * `hash_block_len` is the underlying hash module's block size used by the
///   integrity check (`SHA1.block_size`=64, `SHA512.block_size`=128).
///
/// For `CALG_HMAC` (0x8009) these differ (64 vs 128), so both are tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashAlg {
    /// SHA512 module if true, SHA1 if false.
    pub is_sha512: bool,
    /// Output digest length in bytes (20 for SHA1, 64 for SHA512).
    pub digest_len: usize,
    /// `deriveKey` salt/block field (impacket `ALGORITHMS_DATA[..][4]`).
    pub derive_block_len: usize,
    /// Underlying hash module block size (used by the integrity HMAC).
    pub hash_block_len: usize,
}

/// Resolve a DPAPI `algId` (the hash algorithm) to its properties.
///
/// Recognises `CALG_SHA` (0x8004 → SHA1), `CALG_HMAC` (0x8009 → SHA512 module,
/// 64-byte derive block) and `CALG_SHA_512` (0x800e → SHA512, 128-byte derive
/// block). Any other value falls back to SHA1, matching the historical default.
pub fn hash_alg(alg_id_hash: u32) -> HashAlg {
    match alg_id_hash {
        0x8009 => HashAlg {
            is_sha512: true,
            digest_len: 64,
            derive_block_len: 64,
            hash_block_len: 128,
        },
        0x800E => HashAlg {
            is_sha512: true,
            digest_len: 64,
            derive_block_len: 128,
            hash_block_len: 128,
        },
        _ => HashAlg {
            is_sha512: false,
            digest_len: 20,
            derive_block_len: 64,
            hash_block_len: 64,
        },
    }
}

/// A parsed DPAPI data blob, mirroring impacket's `DPAPI_BLOB` structure.
///
/// Field names follow impacket: `salt` is the session-key salt, `hmac` is the
/// length-prefixed `HMac` field, `ciphertext` is `Data`, and `sign` is the
/// trailing integrity HMAC (`Sign`). `to_sign` is the byte range impacket signs
/// (`rawData[20 .. len - SignLen - 4]`), retained so the integrity check needs
/// no re-parse.
#[derive(Debug, Clone)]
pub struct DpapiBlob {
    pub version: u32,
    pub master_key_guid: [u8; 16],
    pub description: String,
    pub alg_id_encrypt: u32,
    pub alg_id_hash: u32,
    pub salt: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub hmac: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub sign: Vec<u8>,
    pub to_sign: Vec<u8>,
}

/// Read a length-prefixed (`<u32` length then bytes) field at `*pos`.
fn read_len_prefixed<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], DpapiError> {
    let len = read_u32(data, pos) as usize;
    let slice = data.get(*pos..*pos + len).ok_or(DpapiError::TooShort {
        needed: *pos + len,
        got: data.len(),
    })?;
    *pos += len;
    Ok(slice)
}

pub fn parse_dpapi_blob(data: &[u8]) -> Result<DpapiBlob, DpapiError> {
    // Fixed header: version(4) + providerGUID(16) + mkVersion(4) + mkGUID(16)
    //             + flags(4) + descLen(4) = 48 bytes.
    if data.len() < 48 {
        return Err(DpapiError::TooShort {
            needed: 48,
            got: data.len(),
        });
    }

    let mut pos = 0usize;

    let version = read_u32(data, &mut pos);
    if version != 1 && version != 2 {
        return Err(DpapiError::UnsupportedVersion(version));
    }
    pos += 16; // provider GUID
    let _mk_version = read_u32(data, &mut pos);
    let master_key_guid: [u8; 16] =
        data[pos..pos + 16]
            .try_into()
            .map_err(|_| DpapiError::TooShort {
                needed: pos + 16,
                got: data.len(),
            })?;
    pos += 16;
    let _flags = read_u32(data, &mut pos);

    let desc_bytes = read_len_prefixed(data, &mut pos)?;
    let description = decode_utf16le(desc_bytes);

    let alg_id_encrypt = read_u32(data, &mut pos);
    let _crypt_algo_len = read_u32(data, &mut pos);

    let salt = read_len_prefixed(data, &mut pos)?.to_vec();
    let hmac_key = read_len_prefixed(data, &mut pos)?.to_vec();

    let alg_id_hash = read_u32(data, &mut pos);
    let _hash_algo_len = read_u32(data, &mut pos);

    let hmac = read_len_prefixed(data, &mut pos)?.to_vec();
    let ciphertext = read_len_prefixed(data, &mut pos)?.to_vec();

    // Region impacket signs: from offset 20 up to (but excluding) SignLen + Sign.
    let sign_len_pos = pos;
    let sign = read_len_prefixed(data, &mut pos)?.to_vec();
    if sign_len_pos < 20 {
        return Err(DpapiError::TooShort {
            needed: 20,
            got: sign_len_pos,
        });
    }
    let to_sign = data[20..sign_len_pos].to_vec();

    Ok(DpapiBlob {
        version,
        master_key_guid,
        description,
        alg_id_encrypt,
        alg_id_hash,
        salt,
        hmac_key,
        hmac,
        ciphertext,
        sign,
        to_sign,
    })
}

/// Decode a UTF-16LE byte string, trimming trailing NULs.
fn decode_utf16le(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return String::new();
    }
    let words: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words)
        .trim_end_matches('\0')
        .to_string()
}

/// Read a little-endian u32 at `*pos`, advancing `pos` by 4.
/// Out-of-range yields 0 (never panics); callers range-check before relying on
/// the value, so a 0 here is a defensive fallback, not a silent success.
#[inline]
fn read_u32(data: &[u8], pos: &mut usize) -> u32 {
    let v = data
        .get(*pos..*pos + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes);
    *pos += 4;
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Build a structurally-valid DPAPI_BLOB (impacket layout) for parse tests.
    fn make_blob(
        crypt_algo: u32,
        hash_algo: u32,
        salt: &[u8],
        hmac_key: &[u8],
        hmac: &[u8],
        data: &[u8],
        sign: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u32.to_le_bytes()); // version
        v.extend_from_slice(&[0u8; 16]); // provider GUID
        v.extend_from_slice(&0u32.to_le_bytes()); // master key version
        v.extend_from_slice(&[0xAAu8; 16]); // master key GUID
        v.extend_from_slice(&0u32.to_le_bytes()); // flags
        v.extend_from_slice(&0u32.to_le_bytes()); // desc length (empty)
        v.extend_from_slice(&crypt_algo.to_le_bytes());
        v.extend_from_slice(&256u32.to_le_bytes()); // crypt algo len
        v.extend_from_slice(&(salt.len() as u32).to_le_bytes());
        v.extend_from_slice(salt);
        v.extend_from_slice(&(hmac_key.len() as u32).to_le_bytes());
        v.extend_from_slice(hmac_key);
        v.extend_from_slice(&hash_algo.to_le_bytes());
        v.extend_from_slice(&512u32.to_le_bytes()); // hash algo len
        v.extend_from_slice(&(hmac.len() as u32).to_le_bytes());
        v.extend_from_slice(hmac);
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
        v.extend_from_slice(&(sign.len() as u32).to_le_bytes());
        v.extend_from_slice(sign);
        v
    }

    // A real Windows-minted DPAPI blob (Vector 1, hashAlgo=0x800e SHA512,
    // cryptAlgo=0x6610 AES-256); fields cross-checked against impacket 0.12.0.
    const REAL_BLOB_HEX: &str = "01000000d08c9ddf0115d1118c7a00c04fc297eb0100000033f19f5ee340be4a8a2e2b4e62bd0cc6000000000200000000001066000000010000200000000d1af96e5e102266fd36d96ac7d1595552e5a4e972463f77e6e227f22d5fc8df000000000e8000000002000020000000834f3c5710c8a7474f7dbcea8ba28ab8e4d4443f50a0c63ff4eba1cce485295f20000000b61d7576c0c6caf3690edb247bde3f7edaa59580e3b4be1265ea78e8c1b8a61d400000001c03ab807147742649b6bdfd1c1344d178bb163842d70abacfd51233af909cb81a677ec05d8db996f587ef5ac410dc189beda756eb0d1b6ee376823e80968538";

    #[test]
    fn parse_rejects_too_short() {
        assert!(parse_dpapi_blob(&[0u8; 10]).is_err());
    }

    #[test]
    fn parse_extracts_master_key_guid() {
        let blob = make_blob(
            0x6610,
            0x8004,
            &[0xEEu8; 16],
            &[],
            &[0xCCu8; 20],
            &[0xDDu8; 16],
            &[0xCCu8; 20],
        );
        let result = parse_dpapi_blob(&blob).expect("should parse");
        assert_eq!(result.master_key_guid, [0xAA; 16]);
    }

    #[test]
    fn parse_extracts_alg_id_encrypt() {
        let blob = make_blob(
            0x6610,
            0x8004,
            &[0xEEu8; 16],
            &[],
            &[0xCCu8; 20],
            &[0xDDu8; 16],
            &[0xCCu8; 20],
        );
        let result = parse_dpapi_blob(&blob).expect("should parse");
        assert_eq!(result.alg_id_encrypt, 0x6610);
    }

    #[test]
    fn parse_extracts_salt_and_ciphertext() {
        let salt = [0xEEu8; 32];
        let data = [0xDDu8; 32];
        let blob = make_blob(
            0x6610,
            0x8004,
            &salt,
            &[],
            &[0xCCu8; 20],
            &data,
            &[0xCCu8; 20],
        );
        let result = parse_dpapi_blob(&blob).expect("should parse");
        assert_eq!(result.salt, salt);
        assert_eq!(result.ciphertext, data);
    }

    // Tier-1: field offsets must match impacket's parse of a real Windows blob.
    #[test]
    fn parse_real_blob_matches_impacket_fields() {
        let result = parse_dpapi_blob(&hex(REAL_BLOB_HEX)).expect("should parse");
        assert_eq!(result.alg_id_encrypt, 0x6610);
        assert_eq!(result.alg_id_hash, 0x800E);
        assert_eq!(
            result.salt,
            hex("0d1af96e5e102266fd36d96ac7d1595552e5a4e972463f77e6e227f22d5fc8df")
        );
        assert!(result.hmac_key.is_empty());
        assert_eq!(
            result.hmac,
            hex("834f3c5710c8a7474f7dbcea8ba28ab8e4d4443f50a0c63ff4eba1cce485295f")
        );
        assert_eq!(
            result.ciphertext,
            hex("b61d7576c0c6caf3690edb247bde3f7edaa59580e3b4be1265ea78e8c1b8a61d")
        );
        assert_eq!(result.sign.len(), 64);
    }
}
