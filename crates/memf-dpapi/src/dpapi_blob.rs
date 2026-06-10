use crate::DpapiError;

#[derive(Debug, Clone)]
pub struct DpapiBlob {
    pub version: u32,
    pub master_key_guid: [u8; 16],
    pub description: String,
    pub alg_id_encrypt: u32,
    pub alg_id_hash: u32,
    pub hmac_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub hmac: Vec<u8>,
}

pub fn parse_dpapi_blob(data: &[u8]) -> Result<DpapiBlob, DpapiError> {
    // Minimum fixed header: 4 (version) + 16 (provider GUID) + 16 (mk GUID)
    //                      + 4 (flags) + 4 (desc len) = 44 bytes
    if data.len() < 44 {
        return Err(DpapiError::TooShort { needed: 44, got: data.len() });
    }

    let mut pos = 0usize;

    let version = read_u32(data, &mut pos);
    if version != 1 && version != 2 {
        return Err(DpapiError::UnsupportedVersion(version));
    }
    pos += 16; // skip provider GUID
    // Guarded by the `data.len() < 44` check above (here pos == 20, pos+16 == 36);
    // the fallback keeps construction panic-free if that invariant ever changes.
    let master_key_guid: [u8; 16] = data
        .get(pos..pos + 16)
        .and_then(|s| s.try_into().ok())
        .unwrap_or([0u8; 16]);
    pos += 16;
    let _flags = read_u32(data, &mut pos);
    let desc_len = read_u32(data, &mut pos) as usize;

    if pos + desc_len > data.len() {
        return Err(DpapiError::TooShort { needed: pos + desc_len, got: data.len() });
    }
    let desc_bytes = &data[pos..pos + desc_len];
    pos += desc_len;

    let description = if desc_len >= 2 {
        let words: Vec<u16> = desc_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&words)
            .trim_end_matches('\0')
            .to_string()
    } else {
        String::new()
    };

    // Need 20 more bytes: algIdEncrypt(4) + algIdHash(4) + dataLen(4) + hmacKeyLen(4) + algIdHash2(4)
    if pos + 20 > data.len() {
        return Err(DpapiError::TooShort { needed: pos + 20, got: data.len() });
    }
    let alg_id_encrypt = read_u32(data, &mut pos);
    let alg_id_hash = read_u32(data, &mut pos);
    let _data_len = read_u32(data, &mut pos);
    let hmac_key_len = read_u32(data, &mut pos) as usize;
    pos += 4; // skip repeated algIdHash

    if pos + hmac_key_len > data.len() {
        return Err(DpapiError::TooShort { needed: pos + hmac_key_len, got: data.len() });
    }
    let hmac_key = data[pos..pos + hmac_key_len].to_vec();
    pos += hmac_key_len;

    // HMAC digest size depends on hash algorithm
    let digest_len: usize = match alg_id_hash {
        0x8004 => 20, // SHA1
        0x800C => 64, // SHA512
        _ => 20,      // default to SHA1 digest size
    };

    if data.len() < pos + digest_len {
        return Err(DpapiError::TooShort { needed: pos + digest_len, got: data.len() });
    }
    let hmac = data[data.len() - digest_len..].to_vec();
    let ciphertext = data[pos..data.len() - digest_len].to_vec();

    Ok(DpapiBlob {
        version,
        master_key_guid,
        description,
        alg_id_encrypt,
        alg_id_hash,
        hmac_key,
        ciphertext,
        hmac,
    })
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

    fn make_minimal_blob(desc_bytes: &[u8], hmac_key: &[u8], ciphertext: &[u8], hmac: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u32.to_le_bytes()); // version
        v.extend_from_slice(&[0u8; 16]);           // provider GUID
        v.extend_from_slice(&[0xAAu8; 16]);        // master key GUID
        v.extend_from_slice(&0u32.to_le_bytes());  // flags
        v.extend_from_slice(&(desc_bytes.len() as u32).to_le_bytes()); // desc length
        v.extend_from_slice(desc_bytes);
        v.extend_from_slice(&0x6610u32.to_le_bytes()); // AES-256
        v.extend_from_slice(&0x8004u32.to_le_bytes()); // SHA1
        let data_len = 4 + 4 + hmac_key.len() + ciphertext.len() + hmac.len();
        v.extend_from_slice(&(data_len as u32).to_le_bytes());
        v.extend_from_slice(&(hmac_key.len() as u32).to_le_bytes());
        v.extend_from_slice(&0x8004u32.to_le_bytes()); // algIdHash repeated
        v.extend_from_slice(hmac_key);
        v.extend_from_slice(ciphertext);
        v.extend_from_slice(hmac);
        v
    }

    #[test]
    fn parse_rejects_too_short() {
        assert!(parse_dpapi_blob(&[0u8; 10]).is_err());
    }

    #[test]
    fn parse_extracts_master_key_guid() {
        let blob = make_minimal_blob(&[], &[0xBBu8; 20], &[0u8; 16], &[0xCCu8; 20]);
        let result = parse_dpapi_blob(&blob).expect("should parse");
        assert_eq!(result.master_key_guid, [0xAA; 16]);
    }

    #[test]
    fn parse_extracts_alg_id_encrypt() {
        let blob = make_minimal_blob(&[], &[0xBBu8; 20], &[0u8; 16], &[0xCCu8; 20]);
        let result = parse_dpapi_blob(&blob).expect("should parse");
        assert_eq!(result.alg_id_encrypt, 0x6610);
    }

    #[test]
    fn parse_extracts_hmac_key_and_ciphertext() {
        let hmac_key = [0xBBu8; 20];
        let ciphertext = [0xDDu8; 32];
        let hmac = [0xCCu8; 20];
        let blob = make_minimal_blob(&[], &hmac_key, &ciphertext, &hmac);
        let result = parse_dpapi_blob(&blob).expect("should parse");
        assert_eq!(result.hmac_key, hmac_key);
        assert_eq!(result.ciphertext, ciphertext);
    }
}
