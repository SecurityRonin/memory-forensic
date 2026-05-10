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
    todo!()
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
