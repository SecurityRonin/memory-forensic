//! MITRE ATT&CK identifier types and validation.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_technique_id() {
        let id = MitreAttackId::new("T1055").expect("T1055 should be valid");
        assert_eq!(id.as_str(), "T1055");
    }

    #[test]
    fn valid_sub_technique_id() {
        let id = MitreAttackId::new("T1055.001").expect("T1055.001 should be valid");
        assert_eq!(id.as_str(), "T1055.001");
    }

    #[test]
    fn invalid_technique_id_bad_prefix() {
        let result = MitreAttackId::new("X9999");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_technique_id_empty() {
        let result = MitreAttackId::new("");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_technique_id_no_digits() {
        let result = MitreAttackId::new("Tabcd");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_sub_technique_too_short() {
        let result = MitreAttackId::new("T1055.");
        assert!(result.is_err());
    }

    #[test]
    fn mitre_attack_id_serializes() {
        let id = MitreAttackId::new("T1055").unwrap();
        let json = serde_json::to_string(&id).expect("should serialize");
        assert_eq!(json, "\"T1055\"");
    }
}
