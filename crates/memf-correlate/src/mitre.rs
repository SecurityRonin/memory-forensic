//! MITRE ATT&CK identifier types and validation.

use serde::Serialize;

/// A validated MITRE ATT&CK technique identifier (e.g. `T1055`, `T1055.001`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MitreAttackId(String);

/// Error returned when a MITRE ATT&CK ID fails validation.
#[derive(Debug, thiserror::Error)]
#[error("invalid MITRE ATT&CK ID: {0}")]
pub struct InvalidMitreId(String);

impl MitreAttackId {
    /// Create a new `MitreAttackId` after validating the format.
    ///
    /// Accepts `T<digits>` or `T<digits>.<digits>` (e.g. `T1055`, `T1055.001`).
    pub fn new(id: &str) -> Result<Self, InvalidMitreId> {
        if !Self::is_valid(id) {
            return Err(InvalidMitreId(id.to_string()));
        }
        Ok(Self(id.to_string()))
    }

    /// Returns the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(id: &str) -> bool {
        // Must start with 'T' followed by digits, optionally '.digits'
        let Some(rest) = id.strip_prefix('T') else {
            return false;
        };

        if let Some((technique, sub)) = rest.split_once('.') {
            !technique.is_empty()
                && technique.chars().all(|c| c.is_ascii_digit())
                && !sub.is_empty()
                && sub.chars().all(|c| c.is_ascii_digit())
        } else {
            !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
        }
    }
}

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
