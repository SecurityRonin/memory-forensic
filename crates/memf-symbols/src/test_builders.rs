//! Test builders for synthetic symbol tables.

use serde_json::{json, Value};
use std::collections::HashMap;

/// Builds a minimal ISF JSON document for testing.
#[derive(Default)]
pub struct IsfBuilder {
    structs: HashMap<String, IsfStruct>,
    symbols: HashMap<String, u64>,
    base_types: HashMap<String, (u64, bool)>,
}

struct IsfStruct {
    size: u64,
    fields: Vec<(String, u64, String)>, // (name, offset, type_name)
}

impl IsfBuilder {
    /// Create a new builder with common base types pre-registered.
    pub fn new() -> Self {
        todo!()
    }

    /// Add a struct type with its total size.
    pub fn add_struct(mut self, name: &str, size: u64) -> Self {
        todo!()
    }

    /// Add a field to a struct.
    pub fn add_field(
        mut self,
        struct_name: &str,
        field_name: &str,
        offset: u64,
        type_name: &str,
    ) -> Self {
        todo!()
    }

    /// Add a kernel symbol with its virtual address.
    pub fn add_symbol(mut self, name: &str, address: u64) -> Self {
        todo!()
    }

    /// Build the ISF JSON as a `serde_json::Value`.
    pub fn build_json(&self) -> Value {
        todo!()
    }

    /// Build the ISF JSON as a byte vector (UTF-8 encoded).
    pub fn build_bytes(&self) -> Vec<u8> {
        todo!()
    }

    /// Build a minimal ISF JSON for Linux process walking tests.
    pub fn linux_process_preset() -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_valid_json() {
        let json = IsfBuilder::new()
            .add_struct("task_struct", 100)
            .add_field("task_struct", "pid", 8, "int")
            .add_symbol("init_task", 0xFFFF_0000)
            .build_json();

        assert_eq!(json["metadata"]["format"], "6.2.0");
        assert_eq!(json["user_types"]["task_struct"]["size"], 100);
        assert_eq!(
            json["user_types"]["task_struct"]["fields"]["pid"]["offset"],
            8
        );
        assert_eq!(json["symbols"]["init_task"]["address"], 0xFFFF_0000u64);
    }

    #[test]
    fn linux_preset_has_required_fields() {
        let json = IsfBuilder::linux_process_preset().build_json();

        let ts = &json["user_types"]["task_struct"];
        assert_eq!(ts["size"], 9024);
        assert!(ts["fields"]["pid"]["offset"].is_number());
        assert!(ts["fields"]["comm"]["offset"].is_number());
        assert!(ts["fields"]["tasks"]["offset"].is_number());
        assert!(ts["fields"]["mm"]["offset"].is_number());

        let lh = &json["user_types"]["list_head"];
        assert_eq!(lh["size"], 16);

        assert!(json["symbols"]["init_task"]["address"].is_number());
        assert!(json["symbols"]["linux_banner"]["address"].is_number());
    }

    #[test]
    fn build_bytes_is_valid_json() {
        let bytes = IsfBuilder::linux_process_preset().build_bytes();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed["metadata"]["format"].is_string());
    }
}
