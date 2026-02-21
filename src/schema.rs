//! Entity registry and payload encoding/decoding utilities.
//!
//! This module provides functionality to:
//! - Initialize an entity registry from proto files
//! - Convert protobuf payloads to/from JSON
//! - Validate entity types against the registry
//!
//! REFACTOR NOTE: Internals updated to use descriptor-based reflection
//! while maintaining strict backwards compatibility with the public API.

use crate::proto_parser::{self, ProtoMessage};
use prost::Message as _;
use prost_reflect::{DeserializeOptions, DynamicMessage, MessageDescriptor};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{OnceLock, RwLock};

// Registry of valid entity types and their message definitions
static ENTITY_REGISTRY: OnceLock<RwLock<HashMap<String, ProtoMessage>>> = OnceLock::new();
// Runtime descriptors used for robust protobuf encode/decode.
static DESCRIPTOR_REGISTRY: OnceLock<RwLock<HashMap<String, MessageDescriptor>>> = OnceLock::new();

// ==========================================
//           Public API (Unchanged)
// ==========================================

/// Initialize the entity registry from a proto file.
/// This should be called once at application startup.
/// This function is idempotent - if the registry is already initialized, it updates it.
pub fn initialize_entity_registry(proto_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let messages = proto_parser::parse_proto_file(proto_path)?;
    let pool = proto_parser::descriptor_pool_from_file(proto_path)?;
    initialize_registry(messages, pool.all_messages().collect())
}

/// Initialize the entity registry from proto content string.
/// This should be called once at application startup.
/// This function is idempotent - if the registry is already initialized, it updates it.
pub fn initialize_entity_registry_from_content(
    content: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Timestamp fields (created_at_utc, updated_at_utc, deleted_at_utc) are now
    // provided at the top level in IngestRecord, so we no longer add them to payload messages
    let messages = proto_parser::parse_proto_content(content)?;
    let pool = proto_parser::descriptor_pool_from_content(content)?;
    initialize_registry(messages, pool.all_messages().collect())
}

fn initialize_registry(
    messages: Vec<ProtoMessage>,
    descriptors: Vec<MessageDescriptor>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = HashMap::new();
    let mut descriptor_by_name = HashMap::new();
    for desc in descriptors {
        descriptor_by_name.insert(desc.name().to_string(), desc);
    }
    let mut descriptor_registry = HashMap::new();

    fn register_recursive(
        msg: ProtoMessage,
        reg: &mut HashMap<String, ProtoMessage>,
        desc_map: &HashMap<String, MessageDescriptor>,
        desc_reg: &mut HashMap<String, MessageDescriptor>,
    ) {
        if let Some(desc) = desc_map.get(&msg.name) {
            desc_reg.insert(msg.name.clone(), desc.clone());
        }
        reg.insert(msg.name.clone(), msg.clone());
        for nested in msg.nested_messages {
            register_recursive(nested, reg, desc_map, desc_reg);
        }
    }

    for message in messages {
        register_recursive(
            message,
            &mut registry,
            &descriptor_by_name,
            &mut descriptor_registry,
        );
    }

    // Initialize the registry if not already done
    let registry_lock = ENTITY_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()));
    let mut reg = registry_lock
        .write()
        .map_err(|_| "entity registry lock poisoned")?;
    *reg = registry;

    let descriptor_lock = DESCRIPTOR_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()));
    let mut desc_reg = descriptor_lock
        .write()
        .map_err(|_| "descriptor registry lock poisoned")?;
    *desc_reg = descriptor_registry;

    Ok(())
}

/// Reload the entity registry from a proto file.
/// This allows updating the schema at runtime.
pub fn reload_entity_registry(proto_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    initialize_entity_registry(proto_path)
}

/// Get the message definition for an entity type.
pub fn get_message_definition(entity_type: &str) -> Result<ProtoMessage, String> {
    let registry = ENTITY_REGISTRY
        .get()
        .ok_or("Entity registry not initialized. Call initialize_entity_registry first.")?;

    let reg = registry
        .read()
        .map_err(|_| "entity registry lock poisoned".to_string())?;
    reg.get(entity_type)
        .cloned()
        .ok_or_else(|| format!("unknown entity type: {entity_type}"))
}

/// Check if an entity type is valid.
pub fn is_valid_entity_type(entity_type: &str) -> bool {
    ENTITY_REGISTRY
        .get()
        .and_then(|registry| {
            let reg = registry.read().ok()?;
            reg.get(entity_type).map(|_| ())
        })
        .is_some()
}

/// Get all registered entity types.
pub fn get_entity_types() -> Vec<String> {
    ENTITY_REGISTRY
        .get()
        .and_then(|registry| {
            let reg = registry.read().ok()?;
            Some(reg.keys().cloned().collect())
        })
        .unwrap_or_default()
}

/// Convert a protobuf payload to JSON for a given entity type.
pub fn payload_to_json(entity_type: &str, payload: &[u8]) -> Result<Value, String> {
    payload_to_json_partial(entity_type, payload, false)
}

/// Convert a protobuf payload to JSON, optionally excluding empty fields.
pub fn payload_to_json_partial(
    entity_type: &str,
    payload: &[u8],
    partial: bool,
) -> Result<Value, String> {
    let descriptor = get_message_descriptor(entity_type)?;
    let message = DynamicMessage::decode(descriptor, payload).map_err(|e| {
        format!("Failed to decode payload for entity type '{entity_type}': {e}")
    })?;
    let mut json = serde_json::to_value(&message)
        .map_err(|e| format!("Failed to convert payload to JSON for '{entity_type}': {e}"))?;

    if !partial {
        remove_empty_top_level_fields(&mut json);
    }

    Ok(json)
}

/// Encode JSON to protobuf wire format for a given entity type.
pub fn json_to_payload(entity_type: &str, json: &Value) -> Result<Vec<u8>, String> {
    if !json.is_object() {
        return Err("JSON must be an object".to_string());
    }

    let descriptor = get_message_descriptor(entity_type)?;
    let options = DeserializeOptions::new().deny_unknown_fields(false);
    let json_text = serde_json::to_string(json)
        .map_err(|e| format!("Failed to serialize JSON payload for '{entity_type}': {e}"))?;
    let mut deserializer = serde_json::Deserializer::from_str(&json_text);
    let message = DynamicMessage::deserialize_with_options(descriptor, &mut deserializer, &options)
        .map_err(|e| format!("Failed to convert JSON to payload for entity type '{entity_type}': {e}"))?;
    Ok(message.encode_to_vec())
}

fn get_message_descriptor(entity_type: &str) -> Result<MessageDescriptor, String> {
    let registry = DESCRIPTOR_REGISTRY.get().ok_or(
        "Entity registry not initialized. Call initialize_entity_registry first.",
    )?;
    let reg = registry
        .read()
        .map_err(|_| "descriptor registry lock poisoned".to_string())?;
    reg.get(entity_type)
        .cloned()
        .ok_or_else(|| format!("unknown entity type: {entity_type}"))
}

fn remove_empty_top_level_fields(value: &mut Value) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    obj.retain(|_, field_value| !is_empty_json_value(field_value));
}

fn is_empty_json_value(value: &Value) -> bool {
    match value {
        Value::String(s) => s.is_empty(),
        Value::Number(n) => {
            n.as_u64().map(|v| v == 0).unwrap_or(false)
                && n.as_f64().map(|v| v == 0.0).unwrap_or(false)
        }
        Value::Bool(b) => !*b,
        Value::Null => true,
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}
