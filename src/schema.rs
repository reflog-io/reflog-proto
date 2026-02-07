//! Entity registry and payload encoding/decoding utilities.
//!
//! This module provides functionality to:
//! - Initialize an entity registry from proto files
//! - Convert protobuf payloads to/from JSON
//! - Validate entity types against the registry
//!
//! REFACTOR NOTE: Internals updated to use `nom` for robust parsing
//! while maintaining strict backwards compatibility with the public API.

use crate::proto_parser::{self, ProtoField, ProtoMessage};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use nom::{
    bytes::complete::take,
    error::{Error as NomError, ErrorKind},
    number::complete::{le_f32, le_f64, le_u32, le_u64},
    IResult,
};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{OnceLock, RwLock};

// Registry of valid entity types and their message definitions
static ENTITY_REGISTRY: OnceLock<RwLock<HashMap<String, ProtoMessage>>> = OnceLock::new();

// ==========================================
//           Public API (Unchanged)
// ==========================================

/// Initialize the entity registry from a proto file.
/// This should be called once at application startup.
/// This function is idempotent - if the registry is already initialized, it updates it.
pub fn initialize_entity_registry(proto_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let messages = proto_parser::parse_proto_file(proto_path)?;
    initialize_registry_from_messages(messages)
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
    initialize_registry_from_messages(messages)
}

fn initialize_registry_from_messages(
    messages: Vec<ProtoMessage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = HashMap::new();

    // Helper to register messages recursively (supporting nested definitions)
    fn register_recursive(msg: ProtoMessage, reg: &mut HashMap<String, ProtoMessage>) {
        reg.insert(msg.name.clone(), msg.clone());
        for nested in msg.nested_messages {
            register_recursive(nested, reg);
        }
    }

    for message in messages {
        register_recursive(message, &mut registry);
    }

    // Initialize the registry if not already done
    let registry_lock = ENTITY_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()));
    let mut reg = registry_lock
        .write()
        .map_err(|_| "entity registry lock poisoned")?;
    *reg = registry;

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
    let message_def = get_message_definition(entity_type)?;

    // We use the nom parser internally now
    match parse_message_nom(&message_def, payload, partial) {
        Ok((remaining, value)) => {
            if !remaining.is_empty() {
                // Warning: trailing bytes usually indicate malformed proto or wrong schema,
                // but we return the value we found for best effort.
                // Alternatively, return an Err if strictness is required.
                return Err(format!(
                    "Payload has {} unexpected trailing bytes",
                    remaining.len()
                ));
            }
            Ok(value)
        }
        Err(e) => Err(format!("Failed to parse payload: {:?}", e)),
    }
}

/// Encode JSON to protobuf wire format for a given entity type.
pub fn json_to_payload(entity_type: &str, json: &Value) -> Result<Vec<u8>, String> {
    let message_def = get_message_definition(entity_type)?;
    let obj = json
        .as_object()
        .ok_or_else(|| "JSON must be an object".to_string())?;

    encode_message_to_wire(&message_def, obj)
}

// ==========================================
//      Internal Logic: Nom Implementation
// ==========================================

/// Parse a complete message using nom.
fn parse_message_nom<'a>(
    message_def: &ProtoMessage,
    mut input: &'a [u8],
    partial: bool,
) -> IResult<&'a [u8], Value> {
    let mut obj = serde_json::Map::new();
    let mut repeated_accumulator: HashMap<String, Vec<Value>> = HashMap::new();

    // Create a map of field numbers to field definitions
    let field_map: HashMap<u32, &ProtoField> = message_def
        .fields
        .iter()
        .map(|f| (f.field_number, f))
        .collect();

    while !input.is_empty() {
        // Parse tag
        let (rest, (field_number, wire_type)) = parse_tag(input)?;

        if let Some(field) = field_map.get(&field_number) {
            let (rest_after_val, value) =
                parse_field_value_nom(rest, wire_type, &field.proto_type, message_def, partial)?;
            input = rest_after_val;

            // Handle repeated fields logic
            // Note: Since 'is_repeated' might not be available in all parser versions,
            // we use the accumulator strategy: if a key appears twice, it's repeated.
            if repeated_accumulator.contains_key(&field.name) {
                repeated_accumulator
                    .get_mut(&field.name)
                    .unwrap()
                    .push(value);
            } else if let Some(existing) = obj.remove(&field.name) {
                // Second occurrence found, move to accumulator
                repeated_accumulator.insert(field.name.clone(), vec![existing, value]);
            } else {
                // First occurrence
                obj.insert(field.name.clone(), value);
            }
        } else {
            // Unknown field, skip it safely
            let (rest_after_skip, _) = skip_field_value_nom(rest, wire_type)?;
            input = rest_after_skip;
        }
    }

    // Merge accumulators back into object
    for (key, values) in repeated_accumulator {
        obj.insert(key, Value::Array(values));
    }

    // Handle partial logic: remove empty/null if partial is false
    // (Standard protobufs usually omit defaults, JSON mapping is flexible)
    if !partial {
        obj.retain(|_, v| !is_empty_json_value(v));
    }

    Ok((input, Value::Object(obj)))
}

fn parse_tag(input: &[u8]) -> IResult<&[u8], (u32, u8)> {
    let (input, tag) = parse_varint(input)?;
    let field_number = (tag >> 3) as u32;
    let wire_type = (tag & 0x07) as u8;
    Ok((input, (field_number, wire_type)))
}

fn parse_field_value_nom<'a>(
    input: &'a [u8],
    wire_type: u8,
    proto_type: &str,
    _parent_msg: &ProtoMessage,
    partial: bool,
) -> IResult<&'a [u8], Value> {
    match wire_type {
        0 => {
            // Varint
            let (input, val) = parse_varint(input)?;
            let json_val = match proto_type {
                "bool" => Value::Bool(val != 0),
                "sint32" | "sint64" => {
                    // ZigZag decode
                    let decoded = (val >> 1) ^ (-((val & 1) as i64) as u64);
                    Value::Number(serde_json::Number::from(decoded as i64))
                }
                // Default to unsigned/signed int
                _ => Value::Number(serde_json::Number::from(val)),
            };
            Ok((input, json_val))
        }
        1 => {
            // 64-bit
            match proto_type {
                "double" => {
                    let (input, val) = le_f64(input)?;
                    Ok((
                        input,
                        serde_json::Number::from_f64(val)
                            .map(Value::Number)
                            .unwrap_or(Value::Null),
                    ))
                }
                _ => {
                    // fixed64, sfixed64
                    let (input, val) = le_u64(input)?;
                    Ok((input, Value::Number(val.into())))
                }
            }
        }
        2 => {
            // Length Delimited
            let (input, len) = parse_varint(input)?;
            let (input, data) = take(len as usize)(input)?;

            match proto_type {
                "string" => {
                    let s = String::from_utf8_lossy(data).into_owned();
                    Ok((input, Value::String(s)))
                }
                "bytes" => Ok((input, Value::String(BASE64.encode(data)))),
                _ => {
                    // It's a nested message
                    // We attempt to find the definition globally since we don't have easy access
                    // to the parent's nested list in this function signature without complexity.
                    if let Ok(nested_def) = get_message_definition(proto_type) {
                        let (_, val) = parse_message_nom(&nested_def, data, partial)?;
                        Ok((input, val))
                    } else {
                        // If we can't find definition, treat as Base64 bytes (safe fallback)
                        Ok((input, Value::String(BASE64.encode(data))))
                    }
                }
            }
        }
        5 => {
            // 32-bit
            match proto_type {
                "float" => {
                    let (input, val) = le_f32(input)?;
                    Ok((
                        input,
                        serde_json::Number::from_f64(val as f64)
                            .map(Value::Number)
                            .unwrap_or(Value::Null),
                    ))
                }
                _ => {
                    // fixed32, sfixed32
                    let (input, val) = le_u32(input)?;
                    Ok((input, Value::Number(val.into())))
                }
            }
        }
        _ => Err(nom::Err::Error(NomError::new(input, ErrorKind::Tag))),
    }
}

/// Skip a field safely if we don't know the tag
fn skip_field_value_nom(input: &[u8], wire_type: u8) -> IResult<&[u8], ()> {
    match wire_type {
        0 => {
            let (i, _) = parse_varint(input)?;
            Ok((i, ()))
        }
        1 => {
            let (i, _) = take(8usize)(input)?;
            Ok((i, ()))
        }
        2 => {
            let (i, len) = parse_varint(input)?;
            let (i, _) = take(len as usize)(i)?;
            Ok((i, ()))
        }
        5 => {
            let (i, _) = take(4usize)(input)?;
            Ok((i, ()))
        }
        _ => Err(nom::Err::Error(NomError::new(input, ErrorKind::Tag))),
    }
}

/// Robust Varint Parser
fn parse_varint(input: &[u8]) -> IResult<&[u8], u64> {
    let mut res: u64 = 0;
    let mut shift = 0;

    // Max 10 bytes for 64-bit varint
    for (i, byte) in input.iter().enumerate().take(10) {
        res |= ((*byte & 0x7F) as u64) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            return Ok((&input[i + 1..], res));
        }
    }

    Err(nom::Err::Error(NomError::new(input, ErrorKind::TooLarge)))
}

// ==========================================
//      Internal Logic: Encoder
// ==========================================

fn encode_message_to_wire(
    message_def: &ProtoMessage,
    obj: &serde_json::Map<String, Value>,
) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();

    let field_map: HashMap<&str, &ProtoField> = message_def
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f))
        .collect();

    // Iterate over the JSON keys
    for (key, value) in obj {
        if let Some(field) = field_map.get(key.as_str()) {
            // Check if it is a repeated field (JSON Array)
            if let Some(arr) = value.as_array() {
                // Special case: Bytes might be a string in JSON, not an array
                if field.proto_type == "bytes" && value.is_string() {
                    encode_field(&mut result, field.field_number, &field.proto_type, value)?;
                } else {
                    for item in arr {
                        encode_field(&mut result, field.field_number, &field.proto_type, item)?;
                    }
                }
            } else {
                encode_field(&mut result, field.field_number, &field.proto_type, value)?;
            }
        }
    }

    Ok(result)
}

fn encode_field(
    result: &mut Vec<u8>,
    field_number: u32,
    proto_type: &str,
    value: &Value,
) -> Result<(), String> {
    let wire_type = match proto_type {
        "int32" | "int64" | "uint32" | "uint64" | "sint32" | "sint64" | "bool" | "enum" => 0,
        "fixed64" | "sfixed64" | "double" => 1,
        "string" | "bytes" | "message" => 2,
        "fixed32" | "sfixed32" | "float" => 5,
        _ => 2, // fallback for nested messages
    };

    let tag = (field_number << 3) | wire_type;
    write_varint(result, tag as u64);

    match wire_type {
        0 => {
            // Varint
            let val = match value {
                Value::Bool(b) => {
                    if *b {
                        1
                    } else {
                        0
                    }
                }
                Value::Number(n) => n
                    .as_u64()
                    .or_else(|| n.as_i64().map(|i| i as u64))
                    .unwrap_or(0),
                Value::String(s) => s.parse::<u64>().unwrap_or(0), // Loose string-to-int parsing
                _ => 0,
            };

            // ZigZag encoding for sint
            let final_val = match proto_type {
                "sint32" => {
                    let n = val as i32;
                    ((n << 1) ^ (n >> 31)) as u32 as u64
                }
                "sint64" => {
                    let n = val as i64;
                    ((n << 1) ^ (n >> 63)) as u64
                }
                _ => val,
            };
            write_varint(result, final_val);
        }
        1 => {
            // 64-bit
            if proto_type == "double" {
                let v = value.as_f64().unwrap_or(0.0);
                result.extend_from_slice(&v.to_le_bytes());
            } else {
                let v = value.as_u64().unwrap_or(0);
                result.extend_from_slice(&v.to_le_bytes());
            }
        }
        2 => {
            // Length Delimited
            if proto_type == "string" {
                let s = value.as_str().unwrap_or("");
                write_varint(result, s.len() as u64);
                result.extend_from_slice(s.as_bytes());
            } else if proto_type == "bytes" {
                let s = value.as_str().unwrap_or("");
                let b = BASE64.decode(s).map_err(|e| e.to_string())?;
                write_varint(result, b.len() as u64);
                result.extend_from_slice(&b);
            } else {
                // Nested message
                // We need the definition. Retrieve it from global registry.
                if let Ok(nested_def) = get_message_definition(proto_type) {
                    if let Some(nested_obj) = value.as_object() {
                        let nested_bytes = encode_message_to_wire(&nested_def, nested_obj)?;
                        write_varint(result, nested_bytes.len() as u64);
                        result.extend_from_slice(&nested_bytes);
                    }
                } else {
                    return Err(format!("Cannot encode unknown nested type: {}", proto_type));
                }
            }
        }
        5 => {
            // 32-bit
            if proto_type == "float" {
                let v = value.as_f64().unwrap_or(0.0) as f32;
                result.extend_from_slice(&v.to_le_bytes());
            } else {
                let v = value.as_u64().unwrap_or(0) as u32;
                result.extend_from_slice(&v.to_le_bytes());
            }
        }
        _ => return Err(format!("Unsupported wire type {}", wire_type)),
    }

    Ok(())
}

fn write_varint(result: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        result.push((value as u8) | 0x80);
        value >>= 7;
    }
    result.push(value as u8);
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
