//! Entity registry and payload encoding/decoding utilities.
//!
//! This module provides functionality to:
//! - Initialize an entity registry from proto files
//! - Convert protobuf payloads to/from JSON
//! - Validate entity types against the registry

use crate::proto_parser::{self, ProtoField, ProtoMessage};
use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{OnceLock, RwLock};

// Registry of valid entity types and their message definitions
static ENTITY_REGISTRY: OnceLock<RwLock<HashMap<String, ProtoMessage>>> = OnceLock::new();

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
pub fn initialize_entity_registry_from_content(content: &str) -> Result<(), Box<dyn std::error::Error>> {
    let messages = proto_parser::parse_proto_content(content)?;
    initialize_registry_from_messages(messages)
}

fn initialize_registry_from_messages(messages: Vec<proto_parser::ProtoMessage>) -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = HashMap::new();
    for message in messages {
        // Convert message name to entity type (lowercase)
        let entity_type = message.name.to_lowercase();
        registry.insert(entity_type, message);
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
            reg.get(entity_type).is_some().then_some(())
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
    decode_wire_format_to_json(&message_def, payload, partial)
}

/// Decode protobuf wire format to JSON using field definitions.
fn decode_wire_format_to_json(
    message_def: &ProtoMessage,
    payload: &[u8],
    partial: bool,
) -> Result<Value, String> {
    // Create a map of field numbers to field definitions
    let field_map: HashMap<u32, &ProtoField> = message_def
        .fields
        .iter()
        .map(|f| (f.field_number, f))
        .collect();

    let mut obj = serde_json::Map::new();
    let mut pos = 0;

    while pos < payload.len() {
        // Read tag (field number and wire type)
        let (tag, bytes_read) = read_varint(&payload[pos..])?;
        pos += bytes_read;

        let field_number = (tag >> 3) as u32;
        let wire_type = tag & 0x7;

        if let Some(field) = field_map.get(&field_number) {
            // Decode the field value
            let (value, bytes_consumed) = decode_field_value(
                &payload[pos..],
                wire_type,
                &field.proto_type,
            )?;
            pos += bytes_consumed;

            // Only include non-empty fields in partial mode
            if !partial || !is_empty_json_value(&value) {
                obj.insert(field.name.clone(), value);
            }
        } else {
            // Unknown field, skip it
            let (_, bytes_consumed) = skip_field_value(&payload[pos..], wire_type)?;
            pos += bytes_consumed;
        }
    }

    Ok(Value::Object(obj))
}

/// Maximum bytes for a valid varint (10 bytes can encode up to 70 bits, but we only need 64).
const MAX_VARINT_BYTES: usize = 10;

/// Read a varint from the buffer with proper bounds checking.
///
/// Returns the decoded value and number of bytes consumed.
fn read_varint(buf: &[u8]) -> Result<(u64, usize), String> {
    if buf.is_empty() {
        return Err("unexpected end of buffer: empty input".to_string());
    }

    let mut result = 0u64;
    let mut shift = 0;
    let max_bytes = buf.len().min(MAX_VARINT_BYTES);

    for (i, &byte) in buf.iter().take(max_bytes).enumerate() {
        // Check for overflow before shifting
        if shift >= 64 {
            return Err("varint overflow: value exceeds 64 bits".to_string());
        }

        // Add the 7 low bits to the result
        let value_bits = (byte & 0x7F) as u64;

        // Check if this would overflow when shifted
        if shift > 0 && value_bits > (u64::MAX >> shift) {
            return Err("varint overflow: would exceed u64::MAX".to_string());
        }

        result |= value_bits << shift;

        // If high bit is not set, we're done
        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }

        shift += 7;
    }

    // If we get here, we read max_bytes without finding the end
    if buf.len() < MAX_VARINT_BYTES {
        Err("unexpected end of buffer: incomplete varint".to_string())
    } else {
        Err("varint too long: exceeds 10 bytes".to_string())
    }
}

/// Decode a field value based on wire type and proto type.
fn decode_field_value(
    buf: &[u8],
    wire_type: u64,
    proto_type: &str,
) -> Result<(Value, usize), String> {
    match wire_type {
        0 => {
            // Varint
            let (value, bytes_read) = read_varint(buf)?;
            match proto_type {
                "bool" => Ok((Value::Bool(value != 0), bytes_read)),
                "int32" | "sint32" => {
                    // Zigzag decode for sint32
                    let decoded = ((value >> 1) as i32) ^ (-((value & 1) as i32));
                    Ok((Value::Number(decoded.into()), bytes_read))
                }
                "int64" | "sint64" => {
                    // Zigzag decode for sint64
                    let decoded = ((value >> 1) as i64) ^ (-((value & 1) as i64));
                    Ok((Value::Number(decoded.into()), bytes_read))
                }
                "uint32" | "uint64" => Ok((Value::Number(value.into()), bytes_read)),
                _ => Ok((Value::Number(value.into()), bytes_read)),
            }
        }
        1 => {
            // 64-bit fixed
            if buf.len() < 8 {
                return Err("insufficient bytes for 64-bit fixed".to_string());
            }
            let bytes_consumed = 8;
            match proto_type {
                "fixed64" | "sfixed64" => {
                    let value = u64::from_le_bytes([
                        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                    ]);
                    Ok((Value::Number(value.into()), bytes_consumed))
                }
                "double" => {
                    let bits = u64::from_le_bytes([
                        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
                    ]);
                    let value = f64::from_bits(bits);
                    serde_json::Number::from_f64(value)
                        .map(|n| (Value::Number(n), bytes_consumed))
                        .ok_or_else(|| "invalid double value".to_string())
                }
                _ => Err(format!("unexpected 64-bit fixed for type {}", proto_type)),
            }
        }
        2 => {
            // Length-delimited
            let (length, length_bytes) = read_varint(buf)?;
            let length = length as usize;

            if buf.len() < length_bytes + length {
                return Err(format!(
                    "insufficient bytes for length-delimited field: need {} + {}, have {}",
                    length_bytes, length, buf.len()
                ));
            }
            let bytes_consumed = length_bytes + length;
            let data = &buf[length_bytes..length_bytes + length];

            match proto_type {
                "string" => {
                    let s = String::from_utf8(data.to_vec())
                        .map_err(|e| format!("invalid UTF-8 string: {e}"))?;
                    Ok((Value::String(s), bytes_consumed))
                }
                "bytes" => {
                    Ok((
                        Value::String(base64::engine::general_purpose::STANDARD.encode(data)),
                        bytes_consumed,
                    ))
                }
                _ => {
                    // Nested message or unknown type - encode as base64
                    Ok((
                        Value::String(base64::engine::general_purpose::STANDARD.encode(data)),
                        bytes_consumed,
                    ))
                }
            }
        }
        5 => {
            // 32-bit fixed
            if buf.len() < 4 {
                return Err("insufficient bytes for 32-bit fixed".to_string());
            }
            let bytes_consumed = 4;
            match proto_type {
                "fixed32" | "sfixed32" => {
                    let value = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    Ok((Value::Number(value.into()), bytes_consumed))
                }
                "float" => {
                    let bits = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let value = f32::from_bits(bits);
                    serde_json::Number::from_f64(value as f64)
                        .map(|n| (Value::Number(n), bytes_consumed))
                        .ok_or_else(|| "invalid float value".to_string())
                }
                _ => Err(format!("unexpected 32-bit fixed for type {}", proto_type)),
            }
        }
        _ => Err(format!("unsupported wire type: {}", wire_type)),
    }
}

/// Skip a field value in the wire format.
fn skip_field_value(buf: &[u8], wire_type: u64) -> Result<(Value, usize), String> {
    match wire_type {
        0 => {
            // Varint
            read_varint(buf).map(|(_, bytes_read)| (Value::Null, bytes_read))
        }
        1 => {
            // 64-bit fixed
            if buf.len() < 8 {
                return Err(format!(
                    "insufficient bytes for 64-bit fixed: need 8, have {}",
                    buf.len()
                ));
            }
            Ok((Value::Null, 8))
        }
        2 => {
            // Length-delimited
            let (length, length_bytes) = read_varint(buf)?;
            let length = length as usize;

            if buf.len() < length_bytes + length {
                return Err(format!(
                    "insufficient bytes for length-delimited field: need {} + {}, have {}",
                    length_bytes, length, buf.len()
                ));
            }
            Ok((Value::Null, length_bytes + length))
        }
        5 => {
            // 32-bit fixed
            if buf.len() < 4 {
                return Err(format!(
                    "insufficient bytes for 32-bit fixed: need 4, have {}",
                    buf.len()
                ));
            }
            Ok((Value::Null, 4))
        }
        3 | 4 => {
            // Wire types 3 and 4 are deprecated (start/end group)
            Err(format!("deprecated wire type {} (groups are not supported)", wire_type))
        }
        _ => Err(format!("unsupported wire type: {} (valid types: 0, 1, 2, 5)", wire_type)),
    }
}

/// Check if a JSON value is empty.
fn is_empty_json_value(value: &Value) -> bool {
    match value {
        Value::String(s) => s.is_empty(),
        Value::Number(n) => n.as_u64().map(|v| v == 0).unwrap_or(false),
        Value::Bool(b) => !*b,
        Value::Null => true,
        _ => false,
    }
}

/// Encode JSON to protobuf wire format for a given entity type.
pub fn json_to_payload(entity_type: &str, json: &Value) -> Result<Vec<u8>, String> {
    let message_def = get_message_definition(entity_type)?;

    let obj = json.as_object()
        .ok_or_else(|| "JSON must be an object".to_string())?;

    let mut result = Vec::new();

    // Create a map of field names to field definitions
    let field_map: HashMap<&str, &ProtoField> = message_def
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f))
        .collect();

    // Encode fields in field number order
    let mut fields: Vec<(&ProtoField, &Value)> = obj
        .iter()
        .filter_map(|(name, value)| {
            field_map.get(name.as_str()).map(|field| (*field, value))
        })
        .collect();

    fields.sort_by_key(|(field, _)| field.field_number);

    for (field, value) in fields {
        encode_field(&mut result, field.field_number, &field.proto_type, value)?;
    }

    Ok(result)
}

/// Encode a single field to wire format.
fn encode_field(result: &mut Vec<u8>, field_number: u32, proto_type: &str, value: &Value) -> Result<(), String> {
    // Write tag (field number << 3 | wire_type)
    let wire_type = match proto_type {
        "int32" | "int64" | "uint32" | "uint64" | "sint32" | "sint64" | "bool" | "enum" => 0, // Varint
        "fixed64" | "sfixed64" | "double" => 1, // 64-bit fixed
        "string" | "bytes" | "message" => 2, // Length-delimited
        "fixed32" | "sfixed32" | "float" => 5, // 32-bit fixed
        _ => 2, // Default to length-delimited for unknown types
    };

    let tag = (field_number << 3) | wire_type;
    write_varint(result, tag as u64);

    match wire_type {
        0 => {
            // Varint
            let varint_value = match proto_type {
                "bool" => {
                    value.as_bool()
                        .ok_or("expected bool for field")? as u64
                }
                "int32" | "sint32" => {
                    let i = value.as_i64()
                        .ok_or("expected integer for field")? as i32;
                    // Zigzag encode for sint32
                    ((i << 1) ^ (i >> 31)) as u32 as u64
                }
                "int64" | "sint64" => {
                    let i = value.as_i64()
                        .ok_or("expected integer for field")?;
                    // Zigzag encode for sint64
                    ((i << 1) ^ (i >> 63)) as u64
                }
                "uint32" | "uint64" => {
                    value.as_u64()
                        .ok_or("expected unsigned integer for field")?
                }
                _ => {
                    value.as_u64()
                        .ok_or("expected integer for field")?
                }
            };
            write_varint(result, varint_value);
        }
        1 => {
            // 64-bit fixed
            match proto_type {
                "fixed64" | "sfixed64" => {
                    let v = value.as_u64()
                        .ok_or("expected unsigned integer for field")?;
                    result.extend_from_slice(&v.to_le_bytes());
                }
                "double" => {
                    let v = value.as_f64()
                        .ok_or("expected number for field")?;
                    result.extend_from_slice(&v.to_bits().to_le_bytes());
                }
                _ => return Err(format!("unexpected 64-bit fixed type: {}", proto_type)),
            }
        }
        2 => {
            // Length-delimited
            match proto_type {
                "string" => {
                    let s = value.as_str()
                        .ok_or("expected string for field")?;
                    let bytes = s.as_bytes();
                    write_varint(result, bytes.len() as u64);
                    result.extend_from_slice(bytes);
                }
                "bytes" => {
                    // Assume base64 encoded bytes
                    let s = value.as_str()
                        .ok_or("expected string (base64) for bytes field")?;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(s)
                        .map_err(|e| format!("invalid base64: {}", e))?;
                    write_varint(result, bytes.len() as u64);
                    result.extend_from_slice(&bytes);
                }
                _ => {
                    // Unknown type, try to encode as string
                    let s = value.as_str()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| value.to_string());
                    let bytes = s.as_bytes();
                    write_varint(result, bytes.len() as u64);
                    result.extend_from_slice(bytes);
                }
            }
        }
        5 => {
            // 32-bit fixed
            match proto_type {
                "fixed32" | "sfixed32" => {
                    let v = value.as_u64()
                        .ok_or("expected unsigned integer for field")? as u32;
                    result.extend_from_slice(&v.to_le_bytes());
                }
                "float" => {
                    let v = value.as_f64()
                        .ok_or("expected number for field")? as f32;
                    result.extend_from_slice(&v.to_bits().to_le_bytes());
                }
                _ => return Err(format!("unexpected 32-bit fixed type: {}", proto_type)),
            }
        }
        _ => return Err(format!("unsupported wire type: {}", wire_type)),
    }

    Ok(())
}

/// Write a varint to the buffer.
fn write_varint(result: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            result.push(byte);
            break;
        } else {
            result.push(byte | 0x80);
        }
    }
}
