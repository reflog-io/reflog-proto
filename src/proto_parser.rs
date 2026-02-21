//! Parser for .proto files to extract message and field definitions.
//! Uses protobuf descriptors for robust schema introspection.

use prost_reflect::{DescriptorPool, FieldDescriptor, Kind, MessageDescriptor, Value};
use protox::Compiler;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ProtoField {
    pub name: String,
    pub proto_type: String,
    pub field_number: u32,
    pub foreign_key: Option<String>, // Format: "EntityType.field_name"
    pub relationship_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProtoMessage {
    pub name: String,
    pub fields: Vec<ProtoField>,
    pub nested_messages: Vec<ProtoMessage>,
}

/// Parse a proto file and extract entity message definitions.
pub fn parse_proto_file(
    proto_path: &std::path::Path,
) -> Result<Vec<ProtoMessage>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(proto_path)?;
    let virtual_name = proto_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("schema.proto");
    let include_dir = proto_path.parent().unwrap_or_else(|| Path::new("."));
    parse_proto_content_internal(&content, virtual_name, Some(include_dir))
}

/// Parse proto content and extract entity message definitions.
/// Note: Timestamp fields (created_at_utc, updated_at_utc, deleted_at_utc) are now
/// provided at the top level in IngestRecord, so they are no longer added to payload messages.
pub fn parse_proto_content(content: &str) -> Result<Vec<ProtoMessage>, Box<dyn std::error::Error>> {
    parse_proto_content_internal(content, "schema.proto", None)
}

pub(crate) fn descriptor_pool_from_file(
    proto_path: &Path,
) -> Result<DescriptorPool, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(proto_path)?;
    let virtual_name = proto_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("schema.proto");
    let include_dir = proto_path.parent().unwrap_or_else(|| Path::new("."));
    build_descriptor_pool(&content, virtual_name, Some(include_dir))
}

pub(crate) fn descriptor_pool_from_content(
    content: &str,
) -> Result<DescriptorPool, Box<dyn std::error::Error>> {
    build_descriptor_pool(content, "schema.proto", None)
}

fn parse_proto_content_internal(
    content: &str,
    virtual_file_name: &str,
    include_dir: Option<&Path>,
) -> Result<Vec<ProtoMessage>, Box<dyn std::error::Error>> {
    let pool = build_descriptor_pool(content, virtual_file_name, include_dir)?;
    let root_file = pool
        .get_file_by_name(virtual_file_name)
        .ok_or_else(|| format!("compiled descriptor missing file {virtual_file_name}"))?;

    let excluded_messages = [
        "IngestRecord",
        "IngestResponse",
        "Operation",
        "HealthCheckRequest",
        "HealthCheckResponse",
        "GetProtosRequest",
        "GetProtosResponse",
    ];

    let mut result = Vec::new();
    for message in root_file.messages() {
        if excluded_messages.contains(&message.name()) {
            continue;
        }
        if message.is_map_entry() {
            continue;
        }
        result.push(convert_message(message));
    }

    Ok(result)
}

fn build_descriptor_pool(
    content: &str,
    virtual_file_name: &str,
    include_dir: Option<&Path>,
) -> Result<DescriptorPool, Box<dyn std::error::Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temp_dir = std::env::temp_dir().join(format!("reflog_proto_{unique}"));
    std::fs::create_dir_all(&temp_dir)?;

    let file_path = temp_dir.join(virtual_file_name);
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&file_path, content)?;

    // Provide built-in custom options for standalone content parsing.
    // This makes `parse_proto_content` work when the schema imports `options.proto`.
    if virtual_file_name != "options.proto" {
        std::fs::write(temp_dir.join("options.proto"), include_str!("../proto/options.proto"))?;
    }

    let mut include_paths = vec![temp_dir.as_path()];
    if let Some(include) = include_dir {
        include_paths.push(include);
    }

    let mut compiler = Compiler::new(include_paths)?;
    compiler
        .include_imports(true)
        .include_source_info(true)
        .open_files([virtual_file_name])?;
    let encoded = compiler.encode_file_descriptor_set();
    let pool = DescriptorPool::decode(encoded.as_slice())?;

    let _ = std::fs::remove_dir_all(&temp_dir);
    Ok(pool)
}

fn convert_message(message: MessageDescriptor) -> ProtoMessage {
    let fields = message.fields().map(convert_field).collect();
    let nested_messages = message
        .child_messages()
        .filter(|child| !child.is_map_entry())
        .map(convert_message)
        .collect();

    ProtoMessage {
        name: message.name().to_string(),
        fields,
        nested_messages,
    }
}

fn convert_field(field: FieldDescriptor) -> ProtoField {
    let mut foreign_key = None;
    let mut relationship_type = None;

    let options = field.options();
    for (extension, value) in options.extensions() {
        let short_name = extension.name();
        let full_name = extension.full_name();
        if short_name == "foreign_key" || full_name.ends_with(".foreign_key") {
            foreign_key = dynamic_value_as_string(value);
        } else if short_name == "relationship_type" || full_name.ends_with(".relationship_type") {
            relationship_type = dynamic_value_as_string(value);
        }
    }
    ProtoField {
        name: field.name().to_string(),
        proto_type: kind_to_proto_type(field.kind()),
        field_number: field.number(),
        foreign_key,
        relationship_type,
    }
}

fn kind_to_proto_type(kind: Kind) -> String {
    match kind {
        Kind::Double => "double".to_string(),
        Kind::Float => "float".to_string(),
        Kind::Int32 => "int32".to_string(),
        Kind::Int64 => "int64".to_string(),
        Kind::Uint32 => "uint32".to_string(),
        Kind::Uint64 => "uint64".to_string(),
        Kind::Sint32 => "sint32".to_string(),
        Kind::Sint64 => "sint64".to_string(),
        Kind::Fixed32 => "fixed32".to_string(),
        Kind::Fixed64 => "fixed64".to_string(),
        Kind::Sfixed32 => "sfixed32".to_string(),
        Kind::Sfixed64 => "sfixed64".to_string(),
        Kind::Bool => "bool".to_string(),
        Kind::String => "string".to_string(),
        Kind::Bytes => "bytes".to_string(),
        Kind::Message(msg) => msg.name().to_string(),
        Kind::Enum(enum_desc) => enum_desc.name().to_string(),
    }
}

fn dynamic_value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}
