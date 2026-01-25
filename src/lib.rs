//! Shared protobuf definitions and schema utilities for reflog.
//!
//! This crate provides:
//! - Compiled protobuf types (`pb`)
//! - Proto file parsing (`proto_parser`)
//! - Entity registry and payload decoding (`schema`)
//! - Embedded proto file content
//!
//! # Usage
//!
//! Add to your `Cargo.toml`:
//!
//! ```toml
//! # For local development:
//! reflog-proto = { path = "../reflog-proto" }
//!
//! # Or via Git:
//! reflog-proto = { git = "ssh://git@github.com/yourorg/reflog-proto.git" }
//! ```

pub mod pb {
    tonic::include_proto!("reflog.v1");
}

pub mod proto_parser;
pub mod schema;

/// The embedded custom.proto file content.
/// Use this with `initialize_entity_registry_from_content` to avoid needing proto files at runtime.
pub const CUSTOM_PROTO_CONTENT: &str = include_str!("../proto/custom.proto");

// Re-export commonly used types
pub use proto_parser::{ProtoField, ProtoMessage};
pub use schema::{
    get_entity_types, get_message_definition, initialize_entity_registry,
    initialize_entity_registry_from_content, is_valid_entity_type, json_to_payload,
    payload_to_json, payload_to_json_partial, reload_entity_registry,
};
