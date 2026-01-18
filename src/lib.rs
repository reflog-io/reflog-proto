//! Shared protobuf definitions and schema utilities for reflog.
//!
//! This crate provides:
//! - Proto file parsing (`proto_parser`)
//! - Entity registry and payload decoding (`schema`)
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

pub mod proto_parser;
pub mod schema;

// Re-export commonly used types
pub use proto_parser::{ProtoField, ProtoMessage};
pub use schema::{
    get_entity_types,
    get_message_definition,
    initialize_entity_registry,
    is_valid_entity_type,
    json_to_payload,
    payload_to_json,
    payload_to_json_partial,
    reload_entity_registry,
};
