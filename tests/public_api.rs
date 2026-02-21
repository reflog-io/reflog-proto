use prost::Message as _;
use reflog_proto::pb::IngestRecord;
use reflog_proto::{
    get_entity_types, get_message_definition, initialize_entity_registry,
    initialize_entity_registry_from_content, is_valid_entity_type, json_to_payload,
    payload_to_json, payload_to_json_partial, reload_entity_registry,
};
use reflog_proto::proto_parser::{parse_proto_content, parse_proto_file};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const PROTO_WITH_CUSTOM_OPTIONS: &str = r#"
syntax = "proto3";
package reflog.v1;
import "options.proto";

message User {
  string id = 1;
  string name = 2;
}

message Repo {
  string id = 1;
  string owner_id = 2 [(reflog.v1.foreign_key) = "User.id", (reflog.v1.relationship_type) = "many_to_one"];
  optional bool is_active = 3;
  bytes avatar = 4;
  repeated string tags = 5;
  Profile profile = 6;

  message Profile {
    string bio = 1;
    int32 score = 2;
  }
}
"#;

const PROTO_V1: &str = r#"
syntax = "proto3";
package reflog.v1;

message User {
  string id = 1;
  string name = 2;
}

message Repo {
  string id = 1;
  string owner_id = 2;
  optional bool is_active = 3;
  bytes avatar = 4;
  repeated string tags = 5;
  Profile profile = 6;

  message Profile {
    string bio = 1;
    int32 score = 2;
  }
}
"#;

const PROTO_V2: &str = r#"
syntax = "proto3";
package reflog.v1;

message User {
  string id = 1;
}

message Team {
  string id = 1;
  string owner_id = 2;
}
"#;

fn tests_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    match tests_lock().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("reflog_proto_test_{prefix}_{nanos}"));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn write_proto_file(path: &Path, content: &str) {
    fs::write(path, content).expect("proto file should be written");
}

#[test]
fn parse_proto_content_extracts_messages_nested_types_and_custom_options() {
    let _guard = lock_tests();
    let messages = parse_proto_content(PROTO_WITH_CUSTOM_OPTIONS).expect("content should parse");
    assert!(messages.iter().any(|m| m.name == "User"));
    let repo = messages
        .iter()
        .find(|m| m.name == "Repo")
        .expect("Repo message should exist");

    let owner_id = repo
        .fields
        .iter()
        .find(|f| f.name == "owner_id")
        .expect("owner_id field should exist");
    assert_eq!(owner_id.foreign_key.as_deref(), Some("User.id"));
    assert_eq!(owner_id.relationship_type.as_deref(), Some("many_to_one"));

    let nested = repo
        .nested_messages
        .iter()
        .find(|m| m.name == "Profile")
        .expect("Profile nested message should be captured");
    assert!(nested.fields.iter().any(|f| f.name == "bio"));
}

#[test]
fn parse_proto_file_reads_schema_from_disk() {
    let _guard = lock_tests();
    let dir = temp_dir("parse_file");
    let path = dir.join("schema.proto");
    write_proto_file(&path, PROTO_V1);

    let messages = parse_proto_file(&path).expect("file-based parse should work");
    assert!(messages.iter().any(|m| m.name == "Repo"));
}

#[test]
fn initialize_and_lookup_registry_from_content() {
    let _guard = lock_tests();
    initialize_entity_registry_from_content(PROTO_V1).expect("registry should initialize");

    assert!(is_valid_entity_type("User"));
    assert!(is_valid_entity_type("Repo"));
    assert!(is_valid_entity_type("Profile"));
    assert!(!is_valid_entity_type("DoesNotExist"));

    let types = get_entity_types();
    assert!(types.contains(&"User".to_string()));
    assert!(types.contains(&"Repo".to_string()));

    let repo = get_message_definition("Repo").expect("Repo definition should exist");
    let id = repo
        .fields
        .iter()
        .find(|f| f.name == "id")
        .expect("id field should exist");
    assert_eq!(id.field_number, 1);
}

#[test]
fn json_payload_roundtrip_and_partial_filtering_behaves_as_expected() {
    let _guard = lock_tests();
    initialize_entity_registry_from_content(PROTO_V1).expect("registry should initialize");

    let input = json!({
        "id": "repo_1",
        "ownerId": "user_1",
        "isActive": false,
        "avatar": "AQI=",
        "tags": ["rust", "proto"],
        "profile": {
            "bio": "hello",
            "score": 42
        }
    });

    let payload = json_to_payload("Repo", &input).expect("json should encode");
    assert!(!payload.is_empty());

    let decoded_full = payload_to_json_partial("Repo", &payload, true).expect("payload should decode");
    assert_eq!(decoded_full["id"], "repo_1");
    assert_eq!(decoded_full["ownerId"], "user_1");
    assert_eq!(decoded_full["isActive"], false);
    assert_eq!(decoded_full["avatar"], "AQI=");

    let decoded_filtered = payload_to_json("Repo", &payload).expect("payload should decode");
    assert_eq!(decoded_filtered["id"], "repo_1");
    assert_eq!(decoded_filtered["ownerId"], "user_1");
    assert!(decoded_filtered.get("isActive").is_none());
}

#[test]
fn initialize_from_file_and_reload_registry_updates_entity_set() {
    let _guard = lock_tests();
    let dir = temp_dir("reload");
    let path = dir.join("schema.proto");

    write_proto_file(&path, PROTO_V1);
    initialize_entity_registry(&path).expect("registry should initialize from file");
    assert!(is_valid_entity_type("Repo"));
    assert!(!is_valid_entity_type("Team"));

    write_proto_file(&path, PROTO_V2);
    reload_entity_registry(&path).expect("reload should succeed");
    assert!(!is_valid_entity_type("Repo"));
    assert!(is_valid_entity_type("Team"));
}

#[test]
fn public_api_returns_clear_errors_for_invalid_inputs() {
    let _guard = lock_tests();
    initialize_entity_registry_from_content(PROTO_V1).expect("registry should initialize");

    let unknown = payload_to_json("Nope", &[1, 2, 3]).expect_err("unknown type should error");
    assert!(unknown.contains("unknown entity type"));

    let invalid_json = json!("not-an-object");
    let err = json_to_payload("Repo", &invalid_json).expect_err("non-object json should error");
    assert!(err.contains("JSON must be an object"));

    let bad_proto = "syntax = \"proto3\"; message Broken { string x = ; }";
    assert!(initialize_entity_registry_from_content(bad_proto).is_err());

    // This should parse because custom options are resolved through preserved descriptor extensions.
    initialize_entity_registry_from_content(PROTO_WITH_CUSTOM_OPTIONS)
        .expect("custom options should be interpreted");
}

#[test]
fn generated_pb_types_are_usable_and_roundtrip_with_prost() {
    let _guard = lock_tests();
    let msg = IngestRecord {
        entity_type: "Repo".to_string(),
        entity_id: "repo_123".to_string(),
        operation: 1,
        payload: vec![0x01, 0x02, 0x03],
        received_at_utc: 123_456,
        created_at_utc: Some(111),
        updated_at_utc: Some(222),
        deleted_at_utc: None,
    };

    let bytes = msg.encode_to_vec();
    let decoded = IngestRecord::decode(bytes.as_slice()).expect("decode should work");

    assert_eq!(decoded.entity_type, "Repo");
    assert_eq!(decoded.entity_id, "repo_123");
    assert_eq!(decoded.operation, 1);
    assert_eq!(decoded.payload, vec![0x01, 0x02, 0x03]);
    assert_eq!(decoded.created_at_utc, Some(111));
    assert_eq!(decoded.updated_at_utc, Some(222));
    assert_eq!(decoded.deleted_at_utc, None);
}
