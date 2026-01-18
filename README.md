# reflog-proto

Shared protobuf definitions and schema utilities for reflog.

## Usage

Add to your `Cargo.toml`:

```toml
# Via Git (recommended for cross-repo usage):
reflog-proto = { git = "ssh://git@github.com/reflog-io/reflog-proto.git" }

# Or pin to a specific tag:
reflog-proto = { git = "ssh://git@github.com/reflog-io/reflog-proto", tag = "v0.1.0" }

# For local development:
reflog-proto = { path = "../reflog-proto" }
```

## Features

- **Proto file parsing**: Extract message and field definitions from `.proto` files
- **Entity registry**: Runtime registry of valid entity types
- **Payload encoding/decoding**: Convert between protobuf wire format and JSON

## Example

```rust
use reflog_proto::{initialize_entity_registry, payload_to_json, json_to_payload};
use std::path::Path;

// Initialize from a proto file
initialize_entity_registry(Path::new("path/to/custom.proto"))?;

// Decode a protobuf payload to JSON
let json = payload_to_json("user", &payload_bytes)?;

// Encode JSON to protobuf
let payload = json_to_payload("user", &json)?;
```

## Proto Files

The `proto/` directory contains the shared proto definitions:

- `ingest.proto` - Core ingest service messages
- `options.proto` - Custom field options (foreign keys, relationships)
- `custom.proto` - Example entity definitions (User, Article, Comment)

## License

MIT
