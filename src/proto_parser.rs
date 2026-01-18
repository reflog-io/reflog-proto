//! Parser for .proto files to extract message and field definitions.

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
}

/// Parse a proto file and extract entity message definitions.
/// Excludes system messages like IngestRecord, IngestResponse, etc.
pub fn parse_proto_file(proto_path: &std::path::Path) -> Result<Vec<ProtoMessage>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(proto_path)?;
    let lines: Vec<&str> = content.lines().collect();

    let mut messages = Vec::new();
    let mut current_message: Option<String> = None;
    let mut current_fields: Vec<ProtoField> = Vec::new();
    let mut in_message = false;

    // Messages to exclude (system messages)
    let excluded_messages = ["IngestRecord", "IngestResponse", "Operation",
                            "HealthCheckRequest", "HealthCheckResponse",
                            "GetProtosRequest", "GetProtosResponse"];

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Detect message start
        if trimmed.starts_with("message ") {
            // Save previous message if any
            if let Some(msg_name) = current_message.take() {
                if !excluded_messages.contains(&msg_name.as_str()) {
                    messages.push(ProtoMessage {
                        name: msg_name,
                        fields: current_fields.clone(),
                    });
                }
                current_fields.clear();
            }

            let message_name = trimmed
                .strip_prefix("message ")
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("")
                .to_string();

            if !excluded_messages.contains(&message_name.as_str()) {
                current_message = Some(message_name);
                in_message = true;
            }
            continue;
        }

        // Detect message end
        if trimmed == "}" && in_message {
            if let Some(msg_name) = current_message.take() {
                if !excluded_messages.contains(&msg_name.as_str()) {
                    messages.push(ProtoMessage {
                        name: msg_name,
                        fields: current_fields.clone(),
                    });
                }
                current_fields.clear();
            }
            in_message = false;
            continue;
        }

        // Parse fields within a message
        if in_message && current_message.is_some() {
            if let Some(field) = parse_field_line(line, i, &lines) {
                current_fields.push(field);
            }
        }
    }

    // Handle last message if file doesn't end with }
    if let Some(msg_name) = current_message {
        if !excluded_messages.contains(&msg_name.as_str()) {
            messages.push(ProtoMessage {
                name: msg_name,
                fields: current_fields,
            });
        }
    }

    Ok(messages)
}

fn parse_field_line(line: &str, line_idx: usize, all_lines: &[&str]) -> Option<ProtoField> {
    let trimmed = line.trim();

    // Skip empty lines, comments, and closing braces
    if trimmed.is_empty() || trimmed.starts_with("//") || trimmed == "}" {
        return None;
    }

    // Check if this line has field options (foreign_key annotations)
    let has_options = trimmed.contains("[(reflog.v1.foreign_key)");

    // Find the field definition - it might be on this line or previous lines
    let mut field_type = String::new();
    let mut field_name = String::new();
    let mut field_number = 0u32;
    let mut full_line = trimmed.to_string();

    // If options are on a separate line, combine with previous line
    if has_options && !trimmed.contains('=') {
        // Look for the field definition on previous lines
        for j in (line_idx.saturating_sub(3)..line_idx).rev() {
            if let Some(prev_line) = all_lines.get(j) {
                let prev_trimmed = prev_line.trim();
                if prev_trimmed.contains('=') && !prev_trimmed.starts_with("//") {
                    full_line = format!("{} {}", prev_trimmed, trimmed);
                    break;
                }
            }
        }
    }

    // Parse field definition: "type field_name = number" or "type field_name = number [(options)]"
    // Remove everything after '[' if present, then parse
    let field_def_part = if let Some(bracket_pos) = full_line.find('[') {
        &full_line[..bracket_pos]
    } else {
        &full_line
    };

    // Remove semicolon
    let field_def_part = field_def_part.trim_end_matches(';').trim();

    // Split by whitespace
    let parts: Vec<&str> = field_def_part.split_whitespace().collect();
    if parts.len() >= 3 {
        field_type = parts[0].to_string();
        field_name = parts[1].to_string();

        // Extract field number from "= number"
        if parts.len() >= 3 && parts[2] == "=" && parts.len() >= 4 {
            field_number = parts[3].parse().unwrap_or(0);
        } else if parts[2].starts_with('=') {
            // Handle "=number" without space
            let num_str = parts[2].trim_start_matches('=');
            field_number = num_str.parse().unwrap_or(0);
        }
    }

    if field_name.is_empty() || field_number == 0 {
        return None;
    }

    // Extract foreign_key and relationship_type from annotations
    let mut foreign_key = None;
    let mut relationship_type = None;

    if has_options {
        // Extract foreign_key option value
        if let Some(start) = full_line.find("foreign_key) = \"") {
            let start_idx = start + "foreign_key) = \"".len();
            if let Some(end) = full_line[start_idx..].find('"') {
                foreign_key = Some(full_line[start_idx..start_idx + end].to_string());
            }
        }

        // Extract relationship_type option value
        if let Some(start) = full_line.find("relationship_type) = \"") {
            let start_idx = start + "relationship_type) = \"".len();
            if let Some(end) = full_line[start_idx..].find('"') {
                relationship_type = Some(full_line[start_idx..start_idx + end].to_string());
            }
        }
    }

    Some(ProtoField {
        name: field_name,
        proto_type: field_type,
        field_number,
        foreign_key,
        relationship_type,
    })
}
