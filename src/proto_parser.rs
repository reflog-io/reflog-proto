//! Parser for .proto files to extract message and field definitions.
//! Uses `nom` to handle grammar, nesting, and whitespace robustly.

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_until},
    character::complete::{alpha1, alphanumeric1, char, digit1, multispace1, none_of},
    combinator::{map, opt, recognize, value},
    multi::{many0, separated_list0},
    sequence::{delimited, pair, preceded, tuple},
    IResult,
};
use std::collections::HashMap;

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
    parse_proto_content(&content)
}

/// Parse proto content and extract entity message definitions.
pub fn parse_proto_content(
    content: &str,
) -> Result<Vec<ProtoMessage>, Box<dyn std::error::Error>> {
    // 1. Run the nom parser on the whole content
    let (_, mut items) = parse_proto_root(content)
        .map_err(|e| format!("Failed to parse proto file: {}", e))?;

    // 2. Filter out system messages
    // (We do this post-parse to keep the grammar clean)
    let excluded_messages = [
        "IngestRecord", "IngestResponse", "Operation",
        "HealthCheckRequest", "HealthCheckResponse",
        "GetProtosRequest", "GetProtosResponse",
    ];

    items.retain(|msg| !excluded_messages.contains(&msg.name.as_str()));

    Ok(items)
}

// ==========================================
//           Nom Parser Logic
// ==========================================

/// Parses whitespace and comments (// ... or /* ... */)
fn ws(input: &str) -> IResult<&str, &str> {
    recognize(many0(alt((
        multispace1,
        preceded(tag("//"), take_until("\n")),
        recognize(delimited(tag("/*"), take_until("*/"), tag("*/"))),
    ))))(input)
}

/// Helper to wrap a parser with whitespace handling
fn ws_delimited<'a, O, F>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    delimited(ws, inner, ws)
}

/// Identifiers (e.g., MessageName, field_name, package.name)
fn identifier(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0(alt((alphanumeric1, tag("_"), tag(".")))),
    ))(input)
}

/// Parse a quoted string literal: "value"
fn string_literal(input: &str) -> IResult<&str, String> {
    delimited(
        char('"'),
        map(many0(none_of("\"")), |chars: Vec<char>| chars.into_iter().collect()),
        char('"'),
    )(input)
}

/// Parse field options: [(reflog.v1.foreign_key) = "Val", (other) = "x"]
fn parse_field_options(input: &str) -> IResult<&str, HashMap<String, String>> {
    let option_pair = map(
        tuple((
            opt(char('(')),
            identifier,
            opt(char(')')),
            ws_delimited(char('=')),
            string_literal
        )),
        |(_, key, _, _, val)| (key.to_string(), val)
    );

    let options_list = delimited(
        char('['),
        separated_list0(ws_delimited(char(',')), option_pair),
        char(']')
    );

    map(options_list, |opts| opts.into_iter().collect())(input)
}

/// Parse a single field definition
/// matches: `optional string name = 1 [(options)];`
fn parse_proto_field(input: &str) -> IResult<&str, ProtoField> {
    let (input, _) = opt(ws_delimited(alt((tag("repeated"), tag("optional"), tag("required")))))(input)?;

    // Parse Type (handles map<string, int> and standard types)
    let (input, proto_type) = ws_delimited(recognize(pair(
        identifier,
        opt(delimited(char('<'), is_not(">"), char('>')))
    )))(input)?;

    let (input, name) = ws_delimited(identifier)(input)?;
    let (input, _) = ws_delimited(char('='))(input)?;
    let (input, field_number) = ws_delimited(digit1)(input)?;

    // Parse Options (optional)
    let (input, options) = opt(ws_delimited(parse_field_options))(input)?;
    let (input, _) = ws_delimited(char(';'))(input)?;

    // Extract special keys
    let mut foreign_key = None;
    let mut relationship_type = None;

    if let Some(opts) = options {
        // We look for keys ending in foreign_key or relationship_type
        // to handle fully qualified keys like `reflog.v1.foreign_key`
        for (k, v) in opts {
            if k.contains("foreign_key") {
                foreign_key = Some(v);
            } else if k.contains("relationship_type") {
                relationship_type = Some(v);
            }
        }
    }

    Ok((input, ProtoField {
        name: name.to_string(),
        proto_type: proto_type.to_string(),
        field_number: field_number.parse().unwrap_or(0),
        foreign_key,
        relationship_type,
    }))
}

/// Parse a Message block (recursive)
fn parse_message(input: &str) -> IResult<&str, ProtoMessage> {
    let (input, _) = ws_delimited(tag("message"))(input)?;
    let (input, name) = ws_delimited(identifier)(input)?;
    let (input, _) = ws_delimited(char('{'))(input)?;

    // Inner loop to handle contents of message
    // We only care about Fields and Nested Messages, but we must parse (and ignore)
    // things like `option`, `reserved`, etc., so the parser doesn't get stuck.
    #[derive(Clone)]
    enum Item {
        Field(ProtoField),
        Nested(ProtoMessage),
        Ignored,
    }

    let (input, items) = many0(alt((
        map(parse_message, Item::Nested),
        map(parse_proto_field, Item::Field),
        // Ignorables:
        // 1. Reserved statements: reserved 1, 2;
        value(Item::Ignored, tuple((ws_delimited(tag("reserved")), take_until(";"), char(';')))),
        // 2. Option statements: option (x) = y;
        value(Item::Ignored, tuple((ws_delimited(tag("option")), take_until(";"), char(';')))),
        // 3. Map fields (if using `map` keyword specifically, though `parse_proto_field` handles map types)
        // 4. OneOfs (simple skip for now, can be expanded)
        value(Item::Ignored, tuple((ws_delimited(tag("oneof")), identifier, ws_delimited(char('{')), take_until("}")))),
    )))(input)?;

    let (input, _) = ws_delimited(char('}'))(input)?;

    let mut fields = Vec::new();
    let mut nested_messages = Vec::new();

    for item in items {
        match item {
            Item::Field(f) => fields.push(f),
            Item::Nested(m) => nested_messages.push(m),
            Item::Ignored => {}
        }
    }

    Ok((input, ProtoMessage {
        name: name.to_string(),
        fields,
        nested_messages,
    }))
}

/// Top level parser: handles syntax decl, package, imports, service, and messages
fn parse_proto_root(input: &str) -> IResult<&str, Vec<ProtoMessage>> {
    let (input, _) = ws(input)?; // Consume leading whitespace

    let (input, found_items) = many0(alt((
        map(parse_message, Some),
        // Skip Syntax
        value(None, tuple((ws_delimited(tag("syntax")), take_until(";"), char(';')))),
        // Skip Package
        value(None, tuple((ws_delimited(tag("package")), take_until(";"), char(';')))),
        // Skip Imports
        value(None, tuple((ws_delimited(tag("import")), take_until(";"), char(';')))),
        // Skip Options
        value(None, tuple((ws_delimited(tag("option")), take_until(";"), char(';')))),
        // Skip Service (and its body)
        value(None, tuple((
            ws_delimited(tag("service")),
            identifier,
            ws_delimited(char('{')),
            take_until("}"), // Lazy skip of service body
            char('}')
        ))),
    )))(input)?;

    Ok((input, found_items.into_iter().flatten().collect()))
}
