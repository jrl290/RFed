//! Encode and decode the rfed.node announce payload.
//!
//! Format: msgpack array  `[display_name: bin, stamp_cost: uint|nil, protocol_version: uint]`
//!
//! This mirrors the LXMF propagation node announce format so that future
//! tools that already parse LXMF announces can easily support rfed nodes.

use rmpv::{encode::write_value, decode::read_value, Value};

pub const PROTOCOL_VERSION: u8 = 1;

pub struct NodeAnnounce {
    pub display_name: String,
    pub stamp_cost: Option<u32>,
    pub protocol_version: u8,
}

/// Encode an rfed.node announce payload as a msgpack byte array.
pub fn encode_node_announce(display_name: &str, stamp_cost: Option<u32>) -> Vec<u8> {
    let cost_value = match stamp_cost {
        Some(c) => Value::Integer(c.into()),
        None    => Value::Nil,
    };
    let payload = Value::Array(vec![
        Value::Binary(display_name.as_bytes().to_vec()),
        cost_value,
        Value::Integer(PROTOCOL_VERSION.into()),
    ]);
    let mut buf = Vec::new();
    let _ = write_value(&mut buf, &payload);
    buf
}

/// Decode an rfed.node announce payload. Returns `None` on malformed input.
pub fn decode_node_announce(data: &[u8]) -> Option<NodeAnnounce> {
    let value = read_value(&mut std::io::Cursor::new(data)).ok()?;
    let items = match value {
        Value::Array(v) => v,
        _ => return None,
    };

    let display_name = items.first().and_then(|v| match v {
        Value::Binary(b) => String::from_utf8(b.clone()).ok(),
        Value::String(s) => Some(s.as_str().unwrap_or("").to_string()),
        _ => None,
    }).unwrap_or_default();

    let stamp_cost = items.get(1).and_then(|v| match v {
        Value::Integer(i) => i.as_u64().map(|n| n as u32),
        _ => None,
    });

    let protocol_version = items.get(2).and_then(|v| match v {
        Value::Integer(i) => i.as_u64().map(|n| n as u8),
        _ => None,
    }).unwrap_or(0);

    Some(NodeAnnounce { display_name, stamp_cost, protocol_version })
}
