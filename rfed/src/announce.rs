//! Encode and decode the rfed.node announce payload (SPEC §12).
//!
//! Format: msgpack array
//! `[display_name: bin, channel_stamp_cost: uint|nil, protocol_version: uint,
//!   propagation_stamp_cost: uint|nil, propagation_transfer_limit_kb: uint|nil]`
//!
//! `channel_stamp_cost` is `nil` when channel-SEND PoW is disabled. It was
//! named `stamp_cost` before 2026-11-13; its value and place are unchanged.
//! The last two are the stamp cost and per-message limit of this node's
//! `lxmf.propagation` (the same values as that destination's own announce),
//! `nil` when the node runs no propagation node. They are appended, so a
//! reader takes the positions it knows and ignores the rest: a version-1
//! node sends three elements.
//!
//! This mirrors the LXMF propagation node announce format so that future
//! tools that already parse LXMF announces can easily support rfed nodes.

use rmpv::{encode::write_value, decode::read_value, Value};

/// 2 from the 2026-11-13 revision: the appended propagation fields, the LXMF
/// propagation paths on `rfed.link`, and the channel push `/channel/delivery`
/// (RFed-spec/Link.md). 1 before it.
pub const PROTOCOL_VERSION: u8 = 2;

/// What a client needs to upload to this node's propagation node over
/// `rfed.link`: the stamp cost, and the per-message limit in KB of 1000 B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropagationTerms {
    pub stamp_cost: u32,
    pub transfer_limit_kb: u64,
}

#[derive(Debug)]
pub struct NodeAnnounce {
    pub display_name: String,
    /// Position 1, formerly `stamp_cost`.
    pub channel_stamp_cost: Option<u32>,
    pub protocol_version: u8,
    /// Positions 3 and 4; `None` from a version-1 node or one without a
    /// propagation node.
    pub propagation: Option<PropagationTerms>,
}

/// Encode an rfed.node announce payload as a msgpack byte array.
pub fn encode_node_announce(
    display_name: &str,
    channel_stamp_cost: Option<u32>,
    propagation: Option<PropagationTerms>,
) -> Vec<u8> {
    let uint_or_nil = |v: Option<u64>| match v {
        Some(n) => Value::Integer(n.into()),
        None => Value::Nil,
    };
    let payload = Value::Array(vec![
        Value::Binary(display_name.as_bytes().to_vec()),
        uint_or_nil(channel_stamp_cost.map(u64::from)),
        Value::Integer(PROTOCOL_VERSION.into()),
        uint_or_nil(propagation.map(|p| u64::from(p.stamp_cost))),
        uint_or_nil(propagation.map(|p| p.transfer_limit_kb)),
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

    let uint_at = |i: usize| items.get(i).and_then(|v| match v {
        Value::Integer(n) => n.as_u64(),
        _ => None,
    });

    let channel_stamp_cost = uint_at(1).map(|n| n as u32);
    let protocol_version = uint_at(2).map(|n| n as u8).unwrap_or(0);
    let propagation = match (uint_at(3), uint_at(4)) {
        (Some(cost), Some(limit)) => Some(PropagationTerms {
            stamp_cost: cost as u32,
            transfer_limit_kb: limit,
        }),
        _ => None,
    };

    Some(NodeAnnounce { display_name, channel_stamp_cost, protocol_version, propagation })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_with_propagation_announces_five_fields_and_version_2() {
        let terms = PropagationTerms { stamp_cost: 16, transfer_limit_kb: 256 };
        let data = encode_node_announce("node", Some(12), Some(terms));
        let items = match read_value(&mut std::io::Cursor::new(&data)).unwrap() {
            Value::Array(v) => v,
            other => panic!("not an array: {other:?}"),
        };
        assert_eq!(items.len(), 5);
        assert_eq!(items[0], Value::Binary(b"node".to_vec()));
        assert_eq!(items[1], Value::Integer(12.into()));
        assert_eq!(items[2], Value::Integer(2.into()));
        assert_eq!(items[3], Value::Integer(16.into()));
        assert_eq!(items[4], Value::Integer(256.into()));

        let ann = decode_node_announce(&data).unwrap();
        assert_eq!(ann.display_name, "node");
        assert_eq!(ann.channel_stamp_cost, Some(12));
        assert_eq!(ann.protocol_version, 2);
        assert_eq!(ann.propagation, Some(terms));
    }

    #[test]
    fn a_node_without_propagation_sends_nil_for_its_terms() {
        let data = encode_node_announce("node", None, None);
        let items = match read_value(&mut std::io::Cursor::new(&data)).unwrap() {
            Value::Array(v) => v,
            other => panic!("not an array: {other:?}"),
        };
        assert_eq!(items.len(), 5);
        assert_eq!(items[1], Value::Nil);
        assert_eq!(items[2], Value::Integer(2.into()));
        assert_eq!(items[3], Value::Nil);
        assert_eq!(items[4], Value::Nil);
        let ann = decode_node_announce(&data).unwrap();
        assert_eq!(ann.channel_stamp_cost, None);
        assert_eq!(ann.propagation, None);
    }

    #[test]
    fn a_version_1_announce_still_decodes() {
        // `[name, stamp_cost, 1]`: every rfed before the 2026-11-13 revision.
        let v1 = Value::Array(vec![
            Value::Binary(b"old".to_vec()),
            Value::Integer(8.into()),
            Value::Integer(1.into()),
        ]);
        let mut data = Vec::new();
        write_value(&mut data, &v1).unwrap();
        let ann = decode_node_announce(&data).unwrap();
        assert_eq!(ann.display_name, "old");
        assert_eq!(ann.channel_stamp_cost, Some(8));
        assert_eq!(ann.protocol_version, 1);
        assert_eq!(ann.propagation, None);
    }
}
