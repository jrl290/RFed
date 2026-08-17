//! RNS destination setup and handler wiring for the Federation Node.
//!
//! Four inbound destinations are registered:
//!
//!   rfed.node      — Node announce + peer manifest/sync (OFFER, MESSAGE_GET)
//!                    Backup push, capabilities query
//!   rfed.delivery  — Client inbox pull (PULL request proves private key)
//!   rfed.channel   — Inbound inner blobs + subscription control
//!                    (SEND packet, SUBSCRIBE / UNSUBSCRIBE requests)
//!   rfed.notify    — Notify registration (REGISTER / UNREGISTER / CLEAR requests)
//!
//! # Wire format (CHANNEL MESSAGES ARE LXMF PACKAGES)
//!
//! Channel send/fanout packet payload:
//!     [ channel_id_hash(16) | inner_blob(*) ]
//!
//! * `channel_id_hash` is the channel **identity hash** — i.e. what
//!   subscribers register with `/rfed/subscribe`, what RFed routes on
//!   in `subscription_table`, and what the Retichat clients call
//!   `Channel.id`. RFed never inspects, decrypts or re-derives this.
//! * `inner_blob` is byte-identical to the EC-encrypted authentication
//!   payload `lxmf_rust::LXMessage::pack(PROPAGATED)` produces — the
//!   tail after the destination_hash:
//!     `EC_encrypted(source_hash || signature || msgpack_payload)`.
//!   Receivers reconstruct the canonical LXMF block by prepending the
//!   `lxmf.delivery` destination_hash for the channel identity (re-derived
//!   from the channel name) and feed that to
//!   `LXMessage::unpack_from_bytes(_, Some(PROPAGATED))`, which validates
//!   the Ed25519 signature against the cached source identity.
//! RFed treats `inner_blob` OPAQUELY — never decrypts, parses, or modifies it.
//!
//! # Delivery model
//!
//! The blob store (keyed by channel_hash) is used **only** for inter-node sync.
//! It is never queried by clients directly.
//!
//! Client delivery has two paths:
//!   1. **Live fanout** — subscriber is online, outer envelope sent immediately.
//!   2. **Deferred queue** — subscriber offline; inner blob held in the deferred
//!      queue (keyed by subscriber_hash).  Flushed on announce or on PULL.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use app_links::{self as rns_app_links, AppLinks};
use reticulum_rust::destination::{Destination, DestinationType, ALLOW_ALL};
use reticulum_rust::identity::{self, Identity};
use reticulum_rust::link::{Link, LinkHandle, RequestReceipt, MODE_AES256_CBC};
use reticulum_rust::lxstamper::LXStamper;
use reticulum_rust::packet::Packet;
use reticulum_rust::transport::{AnnounceHandler, Transport};
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use crate::announce;
use crate::blob_store::BlobStore;

/// Decode a msgpack binary value (bin8/bin16/bin32) to Vec<u8>.
/// rmp_serde::from_slice::<Vec<u8>> treats Vec<u8> as a msgpack array;
/// use this helper when the peer sends raw bytes encoded as msgpack bin.
fn decode_msgpack_bin(data: &[u8]) -> Vec<u8> {
    let mut cur = Cursor::new(data);
    match rmpv::decode::read_value(&mut cur) {
        Ok(rmpv::Value::Binary(b)) => b,
        _ => Vec::new(),
    }
}

/// Parse and verify a signed payload: msgpack fixarray-3 [bin/str value, bin(64) pubkey, bin(64) sig].
///
/// Returns `(value_bytes, subscriber_identity_hash, public_key)` on success,
/// or an error string.
/// The subscriber hash is derived from the pubkey using `Identity::from_public_key` — identical
/// to how Reticulum derives it, so no separate identity-lookup is needed.
fn verify_signed_payload(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let mut cur = Cursor::new(data);
    let top = rmpv::decode::read_value(&mut cur)
        .map_err(|e| format!("msgpack decode: {e}"))?;
    let arr = match top {
        rmpv::Value::Array(a) if a.len() == 3 => a,
        _ => return Err(format!("expected fixarray-3, got {:?}", top)),
    };

    let value: Vec<u8> = match &arr[0] {
        rmpv::Value::Binary(b) => b.clone(),
        rmpv::Value::String(s) => s.as_bytes().to_vec(),
        other => return Err(format!("payload[0] not bin/str: {:?}", other)),
    };
    let pubkey: Vec<u8> = match &arr[1] {
        rmpv::Value::Binary(b) => b.clone(),
        _ => return Err("payload[1] not bin (pubkey)".into()),
    };
    let sig: Vec<u8> = match &arr[2] {
        rmpv::Value::Binary(b) => b.clone(),
        _ => return Err("payload[2] not bin (sig)".into()),
    };

    if pubkey.len() != 64 { return Err(format!("pubkey len {} != 64", pubkey.len())); }
    if sig.len()    != 64 { return Err(format!("sig len {} != 64", sig.len())); }

    let id = Identity::from_public_key(&pubkey)
        .map_err(|e| format!("from_public_key: {e}"))?;
    if !id.validate(&sig, &value) {
        return Err("signature verification failed".into());
    }
    let subscriber_hash = id.hash.ok_or("identity has no hash after from_public_key")?;
    Ok((value, subscriber_hash, pubkey))
}

fn encode_stream_open_response(ok: bool, reason: Option<&str>) -> Vec<u8> {
    let response = rmpv::Value::Array(vec![
        rmpv::Value::Boolean(ok),
        match reason {
            Some(reason) => rmpv::Value::String(reason.into()),
            None => rmpv::Value::Nil,
        },
    ]);
    let mut buf = Vec::new();
    let _ = rmpv::encode::write_value(&mut buf, &response);
    buf
}

fn decode_channel_stream_filters(value_bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if value_bytes.len() == 16 {
        return Ok(vec![value_bytes.to_vec()]);
    }

    let mut cur = Cursor::new(value_bytes);
    let value = rmpv::decode::read_value(&mut cur)
        .map_err(|e| format!("channel stream config decode: {e}"))?;
    let items = match value {
        rmpv::Value::Array(items) => items,
        other => {
            return Err(format!(
                "channel stream config must be bin(16) or array of bin(16), got {:?}",
                other
            ));
        }
    };

    let mut filters = Vec::new();
    for item in items {
        let channel_hash = match item {
            rmpv::Value::Binary(hash) => hash,
            other => {
                return Err(format!(
                    "channel stream config entries must be bin(16), got {:?}",
                    other
                ));
            }
        };
        if channel_hash.len() != 16 {
            return Err(format!(
                "channel stream config entry len {} != 16",
                channel_hash.len()
            ));
        }
        if !filters.iter().any(|existing| existing == &channel_hash) {
            filters.push(channel_hash);
        }
    }

    Ok(filters)
}

fn decode_channel_pull_request(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() == 16 {
        return Ok(data.to_vec());
    }

    let channel_hash = decode_msgpack_bin(data);
    if channel_hash.len() != 16 {
        return Err(format!(
            "channel pull request must carry bin(16) channel hash, got {} bytes",
            channel_hash.len()
        ));
    }
    Ok(channel_hash)
}

fn encode_pull_response(pending: Vec<PendingBlob>, more_pending: bool) -> Vec<u8> {
    let pairs_val: Vec<rmpv::Value> = pending
        .into_iter()
        .map(|pb| {
            rmpv::Value::Array(vec![
                rmpv::Value::Binary(pb.channel_hash),
                rmpv::Value::Binary(pb.blob),
            ])
        })
        .collect();
    let envelope = rmpv::Value::Array(vec![
        rmpv::Value::Array(pairs_val),
        rmpv::Value::Boolean(more_pending),
    ]);
    let mut buf = Vec::new();
    let _ = rmpv::encode::write_value(&mut buf, &envelope);
    buf
}

fn lxmf_delivery_hash_from_pubkey(pubkey: &[u8]) -> Result<Vec<u8>, String> {
    let identity = Identity::from_public_key(pubkey)
        .map_err(|e| format!("from_public_key: {e}"))?;
    Destination::new_outbound(
        Some(identity),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )
    .map(|dest| dest.hash)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotifyCommandKind {
    Register,
    Unregister,
    Clear,
}

struct NotifyCommand {
    kind: NotifyCommandKind,
    relay_hash: Option<String>,
    channel_hash: Option<Vec<u8>>,
}

fn parse_notify_legacy_value(value_bytes: &[u8]) -> (String, Option<Vec<u8>>) {
    let mut cur = Cursor::new(value_bytes);
    match rmpv::decode::read_value(&mut cur) {
        Ok(rmpv::Value::Array(mut arr)) if arr.len() >= 2 => {
            let relay = match arr.remove(0) {
                rmpv::Value::String(s) => s.into_str().unwrap_or_default().to_string(),
                _ => String::new(),
            };
            let ch = match arr.remove(0) {
                rmpv::Value::Binary(b) if b.len() == 16 => Some(b),
                _ => None,
            };
            (relay, ch)
        }
        _ => (String::from_utf8(value_bytes.to_vec()).unwrap_or_default(), None),
    }
}

fn parse_notify_command(
    value_bytes: &[u8],
    default_kind: Option<NotifyCommandKind>,
) -> Result<NotifyCommand, String> {
    if default_kind == Some(NotifyCommandKind::Clear) && value_bytes.is_empty() {
        return Ok(NotifyCommand {
            kind: NotifyCommandKind::Clear,
            relay_hash: None,
            channel_hash: None,
        });
    }

    let mut cur = Cursor::new(value_bytes);
    if let Ok(rmpv::Value::Array(mut arr)) = rmpv::decode::read_value(&mut cur) {
        if arr.len() >= 3 {
            if let rmpv::Value::String(op) = arr.remove(0) {
                let kind = match op.into_str().unwrap_or_default().as_ref() {
                    "register" => NotifyCommandKind::Register,
                    "unregister" => NotifyCommandKind::Unregister,
                    "clear" => NotifyCommandKind::Clear,
                    other => return Err(format!("unknown notify op '{other}'")),
                };
                if let Some(expected) = default_kind {
                    if expected != kind {
                        return Err(format!(
                            "notify op mismatch: payload={:?} handler={:?}",
                            kind, expected
                        ));
                    }
                }
                let relay_hash = match arr.remove(0) {
                    rmpv::Value::String(s) => {
                        let relay = s.into_str().unwrap_or_default().to_string();
                        if relay.is_empty() { None } else { Some(relay) }
                    }
                    rmpv::Value::Nil => None,
                    _ => None,
                };
                let channel_hash = match arr.remove(0) {
                    rmpv::Value::Binary(b) if b.len() == 16 => Some(b),
                    _ => None,
                };
                return Ok(NotifyCommand {
                    kind,
                    relay_hash,
                    channel_hash,
                });
            }
        }
    }

    let kind = default_kind.ok_or("notify DATA payload missing op")?;
    let (relay_hash, channel_hash) = parse_notify_legacy_value(value_bytes);
    Ok(NotifyCommand {
        kind,
        relay_hash: if relay_hash.is_empty() { None } else { Some(relay_hash) },
        channel_hash,
    })
}

fn handle_notify_command(
    node: &Arc<Mutex<FedNode>>,
    command: NotifyCommand,
    subscriber_hash: Vec<u8>,
    pubkey: Option<Vec<u8>>,
) -> Result<(), String> {
    match command.kind {
        NotifyCommandKind::Register => {
            let relay_hash = command
                .relay_hash
                .ok_or("notify/register: empty relay hash")?;

            validate_relay_hash(&relay_hash)
                .map_err(|reason| format!("notify registration rejected: {reason}"))?;

            let relay_hash_bytes: Vec<u8> = match (0..relay_hash.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&relay_hash[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
            {
                Ok(bytes) if bytes.len() == 16 => bytes,
                _ => return Err(format!("notify/register: invalid relay hash {relay_hash}")),
            };

            let pubkey = pubkey.ok_or("notify/register: missing pubkey")?;
            let _ = Identity::remember_destination(&relay_hash_bytes, &pubkey, None);
            Transport::request_path(&relay_hash_bytes, None, None, None, None);

            if let Ok(guard) = node.lock() {
                if !guard.config.policy_for(&subscriber_hash).allow_notify_registration {
                    return Err(format!(
                        "notify registration denied for {} (policy)",
                        reticulum_rust::hexrep(&subscriber_hash, false),
                    ));
                }
                if let Ok(mut notify) = guard.notify_registry.lock() {
                    if let Some(ref ch) = command.channel_hash {
                        notify.register(subscriber_hash.clone(), Some(ch.clone()), relay_hash.clone());
                        log(
                            format!(
                                "[rfed] notify/register stored channel subscriber={} channel={} relay={}",
                                reticulum_rust::hexrep(&subscriber_hash, false),
                                reticulum_rust::hexrep(ch, false),
                                relay_hash,
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                    } else {
                        let lxmf_delivery_hash = Destination::hash(
                            Some(&subscriber_hash), "lxmf", &["delivery"],
                        );
                        notify.register(lxmf_delivery_hash.clone(), None, relay_hash.clone());
                        log(
                            format!(
                                "[rfed] notify/register stored lxmf subscriber={} delivery={} relay={}",
                                reticulum_rust::hexrep(&subscriber_hash, false),
                                reticulum_rust::hexrep(&lxmf_delivery_hash, false),
                                relay_hash,
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                    }
                }
            }
            Ok(())
        }
        NotifyCommandKind::Unregister => {
            let relay_hash = command
                .relay_hash
                .ok_or("notify/unregister: empty relay hash")?;
            if let Ok(guard) = node.lock() {
                if let Ok(mut notify) = guard.notify_registry.lock() {
                    if let Some(ref ch) = command.channel_hash {
                        notify.unregister(&subscriber_hash, Some(ch.as_slice()), &relay_hash);
                    } else {
                        let lxmf_delivery_hash = Destination::hash(
                            Some(&subscriber_hash), "lxmf", &["delivery"],
                        );
                        notify.unregister(&lxmf_delivery_hash, None, &relay_hash);
                    }
                }
            }
            Ok(())
        }
        NotifyCommandKind::Clear => {
            if let Ok(guard) = node.lock() {
                if let Ok(mut notify) = guard.notify_registry.lock() {
                    notify.clear(&subscriber_hash);
                }
            }
            Ok(())
        }
    }
}

use crate::config::NodeConfig;
use crate::deferred_queue::{DeferredQueue, PendingBlob};
use crate::distro::{self, DistroAnnounceStore, DistroTable};
use crate::fanout;
use crate::lxmf_propagation::LxmfPropagationNode;
use crate::notify::{dispatch_notify, HookRegistry, NotifyRegistry, validate_relay_hash};
use crate::stream_registry::{ChannelStreamRegistry, PropagationStreamRegistry};
use crate::subscription::SubscriptionTable;
use crate::sync::{FedSync, OFFER_PATH, MESSAGE_GET_PATH, BACKUP_PUSH_PATH};

// ── Request paths ────────────────────────────────────────────────────────────

/// Client proves ownership of a destination by signing; server drains and returns pending blobs.
pub const PULL_PATH: &str = "/rfed/pull";
/// Client subscribes to a channel.
pub const SUBSCRIBE_PATH: &str = "/rfed/subscribe";
/// Client unsubscribes from a channel.
pub const UNSUBSCRIBE_PATH: &str = "/rfed/unsubscribe";
/// Client registers a notify relay.
pub const NOTIFY_REGISTER_PATH: &str = "/rfed/notify/register";
/// Client deregisters a specific notify relay.
pub const NOTIFY_UNREGISTER_PATH: &str = "/rfed/notify/unregister";
/// Client clears all notify relay registrations.
pub const NOTIFY_CLEAR_PATH: &str = "/rfed/notify/clear";
/// Client queries node capabilities and enabled features.
pub const CAPABILITIES_PATH: &str = "/rfed/capabilities";
/// Client opens a live per-channel stream on an established link.
pub const CHANNEL_STREAM_OPEN_PATH: &str = "/rfed/channel/stream/open";
/// Client opens a live propagation stream on an established link.
pub const PROPAGATION_STREAM_OPEN_PATH: &str = "/rfed/propagation/stream/open";

/// RNS app namespace for all rfed destinations.
pub const APP_NAME: &str = "rfed";

/// Service-path refresh interval (seconds).  Channel/delivery/notify/
/// lxmf.propagation are kept fresh on every directly-connected interface
/// well within the Reticulum 1-hour path TTL so clients never have to learn
/// them via stale federation-flooded copies.
pub const SERVICE_REFRESH_INTERVAL_SECS: u64 = 15 * 60;

/// Number of workblock expansion rounds for rfed stamp PoW.
/// The actual anti-spam difficulty is controlled by `stamp_cost` (required leading
/// zero bits); these expansion rounds just bind the workblock to the blob hash.
const STAMP_EXPAND_ROUNDS: u32 = 16;

/// Default page size for `/rfed/pull` when the per-tier policy does not set
/// `deferred_pull_batch_limit`.  PULL is user-initiated paging (mirrors chat
/// history "Load earlier messages"): each request returns at most this many
/// pending blobs plus a `more_pending` flag so the client knows whether to
/// offer another page.
const DEFAULT_PULL_PAGE_SIZE: usize = 25;

// ── FedNode ──────────────────────────────────────────────────────────────────

/// Central state for a running Federation Node.
///
/// Owns all four RNS inbound destinations, the blob store, subscription table,
/// deferred delivery queue, notify registry, and inter-node sync engine.
/// Wrapped in `Arc<Mutex<FedNode>>` and shared across all callback closures
/// via a `Weak` self-reference to avoid reference cycles.
pub struct FedNode {
    pub identity: Identity,
    pub config: NodeConfig,

    pub blob_store: Arc<Mutex<BlobStore>>,
    pub subscription_table: Arc<Mutex<SubscriptionTable>>,
    pub distro_table: Arc<Mutex<DistroTable>>,
    /// Device-signed announces this node replays on behalf of distro identities.
    pub distro_announces: Arc<Mutex<DistroAnnounceStore>>,
    pub hook_registry: Arc<Mutex<HookRegistry>>,
    pub notify_registry: Arc<Mutex<NotifyRegistry>>,
    pub sync: Arc<Mutex<FedSync>>,
    pub deferred_queue: Arc<Mutex<DeferredQueue>>,

    /// Optional full `lxmf.propagation` node (None when disabled).
    pub lxmf_propagation: Option<Arc<Mutex<LxmfPropagationNode>>>,

    // Inbound RNS destinations
    pub node_dest: Destination,
    pub delivery_dest: Destination,
    /// DEPRECATED — replaced by the four split aspects
    /// (rfed.channel.{subscribe,unsubscribe,publish,pull}).
    /// Kept registered for one transition release so in-the-wild Retichat
    /// builds keep working. Remove after Retichat clients migrate.
    /// See REFACTOR.md (2026-05-17).
    pub channel_dest: Destination,
    /// DEPRECATED — replaced by rfed.notify.{register,unregister}.
    /// See REFACTOR.md (2026-05-17).
    pub notify_dest: Destination,

    // ── New split aspects (REFACTOR.md 2026-05-17) ──────────────────
    pub channel_subscribe_dest: Destination,
    pub channel_unsubscribe_dest: Destination,
    pub channel_publish_dest: Destination,
    pub channel_pull_dest: Destination,
    pub notify_register_dest: Destination,
    pub notify_unregister_dest: Destination,
    pub channel_stream_dest: Destination,
    pub propagation_stream_dest: Destination,

    // ── Distro (multi-device fanout) ─────────────────────────────────
    pub distro_register_dest: Destination,
    pub distro_unregister_dest: Destination,
    pub distro_list_dest: Destination,

    pub channel_streams: Arc<Mutex<ChannelStreamRegistry>>,
    pub propagation_streams: Arc<Mutex<PropagationStreamRegistry>>,

    /// Active outbound sync links keyed by peer destination hash.
    /// Pruned each tick_sync — dead links are removed so a new link can be
    /// opened on the next attempt.
    pub sync_links: HashMap<Vec<u8>, LinkHandle>,

    /// Pending (subscriber_hash, channel_hash) pairs awaiting backup delivery to
    /// the configured backup node.  Drained by `tick_backup_delivery`.
    pub pending_backup_pushes: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>,

    /// Auto-selected backup node destination hash.  Set by `tick_backup_delivery`
    /// when no explicit primary/secondary nodes cover the need.
    /// Cleared when the selected peer stops being alive.
    pub selected_backups: Vec<Vec<u8>>,

    /// Weak self-reference so callbacks can reach FedNode without a cycle.
    pub(crate) self_handle: Option<Weak<Mutex<FedNode>>>,
}

/// Collaborators a distro fan-out needs once the `FedNode` guard is gone.
///
/// `distro_fanout` already takes a device snapshot, but its `hooks`,
/// `propagation_streams`, deferred queue and config were still borrowed out of
/// the guard, which kept the `FedNode` mutex alive for the whole fan-out. These
/// are `Arc`s and an owned config, so the guard can be dropped first.
pub(crate) struct DistroFanoutCtx {
    pub hook_registry: Arc<Mutex<HookRegistry>>,
    pub propagation_streams: Arc<Mutex<PropagationStreamRegistry>>,
    pub deferred_queue: Arc<Mutex<DeferredQueue>>,
    pub notify_registry: Arc<Mutex<NotifyRegistry>>,
    pub config: NodeConfig,
}

impl FedNode {
    /// The `Arc`s and config a distro fan-out needs after the guard is
    /// released. See `DistroFanoutCtx`.
    pub(crate) fn distro_fanout_ctx(&self) -> DistroFanoutCtx {
        DistroFanoutCtx {
            hook_registry: Arc::clone(&self.hook_registry),
            propagation_streams: Arc::clone(&self.propagation_streams),
            deferred_queue: Arc::clone(&self.deferred_queue),
            notify_registry: Arc::clone(&self.notify_registry),
            config: self.config.clone(),
        }
    }

    /// Snapshot everything a channel fan-out needs, so the caller can release
    /// the `FedNode` mutex before any delivery happens.
    ///
    /// NEVER REMOVE this in favour of fanning out with the guard still held.
    /// Delivery does unbounded network work per subscriber (7–16s per link on
    /// the polled HTTP transport); holding this mutex across it stalls every
    /// request callback — `subscribe_cb` logs `LOCK-WARN` and the browser
    /// client times out with `/rfed/subscribe did not respond`. See
    /// `fanout::FanoutPlan`.
    pub fn plan_channel_fanout(&self, channel_dest_hash: &[u8]) -> fanout::FanoutPlan {
        let subscribers = self
            .subscription_table
            .lock()
            .map(|t| t.get_subscribers_with_owner(channel_dest_hash))
            .unwrap_or_default();

        let deferred_limits = subscribers
            .iter()
            .map(|(sub_hash, _)| {
                let limit = self.config.policy_for(sub_hash).deferred_queue_limit;
                (sub_hash.clone(), limit)
            })
            .collect();

        fanout::FanoutPlan {
            subscribers,
            deferred_limits,
            hook_registry: Arc::clone(&self.hook_registry),
            notify_registry: Arc::clone(&self.notify_registry),
            deferred_queue: Arc::clone(&self.deferred_queue),
            channel_streams: Arc::clone(&self.channel_streams),
        }
    }

    pub fn new(identity: Identity, config: NodeConfig) -> Result<Self, String> {
        // ── Ensure directories exist ─────────────────────────────────
        for dir in [config.blob_store_dir()] {
            if let Err(e) = std::fs::create_dir_all(&dir) {
                if !dir.is_dir() {
                    return Err(format!("Cannot create {:?}: {e}", dir));
                }
            }
        }

        // ── Subsystem initialisation ─────────────────────────────────
        let storage_limit = config.storage_limit_bytes;

        let blob_store = Arc::new(Mutex::new(BlobStore::open(
            config.blob_store_dir(),
            storage_limit,
        )));

        let subscription_table = Arc::new(Mutex::new(SubscriptionTable::load(
            config.subscription_file(),
        )));

        let distro_table = Arc::new(Mutex::new(DistroTable::load(
            config.distro_file(),
        )));

        let distro_announces = Arc::new(Mutex::new(DistroAnnounceStore::load(
            config.distro_announce_file(),
        )));

        let hook_registry = Arc::new(Mutex::new(HookRegistry::new()));
        let notify_registry = Arc::new(Mutex::new(NotifyRegistry::load(
            config.notify_registry_file(),
        )));
        let deferred_queue = Arc::new(Mutex::new(DeferredQueue::load(
            config.deferred_queue_file(),
        )));
        let channel_streams = Arc::new(Mutex::new(ChannelStreamRegistry::default()));
        let propagation_streams = Arc::new(Mutex::new(PropagationStreamRegistry::default()));

        let mut fed_sync = FedSync::new(
            Arc::clone(&blob_store),
            Arc::clone(&subscription_table),
            Arc::clone(&distro_table),
        );
        fed_sync.from_static_only = config.from_static_only;
        fed_sync.static_peers = config.static_peers.clone();
        fed_sync.peer_state_file = Some(config.peer_state_file());
        if let Some(lim) = config.transfer_limit_bytes {
            fed_sync.transfer_limit_bytes = Some(lim as f64);
        }
        if let Some(lim) = config.sync_limit_bytes {
            fed_sync.sync_limit_bytes = Some(lim as f64);
        }
        let sync = Arc::new(Mutex::new(fed_sync));

        // ── RNS destinations ────────────────────────────────────────
        let node_dest = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["node".to_string()],
        )?;

        let delivery_dest = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["delivery".to_string()],
        )?;

        let channel_dest = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["channel".to_string()],
        )?;

        let notify_dest = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["notify".to_string()],
        )?;;

        // ── Split aspects (REFACTOR.md 2026-05-17) ──────────────────
        // Registered alongside the legacy channel/notify destinations so
        // clients can migrate one at a time. Same identity, distinct aspect
        // strings → distinct destination hashes on the wire.
        let mk_inbound = |aspects: Vec<String>| -> Result<Destination, String> {
            Destination::new_inbound(
                Some(identity.clone()),
                DestinationType::Single,
                APP_NAME.to_string(),
                aspects,
            )
        };
        let channel_subscribe_dest   = mk_inbound(vec!["channel".into(), "subscribe".into()])?;
        let channel_unsubscribe_dest = mk_inbound(vec!["channel".into(), "unsubscribe".into()])?;
        let channel_publish_dest     = mk_inbound(vec!["channel".into(), "publish".into()])?;
        let channel_pull_dest        = mk_inbound(vec!["channel".into(), "pull".into()])?;
        let channel_stream_dest      = mk_inbound(vec!["channel".into(), "stream".into()])?;
        let propagation_stream_dest  = mk_inbound(vec!["propagation".into(), "stream".into()])?;
        let notify_register_dest     = mk_inbound(vec!["notify".into(), "register".into()])?;
        let notify_unregister_dest   = mk_inbound(vec!["notify".into(), "unregister".into()])?;

        // ── Distro destinations ──────────────────────────────────────
        let distro_register_dest   = mk_inbound(vec!["distro".into(), "register".into()])?;
        let distro_unregister_dest = mk_inbound(vec!["distro".into(), "unregister".into()])?;
        let distro_list_dest       = mk_inbound(vec!["distro".into(), "list".into()])?;

        if let Ok(mut s) = sync.lock() {
            s.set_local_node_hash(node_dest.hash.clone());
        }

        Ok(FedNode {
            identity,
            config,
            blob_store,
            subscription_table,
            distro_table,
            distro_announces,
            hook_registry,
            notify_registry,
            sync,
            deferred_queue,
            channel_streams,
            propagation_streams,
            lxmf_propagation: None,
            node_dest,
            delivery_dest,
            channel_dest,
            notify_dest,
            channel_subscribe_dest,
            channel_unsubscribe_dest,
            channel_publish_dest,
            channel_pull_dest,
            channel_stream_dest,
            propagation_stream_dest,
            notify_register_dest,
            notify_unregister_dest,
            distro_register_dest,
            distro_unregister_dest,
            distro_list_dest,
            sync_links: HashMap::new(),
            pending_backup_pushes: Arc::new(Mutex::new(Vec::new())),
            selected_backups: Vec::new(),
            self_handle: None,
        })
    }

    /// Broadcast the rfed.node announce + the three service announces
    /// (channel, delivery, notify) immediately and synchronously.
    ///
    /// No sleeps, no spawned threads, no fixed delay before the first send
    /// (see DESIGN_PRINCIPLES.md §3).  Periodic refresh and on-interface-up
    /// re-announce are handled by `publish_destinations()` registering with
    /// `Transport`'s announce daemon.
    pub fn announce(&mut self) {
        // Treat stamp_cost=0 as disabled (same as None) to avoid accidental
        // stamp-tail stripping when operators mean "no PoW required".
        let announce_stamp_cost = self.config.default_policy.stamp_cost.filter(|c| *c > 0);
        let app_data = announce::encode_node_announce(
            &self.config.display_name,
            announce_stamp_cost,
        );
        // Distro registration is the bootstrap route for all Distro clients.
        // Announce it first so backbone announce pacing cannot strand it behind
        // the rest of the service-destination burst.
        let _ = self.distro_register_dest.announce(None, false, None, None, true);
        self.node_dest.set_default_app_data(Some(app_data.clone()));
        let _ = self.node_dest.announce(Some(&app_data), false, None, None, true);
        log(
            format!("[rfed] announced node {}", hexrep(&self.node_dest.hash, false)),
            LOG_NOTICE, false, false,
        );
        // Service destinations: clients can discover them via path requests
        // without knowing the hash in advance.
        let _ = self.channel_dest.announce(None, false, None, None, true);
        let _ = self.delivery_dest.announce(None, false, None, None, true);
        let _ = self.notify_dest.announce(None, false, None, None, true);
        // New split aspects (REFACTOR.md 2026-05-17).  Stamp policy rides on
        // the publish destination since that's where SEND lands (matches
        // `publish_destinations()` below).  Set default_app_data so the
        // Transport announce daemon's interface-up re-announces (which call
        // `dest.announce(None, ...)`) still carry the stamp policy.
        self.channel_publish_dest.set_default_app_data(Some(app_data.clone()));
        let _ = self.channel_subscribe_dest.announce(None, false, None, None, true);
        let _ = self.channel_unsubscribe_dest.announce(None, false, None, None, true);
        let _ = self.channel_publish_dest.announce(Some(&app_data), false, None, None, true);
        let _ = self.channel_pull_dest.announce(None, false, None, None, true);
        let _ = self.channel_stream_dest.announce(None, false, None, None, true);
        let _ = self.propagation_stream_dest.announce(None, false, None, None, true);
        let _ = self.notify_register_dest.announce(None, false, None, None, true);
        let _ = self.notify_unregister_dest.announce(None, false, None, None, true);
        let _ = self.distro_unregister_dest.announce(None, false, None, None, true);
        let _ = self.distro_list_dest.announce(None, false, None, None, true);
        self.replay_distro_announces();
    }

    /// Rebroadcast every stored pre-signed distro announce.
    ///
    /// These are not owned destinations, so `Transport`'s announce daemon will
    /// not refresh them — this node has to replay them itself to keep the
    /// distro address inside the Reticulum path TTL.
    pub fn replay_distro_announces(&self) {
        // Snapshot and release the lock before any network work; replaying
        // broadcasts on every interface. See the note on `distro_fanout`.
        let announces = match self.distro_announces.lock() {
            Ok(store) => store.snapshot(),
            Err(_) => return,
        };
        for announce in &announces {
            match distro::replay_distro_announce(announce) {
                Ok(()) => log(
                    format!(
                        "[distro] replayed announce for {}",
                        hexrep(&announce.distro_lxmf_hash, false)
                    ),
                    LOG_DEBUG, false, false,
                ),
                Err(e) => log(
                    format!(
                        "[distro] announce replay failed for {}: {e}",
                        hexrep(&announce.distro_lxmf_hash, false)
                    ),
                    LOG_WARNING, false, false,
                ),
            }
        }
    }

    /// Opt all four locally-registered destinations into Transport's
    /// announce daemon so they are automatically re-announced:
    ///   * once on every false→true online transition of any interface, and
    ///   * every `refresh_interval` thereafter.
    ///
    /// rfed.node refreshes at the configured `announce_interval_secs`
    /// (default 6h); the three service destinations refresh every
    /// `SERVICE_REFRESH_INTERVAL_SECS` (15min) so they always stay fresh
    /// inside the Reticulum 1-hour path TTL.
    pub fn publish_destinations(&self) {
        use reticulum_rust::transport::Transport;
        // Keep channel/node announce stamp policy aligned with SEND parsing:
        // only positive costs mean "stamp required".
        let announce_stamp_cost = self.config.default_policy.stamp_cost.filter(|c| *c > 0);
        let app_data = announce::encode_node_announce(
            &self.config.display_name,
            announce_stamp_cost,
        );
        Transport::publish_destination(
            self.node_dest.hash.clone(),
            Some(Duration::from_secs(self.config.announce_interval_secs)),
            Some(app_data.clone()),
        );
        let svc = Some(Duration::from_secs(SERVICE_REFRESH_INTERVAL_SECS));
        // Publish the channel SEND stamp policy on rfed.channel itself so
        // senders can autoconfigure before their first fire-and-forget send.
        Transport::publish_destination(self.channel_dest.hash.clone(), svc, Some(app_data.clone()));
        Transport::publish_destination(self.delivery_dest.hash.clone(), svc, None);
        Transport::publish_destination(self.notify_dest.hash.clone(), svc, None);
        // New split aspects (REFACTOR.md 2026-05-17). Stamp policy rides on
        // the publish destination since that's where SEND lands.
        Transport::publish_destination(self.channel_subscribe_dest.hash.clone(),   svc, None);
        Transport::publish_destination(self.channel_unsubscribe_dest.hash.clone(), svc, None);
        Transport::publish_destination(self.channel_publish_dest.hash.clone(),     svc, Some(app_data));
        Transport::publish_destination(self.channel_pull_dest.hash.clone(),        svc, None);
        Transport::publish_destination(self.channel_stream_dest.hash.clone(),      svc, None);
        Transport::publish_destination(self.propagation_stream_dest.hash.clone(),  svc, None);
        Transport::publish_destination(self.notify_register_dest.hash.clone(),     svc, None);
        Transport::publish_destination(self.notify_unregister_dest.hash.clone(),   svc, None);
        Transport::publish_destination(self.distro_register_dest.hash.clone(),     svc, None);
        Transport::publish_destination(self.distro_unregister_dest.hash.clone(),   svc, None);
        Transport::publish_destination(self.distro_list_dest.hash.clone(),         svc, None);
    }

    /// Explicitly persist all in-memory state to disk.
    ///
    /// Called during graceful shutdown so that no pending mutations are lost.
    pub fn save_all(&self) {
        if let Ok(s) = self.sync.lock() {
            s.save_peers();
        }
        if let Ok(s) = self.subscription_table.lock() {
            let _ = s.save();
        }
        if let Ok(n) = self.notify_registry.lock() {
            let _ = n.save();
        }
        if let Ok(q) = self.deferred_queue.lock() {
            let _ = q.save();
        }
        if let Ok(d) = self.distro_table.lock() {
            let _ = d.save();
        }
        if let Ok(a) = self.distro_announces.lock() {
            let _ = a.save();
        }
        log("[rfed] all state persisted to disk", LOG_NOTICE, false, false);
    }

    /// Called from the main event loop — drives pending peer sync sessions.
    ///
    /// For each peer that is due for a sync attempt, opens an outbound encrypted
    /// Link to their rfed.node destination.  The link_established callback then
    /// runs `run_sync_session()` which handles the OFFER → MESSAGE_GET flow.
    pub fn tick_sync(&mut self) {
        let tick_start = Instant::now();
        // Prune links that have closed since the last tick.
        // Retaining only live links prevents stale entries from blocking
        // new connection attempts.
        self.sync_links.retain(|_, link| link.is_alive());

        // Collect due peers quickly, then release the sync lock before
        // iterating.  This prevents a slow peer from blocking client links.
        let due: Vec<Vec<u8>> = if let Ok(mut s) = self.sync.lock() {
            s.tick()
        } else {
            return;
        };

        for peer_hash in due {
            // Skip if we already have a live link to this peer.
            if self.sync_links.contains_key(&peer_hash) {
                continue;
            }

            // One-shot rfed.node sync sessions still create a fresh request/
            // response link, but AppLinks owns the liveness race that decides
            // when that one-shot can start.
            AppLinks::open(&peer_hash, APP_NAME, &["node"]);
            if AppLinks::status(&peer_hash) != rns_app_links::APP_LINK_ACTIVE {
                if let Ok(mut s) = self.sync.lock() {
                    if let Some(p) = s.peers.get_mut(&peer_hash) {
                        p.next_sync_attempt = crate::sync::now_secs() + 5.0;
                    }
                }
                continue;
            }

            let identity = match Identity::recall(&peer_hash) {
                Some(id) => id,
                None => {
                    Transport::request_path(&peer_hash, None, None, None, None);
                    if let Ok(mut s) = self.sync.lock() {
                        if let Some(p) = s.peers.get_mut(&peer_hash) {
                            p.next_sync_attempt = crate::sync::now_secs() + 5.0;
                        }
                    }
                    continue;
                }
            };

            let dest = match Destination::new_outbound(
                Some(identity),
                DestinationType::Single,
                APP_NAME.to_string(),
                vec!["node".to_string()],
            ) {
                Ok(d) => d,
                Err(e) => {
                    log(format!("[sync] dest error for {}: {e}",
                        hexrep(&peer_hash, false)), LOG_WARNING, false, false);
                    continue;
                }
            };

            let link = match Link::new_outbound(dest, MODE_AES256_CBC) {
                Ok(l) => l,
                Err(e) => {
                    log(format!("[sync] link error for {}: {e}",
                        hexrep(&peer_hash, false)), LOG_WARNING, false, false);
                    continue;
                }
            };

            let handle = LinkHandle::spawn(link);
            let node_weak = self.self_handle.as_ref().cloned();
            let ph = peer_hash.clone();

            // link_established → start the OFFER → MESSAGE_GET session.
            // The callback receives the live LinkHandle `h` from the actor.
            let pw_est = node_weak.clone();
            let ph_est = ph.clone();
            handle.set_link_established_callback(Some(Arc::new(move |h: LinkHandle| {
                run_sync_session(h, ph_est.clone(), pw_est.clone());
            })));

            // link_closed → clean up the sync link entry so tick_sync knows
            // the link is dead and a new attempt may be scheduled.
            let pw_cls = node_weak.clone();
            let ph_cls = ph.clone();
            handle.set_link_closed_callback(Some(Arc::new(move |_: LinkHandle| {
                if let Some(arc) = pw_cls.as_ref().and_then(|w| w.upgrade()) {
                    if let Ok(mut node) = arc.lock() {
                        node.sync_links.remove(&ph_cls);
                    }
                }
            })));

            if let Err(e) = handle.initiate() {
                log(format!("[sync] link initiate failed for {}: {e}",
                    hexrep(&peer_hash, false)), LOG_WARNING, false, false);
                continue;
            }
            // Link actor registers itself in LinkMsg::Initiate.  An external
            // register here would emit "(replaced existing entry)" per LR.

            log(format!("[sync] link opening to {}", hexrep(&peer_hash, false)),
                LOG_DEBUG, false, false);

            if let Ok(mut s) = self.sync.lock() {
                s.sync_started(&peer_hash);
            }
            self.sync_links.insert(peer_hash, handle);
        }
        let held = tick_start.elapsed();
        if held > Duration::from_secs(1) {
            log(format!("[rfed] LOCK-WARN tick_sync: held FedNode lock for {:.2}s", held.as_secs_f64()), LOG_WARNING, false, false);
        }
    }

    /// Three backup-related tasks run every 30 seconds:
    ///
    /// 1. **Push own subscriptions**: drain `pending_backup_pushes` and
    ///    forward to ONE backup node (designated or auto-selected).
    /// 2. **Failover + chain-of-custody re-push**: scan backup entries WE hold;
    ///    when an owner's path has decayed, deliver blobs AND re-push those
    ///    entries to our backup so the chain extends.
    /// 3. **Prune**: remove stale backup entries whose upstream custodian
    ///    stopped refreshing them (owner recovered → chain unravels).
    pub fn tick_backup_delivery(&mut self) {
        let tick_start = Instant::now();
        // ── Helper: resolve a backup node from config or auto-select ───
        let resolve_backup = |selected: &mut Vec<Vec<u8>>,
                              sync: &Arc<Mutex<FedSync>>,
                              config: &NodeConfig|
            -> Option<Vec<u8>>
        {
            let is_alive = |h: &[u8]| -> bool {
                sync.lock().ok()
                    .map(|s| s.peers.get(h)
                        .map(|p| p.alive).unwrap_or(false))
                    .unwrap_or(false)
            };

            // Priority 1: primary_node if alive.
            if let Some(ref h) = config.primary_node {
                if is_alive(h) {
                    return Some(h.clone());
                }
            }
            // Priority 2: first alive secondary.
            if let Some(h) = config.secondary_nodes.iter().find(|h| is_alive(h)) {
                return Some(h.clone());
            }
            // Priority 3: primary even if not alive (will retry next tick).
            if let Some(ref h) = config.primary_node {
                return Some(h.clone());
            }
            // Priority 4: first secondary even if not alive.
            if let Some(h) = config.secondary_nodes.first() {
                return Some(h.clone());
            }
            // Priority 5: auto-select best alive peer.
            let still_alive = selected.first().map(|h| is_alive(h)).unwrap_or(false);
            if still_alive {
                return selected.first().cloned();
            }
            let best = sync.lock().ok().and_then(|s| {
                s.peers.values()
                    .filter(|p| p.alive)
                    .max_by(|a, b| {
                        a.last_heard.partial_cmp(&b.last_heard)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|p| p.destination_hash.clone())
            });
            match &best {
                Some(h) => {
                    log(
                        format!("[backup] auto-selected backup node {}",
                            hexrep(h, false)),
                        LOG_NOTICE, false, false,
                    );
                    *selected = vec![h.clone()];
                }
                None => {
                    if !selected.is_empty() {
                        log("[backup] no alive peers \u{2014} backup node deselected",
                            LOG_NOTICE, false, false);
                    }
                    selected.clear();
                }
            }
            best
        };

        let backup_hash = resolve_backup(
            &mut self.selected_backups, &self.sync, &self.config,
        );

        // ── Part 1: push OWN pending registrations ────────────────────
        let pending: Vec<(Vec<u8>, Vec<u8>)> = self
            .pending_backup_pushes
            .lock()
            .ok()
            .map(|mut q| q.drain(..).collect())
            .unwrap_or_default();
        if !pending.is_empty() {
            if let Some(ref hash) = backup_hash {
                push_subscriptions_to_backup(
                    hash.clone(),
                    pending,
                    self.self_handle.clone(),
                    self.identity.clone(),
                );
            } else {
                // No backup available — put them back for next tick.
                if let Ok(mut q) = self.pending_backup_pushes.lock() {
                    q.extend(pending);
                }
            }
        }

        // ── Part 2: prune stale backup entries (chain unravel) ────────
        // TTL must be at least 3× the backup push tick (90s) so that backup
        // subscriptions survive multiple tick cycles before being pruned.
        // owner_offline_secs * 2 can be < BACKUP_TICK_SECS (30s) when
        // owner_offline_secs is configured small (e.g. 12s → TTL=24s < 30s).
        let ttl = (self.config.owner_offline_secs * 2.0).max(90.0);
        if let Ok(mut table) = self.subscription_table.lock() {
            let pruned = table.prune_stale_backups(ttl);
            if pruned > 0 {
                log(
                    format!("[backup] pruned {pruned} stale backup entry(ies) (TTL {ttl:.0}s)"),
                    LOG_NOTICE, false, false,
                );
            }
        }

        // ── Part 3: failover delivery + chain-of-custody re-push ──────
        let adopted = backup_delivery_tick(
            Arc::clone(&self.subscription_table),
            Arc::clone(&self.blob_store),
            Arc::clone(&self.deferred_queue),
            Arc::clone(&self.notify_registry),
            &self.config,
            Arc::clone(&self.sync),
            self.config.owner_offline_secs,
        );

        // Re-push adopted entries so the chain extends.
        if !adopted.is_empty() {
            if let Some(ref hash) = backup_hash {
                let adopted_count = adopted.len();
                let repush = adopted_pairs_for_chain_extension(adopted, hash.as_slice());
                let skipped = adopted_count.saturating_sub(repush.len());

                if skipped > 0 {
                    log(
                        format!(
                            "[backup] skipping {skipped} adopted entry(ies) that would bounce back to owner {}",
                            hexrep(hash, false),
                        ),
                        LOG_NOTICE, false, false,
                    );
                }

                if !repush.is_empty() {
                    log(
                        format!(
                            "[backup] re-pushing {} adopted entry(ies) to backup {}",
                            repush.len(),
                            hexrep(hash, false),
                        ),
                        LOG_NOTICE, false, false,
                    );
                    push_subscriptions_to_backup(
                        hash.clone(),
                        repush,
                        self.self_handle.clone(),
                        self.identity.clone(),
                    );
                }
            }
        }
        let held = tick_start.elapsed();
        if held > Duration::from_secs(1) {
            log(format!("[rfed] LOCK-WARN tick_backup_delivery: held FedNode lock for {:.2}s", held.as_secs_f64()), LOG_WARNING, false, false);
        }
    }
}

// ── Sync session (runs inside link_established callback) ────────────────────

/// Drive a single OFFER → MESSAGE_GET sync session over an established link.
///
/// Called from the `link_established` callback on a background thread.
///
/// Flow:
///   1. Send OFFER with our local manifest → receive peer's manifest.
///   2. Compute gap = peer's manifest − our locally held IDs.
///   3. If gap is non-empty, send MESSAGE_GET for those IDs → receive blobs.
///   4. Ingest blobs and tear the link down.
fn run_sync_session(
    link_handle: LinkHandle,
    peer_hash: Vec<u8>,
    node_weak: Option<Weak<Mutex<FedNode>>>,
) {
    // Build our local manifest — send only the IDs (no channel hashes needed
    // in the outgoing OFFER; the peer uses them just for filtering channels
    // it has subscribers for).
    let our_ids: Vec<Vec<u8>> = if let Some(arc) =
        node_weak.as_ref().and_then(|w| w.upgrade())
    {
        let sync_arc = arc.lock().ok().map(|n| Arc::clone(&n.sync));
        sync_arc.and_then(|s| s.lock().ok().map(|g| {
            g.local_manifest().into_iter().map(|(_, id)| id).collect()
        }))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let offer_payload = match rmp_serde::to_vec(&our_ids) {
        Ok(b) => b,
        Err(e) => {
            log(format!("[sync] offer encode error: {e}"), LOG_WARNING, false, false);
            return;
        }
    };

    let ph_ok = peer_hash.clone();
    let ph_fail = peer_hash.clone();
    let nw_ok = node_weak.clone();
    let nw_fail = node_weak.clone();
    let la_ok = link_handle.clone();
    let la_fail = link_handle.clone();

    // OFFER response callback: receives the peer's manifest, computes the
    // gap (IDs they have that we don't, filtered to our subscribed channels),
    // then issues a MESSAGE_GET for the missing blobs.
    let offer_response: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
        Arc::new(move |receipt| {
            let response = match receipt.response {
                Some(r) => {
                    r
                },
                None => {
                    teardown_sync(&la_ok, &nw_ok, &ph_ok, false);
                    return;
                }
            };

            // Peer manifest is (channel_hash, message_id) pairs — this lets
            // us filter to only channels we have local subscribers for.
            // The gap_from_peer() call acquires blob_store and subscription_table
            // locks exactly once each to avoid potential double-locking.
            let peer_pairs: Vec<(Vec<u8>, Vec<u8>)> = rmp_serde::from_slice(&response)
                .unwrap_or_default();

            // Compute gap: IDs peer has for our subscribed channels that we
            // don't already hold.  gap_from_peer acquires both inner locks
            // exactly once, avoiding a double-lock of subscription_table.
            let want_ids: Vec<Vec<u8>> = if let Some(arc) =
                nw_ok.as_ref().and_then(|w| w.upgrade())
            {
                let sync_arc = arc.lock().ok().map(|n| Arc::clone(&n.sync));
                sync_arc
                    .and_then(|s| s.lock().ok().map(|g| g.gap_from_peer(peer_pairs)))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            if want_ids.is_empty() {
                log(format!("[sync] already up to date with {}",
                    hexrep(&ph_ok, false)), LOG_DEBUG, false, false);
                teardown_sync(&la_ok, &nw_ok, &ph_ok, true);
                return;
            }

            log(format!("[sync] requesting {} blob(s) from {}",
                want_ids.len(), hexrep(&ph_ok, false)), LOG_NOTICE, false, false);

            let get_payload = rmp_serde::to_vec(&want_ids).unwrap_or_default();

            let ph2 = ph_ok.clone();
            let nw2 = nw_ok.clone();
            let la2 = la_ok.clone();
            let la_fail2 = la_ok.clone();
            let ph_fail2 = ph_ok.clone();
            let nw_fail2 = nw_ok.clone();

            let get_response: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
                Arc::new(move |receipt| {
                    let data = receipt.response.unwrap_or_default();

                    // Ingest blobs into the store, then fanout each new one to
                    // local subscribers — same delivery path as a direct SEND packet.
                    // Missed subscribers (offline) are enqueued in the deferred queue
                    // and get a notify wake-up.
                    let ingested: Vec<(Vec<u8>, Vec<u8>)> = if let Some(arc) =
                        nw2.as_ref().and_then(|w| w.upgrade())
                    {
                        let sync_arc = arc.lock().ok().map(|n| Arc::clone(&n.sync));
                        sync_arc
                            .and_then(|s| s.lock().ok().map(|mut g| {
                                g.ingest_message_get_response(&ph2, &data)
                            }))
                            .unwrap_or_default()
                    } else { Vec::new() };

                    let count = ingested.len();

                    // Fanout each newly ingested blob to local subscribers.
                    if !ingested.is_empty() {
                        if let Some(arc) = nw2.as_ref().and_then(|w| w.upgrade()) {
                            // Everything the fan-out needs is snapshotted here,
                            // under the FedNode mutex, and the guard is dropped
                            // at the end of this statement. NEVER move delivery
                            // back inside the lock scope: it does unbounded
                            // network work per subscriber and per device, and
                            // holding the mutex across it wedges every request
                            // callback (/rfed/subscribe on 2026-08-17,
                            // /rfed/distro/register on 2026-08-09).
                            let planned = match arc.lock() {
                                Ok(guard) => {
                                    let distro_devices: std::collections::HashMap<Vec<u8>, Vec<crate::distro::DistroEntry>> =
                                        match guard.distro_table.lock() {
                                            Ok(dtable) => ingested
                                                .iter()
                                                .filter(|(routing_hash, _)| dtable.is_distro(routing_hash))
                                                .map(|(routing_hash, _)| {
                                                    (routing_hash.clone(), dtable.devices_snapshot(routing_hash))
                                                })
                                                .collect(),
                                            Err(_) => std::collections::HashMap::new(),
                                        };
                                    let plans: Vec<fanout::FanoutPlan> = ingested
                                        .iter()
                                        .map(|(routing_hash, _)| guard.plan_channel_fanout(routing_hash))
                                        .collect();
                                    Some((plans, distro_devices, guard.distro_fanout_ctx()))
                                }
                                Err(_) => None,
                            };

                            if let Some((plans, distro_devices, ctx)) = planned {
                                for ((routing_hash, blob), plan) in ingested.iter().zip(plans.iter()) {
                                    // ── Channel fanout ────────────
                                    plan.run(routing_hash, blob);

                                    // ── Distro fanout ────────────
                                    if let Some(devices) = distro_devices.get(routing_hash) {
                                        let dmissed = match ctx.hook_registry.lock() {
                                            Ok(hooks) => crate::distro::distro_fanout(
                                                routing_hash,
                                                blob,
                                                devices,
                                                &hooks,
                                                Some(&ctx.propagation_streams),
                                            ),
                                            Err(_) => Vec::new(),
                                        };
                                        // Enqueue missed distro devices in deferred queue
                                        if !dmissed.is_empty() {
                                            if let Ok(mut deferred) = ctx.deferred_queue.lock() {
                                                for dev_hash in &dmissed {
                                                    let limit = ctx.config
                                                        .policy_for(dev_hash)
                                                        .deferred_queue_limit;
                                                    deferred.enqueue(
                                                        dev_hash.clone(),
                                                        routing_hash.clone(),
                                                        blob.clone(),
                                                        limit,
                                                    );
                                                }
                                            }
                                            // Fire notify wake-ups for deferred devices
                                            if let Ok(notify) = ctx.notify_registry.lock() {
                                                for dev_hash in &dmissed {
                                                    for reg in notify.get_for_channel(dev_hash, None) {
                                                        dispatch_notify(reg, None, Some(routing_hash));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    log(format!("[sync] ingested {count} blob(s) from {}",
                        hexrep(&ph2, false)), LOG_NOTICE, false, false);
                    teardown_sync(&la2, &nw2, &ph2, true);
                });

            let get_failed: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
                Arc::new(move |_| {
                    log(format!("[sync] MESSAGE_GET failed for {}",
                        hexrep(&ph_fail2, false)), LOG_WARNING, false, false);
                    teardown_sync(&la_fail2, &nw_fail2, &ph_fail2, false);
                });

            let _ = la_ok.request(
                crate::sync::MESSAGE_GET_PATH.to_string(),
                get_payload,
                Some(get_response),
                Some(get_failed),
                None,
            );
        });

    // OFFER failed callback
    let offer_failed: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
        Arc::new(move |_| {
            log(format!("[sync] OFFER failed for {}",
                hexrep(&ph_fail, false)), LOG_WARNING, false, false);
            teardown_sync(&la_fail, &nw_fail, &ph_fail, false);
        });

    if link_handle.request(
        crate::sync::OFFER_PATH.to_string(),
        offer_payload,
        Some(offer_response),
        Some(offer_failed),
        None,
    ).is_err() {
        log(format!("[sync] link gone for {} — tearing down",
            hexrep(&peer_hash, false)), LOG_WARNING, false, false);
        teardown_sync(&link_handle, &node_weak, &peer_hash, false);
    }
}

/// Tear down a sync link and record the outcome in FedSync.
fn teardown_sync(
    link: &LinkHandle,
    node_weak: &Option<Weak<Mutex<FedNode>>>,
    peer_hash: &[u8],
    success: bool,
) {
    link.teardown();
    if let Some(arc) = node_weak.as_ref().and_then(|w| w.upgrade()) {
        if let Ok(node) = arc.lock() {
            if let Ok(mut s) = node.sync.lock() {
                if success { s.sync_ok(peer_hash); } else { s.sync_err(peer_hash); }
                s.save_peers();
            }
        }
    }
}

// ── Backup delivery helpers ───────────────────────────────────────────────────

/// Open a link to a backup node and send a batch of backup subscription
/// registrations.  Fire-and-forget: if the path is unavailable, pairs are
/// re-enqueued for the next `tick_backup_delivery` attempt.
///
/// The pattern is:
///   1. Verify path/identity to backup node; re-enqueue pairs if missing.
///   2. Open encrypted Link; in link_established callback:
///      a. Send a signed BACKUP_PUSH request carrying the subscription pairs.
///      b. Tear down the link on response (success or failure).
fn requeue_backup_pairs(
    node_weak: &Option<Weak<Mutex<FedNode>>>,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
) {
    if pairs.is_empty() {
        return;
    }

    if let Some(arc) = node_weak.as_ref().and_then(|w| w.upgrade()) {
        if let Ok(node) = arc.lock() {
            if let Ok(mut q) = node.pending_backup_pushes.lock() {
                q.extend(pairs);
            }
        }
    }
}

fn push_subscriptions_to_backup(
    backup_hash: Vec<u8>,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    node_weak: Option<Weak<Mutex<FedNode>>>,
    our_identity: Identity,
) {
    AppLinks::open(&backup_hash, APP_NAME, &["node"]);
    if AppLinks::status(&backup_hash) != rns_app_links::APP_LINK_ACTIVE {
        log("[backup] no path to backup node — will retry on next tick",
            LOG_DEBUG, false, false);
        requeue_backup_pairs(&node_weak, pairs);
        return;
    }

    let identity = match Identity::recall(&backup_hash) {
        Some(id) => {
            id
        },
        None => {
            Transport::request_path(&backup_hash, None, None, None, None);
            requeue_backup_pairs(&node_weak, pairs);
            return;
        }
    };

    let dest = match Destination::new_outbound(
        Some(identity),
        DestinationType::Single,
        APP_NAME.to_string(),
        vec!["node".to_string()],
    ) {
        Ok(d) => {
            d
        },
        Err(e) => {
            log(format!("[backup] dest error for backup node: {e}"),
                LOG_WARNING, false, false);
            requeue_backup_pairs(&node_weak, pairs);
            return;
        }
    };

    let link = match Link::new_outbound(dest, MODE_AES256_CBC) {
        Ok(l) => {
            l
        },
        Err(e) => {
            log(format!("[backup] link error to backup node: {e}"),
                LOG_WARNING, false, false);
            requeue_backup_pairs(&node_weak, pairs);
            return;
        }
    };

    let handle = LinkHandle::spawn(link);
    let pairs_payload = rmp_serde::to_vec(&pairs).unwrap_or_default();
    let owner_pubkey = match our_identity.get_public_key() {
        Ok(pubkey) => pubkey,
        Err(e) => {
            log(format!("[backup] could not encode backup owner pubkey: {e}"),
                LOG_WARNING, false, false);
            requeue_backup_pairs(&node_weak, pairs);
            return;
        }
    };
    let owner_sig = our_identity.sign(&pairs_payload);
    let signed_payload = {
        let mut encoded = Vec::new();
        let value = rmpv::Value::Array(vec![
            rmpv::Value::Binary(pairs_payload),
            rmpv::Value::Binary(owner_pubkey),
            rmpv::Value::Binary(owner_sig),
        ]);
        let _ = rmpv::encode::write_value(&mut encoded, &value);
        encoded
    };

    // The callback body uses the live LinkHandle `h` passed by the actor,
    // avoiding the old Arc<Mutex<Link>> pattern entirely.
    let payload_for_est = signed_payload.clone();
    let pairs_for_retry = pairs.clone();
    let node_weak_for_retry = node_weak.clone();
    handle.set_link_established_callback(Some(Arc::new(move |h: LinkHandle| {
        let pay = payload_for_est.clone();
        let h_ok = h.clone();
        let h_err = h.clone();
        let retry_pairs_ok = pairs_for_retry.clone();
        let retry_node_ok = node_weak_for_retry.clone();
        let retry_pairs_err = pairs_for_retry.clone();
        let retry_node_err = node_weak_for_retry.clone();
        let ok_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> = Arc::new(move |receipt| {
            let accepted = receipt
                .response
                .as_ref()
                .and_then(|raw| rmp_serde::from_slice::<bool>(raw).ok())
                .unwrap_or(false);

            if accepted {
                log("[backup] backup push accepted by peer", LOG_NOTICE, false, false);
            } else {
                log("[backup] backup push rejected by peer", LOG_WARNING, false, false);
                requeue_backup_pairs(&retry_node_ok, retry_pairs_ok.clone());
            }
            h_ok.teardown();
        });
        let err_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> = Arc::new(move |_| {
            log("[backup] backup push rejected by peer", LOG_WARNING, false, false);
            requeue_backup_pairs(&retry_node_err, retry_pairs_err.clone());
            h_err.teardown();
        });
        let result = h.request(
            BACKUP_PUSH_PATH.to_string(), pay, Some(ok_cb), Some(err_cb), None,
        );
        if result.is_err() {
            log("[backup] backup push request failed to send", LOG_WARNING, false, false);
            requeue_backup_pairs(&node_weak_for_retry, pairs_for_retry.clone());
            h.teardown();
        }
    })));
    let _ = handle.initiate();
    // Link actor registers itself in LinkMsg::Initiate; no external
    // register call needed.
    let _ = handle;
}

/// Scan backup subscriptions held by this node.  For each owner node whose
/// path has decayed (not heard within `owner_offline_secs`), copy that owner's
/// subscribers' channel blobs into the deferred delivery queue so they flush
/// when the subscriber next comes online or PULLs.
///
/// Returns the list of `(subscriber_hash, channel_hash, owner_hash)` triples
/// that were actually delivered ("adopted"). The caller may re-push these to
/// its own backup node so the chain of custody extends further, unless doing
/// so would send them straight back to the current owner.
fn adopted_pairs_for_chain_extension(
    adopted: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    backup_hash: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    adopted
        .into_iter()
        .filter_map(|(subscriber_hash, channel_hash, owner_hash)| {
            if owner_hash.as_slice() == backup_hash {
                None
            } else {
                Some((subscriber_hash, channel_hash))
            }
        })
        .collect()
}

/// Returns the list of `(subscriber_hash, channel_hash, owner_hash)` triples
/// that were actually delivered ("adopted"). The caller may re-push these to
/// its own backup node so the chain of custody extends further, unless doing
/// so would send them straight back to the current owner.
fn backup_delivery_tick(
    subscription_table: Arc<Mutex<crate::subscription::SubscriptionTable>>,
    blob_store: Arc<Mutex<crate::blob_store::BlobStore>>,
    deferred_queue: Arc<Mutex<crate::deferred_queue::DeferredQueue>>,
    notify_registry: Arc<Mutex<crate::notify::NotifyRegistry>>,
    config: &crate::config::NodeConfig,
    sync: Arc<Mutex<crate::sync::FedSync>>,
    owner_offline_secs: f64,
) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let entries = subscription_table
        .lock()
        .ok()
        .map(|s| s.backup_entries_for_tick())
        .unwrap_or_default();
    if entries.is_empty() {
        return Vec::new();
    }

    // Group by owner — one liveness check per owner node.
    // This avoids locking sync once per (sub, channel) pair.
    let mut by_owner: std::collections::HashMap<Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>> =
        std::collections::HashMap::new();
    for (sub_hash, ch_hash, owner_hash) in entries {
        by_owner.entry(owner_hash).or_default().push((sub_hash, ch_hash));
    }

    let mut adopted: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();

    for (owner_hash, subs) in &by_owner {
        // Suppress delivery if the owner node was heard recently via sync peer state.
        let owner_recently_heard = sync.lock().ok()
            .and_then(|s| s.peers.get(owner_hash.as_slice())
                .map(|p| p.alive && (crate::sync::now_secs() - p.last_heard) < owner_offline_secs))
            .unwrap_or(false);
        if owner_recently_heard {
            continue;
        }

        log(
            format!(
                "[backup] owner {} offline \u{2014} checking {} backup subscriber(s)",
                hexrep(owner_hash, false),
                subs.len()
            ),
            LOG_NOTICE, false, false,
        );

        for (sub_hash, ch_hash) in subs {
            // Skip if we already have pending entries; they will flush on announce.
            let has_pending = deferred_queue.lock().ok()
                .map(|q| q.has_pending(sub_hash.as_slice()))
                .unwrap_or(false);
            if has_pending {
                adopted.push((sub_hash.clone(), ch_hash.clone(), owner_hash.clone()));
                continue;
            }

            // Collect all blobs for this channel in one lock acquisition.
            let blobs: Vec<(Vec<u8>, Vec<u8>)> = {
                let store_guard = blob_store.lock().ok();
                if let Some(s) = store_guard {
                    s.message_ids_for_channel(ch_hash.as_slice())
                        .into_iter()
                        .filter_map(|id| s.get(&id).map(|b| (ch_hash.clone(), b)))
                        .collect()
                } else {
                    Vec::new()
                }
            };

            if blobs.is_empty() {
                continue;
            }

            let limit = config.policy_for(sub_hash.as_slice()).deferred_queue_limit;
            let mut enqueued = 0usize;
            if let Ok(mut q) = deferred_queue.lock() {
                for (ch, blob) in &blobs {
                    q.enqueue(sub_hash.clone(), ch.clone(), blob.clone(), limit);
                    enqueued += 1;
                }
            }
            if enqueued > 0 {
                log(
                    format!(
                        "[backup] queued {enqueued} blob(s) for subscriber {} (owner offline)",
                        hexrep(sub_hash, false)
                    ),
                    LOG_NOTICE, false, false,
                );
                adopted.push((sub_hash.clone(), ch_hash.clone(), owner_hash.clone()));
                if let Ok(notify) = notify_registry.lock() {
                    for reg in notify.get_for_channel(sub_hash.as_slice(), Some(ch_hash.as_slice())) {
                        dispatch_notify(reg, None, Some(ch_hash.as_slice()));
                    }
                }
            }
        }
    }
    adopted
}

#[cfg(test)]
mod backup_chain_tests {
    use super::adopted_pairs_for_chain_extension;

    #[test]
    fn adopted_pairs_skip_bounce_back_to_owner() {
        let owner_hash = vec![0x11; 16];
        let next_backup_hash = vec![0x22; 16];
        let adopted = vec![
            (vec![0x31; 16], vec![0x41; 16], owner_hash.clone()),
            (vec![0x32; 16], vec![0x42; 16], next_backup_hash),
        ];

        let filtered = adopted_pairs_for_chain_extension(adopted, owner_hash.as_slice());

        assert_eq!(
            filtered,
            vec![(vec![0x32; 16], vec![0x42; 16])],
            "adopted entries must not be re-pushed back to the current owner"
        );
    }
}

// ── enable() ────────────────────────────────────────────────────────────────

/// Register all four destinations with Reticulum Transport and wire up
/// packet callbacks + request handlers.  Must be called once after
/// `FedNode::new`.
///
/// Initialization order:
///   1. Inject weak self-reference into `FedNode` for callback use.
///   2. Wire all four destinations (node, channel, delivery, notify)
///      plus the stream destinations.
///   3. Load persisted sync peers and request paths.
///   4. Print destination hashes for operator convenience.
///   5. Register announce handlers:
///      - `rfed.node`     → detect/update sync peers.
///      - `rfed.delivery` → flush deferred blobs when subscriber comes online.
pub fn enable(node: Arc<Mutex<FedNode>>) -> Result<(), String> {
    // Inject weak self-reference so callbacks can lock FedNode.
    {
        let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
        guard.self_handle = Some(Arc::downgrade(&node));
    }

    wire_node_destination(&node)?;
    wire_channel_destination(&node)?;
    wire_delivery_destination(&node)?;
    wire_notify_destination(&node)?;
    wire_stream_destinations(&node)?;
    wire_distro_destination(&node)?;

    // MARKER: Distro destinations wired (proves deployment includes distro code)
    log(
        "[rfed] DISTRO MARKER: distro destinations wired successfully".to_string(),
        LOG_NOTICE,
        false,
        false,
    );

    // Load persisted peer state and seed static peers, then request paths
    // for all known/static peers so Reticulum starts routing to them.
    let startup_peer_hashes: Vec<Vec<u8>> = {
        let sync_arc = {
            let guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
            Arc::clone(&guard.sync)
        };
        sync_arc.lock().ok().map(|mut s| {
            s.load_peers();
            s.seed_static_peers();
            s.peers.keys().cloned().collect::<Vec<_>>()
        }).unwrap_or_default()
    };
    for hash in &startup_peer_hashes {
        Transport::request_path(hash, None, None, None, None);
    }

    // Print destination hashes for operator convenience.
    {
        let guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
        for (label, dest) in [
            ("node",     &guard.node_dest),
            ("delivery", &guard.delivery_dest),
            ("channel",  &guard.channel_dest),
            ("notify",   &guard.notify_dest),
            ("channel.subscribe",   &guard.channel_subscribe_dest),
            ("channel.unsubscribe", &guard.channel_unsubscribe_dest),
            ("channel.publish",     &guard.channel_publish_dest),
            ("channel.pull",        &guard.channel_pull_dest),
            ("channel.stream",      &guard.channel_stream_dest),
            ("propagation.stream",  &guard.propagation_stream_dest),
            ("notify.register",     &guard.notify_register_dest),
            ("notify.unregister",   &guard.notify_unregister_dest),
            ("distro.register",     &guard.distro_register_dest),
            ("distro.unregister",   &guard.distro_unregister_dest),
            ("distro.list",         &guard.distro_list_dest),
        ] {
            log(
                format!("[rfed] rfed.{} dest hash: {}", label, hexrep(&dest.hash, false)),
                LOG_NOTICE,
                false,
                false,
            );
        }
    }

    // Register rfed.node announce handler so we detect peers.
    let node_weak = Arc::downgrade(&node);
    Transport::register_announce_handler(AnnounceHandler {
        aspect_filter: Some(format!("{APP_NAME}.node")),
        receive_path_responses: false,
        callback: Arc::new(move |dest_hash, _identity, app_data, _ann_hash, _is_path| {
            let ann = announce::decode_node_announce(app_data);
            let peering_cost = ann.as_ref().and_then(|a| a.stamp_cost);
            if let Some(arc) = node_weak.upgrade() {
                if let Ok(guard) = arc.lock() {
                    // Never sync with ourselves — skip our own announce.
                    if dest_hash == guard.node_dest.hash.as_slice() {
                        return;
                    }
                    if let Ok(mut s) = guard.sync.lock() { s.peer_heard(dest_hash.to_vec(), peering_cost); }
                }
            }
        }),
    });

    // Register rfed.delivery announce handler — flush deferred blobs when a
    // subscriber comes online.  Subscribers announce on their rfed.delivery
    // destination so we observe `APP_NAME.delivery` aspects here.
    //
    // Flow: announce heard → check deferred queue → drain → build outbound
    //   single dest for this subscriber → send each blob as a DATA packet.
    //   If dest build fails, re-enqueue for retry on next announce.
    let delivery_weak = Arc::downgrade(&node);
    Transport::register_announce_handler(AnnounceHandler {
        aspect_filter: Some(format!("{APP_NAME}.delivery")),
        receive_path_responses: false,
        callback: Arc::new(move |dest_hash, identity, _app_data, _ann_hash, _is_path| {
            // The deferred queue is keyed by IDENTITY HASH (not the delivery
            // destination hash).  The identity hash is truncated_hash(pub_key).
            let sub_id_hash: Vec<u8> = match identity.hash.as_ref() {
                Some(h) => h.clone(),
                None => return,
            };

            let arc = match delivery_weak.upgrade() {
                Some(a) => a,
                None => return,
            };
            // Take the collaborators this handler needs and release the FedNode
            // mutex immediately. The flush below sends one packet per blob —
            // network work — and this handler runs on the announce path, so
            // holding the mutex here stalls every request callback exactly the
            // way the channel fan-out did (see FedNode::plan_channel_fanout).
            //
            // NEVER REMOVE the early drop.
            let (deferred_queue, hook_registry, limit) = match arc.lock() {
                Ok(guard) => (
                    Arc::clone(&guard.deferred_queue),
                    Arc::clone(&guard.hook_registry),
                    guard.config.policy_for(&sub_id_hash).deferred_queue_limit,
                ),
                Err(_) => return,
            };

            // Fast-path: skip the lock chain if nothing is queued.
            let has_pending = deferred_queue
                .lock()
                .ok()
                .map(|q| q.has_pending(&sub_id_hash))
                .unwrap_or(false);
            if !has_pending {
                return;
            }

            // Drain the queue for this subscriber (keyed by identity hash).
            let pending = deferred_queue
                .lock()
                .ok()
                .map(|mut q| q.drain(&sub_id_hash))
                .unwrap_or_default();

            if pending.is_empty() {
                return;
            }

            log(
                format!(
                    "[deferred] subscriber {} (delivery {}) back online — flushing {} blob(s)",
                    hexrep(&sub_id_hash, false),
                    hexrep(dest_hash, false),
                    pending.len()
                ),
                LOG_NOTICE,
                false,
                false,
            );

            // Build the outbound delivery destination using the now-known identity.
            let dest_result = reticulum_rust::destination::Destination::new_outbound(
                Some(identity.clone()),
                reticulum_rust::destination::DestinationType::Single,
                APP_NAME.to_string(),
                vec!["delivery".to_string()],
            );
            let dest = match dest_result {
                Ok(d) => d,
                Err(e) => {
                    log(
                        format!("[deferred] failed to build dest for {}: {e}",
                            hexrep(&sub_id_hash, false)),
                        LOG_WARNING,
                        false,
                        false,
                    );
                    // Re-enqueue everything — we'll try again on next announce.
                    if let Ok(mut q) = deferred_queue.lock() {
                        for pb in pending {
                            q.enqueue(sub_id_hash.clone(), pb.channel_hash, pb.blob, limit);
                        }
                    }
                    return;
                }
            };

            let hooks = hook_registry.lock().ok();
            let mut failed: Vec<&crate::deferred_queue::PendingBlob> = Vec::new();
            for pb in &pending {
                // Delivery packet payload: channel_hash(16) | inner_blob
                // Matches the format expected by the subscriber's onRfedBlob handler.
                let mut payload = pb.channel_hash.clone();
                payload.extend_from_slice(&pb.blob);
                let mut packet = reticulum_rust::packet::Packet::new(
                    Some(dest.clone()),
                    payload,
                    reticulum_rust::packet::DATA,
                    reticulum_rust::packet::NONE,
                    reticulum_rust::transport::BROADCAST,
                    reticulum_rust::packet::HEADER_1,
                    None,
                    None,
                    false,
                    reticulum_rust::packet::FLAG_UNSET,
                );
                match packet.send() {
                    // Ok(Some) = transmitted (receipt); keep it drained.
                    Ok(Some(_)) => {
                        if let Some(ref hooks) = hooks {
                            hooks.on_deliver(&sub_id_hash, &pb.blob);
                        }
                    }
                    // Ok(None) = Transport::outbound returned sent=false (no
                    // usable interface/path right now).  Do NOT mark delivered
                    // and do NOT drop it — re-enqueue so the next announce /
                    // path-ready edge retries.  Previously Ok(None) fell through
                    // to on_deliver and the blob was silently lost, which is why
                    // fanned-out distro messages never reached devices.
                    Ok(None) => {
                        log(
                            format!("[deferred] send to {} not transmitted (no usable interface) — re-enqueueing",
                                hexrep(&sub_id_hash, false)),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                        failed.push(pb);
                    }
                    // Err = hard send error — re-enqueue so a later announce retries.
                    Err(e) => {
                        log(
                            format!("[deferred] send to {} failed: {e} — re-enqueueing",
                                hexrep(&sub_id_hash, false)),
                            LOG_WARNING,
                            false,
                            false,
                        );
                        failed.push(pb);
                    }
                }
            }
            // Re-enqueue the blobs that did not transmit so they survive for the
            // next announce / path-ready trigger instead of being dropped.
            if !failed.is_empty() {
                if let Ok(mut q) = deferred_queue.lock() {
                    for pb in failed {
                        q.enqueue(sub_id_hash.clone(), pb.channel_hash.clone(), pb.blob.clone(), limit);
                    }
                }
            }
        }),
    });

    Ok(())
}

// ── rfed.node ────────────────────────────────────────────────────────────────

fn wire_node_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    // OFFER — peer sends its manifest (IDs it has); we return our manifest
    //         so the caller can compute the gap and pull via MESSAGE_GET.
    let sync_offer = {
        let n = Arc::clone(node);
        Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                       _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
            let offered: Vec<Vec<u8>> = rmp_serde::from_slice(data).unwrap_or_default();
            if let Ok(s) = n.lock().map(|g| Arc::clone(&g.sync)) {
                if let Ok(sync) = s.lock() {
                    // handle_offer accepts offered_ids (future: rate limiting)
                    // and returns our own manifest.
                    let manifest = sync.handle_offer(offered);
                    return rmp_serde::to_vec(&manifest).unwrap_or_default();
                }
            }
            Vec::new()
        })
    };

    // MESSAGE_GET — peer requests specific blobs by ID.
    let sync_get = {
        let n = Arc::clone(node);
        Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                       _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
            let ids: Vec<Vec<u8>> = rmp_serde::from_slice(data).unwrap_or_default();
            if let Ok(s) = n.lock().map(|g| Arc::clone(&g.sync)) {
                if let Ok(mut sync) = s.lock() {
                    return sync.handle_message_get(&ids);
                }
            }
            Vec::new()
        })
    };

    // BACKUP_PUSH — owner node registers backup subscriptions on this node.
    // The owner authenticates by signing the request payload with its node
    // identity key material, avoiding any dependency on link-identify ordering.
    let backup_push_node = Arc::clone(node);
    let backup_push_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                        _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let (pairs_bytes, _owner_identity_hash, pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(
                    format!("[backup] invalid BACKUP_PUSH payload: {e}"),
                    LOG_WARNING, false, false,
                );
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };

        let owner_identity = match Identity::from_public_key(&pubkey) {
            Ok(identity) => identity,
            Err(e) => {
                log(
                    format!("[backup] BACKUP_PUSH owner key decode error: {e}"),
                    LOG_WARNING, false, false,
                );
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };

        let owner_hash = match Destination::new_outbound(
            Some(owner_identity),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["node".to_string()],
        ) {
            Ok(dest) => dest.hash,
            Err(e) => {
                log(
                    format!("[backup] BACKUP_PUSH owner hash derivation error: {e}"),
                    LOG_WARNING, false, false,
                );
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };

        let pairs: Vec<(Vec<u8>, Vec<u8>)> = match rmp_serde::from_slice(&pairs_bytes) {
            Ok(pairs) => pairs,
            Err(e) => {
                log(
                    format!("[backup] BACKUP_PUSH pairs decode error: {e}"),
                    LOG_WARNING, false, false,
                );
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };

        let guard = match backup_push_node.lock() {
            Ok(g) => g,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };

        // If trusted_backup_peers is non-empty, only accept from listed nodes.
        let trusted = guard.config.trusted_backup_peers.is_empty()
            || guard.config.trusted_backup_peers.iter().any(|h| h == &owner_hash);
        if !trusted {
            log(
                format!("[backup] rejected BACKUP_PUSH from untrusted owner {}",
                    hexrep(&owner_hash, false)),
                LOG_WARNING, false, false,
            );
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }

        if let Ok(mut subs) = guard.subscription_table.lock() {
            for (sub_hash, ch_hash) in &pairs {
                subs.subscribe_backup(sub_hash.clone(), ch_hash.clone(), owner_hash.clone());
            }
        }
        log(
            format!("[backup] registered {} backup sub(s) from owner {}",
                pairs.len(), hexrep(&owner_hash, false)),
            LOG_NOTICE, false, false,
        );
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    // CAPABILITIES — public query returning node features and config surface.
    // Response is a msgpack map that can be extended over time without
    // breaking older clients (unknown keys are simply ignored).
    let caps_node = Arc::clone(node);
    let capabilities_cb = Arc::new(move |_path: &str, _data: &[u8], _req_id: &[u8],
                                         _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let guard = match caps_node.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let cfg = &guard.config;

        let mut caps: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();

        // Protocol version — bump when wire formats change.
        caps.push((
            rmpv::Value::String("protocol_version".into()),
            rmpv::Value::Integer(1.into()),
        ));

        // Node display name.
        caps.push((
            rmpv::Value::String("display_name".into()),
            rmpv::Value::String(cfg.display_name.clone().into()),
        ));

        // Which commits this binary was built from — rfed plus its three path
        // dependencies. CI builds ghcr rfed:latest from sibling repos cloned at
        // build time and does not rebuild when they change, so a node's actual
        // contents were previously unknowable from the outside. Now you can ask
        // it. See rfed/build.rs and scripts/check-sibling-drift.sh.
        caps.push((
            rmpv::Value::String("build".into()),
            rmpv::Value::String(crate::BUILD_STAMP.into()),
        ));

        // Feature flags — reflects what this node has enabled.
        caps.push((
            rmpv::Value::String("subscription".into()),
            rmpv::Value::Boolean(cfg.default_policy.allow_subscription),
        ));
        caps.push((
            rmpv::Value::String("notify".into()),
            rmpv::Value::Boolean(cfg.default_policy.allow_notify_registration),
        ));
        caps.push((
            rmpv::Value::String("lxmf_propagation".into()),
            rmpv::Value::Boolean(cfg.lxmf_propagation_enabled),
        ));
        caps.push((
            rmpv::Value::String("channel_stream".into()),
            rmpv::Value::Boolean(true),
        ));
        caps.push((
            rmpv::Value::String("propagation_stream".into()),
            rmpv::Value::Boolean(cfg.lxmf_propagation_enabled),
        ));
        caps.push((
            rmpv::Value::String("distro".into()),
            rmpv::Value::Boolean(true),
        ));
        caps.push((
            rmpv::Value::String("backup".into()),
            rmpv::Value::Boolean(cfg.primary_node.is_some() || !cfg.secondary_nodes.is_empty()),
        ));

        // Anti-spam parameters.
        caps.push((
            rmpv::Value::String("stamp_cost".into()),
            match cfg.default_policy.stamp_cost.filter(|c| *c > 0) {
                Some(c) => rmpv::Value::Integer(c.into()),
                None    => rmpv::Value::Nil,
            },
        ));

        let mut buf = Vec::new();
        if rmpv::encode::write_value(&mut buf, &rmpv::Value::Map(caps)).is_ok() {
            buf
        } else {
            Vec::new()
        }
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.node_dest.register_request_handler(
        OFFER_PATH.to_string(), Some(sync_offer), ALLOW_ALL, None, false,
    )?;
    guard.node_dest.register_request_handler(
        MESSAGE_GET_PATH.to_string(), Some(sync_get), ALLOW_ALL, None, false,
    )?;
    guard.node_dest.register_request_handler(
        BACKUP_PUSH_PATH.to_string(), Some(backup_push_cb), ALLOW_ALL, None, false,
    )?;
    guard.node_dest.register_request_handler(
        CAPABILITIES_PATH.to_string(), Some(capabilities_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.node_dest.clone());
    Ok(())
}

// ── rfed.channel ─────────────────────────────────────────────────────────────

fn wire_channel_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    // Snapshot anti-spam knobs once — both are Copy so no lock required later.
    let (stamp_cost, stamp_flexibility) = {
        let guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
        (
            // stamp_cost=0 is semantically disabled and must not trigger
            // stamp-tail parsing.
            guard.config.default_policy.stamp_cost.filter(|c| *c > 0),
            guard.config.default_policy.stamp_flexibility,
        )
    };

    // SEND — fire-and-forget packet; payload is the inner blob (± stamp).
    //
    // Wire format WITHOUT stamp (stamp_cost == None or Some(0)):
    //   channel_hash(16) | inner_blob(*)
    //
    // Wire format WITH stamp (stamp_cost is Some(>0)):
    //   channel_hash(16) | inner_blob(*) | stamp(LXStamper::STAMP_SIZE)
    //
    // When a stamp is required the node validates PoW before accepting the blob.
    // The stamp is stripped before storage so peers receive clean blobs.
    // Payloads at or under the link MDU (431 B) arrive as a single DATA
    // packet; anything larger arrives as a Resource. Both land here.
    let send_node = Arc::clone(node);
    let ingest_send: Arc<dyn Fn(&[u8]) + Send + Sync> = Arc::new(move |data: &[u8]| {
        if data.len() < 17 {
            log("[channel] malformed SEND packet (too short)", LOG_WARNING, false, false);
            return;
        }

        // ── Stamp validation (when configured) ───────────────────────
        let (channel_hash, inner_blob): (&[u8], &[u8]) = if let Some(cost) = stamp_cost {
            // Must have at least 16 (channel) + 1 (blob) + STAMP_SIZE bytes.
            let min_len = 16 + LXStamper::STAMP_SIZE + 1;
            if data.len() < min_len {
                log("[channel] SEND rejected: too short to contain stamp",
                    LOG_WARNING, false, false);
                return;
            }
            let stamp_start = data.len() - LXStamper::STAMP_SIZE;
            let stamp    = &data[stamp_start..];
            let material = &data[..stamp_start]; // channel_hash || inner_blob

            // transient_id binds the stamp to this exact blob+channel pair.
            let transient_id = identity::full_hash(material);
            let workblock    = LXStamper::stamp_workblock(&transient_id, STAMP_EXPAND_ROUNDS);

            // Allow downward flexibility so stamps generated against a slightly
            // older/different cost announcement are still accepted.
            let min_cost = cost.saturating_sub(stamp_flexibility.unwrap_or(0));
            if !LXStamper::stamp_valid(stamp, min_cost, &workblock) {
                // Name the pre-parity stamper explicitly. Before LXStamper was
                // brought back in line with LXMF's Python implementation it
                // built the workblock as a single iterated digest, so an old
                // client's stamp fails here for a reason that has nothing to do
                // with its cost — and "does not meet required cost" would send
                // whoever is debugging it in entirely the wrong direction.
                if LXStamper::is_legacy_stamp(&transient_id, stamp, min_cost, STAMP_EXPAND_ROUNDS) {
                    log("[channel] SEND rejected: client is using the pre-parity stamp workblock \
                         (iterated digest instead of LXMF HKDF expansion) — it needs updating",
                        LOG_WARNING, false, false);
                } else {
                    log("[channel] SEND rejected: stamp does not meet required cost",
                        LOG_WARNING, false, false);
                }
                return;
            }
            log(format!("[channel] stamp accepted (cost>={min_cost})"),
                LOG_DEBUG, false, false);

            (&data[..16], &data[16..stamp_start])
        } else {
            (&data[..16], &data[16..])
        };

        // Store the blob.
        let msg_id_opt = send_node.lock().ok().and_then(|guard| {
            guard.blob_store.lock().ok().and_then(|mut store| {
                store.store(channel_hash, inner_blob).ok()
            })
        });

        if let Some(_msg_id) = msg_id_opt {
            // Fanout to subscribers.
            //
            // The plan is built under the FedNode mutex and the guard is
            // dropped at the end of this statement; `plan.run` then does the
            // network work with no FedNode lock held. NEVER inline the run
            // into the lock scope — that wedged /rfed/subscribe on 2026-08-17
            // (see FedNode::plan_channel_fanout).
            let plan = match send_node.lock() {
                Ok(guard) => Some(guard.plan_channel_fanout(channel_hash)),
                Err(_) => None,
            };
            if let Some(plan) = plan {
                log(
                    format!("[CHANNEL-RX] channel={} blob_bytes={} → fanning out to {} subscriber(s)",
                        hexrep(channel_hash, false),
                        inner_blob.len(),
                        plan.subscribers.len(),
                    ),
                    LOG_NOTICE, false, false,
                );
                plan.run(channel_hash, inner_blob);
            }
        }
    });

    let packet_cb: Arc<dyn Fn(&[u8], &Packet) + Send + Sync> = {
        let ingest = Arc::clone(&ingest_send);
        Arc::new(move |data: &[u8], _packet: &Packet| ingest(data))
    };

    // A link defaults to ACCEPT_NONE, so without this an oversized channel
    // publish is advertised, silently ignored, and never proved — the sender
    // sees nothing at all. ACCEPT_APP additionally requires a `resource`
    // callback to be present (RNS/Link.py:1106).
    let resource_ingest = Arc::clone(&ingest_send);
    let channel_link_established: Arc<dyn Fn(LinkHandle) + Send + Sync> =
        Arc::new(move |link: LinkHandle| {
            link.set_resource_strategy(reticulum_rust::link::ACCEPT_APP);
            let ingest = Arc::clone(&resource_ingest);
            link.set_resource_callbacks(
                Some(Arc::new(|_resource| {})),
                None,
                Some(Arc::new(move |resource: Arc<Mutex<reticulum_rust::resource::Resource>>| {
                    let data: Vec<u8> = match resource.lock() {
                        Ok(r) => {
                            if r.status != reticulum_rust::resource::ResourceStatus::Complete {
                                return;
                            }
                            match r.data.clone() {
                                Some(d) => d,
                                None => return,
                            }
                        }
                        Err(_) => return,
                    };
                    log(
                        format!("[channel] SEND arrived as resource ({} bytes)", data.len()),
                        LOG_DEBUG, false, false,
                    );
                    ingest(&data);
                })),
            );
        });

    // SUBSCRIBE — client registers (subscriber_hash, channel_hash).
    let sub_node = Arc::clone(node);
    let subscribe_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                      _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        // Payload: fixarray-3 [bin(16) channel_hash, bin(64) pubkey, bin(64) sig].
        // Subscriber identity is derived from pubkey; sig proves key ownership.
        let (channel_hash, subscriber_hash, _pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] subscribe_cb: {e}"), LOG_WARNING, false, false);
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };

        if channel_hash.len() != 16 {
            log(format!("[rfed] subscribe_cb: bad channel_hash len={}", channel_hash.len()), LOG_WARNING, false, false);
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }
        let lock_start = Instant::now();
        if let Ok(guard) = sub_node.lock() {
            let lock_held = lock_start.elapsed();
            if lock_held > Duration::from_secs(1) {
                log(format!("[rfed] LOCK-WARN subscribe_cb: FedNode lock acquired after {:.2}s", lock_held.as_secs_f64()), LOG_WARNING, false, false);
            }
            if !guard.config.policy_for(&subscriber_hash).allow_subscription {
                log(
                    format!(
                        "[rfed] subscription denied for {} (policy)",
                        reticulum_rust::hexrep(&subscriber_hash, false),
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
            if let Ok(mut subs) = guard.subscription_table.lock() {
                subs.subscribe(subscriber_hash.clone(), channel_hash.clone());
            }
            // Queue for backup push.
            {
                if let Ok(mut q) = guard.pending_backup_pushes.lock() {
                    const PENDING_BACKUP_CAP: usize = 1024;
                    if q.len() < PENDING_BACKUP_CAP {
                        q.push((subscriber_hash, channel_hash));
                    }
                }
            }
            // Response: [true, stamp_cost_or_nil]
            // stamp_cost is Nil when disabled (including configured 0) so
            // clients skip the stamp tail entirely.
            let cost = guard.config.default_policy.stamp_cost.filter(|c| *c > 0);
            let resp = rmpv::Value::Array(vec![
                rmpv::Value::Boolean(true),
                match cost {
                    Some(c) => rmpv::Value::Integer(rmpv::Integer::from(c as i64)),
                    None    => rmpv::Value::Nil,
                },
            ]);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &resp).unwrap_or_default();
            return buf;
        }
        rmp_serde::to_vec(&false).unwrap_or_default()
    });

    // UNSUBSCRIBE
    let unsub_node = Arc::clone(node);
    let unsubscribe_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                        _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let (channel_hash, subscriber_hash, _pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };
        let lock_start = Instant::now();
        if let Ok(guard) = unsub_node.lock() {
            let lock_held = lock_start.elapsed();
            if lock_held > Duration::from_secs(1) {
                log(format!("[rfed] LOCK-WARN unsubscribe_cb: FedNode lock acquired after {:.2}s", lock_held.as_secs_f64()), LOG_WARNING, false, false);
            }
            if let Ok(mut subs) = guard.subscription_table.lock() {
                subs.unsubscribe(&subscriber_hash, &channel_hash);
            }
        }
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    let pull_node = Arc::clone(node);
    let channel_pull_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                         caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let subscriber_hash = match caller.and_then(|id| id.hash.clone()) {
            Some(h) => h,
            None => return Vec::new(),
        };
        let channel_hash = match decode_channel_pull_request(data) {
            Ok(hash) => hash,
            Err(e) => {
                log(format!("[rfed] channel.pull: {e}"), LOG_WARNING, false, false);
                return encode_pull_response(Vec::new(), false);
            }
        };

        let lock_start = Instant::now();
        if let Ok(guard) = pull_node.lock() {
            let lock_held = lock_start.elapsed();
            if lock_held > Duration::from_secs(1) {
                log(format!("[rfed] LOCK-WARN channel.pull: FedNode lock acquired after {:.2}s", lock_held.as_secs_f64()), LOG_WARNING, false, false);
            }
            let page_size = guard
                .config
                .policy_for(&subscriber_hash)
                .deferred_pull_batch_limit
                .unwrap_or(DEFAULT_PULL_PAGE_SIZE);
            if let Ok(mut deferred) = guard.deferred_queue.lock() {
                let pending = deferred.drain_channel_batch(&subscriber_hash, &channel_hash, page_size);
                let more_pending = deferred.has_pending_channel(&subscriber_hash, &channel_hash);
                return encode_pull_response(pending, more_pending);
            }
        }
        Vec::new()
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.channel_dest.set_packet_callback(Some(packet_cb.clone()));
    guard.channel_dest.set_link_established_callback(Some(channel_link_established.clone()));
    guard.channel_dest.register_request_handler(
        SUBSCRIBE_PATH.to_string(), Some(subscribe_cb.clone()), ALLOW_ALL, None, false,
    )?;
    guard.channel_dest.register_request_handler(
        UNSUBSCRIBE_PATH.to_string(), Some(unsubscribe_cb.clone()), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.channel_dest.clone());

    // ── New split aspects (REFACTOR.md 2026-05-17) ──────────────────
    // Each new destination carries the intent on the wire. Same callbacks,
    // distinct destination hashes. SUBSCRIBE/UNSUBSCRIBE paths are reused
    // since the path string is informational once routed to the right dest.
    guard.channel_publish_dest.set_packet_callback(Some(packet_cb));
    guard.channel_publish_dest.set_link_established_callback(Some(channel_link_established));
    guard.channel_subscribe_dest.register_request_handler(
        SUBSCRIBE_PATH.to_string(), Some(subscribe_cb), ALLOW_ALL, None, false,
    )?;
    guard.channel_unsubscribe_dest.register_request_handler(
        UNSUBSCRIBE_PATH.to_string(), Some(unsubscribe_cb), ALLOW_ALL, None, false,
    )?;
    guard.channel_pull_dest.register_request_handler(
        PULL_PATH.to_string(), Some(channel_pull_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.channel_subscribe_dest.clone());
    Transport::register_destination(guard.channel_unsubscribe_dest.clone());
    Transport::register_destination(guard.channel_publish_dest.clone());
    Transport::register_destination(guard.channel_pull_dest.clone());
    Ok(())
}

// ── rfed.delivery ────────────────────────────────────────────────────────────

fn wire_delivery_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    // PULL — legacy compatibility path. Client proves key ownership via the
    // request's authenticated caller.
    //
    // **User-initiated paging** (mirrors the chat-history "Load earlier
    // messages" UX): each PULL drains at most one page of pending inner blobs
    // for the caller and returns a `more_pending` flag so the client knows
    // whether to offer another page.  Page size = policy
    // `deferred_pull_batch_limit` if set, else `DEFAULT_PULL_PAGE_SIZE`.
    //
    // Draining is atomic from the caller's perspective: the returned blobs are
    // removed before the response is sent.  If the client crashes before
    // processing the bytes, those blobs are gone from this node and can only
    // be recovered via fanout from another session or sync from the origin.
    //
    // Wire format (response): msgpack 2-fixarray
    //     [ Array([ [bin(16) channel_hash, bin(*) blob], ... ]),
    //       Bool(more_pending) ]
    // The previous "flat array of pairs" format is gone — clients MUST decode
    // the 2-element envelope.  Uses rmpv so Python receives proper bytes.
    let pull_node = Arc::clone(node);
    let pull_cb = Arc::new(move |_path: &str, _data: &[u8], _req_id: &[u8],
                                  caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let subscriber_hash = match caller.and_then(|id| id.hash.clone()) {
            Some(h) => h,
            None => return Vec::new(),
        };
        if let Ok(guard) = pull_node.lock() {
            let page_size = guard.config
                .policy_for(&subscriber_hash)
                .deferred_pull_batch_limit
                .unwrap_or(DEFAULT_PULL_PAGE_SIZE);
            if let Ok(mut deferred) = guard.deferred_queue.lock() {
                let pending = deferred.drain_batch(&subscriber_hash, page_size);
                let more_pending = deferred.has_pending(&subscriber_hash);
                return encode_pull_response(pending, more_pending);
            }
        }
        Vec::new()
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.delivery_dest.register_request_handler(
        PULL_PATH.to_string(), Some(pull_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.delivery_dest.clone());
    Ok(())
}

// ── rfed.notify ──────────────────────────────────────────────────────────────

fn wire_notify_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    let packet_node = Arc::clone(node);
    let packet_cb: Arc<dyn Fn(&[u8], &Packet) + Send + Sync> = Arc::new(move |data, _packet| {
        let (value_bytes, subscriber_hash, pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] notify packet: {e}"), LOG_WARNING, false, false);
                return;
            }
        };
        let command = match parse_notify_command(&value_bytes, None) {
            Ok(cmd) => cmd,
            Err(e) => {
                log(format!("[rfed] notify packet: {e}"), LOG_WARNING, false, false);
                return;
            }
        };
        if let Err(e) = handle_notify_command(&packet_node, command, subscriber_hash, Some(pubkey)) {
            log(format!("[rfed] notify packet: {e}"), LOG_WARNING, false, false);
        }
    });

    // NOTIFY_REGISTER — client sends a 32-char hex relay destination hash.
    // Multiple calls with different hashes register additional relays for the
    // same subscriber; duplicate hashes refresh the timestamp only.
    //
    // Two entries are inserted per registration:
    //   1. subscriber_identity_hash → relay_hash  (for channel notify)
    //   2. lxmf.delivery_dest_hash  → relay_hash  (for LXMF propagation notify)
    // This dual-hash approach ensures the propagation handler (which only knows
    // the lxmf.delivery dest hash from message headers) can look up the relay.
    let reg_node = Arc::clone(node);
    let register_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                      _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let (value_bytes, subscriber_hash, pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] notify/register: {e}"), LOG_WARNING, false, false);
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };
        let command = match parse_notify_command(&value_bytes, Some(NotifyCommandKind::Register)) {
            Ok(cmd) => cmd,
            Err(e) => {
                log(format!("[rfed] notify/register: {e}"), LOG_WARNING, false, false);
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };
        if let Err(e) = handle_notify_command(&reg_node, command, subscriber_hash, Some(pubkey)) {
            log(format!("[rfed] notify/register: {e}"), LOG_WARNING, false, false);
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    // NOTIFY_UNREGISTER — remove a specific relay hash for the caller.
    // Payload: msgpack [str(relay_hex), bin(16 channel_hash) | nil], same as REGISTER.
    let unreg_node = Arc::clone(node);
    let unregister_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                        _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let (value_bytes, subscriber_hash, pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };
        let command = match parse_notify_command(&value_bytes, Some(NotifyCommandKind::Unregister)) {
            Ok(cmd) => cmd,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };
        if handle_notify_command(&unreg_node, command, subscriber_hash, Some(pubkey)).is_err() {
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    // NOTIFY_CLEAR — remove ALL relay registrations for the caller.
    // No payload required.
    let clear_node = Arc::clone(node);
    let clear_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                    _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let (value_bytes, subscriber_hash, pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };
        let command = match parse_notify_command(&value_bytes, Some(NotifyCommandKind::Clear)) {
            Ok(cmd) => cmd,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };
        if handle_notify_command(&clear_node, command, subscriber_hash, Some(pubkey)).is_err() {
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.notify_dest.set_packet_callback(Some(packet_cb.clone()));
    let packet_cb_for_link = packet_cb.clone();
    guard.notify_dest.set_link_established_callback(Some(Arc::new(move |mut link: LinkHandle| {
        link.set_packet_callback(Some(packet_cb_for_link.clone()));
    })));
    guard.notify_dest.register_request_handler(
        NOTIFY_REGISTER_PATH.to_string(), Some(register_cb.clone()), ALLOW_ALL, None, false,
    )?;
    guard.notify_dest.register_request_handler(
        NOTIFY_UNREGISTER_PATH.to_string(), Some(unregister_cb.clone()), ALLOW_ALL, None, false,
    )?;
    guard.notify_dest.register_request_handler(
        NOTIFY_CLEAR_PATH.to_string(), Some(clear_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.notify_dest.clone());

    // ── New split aspects (REFACTOR.md 2026-05-17) ──────────────────
    // Same packet/request callbacks, intent split across two destinations.
    // NOTIFY_CLEAR remains on legacy notify_dest only — it has no analog in
    // the new split (clear-all is a maintenance op, not a routing op).
    guard.notify_register_dest.set_packet_callback(Some(packet_cb.clone()));
    let packet_cb_for_reg_link = packet_cb.clone();
    guard.notify_register_dest.set_link_established_callback(Some(Arc::new(move |mut link: LinkHandle| {
        link.set_packet_callback(Some(packet_cb_for_reg_link.clone()));
    })));
    guard.notify_register_dest.register_request_handler(
        NOTIFY_REGISTER_PATH.to_string(), Some(register_cb), ALLOW_ALL, None, false,
    )?;

    guard.notify_unregister_dest.set_packet_callback(Some(packet_cb.clone()));
    let packet_cb_for_unreg_link = packet_cb;
    guard.notify_unregister_dest.set_link_established_callback(Some(Arc::new(move |mut link: LinkHandle| {
        link.set_packet_callback(Some(packet_cb_for_unreg_link.clone()));
    })));
    guard.notify_unregister_dest.register_request_handler(
        NOTIFY_UNREGISTER_PATH.to_string(), Some(unregister_cb), ALLOW_ALL, None, false,
    )?;

    Transport::register_destination(guard.notify_register_dest.clone());
    Transport::register_destination(guard.notify_unregister_dest.clone());
    Ok(())
}

fn wire_stream_destinations(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    let channel_stream_node = Arc::clone(node);
    let channel_stream_open = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                             _caller: Option<&Identity>, link: Option<&LinkHandle>,
                                             _timeout: f64| -> Vec<u8> {
        let link = match link {
            Some(link) => link.clone(),
            None => return encode_stream_open_response(false, Some("no_link")),
        };

        let (value_bytes, subscriber_hash, _pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] channel.stream/open: {e}"), LOG_WARNING, false, false);
                return encode_stream_open_response(false, Some("bad_signature"));
            }
        };

        let channel_hashes = match decode_channel_stream_filters(&value_bytes) {
            Ok(hashes) => hashes,
            Err(e) => {
                log(
                    format!("[rfed] channel.stream/open config: {e}"),
                    LOG_WARNING,
                    false,
                    false,
                );
                return encode_stream_open_response(false, Some("bad_channel_config"));
            }
        };

        let (subscriptions, stream_registry) = match channel_stream_node.lock() {
            Ok(guard) => (
                Arc::clone(&guard.subscription_table),
                Arc::clone(&guard.channel_streams),
            ),
            Err(_) => return encode_stream_open_response(false, Some("internal_error")),
        };

        let subscribed = subscriptions
            .lock()
            .ok()
            .map(|subs| {
                channel_hashes
                    .iter()
                    .all(|channel_hash| subs.is_subscribed(&subscriber_hash, channel_hash))
            })
            .unwrap_or(false);
        if !subscribed {
            return encode_stream_open_response(false, Some("not_subscribed"));
        }

        match stream_registry.lock() {
            Ok(mut registry) => {
                registry.configure(link.clone(), subscriber_hash.clone(), channel_hashes.clone());
            }
            Err(_) => return encode_stream_open_response(false, Some("internal_error")),
        }

        let cleanup_registry = Arc::clone(&stream_registry);
        link.set_link_closed_callback(Some(Arc::new(move |closed_link: LinkHandle| {
            if let Ok(mut registry) = cleanup_registry.lock() {
                registry.remove(closed_link.link_id().as_slice());
            }
        })));

        log(
            format!(
                "[rfed] channel.stream/open configured subscriber={} channels={} link={}",
                hexrep(&subscriber_hash, false),
                channel_hashes.len(),
                hexrep(&link.link_id(), false),
            ),
            LOG_NOTICE,
            false,
            false,
        );

        encode_stream_open_response(true, None)
    });

    let propagation_stream_node = Arc::clone(node);
    let propagation_stream_open = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                                 _caller: Option<&Identity>, link: Option<&LinkHandle>,
                                                 _timeout: f64| -> Vec<u8> {
        let link = match link {
            Some(link) => link.clone(),
            None => return encode_stream_open_response(false, Some("no_link")),
        };

        let (delivery_hash, _subscriber_hash, pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] propagation.stream/open: {e}"), LOG_WARNING, false, false);
                return encode_stream_open_response(false, Some("bad_signature"));
            }
        };

        if delivery_hash.len() != 16 {
            return encode_stream_open_response(false, Some("bad_delivery_hash"));
        }

        let expected_delivery_hash = match lxmf_delivery_hash_from_pubkey(&pubkey) {
            Ok(hash) => hash,
            Err(e) => {
                log(format!("[rfed] propagation.stream/open: {e}"), LOG_WARNING, false, false);
                return encode_stream_open_response(false, Some("bad_pubkey"));
            }
        };

        if expected_delivery_hash != delivery_hash {
            return encode_stream_open_response(false, Some("delivery_mismatch"));
        }

        let (propagation_enabled, stream_registry) = match propagation_stream_node.lock() {
            Ok(guard) => (
                guard.config.lxmf_propagation_enabled,
                Arc::clone(&guard.propagation_streams),
            ),
            Err(_) => return encode_stream_open_response(false, Some("internal_error")),
        };

        if !propagation_enabled {
            return encode_stream_open_response(false, Some("feature_disabled"));
        }

        match stream_registry.lock() {
            Ok(mut registry) => {
                if let Err(code) = registry.register(link.clone(), delivery_hash.clone()) {
                    return encode_stream_open_response(false, Some(code));
                }
            }
            Err(_) => return encode_stream_open_response(false, Some("internal_error")),
        }

        let cleanup_registry = Arc::clone(&stream_registry);
        link.set_link_closed_callback(Some(Arc::new(move |closed_link: LinkHandle| {
            if let Ok(mut registry) = cleanup_registry.lock() {
                registry.remove(closed_link.link_id().as_slice());
            }
        })));

        log(
            format!(
                "[rfed] propagation.stream/open linked delivery={} link={}",
                hexrep(&delivery_hash, false),
                hexrep(&link.link_id(), false),
            ),
            LOG_NOTICE,
            false,
            false,
        );

        encode_stream_open_response(true, None)
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.channel_stream_dest.register_request_handler(
        CHANNEL_STREAM_OPEN_PATH.to_string(),
        Some(channel_stream_open),
        ALLOW_ALL,
        None,
        false,
    )?;
    guard.propagation_stream_dest.register_request_handler(
        PROPAGATION_STREAM_OPEN_PATH.to_string(),
        Some(propagation_stream_open),
        ALLOW_ALL,
        None,
        false,
    )?;
    Transport::register_destination(guard.channel_stream_dest.clone());
    Transport::register_destination(guard.propagation_stream_dest.clone());
    Ok(())
}

// ── rfed.distro ──────────────────────────────────────────────────────────────

fn wire_distro_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    /// Unified distro registration handler (register or unregister).
    ///
    /// Payload (mirrors channel subscribe format):
    ///   msgpack [ bin(64) device_pubkey, bin(64) distro_pubkey, bin(64) sig(device_pubkey) ]
    ///
    /// verify_signed_payload extracts (device_pubkey, distro_identity_hash, distro_pubkey)
    /// and validates sig(device_pubkey) with distro_pubkey, proving the caller holds
    /// the distro private key.
    fn handle_distro_registration(
        node: &Arc<Mutex<FedNode>>,
        data: &[u8],
        register: bool,
    ) -> Result<bool, String> {
        let (device_pubkey, _distro_identity_hash, distro_pubkey) = verify_signed_payload(data)
            .map_err(|e| format!("bad signature: {e}"))?;

        if device_pubkey.len() != 64 {
            return Err(format!("device_pubkey len {} != 64", device_pubkey.len()));
        }
        if distro_pubkey.len() != 64 {
            return Err(format!("distro_pubkey len {} != 64", distro_pubkey.len()));
        }

        // Derive distro identity to compute its lxmf.delivery hash.
        let distro_identity = Identity::from_public_key(&distro_pubkey)
            .map_err(|e| format!("distro pubkey invalid: {e}"))?;

        // Derive distro's lxmf.delivery hash (the routing key for fanout).
        let distro_lxmf_hash = Destination::new_outbound(
            Some(distro_identity),
            DestinationType::Single,
            "lxmf".to_string(),
            vec!["delivery".to_string()],
        )
        .map(|d| d.hash)
        .map_err(|e| format!("distro lxmf.delivery hash: {e}"))?;

        // Derive device's identity and lxmf.delivery hash.
        let device_identity = Identity::from_public_key(&device_pubkey)
            .map_err(|e| format!("device pubkey invalid: {e}"))?;
        let device_lxmf_hash = Destination::new_outbound(
            Some(device_identity),
            DestinationType::Single,
            "lxmf".to_string(),
            vec!["delivery".to_string()],
        )
        .map(|d| d.hash)
        .map_err(|e| format!("device lxmf.delivery hash: {e}"))?;

        let guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
        if let Ok(mut table) = guard.distro_table.lock() {
            if register {
                table.register(distro_lxmf_hash.clone(), device_lxmf_hash.clone(), device_pubkey);
                log(
                    format!(
                        "[distro] registered device {} for distro {}",
                        hexrep(&device_lxmf_hash, false),
                        hexrep(&distro_lxmf_hash, false),
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
            } else {
                table.unregister(&distro_lxmf_hash, &device_lxmf_hash);
                // Once the last device is gone there is nothing to fan out to,
                // so stop advertising a route to this node for the distro.
                if !table.is_distro(&distro_lxmf_hash) {
                    if let Ok(mut announces) = guard.distro_announces.lock() {
                        announces.remove(&distro_lxmf_hash);
                    }
                }
                log(
                    format!(
                        "[distro] unregistered device {} from distro {}",
                        hexrep(&device_lxmf_hash, false),
                        hexrep(&distro_lxmf_hash, false),
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
            }
        }

        Ok(true)
    }

    // ── REGISTER ──────────────────────────────────────────────────────
    let reg_node = Arc::clone(node);
    let register_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                      _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        match handle_distro_registration(&reg_node, data, true) {
            Ok(ok) => rmp_serde::to_vec(&ok).unwrap_or_default(),
            Err(e) => {
                log(format!("[rfed] distro/register: {e}"), LOG_WARNING, false, false);
                rmp_serde::to_vec(&false).unwrap_or_default()
            }
        }
    });

    // ── UNREGISTER ────────────────────────────────────────────────────
    let unreg_node = Arc::clone(node);
    let unregister_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                        _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        match handle_distro_registration(&unreg_node, data, false) {
            Ok(ok) => rmp_serde::to_vec(&ok).unwrap_or_default(),
            Err(e) => {
                log(format!("[rfed] distro/unregister: {e}"), LOG_WARNING, false, false);
                rmp_serde::to_vec(&false).unwrap_or_default()
            }
        }
    });

    // ── LIST ──────────────────────────────────────────────────────────
    // Payload: msgpack [ bin(16) distro_identity_hash, bin(64) distro_pubkey,
    //                      bin(64) sig(distro_identity_hash) ]
    let list_node = Arc::clone(node);
    let list_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                  _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let (value_bytes, _distro_identity_hash, distro_pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] distro/list: {e}"), LOG_WARNING, false, false);
                return rmp_serde::to_vec(&Vec::<Vec<u8>>::new()).unwrap_or_default();
            }
        };

        // value_bytes should be the distro_identity_hash (16 bytes)
        let _ = value_bytes;

        let distro_identity = match Identity::from_public_key(&distro_pubkey) {
            Ok(id) => id,
            Err(_) => return rmp_serde::to_vec(&Vec::<Vec<u8>>::new()).unwrap_or_default(),
        };

        let distro_lxmf_hash = match Destination::new_outbound(
            Some(distro_identity),
            DestinationType::Single,
            "lxmf".to_string(),
            vec!["delivery".to_string()],
        ) {
            Ok(d) => d.hash,
            Err(_) => return rmp_serde::to_vec(&Vec::<Vec<u8>>::new()).unwrap_or_default(),
        };

        let guard = match list_node.lock() {
            Ok(g) => g,
            Err(_) => return rmp_serde::to_vec(&Vec::<Vec<u8>>::new()).unwrap_or_default(),
        };

        let devices: Vec<Vec<u8>> = match guard.distro_table.lock() {
            Ok(table) => table
                .get_devices(&distro_lxmf_hash)
                .iter()
                .map(|e| e.device_lxmf_hash.clone())
                .collect(),
            Err(_) => Vec::new(),
        };

        rmp_serde::to_vec(&devices).unwrap_or_default()
    });

    // ── PULL (also on distro.register for link reuse) ──────────────
    // Clients that already have a link to distro.register can PULL
    // deferred blobs without establishing a separate link to rfed.delivery.
    // This avoids rmap.world dropping rapid successive link requests.
    let pull_distro_node = Arc::clone(node);
    let pull_distro_cb = Arc::new(move |_path: &str, _data: &[u8], _req_id: &[u8],
                                        caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let subscriber_hash = match caller.and_then(|id| id.hash.clone()) {
            Some(h) => h,
            None => return Vec::new(),
        };
        if let Ok(guard) = pull_distro_node.lock() {
            let page_size = guard.config
                .policy_for(&subscriber_hash)
                .deferred_pull_batch_limit
                .unwrap_or(DEFAULT_PULL_PAGE_SIZE);
            if let Ok(mut deferred) = guard.deferred_queue.lock() {
                let pending = deferred.drain_batch(&subscriber_hash, page_size);
                let more_pending = deferred.has_pending(&subscriber_hash);
                return encode_pull_response(pending, more_pending);
            }
        }
        Vec::new()
    });

    // ── ANNOUNCE (pre-signed, replayed on the distro's behalf) ─────────
    // Payload: msgpack [ bin value, bin(64) distro_pubkey, bin(64) sig(value) ]
    // where value = flags(1) | announce_data, flags bit 0 = ratchet present.
    //
    // RFed only ever holds the distro *public* key, so it cannot mint this
    // announce itself. The device that holds the private key signs it and this
    // node rebroadcasts it verbatim — the same thing a transport node does when
    // it answers a path request out of its announce cache.
    let announce_node = Arc::clone(node);
    let announce_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                      _caller: Option<&Identity>, _link: Option<&LinkHandle>, _timeout: f64| -> Vec<u8> {
        let fail = || rmp_serde::to_vec(&false).unwrap_or_default();

        let (value, _distro_identity_hash, distro_pubkey) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] distro/announce: {e}"), LOG_WARNING, false, false);
                return fail();
            }
        };
        let (ratchet, announce_data) = match distro::parse_distro_announce_payload(&value) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] distro/announce: {e}"), LOG_WARNING, false, false);
                return fail();
            }
        };

        let distro_lxmf_hash =
            match distro::verify_distro_announce(&announce_data, ratchet, &distro_pubkey) {
                Ok(h) => h,
                Err(e) => {
                    log(format!("[rfed] distro/announce rejected: {e}"), LOG_WARNING, false, false);
                    return fail();
                }
            };

        // Store under the lock, then release it before touching the network —
        // see the deadlock note on `distro_fanout`.
        let (distro_table, announce_store) = {
            let guard = match announce_node.lock() {
                Ok(g) => g,
                Err(_) => return fail(),
            };
            (
                Arc::clone(&guard.distro_table),
                Arc::clone(&guard.distro_announces),
            )
        };

        // Only advertise a route we can actually serve: without a registered
        // device there is nothing to fan out to.
        let has_device = distro_table
            .lock()
            .map(|t| t.is_distro(&distro_lxmf_hash))
            .unwrap_or(false);
        if !has_device {
            log(
                format!(
                    "[rfed] distro/announce refused for {} — no device registered",
                    hexrep(&distro_lxmf_hash, false)
                ),
                LOG_WARNING, false, false,
            );
            return fail();
        }

        let stored = match announce_store.lock() {
            Ok(mut store) => {
                store.put(distro_lxmf_hash.clone(), announce_data, ratchet);
                store.get(&distro_lxmf_hash).cloned()
            }
            Err(_) => None,
        };

        if let Some(announce) = stored {
            log(
                format!(
                    "[distro] stored pre-signed announce for {} (ratchet={})",
                    hexrep(&distro_lxmf_hash, false), ratchet
                ),
                LOG_NOTICE, false, false,
            );
            if let Err(e) = distro::replay_distro_announce(&announce) {
                log(format!("[distro] announce replay failed: {e}"), LOG_WARNING, false, false);
            }
        }

        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    // ── Request paths ─────────────────────────────────────────────────
    const DISTRO_REGISTER_PATH: &str = "/rfed/distro/register";
    const DISTRO_UNREGISTER_PATH: &str = "/rfed/distro/unregister";
    const DISTRO_LIST_PATH: &str = "/rfed/distro/list";
    const DISTRO_ANNOUNCE_PATH: &str = "/rfed/distro/announce";

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.distro_register_dest.register_request_handler(
        DISTRO_REGISTER_PATH.to_string(), Some(register_cb), ALLOW_ALL, None, false,
    )?;
    // Hosted on distro.register so a client that has already established a link
    // for registration can submit its announce over the same link.
    guard.distro_register_dest.register_request_handler(
        DISTRO_ANNOUNCE_PATH.to_string(), Some(announce_cb), ALLOW_ALL, None, false,
    )?;
    guard.distro_register_dest.register_request_handler(
        PULL_PATH.to_string(), Some(pull_distro_cb), ALLOW_ALL, None, false,
    )?;
    guard.distro_unregister_dest.register_request_handler(
        DISTRO_UNREGISTER_PATH.to_string(), Some(unregister_cb), ALLOW_ALL, None, false,
    )?;
    guard.distro_list_dest.register_request_handler(
        DISTRO_LIST_PATH.to_string(), Some(list_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.distro_register_dest.clone());
    Transport::register_destination(guard.distro_unregister_dest.clone());
    Transport::register_destination(guard.distro_list_dest.clone());
    Ok(())
}

#[cfg(test)]
mod hash_tests {
    //! Pin the on-the-wire destination hashes for RFed's stable destination aspects.
    //!
    //! These hashes are part of the protocol: every client computes them from
    //! the server identity hash to pick the right inbox. If `Destination::hash`,
    //! `APP_NAME`, or any aspect string ever changes, this test must fail loudly
    //! before a new build ships.
    //!
    //! The expected values were independently derived from the canonical formula:
    //!     name_hash = sha256("rfed.<aspect>")[..10]
    //!     dest_hash = sha256(name_hash || identity_hash)[..16]
    //! using identity hash `c287b844b2b6f8d6013b0a962eb2107b`.
    //!
    //! The test also guards against accidental collision with the well-known
    //! `rnstransport.path.request` control hash, which is what tripped us up
    //! during a long debugging session.

    use super::APP_NAME;
    use reticulum_rust::destination::Destination;

    /// Fixed identity hash used for hash derivation in this test.
    /// (Truncated 128-bit identity hash — same shape Reticulum uses everywhere.)
    const TEST_IDENTITY_HASH: [u8; 16] = [
        0xc2, 0x87, 0xb8, 0x44, 0xb2, 0xb6, 0xf8, 0xd6,
        0x01, 0x3b, 0x0a, 0x96, 0x2e, 0xb2, 0x10, 0x7b,
    ];

    /// Hash of the network-wide `rnstransport.path.request` control destination.
    /// The rfed aspects MUST NOT collide with this.
    const RNS_PATH_REQUEST_HASH_HEX: &str = "6b9f66014d9853faab220fba47d02761";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn dest_hash(aspect: &str) -> Vec<u8> {
        Destination::hash(Some(&TEST_IDENTITY_HASH), APP_NAME, &[aspect])
    }

    fn dest_hash_multi(aspects: &[&str]) -> Vec<u8> {
        Destination::hash(Some(&TEST_IDENTITY_HASH), APP_NAME, aspects)
    }

    #[test]
    fn app_name_is_rfed() {
        assert_eq!(APP_NAME, "rfed", "rfed APP_NAME constant must remain \"rfed\"");
    }

    #[test]
    fn rfed_node_hash_is_pinned() {
        assert_eq!(hex(&dest_hash("node")), "0ae25bc66f4cd593dcf7028c50b5a06c");
    }

    #[test]
    fn rfed_delivery_hash_is_pinned() {
        assert_eq!(hex(&dest_hash("delivery")), "bc675d73690974e490e261ec19b4c5d7");
    }

    #[test]
    fn rfed_channel_hash_is_pinned() {
        assert_eq!(hex(&dest_hash("channel")), "b95521001a9c9af5bc0e33904bca56fb");
    }

    #[test]
    fn rfed_notify_hash_is_pinned() {
        assert_eq!(hex(&dest_hash("notify")), "9233db1eefe3c75832ead85956111fbe");
    }

    #[test]
    fn rfed_hashes_do_not_collide_with_rns_path_request() {
        for aspect in ["node", "delivery", "channel", "notify"] {
            let h = hex(&dest_hash(aspect));
            assert_ne!(
                h, RNS_PATH_REQUEST_HASH_HEX,
                "rfed.{aspect} hash must not collide with rnstransport.path.request"
            );
        }
    }

    #[test]
    fn rfed_hashes_are_pairwise_distinct() {
        let aspects = ["node", "delivery", "channel", "notify"];
        for i in 0..aspects.len() {
            for j in (i + 1)..aspects.len() {
                assert_ne!(
                    dest_hash(aspects[i]),
                    dest_hash(aspects[j]),
                    "rfed.{} and rfed.{} must hash to distinct destinations",
                    aspects[i], aspects[j],
                );
            }
        }
    }

    // ── New split aspects (REFACTOR.md 2026-05-17) ────────────────────────
    //
    // Pinned wire hashes for the six split rfed aspects. Derived from the
    // canonical formula using `TEST_IDENTITY_HASH`:
    //     name_hash = sha256("rfed.<a>.<b>")[..10]
    //     dest_hash = sha256(name_hash || identity_hash)[..16]
    // If any of these tests fail, an aspect string was renamed and every
    // client (Python, iOS, Android) must be updated in lock-step.

    #[test]
    fn rfed_channel_subscribe_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["channel", "subscribe"])),
            "459193a74f78e63da3d9539a616c827e",
        );
    }

    #[test]
    fn rfed_channel_unsubscribe_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["channel", "unsubscribe"])),
            "c461e8be136af87fc15350674c689ddc",
        );
    }

    #[test]
    fn rfed_channel_publish_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["channel", "publish"])),
            "d01e4e99d4c386bc35c96af49020495e",
        );
    }

    #[test]
    fn rfed_channel_pull_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["channel", "pull"])),
            "a53c83985f076e6c2f00d0244e83b949",
        );
    }

    #[test]
    fn rfed_channel_stream_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["channel", "stream"])),
            "4b8ea0df6f54a28914d68bf5ee3c54a9",
        );
    }

    #[test]
    fn rfed_propagation_stream_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["propagation", "stream"])),
            "1c95744608edb6ee17aa3220d93a8ffb",
        );
    }

    #[test]
    fn rfed_notify_register_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["notify", "register"])),
            "71f8f6c9da1502ddc483f456bdce2e09",
        );
    }

    #[test]
    fn rfed_notify_unregister_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["notify", "unregister"])),
            "5874773fa010e7fc02bd93d106ea4668",
        );
    }

    // ── Distro aspects ───────────────────────────────────────────────

    #[test]
    fn rfed_distro_register_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["distro", "register"])),
            "6ed6295b6cf0fa6d8762643fdae065f3",
        );
    }

    #[test]
    fn rfed_distro_unregister_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["distro", "unregister"])),
            "cae11f874f5f5527fdd4a3938d6ea5f0",
        );
    }

    #[test]
    fn rfed_distro_list_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash_multi(&["distro", "list"])),
            "fedb1d56c01ef1be44e3c4dd5ccbee18",
        );
    }

    #[test]
    fn rfed_split_aspects_distinct_from_legacy() {
        // Each new two-aspect destination must hash differently from the
        // legacy single-aspect parent it replaces.
        assert_ne!(dest_hash_multi(&["channel", "subscribe"]),   dest_hash("channel"));
        assert_ne!(dest_hash_multi(&["channel", "unsubscribe"]), dest_hash("channel"));
        assert_ne!(dest_hash_multi(&["channel", "publish"]),     dest_hash("channel"));
        assert_ne!(dest_hash_multi(&["channel", "pull"]),        dest_hash("channel"));
        assert_ne!(dest_hash_multi(&["channel", "stream"]),      dest_hash("channel"));
        assert_ne!(dest_hash_multi(&["notify",  "register"]),    dest_hash("notify"));
        assert_ne!(dest_hash_multi(&["notify",  "unregister"]),  dest_hash("notify"));
        assert_ne!(dest_hash_multi(&["distro",  "register"]),    dest_hash("notify"));
        assert_ne!(dest_hash_multi(&["distro",  "unregister"]),  dest_hash("notify"));
        assert_ne!(dest_hash_multi(&["distro",  "list"]),        dest_hash("notify"));
        for legacy in ["node", "delivery", "channel", "notify"] {
            assert_ne!(
                dest_hash_multi(&["propagation", "stream"]),
                dest_hash(legacy),
                "rfed.propagation.stream must not collide with rfed.{legacy}",
            );
        }
    }

    #[test]
    fn rfed_split_aspects_pairwise_distinct() {
        let split: &[&[&str]] = &[
            &["channel", "subscribe"],
            &["channel", "unsubscribe"],
            &["channel", "publish"],
            &["channel", "pull"],
            &["channel", "stream"],
            &["propagation", "stream"],
            &["notify",  "register"],
            &["notify",  "unregister"],
            &["distro",  "register"],
            &["distro",  "unregister"],
            &["distro",  "list"],
        ];
        for i in 0..split.len() {
            for j in (i + 1)..split.len() {
                assert_ne!(
                    dest_hash_multi(split[i]),
                    dest_hash_multi(split[j]),
                    "{:?} and {:?} must hash to distinct destinations",
                    split[i], split[j],
                );
            }
        }
    }

    #[test]
    fn rfed_split_aspects_do_not_collide_with_rns_path_request() {
        let split: &[&[&str]] = &[
            &["channel", "subscribe"],
            &["channel", "unsubscribe"],
            &["channel", "publish"],
            &["channel", "pull"],
            &["channel", "stream"],
            &["propagation", "stream"],
            &["notify",  "register"],
            &["notify",  "unregister"],
            &["distro",  "register"],
            &["distro",  "unregister"],
            &["distro",  "list"],
        ];
        for aspects in split {
            assert_ne!(
                hex(&dest_hash_multi(aspects)),
                RNS_PATH_REQUEST_HASH_HEX,
                "rfed.{} must not collide with rnstransport.path.request",
                aspects.join("."),
            );
        }
    }
}

#[cfg(test)]
mod stream_config_tests {
    use super::decode_channel_stream_filters;

    fn encode_filter_list(filters: &[&[u8]]) -> Vec<u8> {
        let value = rmpv::Value::Array(
            filters
                .iter()
                .map(|hash| rmpv::Value::Binary(hash.to_vec()))
                .collect(),
        );
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value).expect("encode stream filter list");
        buf
    }

    #[test]
    fn channel_stream_filters_accept_legacy_single_hash() {
        let hash = vec![0x11; 16];
        let decoded = decode_channel_stream_filters(&hash).expect("decode legacy single hash");
        assert_eq!(decoded, vec![hash]);
    }

    #[test]
    fn channel_stream_filters_accept_config_array_and_dedup() {
        let first = vec![0x11; 16];
        let second = vec![0x22; 16];
        let payload = encode_filter_list(&[&first, &second, &first]);
        let decoded = decode_channel_stream_filters(&payload).expect("decode config array");
        assert_eq!(decoded, vec![first, second]);
    }

    #[test]
    fn channel_stream_filters_accept_empty_config_array() {
        let payload = encode_filter_list(&[]);
        let decoded = decode_channel_stream_filters(&payload).expect("decode empty config array");
        assert!(decoded.is_empty(), "empty config array must produce no live filters");
    }

    #[test]
    fn channel_stream_filters_reject_non_16_byte_entries() {
        let bad = vec![0x33; 15];
        let payload = encode_filter_list(&[&bad]);
        let err = decode_channel_stream_filters(&payload).expect_err("reject short entry");
        assert!(err.contains("!= 16"), "unexpected error: {err}");
    }
}

/// The lock-scope invariant for fan-out, enforced rather than documented.
///
/// This is the check that was missing twice. On 2026-08-09 `/rfed/distro/register`
/// callbacks blocked forever because `distro_table` was held across a distro
/// fan-out; the fix snapshotted that one table and wrote `NEVER REMOVE` above it.
/// On 2026-08-17 the identical wedge came back from the channel side — the
/// publish path held the whole `FedNode` mutex plus `subscription_table` and
/// `hook_registry` across `fanout_blob`, so `/rfed/subscribe` returned nothing
/// for 26 seconds and the `rfed.distro.register` link never proved. Two
/// instances of one class, and nothing in the repo could tell the difference
/// between "fixed" and "fixed here only".
#[cfg(test)]
mod fanout_lock_scope_tests {
    fn destinations_source() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/destinations.rs"
        ))
        .expect("read destinations.rs")
    }

    fn fanout_source() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/fanout.rs"))
            .expect("read fanout.rs")
    }

    /// `FanoutPlan` must own its data. A lifetime parameter here would mean it
    /// borrows out of the `MutexGuard` again, which is precisely the bug.
    #[test]
    fn fanout_plan_owns_its_data() {
        fn assert_detached<T: Send + 'static>() {}
        assert_detached::<crate::fanout::FanoutPlan>();
    }

    /// `fanout_blob` must take a subscriber snapshot. Taking `&SubscriptionTable`
    /// forces every caller to hold the table across the delivery loop.
    #[test]
    fn fanout_blob_takes_a_snapshot_not_the_table() {
        let source = fanout_source();
        let sig_start = source
            .find("pub fn fanout_blob(")
            .expect("fanout_blob present");
        let sig_end = sig_start
            + source[sig_start..]
                .find("\n) -> ")
                .expect("fanout_blob signature closes");
        let signature = &source[sig_start..sig_end];
        assert!(
            signature.contains("subscribers: &[(Vec<u8>, Option<Vec<u8>>)]"),
            "fanout_blob must take a snapshot of subscribers; taking the \
             SubscriptionTable makes callers hold it across unbounded network work"
        );
        assert!(
            !signature.contains("SubscriptionTable"),
            "fanout_blob must not take the SubscriptionTable — see FanoutPlan"
        );
    }

    /// Delivery must go through `FanoutPlan::run`, which needs no `FedNode`
    /// guard, and never through `fanout_blob` directly from a lock scope.
    #[test]
    fn destinations_deliver_only_through_the_plan() {
        let source = destinations_source();
        // This module names the call in its own assertions, so only look at the
        // code above it.
        let tests_start = source
            .find("mod fanout_lock_scope_tests")
            .expect("this module is in this file");
        assert!(
            !source[..tests_start].contains("fanout::fanout_blob("),
            "destinations.rs must not call fanout_blob directly — build a \
             FanoutPlan under the lock, drop the guard, then plan.run()"
        );
    }

    /// The publish path's guard must not outlive the statement that builds the
    /// plan. Asserting the exact shape is deliberate: if someone restructures
    /// this to hold the guard across `plan.run`, the shape disappears and this
    /// test says why.
    #[test]
    fn publish_path_drops_the_guard_before_delivering() {
        let source = destinations_source();
        let start = source
            .find("let ingest_send:")
            .expect("channel SEND ingest closure present");
        let end = start
            + source[start..]
                .find("let packet_cb:")
                .expect("packet_cb follows the ingest closure");
        let fragment = &source[start..end];

        assert!(
            fragment.contains("Ok(guard) => Some(guard.plan_channel_fanout(channel_hash)),"),
            "the channel SEND path must snapshot the fan-out inside a `let` \
             statement so the FedNode guard is dropped at its end"
        );
        assert!(
            fragment.contains("plan.run(channel_hash, inner_blob);"),
            "the channel SEND path must deliver via FanoutPlan::run"
        );
        // Anything reached through `guard.` after the plan exists is work done
        // while the mutex is still held.
        let plan_built = fragment
            .find("guard.plan_channel_fanout(channel_hash)")
            .expect("plan is built");
        assert!(
            !fragment[plan_built + 1..].contains("guard."),
            "nothing may touch the FedNode guard after the fan-out plan is \
             built — that is the wedge from 2026-08-17"
        );
    }

    /// The deferred-flush announce handler sends one packet per queued blob.
    /// It must take its collaborators and let the guard go first.
    #[test]
    fn deferred_flush_drops_the_guard_before_sending() {
        let source = destinations_source();
        let start = source
            .find("aspect_filter: Some(format!(\"{APP_NAME}.delivery\")),")
            .expect("rfed.delivery announce handler present");
        let end = start
            + source[start..]
                .find("fn wire_node_destination(")
                .expect("wire_node_destination follows the delivery handler");
        let fragment = &source[start..end];

        assert!(
            fragment.contains("let (deferred_queue, hook_registry, limit) = match arc.lock()"),
            "the deferred flush must snapshot its collaborators and release the \
             FedNode mutex before sending"
        );
        assert!(
            !fragment.contains("guard.deferred_queue.lock()"),
            "the deferred flush must not reach through a live FedNode guard"
        );
    }
}

#[cfg(test)]
mod app_links_tests {
    #[test]
    fn one_shot_rfed_node_flows_use_ephemeral_app_links() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/destinations.rs"
        ))
        .expect("read destinations.rs");

        let tick_start = source
            .find("pub fn tick_sync(&mut self)")
            .expect("tick_sync present");
        let push_start = source
            .find("fn push_subscriptions_to_backup(")
            .expect("push_subscriptions_to_backup present");
        let backup_delivery_start = source[push_start..]
            .find("fn backup_delivery_tick(")
            .map(|offset| push_start + offset)
            .expect("backup_delivery_tick present");

        let tick_fragment = &source[tick_start..push_start];
        assert!(
            tick_fragment.contains("AppLinks::open(&peer_hash, APP_NAME, &[\"node\"]);"),
            "tick_sync must route rfed.node readiness through AppLinks::open()"
        );
        assert!(
            tick_fragment.contains(
                "AppLinks::status(&peer_hash) != rns_app_links::APP_LINK_ACTIVE"
            ),
            "tick_sync must wait for the EphemeralLink readiness signal before opening a one-shot sync link"
        );

        let push_fragment = &source[push_start..backup_delivery_start];
        assert!(
            push_fragment.contains("AppLinks::open(&backup_hash, APP_NAME, &[\"node\"]);"),
            "backup pushes must route rfed.node readiness through AppLinks::open()"
        );
        assert!(
            push_fragment.contains(
                "AppLinks::status(&backup_hash) != rns_app_links::APP_LINK_ACTIVE"
            ),
            "backup pushes must wait for the EphemeralLink readiness signal before opening a one-shot backup link"
        );
    }
}

#[cfg(test)]
mod destination_wiring_tests {
    #[test]
    fn channel_pull_and_legacy_delivery_pull_remain_wired() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/destinations.rs"
        ))
        .expect("read destinations.rs");

        let wire_channel_start = source
            .find("fn wire_channel_destination(")
            .expect("wire_channel_destination present");
        let wire_delivery_start = source
            .find("fn wire_delivery_destination(")
            .expect("wire_delivery_destination present");
        let wire_notify_start = source
            .find("fn wire_notify_destination(")
            .expect("wire_notify_destination present");

        let channel_fragment = &source[wire_channel_start..wire_delivery_start];
        let delivery_fragment = &source[wire_delivery_start..wire_notify_start];

        assert!(
            channel_fragment.contains("guard.channel_pull_dest.register_request_handler("),
            "rfed.channel.pull must keep a request handler wired"
        );
        assert!(
            channel_fragment.contains("PULL_PATH.to_string(), Some(channel_pull_cb)"),
            "rfed.channel.pull must serve /rfed/pull via the new handler"
        );
        assert!(
            delivery_fragment.contains("guard.delivery_dest.register_request_handler("),
            "legacy rfed.delivery pull must remain wired for compatibility"
        );
        assert!(
            delivery_fragment.contains("PULL_PATH.to_string(), Some(pull_cb)"),
            "legacy rfed.delivery must continue serving /rfed/pull"
        );
    }

    #[test]
    fn channel_publish_accepts_oversized_sends_as_resources() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/destinations.rs"
        ))
        .expect("read destinations.rs");

        let wire_channel_start = source
            .find("fn wire_channel_destination(")
            .expect("wire_channel_destination present");
        let wire_delivery_start = source
            .find("fn wire_delivery_destination(")
            .expect("wire_delivery_destination present");
        let channel_fragment = &source[wire_channel_start..wire_delivery_start];

        assert!(
            channel_fragment
                .contains("link.set_resource_strategy(reticulum_rust::link::ACCEPT_APP)"),
            "channel links must accept resources; a link defaults to ACCEPT_NONE, \
             which silently drops any publish larger than the 431-byte link MDU"
        );
        assert!(
            channel_fragment.contains("link.set_resource_callbacks("),
            "ACCEPT_APP is inert without a resource callback (RNS/Link.py:1106)"
        );
        for dest in ["channel_dest", "channel_publish_dest"] {
            assert!(
                channel_fragment.contains(&format!(
                    "guard.{dest}.set_link_established_callback(Some(channel_link_established"
                )),
                "rfed.{dest} must arm resource acceptance on every inbound link"
            );
        }
        assert!(
            channel_fragment.contains("let ingest = Arc::clone(&resource_ingest);"),
            "the resource path must reuse the same SEND ingest as the packet path, \
             so stamp validation and fanout cannot drift between the two"
        );
    }
}

#[cfg(test)]
mod wire_format_tests {
    //! Wire-format and stamp-cost regression tests.
    //!
    //! These guard the bug fixes that produced the current PULL/SUBSCRIBE
    //! contract:
    //!
    //!  * PULL response is a 2-element fixarray
    //!        `[ [[bin(16) channel_hash, bin(*) blob], ...], Bool more_pending ]`
    //!    Earlier shipping code returned a flat array of pairs with no
    //!    continuation flag, so the iOS client could never tell whether to
    //!    offer "Load earlier messages".  The envelope MUST stay 2 elements
    //!    and the trailing element MUST stay a bool.
    //!  * SUBSCRIBE response is `[Bool ok, Int|Nil stamp_cost]`.  When the
    //!    operator disables PoW (`stamp_cost == None`) the second slot MUST
    //!    serialise as msgpack Nil, NOT as `0` — a 0 would tell clients to
    //!    compute a 0-cost stamp instead of skipping the stamp tail entirely.
    //!  * `STAMP_EXPAND_ROUNDS` is wedged at 16 across rfed + retichat-ffi +
    //!    iOS.  Bumping it silently invalidates every client's cached
    //!    `stampCost`.  This test fails loud if the constant ever drifts.
    //!  * Stamp validation: a stamp generated against a given cost MUST be
    //!    accepted at that cost, accepted at `cost - flexibility`, and
    //!    rejected against the wrong workblock.
    //!  * `DEFAULT_PULL_PAGE_SIZE` matches the 25-row chat-history page so
    //!    the UX stays consistent with DM "Load earlier messages".

    use super::{DEFAULT_PULL_PAGE_SIZE, STAMP_EXPAND_ROUNDS};
    use reticulum_rust::identity;
    use reticulum_rust::lxstamper::LXStamper;

    /// Re-encode a PULL response with the SAME shape `pull_cb` produces.
    /// If the production encoder ever drifts, update this helper AND
    /// `decode_pull_response` in lockstep.
    fn encode_pull_response(pairs: &[(Vec<u8>, Vec<u8>)], more_pending: bool) -> Vec<u8> {
        let pairs_val: Vec<rmpv::Value> = pairs
            .iter()
            .map(|(ch, blob)| rmpv::Value::Array(vec![
                rmpv::Value::Binary(ch.clone()),
                rmpv::Value::Binary(blob.clone()),
            ]))
            .collect();
        let envelope = rmpv::Value::Array(vec![
            rmpv::Value::Array(pairs_val),
            rmpv::Value::Boolean(more_pending),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &envelope).unwrap();
        buf
    }

    fn decode_pull_response(buf: &[u8]) -> Option<(Vec<(Vec<u8>, Vec<u8>)>, bool)> {
        let mut cursor = std::io::Cursor::new(buf);
        let val = rmpv::decode::read_value(&mut cursor).ok()?;
        let outer = val.as_array()?;
        if outer.len() != 2 {
            return None;
        }
        let pairs_arr = outer[0].as_array()?;
        let more_pending = outer[1].as_bool()?;
        let mut pairs = Vec::with_capacity(pairs_arr.len());
        for entry in pairs_arr {
            let inner = entry.as_array()?;
            if inner.len() != 2 {
                return None;
            }
            let ch = inner[0].as_slice()?.to_vec();
            let blob = inner[1].as_slice()?.to_vec();
            pairs.push((ch, blob));
        }
        Some((pairs, more_pending))
    }

    // ── PULL envelope ────────────────────────────────────────────────

    #[test]
    fn pull_response_envelope_roundtrip_with_pairs() {
        let pairs = vec![
            (vec![0x11u8; 16], b"hello".to_vec()),
            (vec![0x22u8; 16], b"world".to_vec()),
        ];
        let buf = encode_pull_response(&pairs, true);
        let (decoded, more) = decode_pull_response(&buf).expect("envelope must decode");
        assert!(more);
        assert_eq!(decoded, pairs);
    }

    #[test]
    fn pull_response_envelope_roundtrip_empty_no_more() {
        let buf = encode_pull_response(&[], false);
        let (decoded, more) = decode_pull_response(&buf).expect("envelope must decode");
        assert_eq!(decoded.len(), 0);
        assert!(!more, "empty queue MUST report more_pending=false");
    }

    #[test]
    fn pull_response_envelope_is_a_two_element_array() {
        // Outer element MUST be a 2-array.  If a future change adds a third
        // element (e.g. a server timestamp) without bumping a wire version,
        // existing iOS clients will silently misparse.
        let buf = encode_pull_response(&[], false);
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let val = rmpv::decode::read_value(&mut cursor).unwrap();
        let outer = val.as_array().expect("outer must be array");
        assert_eq!(outer.len(), 2, "PULL envelope MUST be a 2-element array");
        assert!(outer[0].as_array().is_some(), "first element MUST be an array");
        assert!(outer[1].as_bool().is_some(), "second element MUST be a bool");
    }

    #[test]
    fn pull_response_inner_pairs_are_two_element_arrays() {
        let pairs = vec![(vec![0xABu8; 16], b"x".to_vec())];
        let buf = encode_pull_response(&pairs, false);
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let val = rmpv::decode::read_value(&mut cursor).unwrap();
        let outer = val.as_array().unwrap();
        let pair = outer[0].as_array().unwrap()[0].as_array().unwrap();
        assert_eq!(pair.len(), 2, "each (channel_hash, blob) entry MUST be a 2-array");
        assert!(pair[0].as_slice().is_some(), "channel_hash MUST be msgpack bin");
        assert!(pair[1].as_slice().is_some(), "blob MUST be msgpack bin");
    }

    // ── SUBSCRIBE response (stamp_cost retrieval contract) ───────────

    /// Re-encode the SUBSCRIBE response in the same shape `subscribe_cb`
    /// produces: `[Bool ok, Int|Nil stamp_cost]`.
    fn encode_subscribe_response(ok: bool, cost: Option<u32>) -> Vec<u8> {
        let resp = rmpv::Value::Array(vec![
            rmpv::Value::Boolean(ok),
            match cost {
                Some(c) => rmpv::Value::Integer(rmpv::Integer::from(c as i64)),
                None    => rmpv::Value::Nil,
            },
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &resp).unwrap();
        buf
    }

    #[test]
    fn subscribe_response_carries_stamp_cost_as_integer() {
        let buf = encode_subscribe_response(true, Some(16));
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let val = rmpv::decode::read_value(&mut cursor).unwrap();
        let arr = val.as_array().expect("response MUST be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_bool(), Some(true));
        assert_eq!(arr[1].as_i64(), Some(16));
    }

    #[test]
    fn subscribe_response_uses_nil_when_stamp_cost_disabled() {
        // When the operator disables PoW the second slot MUST be Nil so the
        // client knows to skip the stamp tail entirely.  Encoding 0 here
        // would be a foot-gun: clients would compute a 0-cost stamp and
        // append a useless 32-byte tail.
        let buf = encode_subscribe_response(true, None);
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let val = rmpv::decode::read_value(&mut cursor).unwrap();
        let arr = val.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr[1].is_nil(), "disabled stamp_cost MUST encode as msgpack Nil");
        assert!(arr[1].as_i64().is_none(), "Nil MUST NOT decode as integer 0");
    }

    #[test]
    fn subscribe_response_failure_uses_bool_false() {
        // When access is denied, the server returns msgpack `false`
        // (single byte 0xc2) so existing clients keep parsing it as a
        // single bool without the [ok, cost] envelope.
        let buf = rmp_serde::to_vec(&false).unwrap();
        assert_eq!(buf.as_slice(), &[0xc2u8]);
    }

    // ── Default PULL page size ───────────────────────────────────────

    #[test]
    fn default_pull_page_size_matches_chat_history_page() {
        // The 25-row default mirrors the DM "Load earlier messages" page so
        // a fresh PULL fills exactly one screen.  Changing this requires a
        // matching tweak to the iOS chat-history page size.
        assert_eq!(DEFAULT_PULL_PAGE_SIZE, 25);
    }

    // ── Stamp validation (cost is RESPECTED) ─────────────────────────

    #[test]
    fn stamp_expand_rounds_is_pinned_at_sixteen() {
        // STAMP_EXPAND_ROUNDS is part of the cross-process contract.  It
        // MUST stay 16 in rfed AND in retichat-ffi AND in the iOS client.
        // If any future change bumps it, every previously-cached client
        // stampCost is silently invalidated.
        assert_eq!(STAMP_EXPAND_ROUNDS, 16);
    }

    #[test]
    fn stamp_generated_at_cost_is_accepted_at_same_cost() {
        // Use a small cost so the test is fast.  Validity is a property
        // of the workblock + leading-zero-bits target, independent of the
        // specific cost chosen.
        let cost = 4u32;
        let channel_hash = vec![0xA5u8; 16];
        let inner_blob = b"unit-test-blob".to_vec();
        let material: Vec<u8> = channel_hash.iter().chain(inner_blob.iter()).copied().collect();
        let transient_id = identity::full_hash(&material);
        let workblock = LXStamper::stamp_workblock(&transient_id, STAMP_EXPAND_ROUNDS);
        let (stamp, _value) = LXStamper::generate_stamp(&transient_id, cost, STAMP_EXPAND_ROUNDS);
        let stamp = stamp.expect("stamp generation must succeed");
        assert_eq!(stamp.len(), LXStamper::STAMP_SIZE, "stamp MUST be STAMP_SIZE bytes");
        assert!(LXStamper::stamp_valid(&stamp, cost, &workblock));
    }

    #[test]
    fn stamp_flexibility_accepts_understrength_stamp() {
        // A stamp produced for cost=4 MUST validate at cost=2 (flexibility=2).
        let cost = 4u32;
        let flexibility = 2u32;
        let channel_hash = vec![0x5Au8; 16];
        let inner_blob = b"flexibility-blob".to_vec();
        let material: Vec<u8> = channel_hash.iter().chain(inner_blob.iter()).copied().collect();
        let transient_id = identity::full_hash(&material);
        let workblock = LXStamper::stamp_workblock(&transient_id, STAMP_EXPAND_ROUNDS);
        let stamp = LXStamper::generate_stamp(&transient_id, cost, STAMP_EXPAND_ROUNDS).0
            .expect("stamp generation must succeed");
        let min_cost = cost.saturating_sub(flexibility);
        assert!(
            LXStamper::stamp_valid(&stamp, min_cost, &workblock),
            "stamp at cost={cost} MUST validate at min_cost={min_cost}",
        );
    }

    #[test]
    fn stamp_with_wrong_workblock_is_rejected() {
        // Same stamp bytes against a DIFFERENT (channel_hash || blob) MUST fail.
        // This proves the workblock binding is what's being checked, not just
        // a leading-zero count on the stamp itself.
        let cost = 4u32;
        let mat_a: Vec<u8> = std::iter::repeat(0xAA).take(32).collect();
        let mat_b: Vec<u8> = std::iter::repeat(0xBB).take(32).collect();
        let tid_a = identity::full_hash(&mat_a);
        let tid_b = identity::full_hash(&mat_b);
        let wb_b = LXStamper::stamp_workblock(&tid_b, STAMP_EXPAND_ROUNDS);
        let stamp_a = LXStamper::generate_stamp(&tid_a, cost, STAMP_EXPAND_ROUNDS).0
            .expect("stamp generation must succeed");
        assert!(
            !LXStamper::stamp_valid(&stamp_a, cost, &wb_b),
            "stamp from material A MUST NOT validate against workblock B",
        );
    }

    #[test]
    fn stamp_undersized_buffer_is_rejected() {
        // A 31-byte buffer (one shy of STAMP_SIZE) MUST NOT be accepted as
        // a stamp — guards against accidental truncation in framing code.
        let workblock = vec![0u8; 32];
        let too_short = vec![0u8; LXStamper::STAMP_SIZE - 1];
        assert!(!LXStamper::stamp_valid(&too_short, 1, &workblock));
    }

    // ── stamp_cost=0 normalisation ────────────────────────────────────
    //
    // Bug: `stamp_cost=Some(0)` (the TOML `stamp_cost = 0` case) was
    // previously treated as "stamp present" throughout destinations.rs.
    // rfed unconditionally stripped 32 bytes (STAMP_SIZE) from every
    // incoming SEND blob tail, truncating EC ciphertext from 96→64 bytes
    // and breaking HMAC on decrypt in synced/backup nodes.
    //
    // Fix: `.filter(|c| *c > 0)` is applied at every point where
    // stamp_cost gates behaviour.  Zero MUST be treated identically to
    // None (disabled) in all five locations.
    //
    // These two tests guard that normalisation:
    //   1. The Option filter itself behaves correctly.
    //   2. The subscribe-response encoder turns the normalised None into
    //      msgpack Nil — not the integer 0 that would instruct clients to
    //      append a 32-byte stamp tail that rfed would then try to strip.

    #[test]
    fn stamp_cost_zero_normalizes_to_none() {
        // `stamp_cost = 0` in TOML arrives as Some(0).
        // After `.filter(|c| *c > 0)` it MUST become None (disabled).
        let from_config: Option<u32> = Some(0);
        let effective = from_config.filter(|c| *c > 0);
        assert!(
            effective.is_none(),
            "stamp_cost=Some(0) MUST normalise to None (disabled); \
             treating it as 'stamp present' causes STAMP_SIZE bytes to be \
             stripped from every blob, corrupting EC ciphertext"
        );

        // Non-zero cost MUST pass through unchanged.
        let nonzero: Option<u32> = Some(16);
        assert_eq!(nonzero.filter(|c| *c > 0), Some(16));

        // An absent cost (never set in TOML) MUST also stay None.
        let absent: Option<u32> = None;
        assert!(absent.filter(|c| *c > 0).is_none());
    }

    #[test]
    fn subscribe_response_stamp_cost_zero_encodes_as_nil_not_integer() {
        // When the operator writes `stamp_cost = 0` the subscribe response
        // MUST send msgpack Nil so clients skip the stamp tail entirely.
        // Sending the integer 0 would make clients compute a stamp and
        // append a useless 32-byte tail that rfed would try to strip,
        // re-triggering the blob-truncation bug on the next send.
        let from_config: Option<u32> = Some(0);
        let effective = from_config.filter(|c| *c > 0); // normalise

        // encode_subscribe_response is the same shape used by subscribe_cb
        let buf = encode_subscribe_response(true, effective);
        let mut cursor = std::io::Cursor::new(&buf[..]);
        let val = rmpv::decode::read_value(&mut cursor).unwrap();
        let arr = val.as_array().unwrap();

        assert!(
            arr[1].is_nil(),
            "stamp_cost=0 in config MUST encode as msgpack Nil in subscribe response; \
             got {:?}",
            arr[1]
        );
        assert!(
            arr[1].as_i64().is_none(),
            "stamp_cost=0 MUST NOT encode as integer 0 in subscribe response"
        );
    }
}
