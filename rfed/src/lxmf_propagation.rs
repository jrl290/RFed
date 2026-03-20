//! Passive `lxmf.propagation` observer for notify wake-up.
//!
//! # What this module is NOT
//!
//! rfed is **not** an `lxmf.propagation` node.  It does not store LXMF
//! messages, does not participate in inter-node LXMF sync (OFFER / GET),
//! and must never forward message content anywhere.
//!
//! # What this module IS
//!
//! rfed announces itself as an `lxmf.propagation` node so that senders
//! targeting offline devices route their packets here.  When a packet
//! arrives, rfed inspects only the recipient destination hash (which is
//! visible in the LXMF wire format without decryption), checks whether that
//! hash has a notify relay registered, fires a wake-up ping, and discards
//! the raw LXMF data immediately.  No content leaves rfed.
//!
//! The device wakes up, connects to its own delivery node / propgation node,
//! and pulls the message through the normal LXMF pull path.  rfed is merely
//! the alarm bell, not the mailbox.
//!
//! # Wire protocol (observed PUT path)
//!
//! 1. Sender establishes a Reticulum Link to rfed's `lxmf.propagation`
//!    destination.
//! 2. `link_established` is called; the link gets a packet callback.
//! 3. Sender sends a msgpack packet on the link:
//!    ```text
//!    [type: int, messages: [[lxmf_payload: bin], ...]]
//!    ```
//!    where each `lxmf_payload` carries an optional PN stamp appended after
//!    the LXMF data (validated by `lx_stamper::validate_pn_stamps`).
//! 4. The first `DESTINATION_LENGTH` (16) bytes of each `lxmf_payload` are
//!    the **opaque recipient destination hash** (visible in plaintext to
//!    propagation nodes for routing; not the message content).
//! 5. For each message whose destination is in the `NotifyRegistry`, rfed
//!    fires a notify wake-up.  The raw LXMF data is then discarded — never
//!    stored, never forwarded.  Messages for unknown destinations are
//!    silently ignored.
//!
//! # Announce app_data format (`lxmf.propagation` standard)
//!
//! ```text
//! msgpack array:
//!   [0]  Boolean(false)              — protocol version marker
//!   [1]  Integer(unix_timestamp)     — announce time
//!   [2]  Boolean(true)               — is active propagation node
//!   [3]  F64(transfer_limit_mb)      — per-transfer limit
//!   [4]  F64(sync_limit_mb)          — per-sync period limit
//!   [5]  [stamp_cost, flexibility, peering_cost]   — ints
//!   [6]  Map{PN_META_NAME → name}    — optional metadata
//! ```

use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lxmf_rust::lx_stamper;
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::Link;
use reticulum_rust::packet::Packet;
use reticulum_rust::{log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};
use rmpv::encode::write_value;
use rmpv::Value;

use crate::config::NodeConfig;
use crate::notify::NotifyRegistry;

// ── Constants ─────────────────────────────────────────────────────────────────

/// LXMF app name (must match the canonical LXMF constant).
const LXMF_APP: &str = "lxmf";
/// Aspect for the propagation destination.
const PROP_ASPECT: &str = "propagation";
/// Recipient hash length in the LXMF wire format (bytes).
const DESTINATION_LENGTH: usize = 16;
/// Minimum accepted propagation stamp cost (matches LXMF default).
pub const DEFAULT_STAMP_COST: u32 = 16;
/// Flexibility window: accept stamps ≥ (cost − flexibility).
pub const DEFAULT_STAMP_FLEXIBILITY: u32 = 3;

// ── Public handle ─────────────────────────────────────────────────────────────

/// Owns the `lxmf.propagation` destination and co-ordinates with the
/// notify registry.  Hold behind `Arc<Mutex<>>` and share with the link
/// established callback via a `Weak`.
pub struct LxmfPropagation {
    /// The `lxmf.propagation` RNS destination.
    pub destination: Destination,
    /// Shared notify registry — checked for every inbound LXMF message.
    registry: Arc<Mutex<NotifyRegistry>>,
    /// Node configuration snapshot (name, stamp parameters, limits).
    stamp_cost: u32,
    stamp_flexibility: u32,
    transfer_limit_mb: f64,
    sync_limit_mb: f64,
    peering_cost: u32,
    node_name: String,
    /// Weak self-reference so link callbacks can reach back here.
    self_handle: Option<Weak<Mutex<LxmfPropagation>>>,
}

impl LxmfPropagation {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create the `lxmf.propagation` destination using `identity`.
    ///
    /// Uses the propagation stamp parameters from `config.default_policy`.
    /// Returns `Err` if the RNS destination cannot be created.
    pub fn new(
        identity: Identity,
        config: &NodeConfig,
        registry: Arc<Mutex<NotifyRegistry>>,
    ) -> Result<Arc<Mutex<Self>>, String> {
        let destination = Destination::new_inbound(
            Some(identity),
            DestinationType::Single,
            LXMF_APP.to_string(),
            vec![PROP_ASPECT.to_string()],
        )?;

        let stamp_cost = config.default_policy.stamp_cost.unwrap_or(DEFAULT_STAMP_COST);
        let stamp_flexibility = config.default_policy.stamp_flexibility
            .unwrap_or(DEFAULT_STAMP_FLEXIBILITY);
        let transfer_limit_mb = config.transfer_limit_bytes
            .map(|b| b as f64 / 1_048_576.0)
            .unwrap_or(500.0);
        let sync_limit_mb = config.sync_limit_bytes
            .map(|b| b as f64 / 1_048_576.0)
            .unwrap_or(2000.0);

        let this = Arc::new(Mutex::new(LxmfPropagation {
            destination,
            registry,
            stamp_cost,
            stamp_flexibility,
            transfer_limit_mb,
            sync_limit_mb,
            peering_cost: config.peering_cost.unwrap_or(18),
            node_name: config.display_name.clone(),
            self_handle: None,
        }));

        // Store weak self-reference for use inside callbacks.
        {
            let mut guard = this.lock().map_err(|_| "LxmfPropagation lock poisoned")?;
            guard.self_handle = Some(Arc::downgrade(&this));
        }

        Ok(this)
    }

    // ── Announce ──────────────────────────────────────────────────────────────

    /// Build the standard LXMF propagation node announce app_data.
    fn build_app_data(&self) -> Vec<u8> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let stamp_costs = Value::Array(vec![
            Value::Integer((self.stamp_cost as i64).into()),
            Value::Integer((self.stamp_flexibility as i64).into()),
            Value::Integer((self.peering_cost as i64).into()),
        ]);

        let mut metadata_entries = Vec::new();
        metadata_entries.push((
            Value::Integer(0x01_i64.into()), // PN_META_NAME
            Value::Binary(self.node_name.as_bytes().to_vec()),
        ));

        let announce_data = Value::Array(vec![
            Value::Boolean(false),                        // [0] protocol marker
            Value::Integer(now.into()),                   // [1] timestamp
            Value::Boolean(true),                         // [2] active node
            Value::F64(self.transfer_limit_mb),           // [3] transfer limit
            Value::F64(self.sync_limit_mb),               // [4] sync limit
            stamp_costs,                                  // [5] stamp params
            Value::Map(metadata_entries),                 // [6] metadata
        ]);

        let mut buf = Vec::new();
        let _ = write_value(&mut buf, &announce_data);
        buf
    }

    /// Announce this node on `lxmf.propagation` (spawns a brief delay thread).
    pub fn announce(arc: &Arc<Mutex<Self>>) {
        let weak = Arc::downgrade(arc);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(20));
            if let Some(arc) = weak.upgrade() {
                if let Ok(mut guard) = arc.lock() {
                    let app_data = guard.build_app_data();
                    guard.destination.set_default_app_data(Some(app_data.clone()));
                    let _ = guard.destination.announce(Some(&app_data), false, None, None, true);
                    log(
                        "[lxmf.prop] announced propagation node",
                        LOG_NOTICE, false, false,
                    );
                }
            }
        });
    }

    // ── Link establishment ────────────────────────────────────────────────────

    /// Register the link-established callback on the propagation destination.
    ///
    /// Must be called after `new()` and before the first announce.
    pub fn wire(arc: &Arc<Mutex<Self>>) -> Result<(), String> {
        let weak = Arc::downgrade(arc);
        let mut guard = arc.lock().map_err(|_| "LxmfPropagation lock poisoned")?;

        guard.destination.set_link_established_callback(Some(Arc::new(move |link| {
            if let Some(arc) = weak.upgrade() {
                if let Ok(guard) = arc.lock() {
                    guard.link_established(link);
                }
            }
        })));

        Ok(())
    }

    fn link_established(&self, link: Arc<Mutex<Link>>) {
        log("[lxmf.prop] link established", LOG_DEBUG, false, false);

        let registry = Arc::clone(&self.registry);
        let stamp_cost = self.stamp_cost;
        let stamp_flexibility = self.stamp_flexibility;

        if let Ok(mut link_guard) = link.lock() {
            link_guard.callbacks.packet = Some(Arc::new(move |data, packet| {
                Self::on_packet(data, packet, &registry, stamp_cost, stamp_flexibility);
            }));
            // We do NOT set resource_strategy = ACCEPT_APP — large resources
            // (batch sync) are not supported in this barebones mode.
        }
    }

    // ── Packet handler ────────────────────────────────────────────────────────

    /// Called for every data packet arriving on a propagation Link.
    ///
    /// Expected format: msgpack `[type: int, messages: [[lxmf_bytes: bin], ...]]`
    fn on_packet(
        data: &[u8],
        _packet: &Packet,
        registry: &Arc<Mutex<NotifyRegistry>>,
        stamp_cost: u32,
        stamp_flexibility: u32,
    ) {
        // Parse outer msgpack array.
        let items = match rmpv::decode::read_value(&mut std::io::Cursor::new(data)) {
            Ok(Value::Array(a)) => a,
            _ => {
                log("[lxmf.prop] malformed packet (not a msgpack array)", LOG_WARNING, false, false);
                return;
            }
        };

        // items[1] is the array of raw LXMF payloads (each with appended stamp).
        let messages: Vec<Vec<u8>> = match items.get(1) {
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(|v| match v {
                    Value::Binary(b) => Some(b.clone()),
                    _ => None,
                })
                .collect(),
            _ => {
                log("[lxmf.prop] packet missing message array", LOG_DEBUG, false, false);
                return;
            }
        };

        if messages.is_empty() {
            return;
        }

        // Validate PN stamps on all messages at once.
        let min_cost = stamp_cost.saturating_sub(stamp_flexibility);
        let validated = lx_stamper::validate_pn_stamps(&messages, min_cost);

        let reg = match registry.lock() {
            Ok(r) => r,
            Err(_) => return,
        };

        let mut fired = 0usize;
        let mut rejected = 0usize;

        for (_, lxmf_data, _stamp_value, _stamp_raw) in &validated {
            if lxmf_data.len() < DESTINATION_LENGTH {
                continue;
            }
            let dest_hash = &lxmf_data[..DESTINATION_LENGTH];

            let regs = reg.get(dest_hash);
            if !regs.is_empty() {
                // Extract sender hash if present (bytes 16..32 of LXMF data).
                let sender = if lxmf_data.len() >= DESTINATION_LENGTH * 2 {
                    Some(&lxmf_data[DESTINATION_LENGTH..DESTINATION_LENGTH * 2])
                } else {
                    None
                };
                // Dispatch a wake-up ping for every registered device.
                for registration in &regs {
                    crate::notify::dispatch_notify(registration, sender, None);
                }
                log(
                    &format!(
                        "[lxmf.prop] dispatched notify for {} ({} registration(s))",
                        reticulum_rust::hexrep(dest_hash, false),
                        regs.len(),
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                fired += 1;
            } else {
                // Not registered — drop silently (this is the filter).
                rejected += 1;
            }
        }

        let total = messages.len();
        let invalid_stamps = total - validated.len();
        if invalid_stamps > 0 || rejected > 0 {
            log(
                &format!(
                    "[lxmf.prop] processed {total} msgs: {fired} notified, \
                     {rejected} unregistered, {invalid_stamps} bad-stamp"
                ),
                LOG_DEBUG,
                false,
                false,
            );
        } else if fired > 0 {
            log(
                &format!("[lxmf.prop] notified {fired}/{total} msgs"),
                LOG_DEBUG,
                false,
                false,
            );
        }
    }
}
