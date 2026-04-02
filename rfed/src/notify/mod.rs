//! Notify dispatch and registry.
//!
//! # Two separate notification paths
//!
//! ## 1. Mobile notify (`lxmf.propagation` → `dispatch_notify`)
//! When a sender uploads a message to rfed's `lxmf.propagation` node, the
//! propagation handler checks the `NotifyRegistry`. If the recipient has
//! registered a notify relay, [`dispatch_notify`] is called routing to the
//! RNS notify adapter.
//!
//! ## 2. Channel delivery hooks (`rfed.channel` → `HookRegistry`)
//! When rfed delivers a channel blob to an online subscriber, any registered
//! [`DeliveryHook`] implementations are fired.  These are for external
//! bridge adapters. Mobile notify adapters do NOT use this path — they are
//! dispatched via `dispatch_notify` only.
//!
//! # Notify relay registration
//! A subscriber registers one or more notify relay nodes by sending their
//! 32-char lowercase hex destination hash (16-byte RNS truncated hash).
//! Multiple relay hashes may be registered for the same subscriber — all
//! will be poked when the subscriber is unreachable.
//!
//! The relay is a Reticulum node operated by the app developer.  It receives
//! a msgpack-encoded Map containing the receiver (subscriber) destination
//! hash plus optional sender and channel hashes, and is responsible for
//! forwarding a wake-up to the device (FCM, APNs, SMS, etc.) using
//! whatever credentials it holds privately.  rfed never makes outbound IP
//! connections — the notify path stays entirely within the Reticulum mesh.
//!
//! Registration protocol paths (on `rfed.notify` destination):
//!   `/rfed/notify/register`   — add a relay hash (msgpack String, 32 hex chars)
//!   `/rfed/notify/unregister` — remove a specific relay hash (same format)
//!   `/rfed/notify/clear`      — remove ALL relay registrations for the caller
//!
//! # Privacy
//! Wake payloads contain destination hashes only (receiver, and optionally
//! sender and channel).  No message content is included.
//!
//! # NotifyRegistry
//! Per-node table mapping `(subscriber_dest_hash, relay_hash)` pairs.
//! Never synced between nodes.  Only the node holding the registration fires
//! the notify, ensuring exactly one wakeup per device regardless of how many
//! nodes the subscriber visits.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub mod rns;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ── Relay hash validation ─────────────────────────────────────────────────────

/// Validate a push relay destination hash at registration time.
///
/// The hash must be a 32-char lowercase hexadecimal string (16-byte RNS
/// truncated destination hash).  No URI scheme prefix is accepted or
/// required.
pub fn validate_relay_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("relay hash must be a 32-char lowercase hex destination hash".into());
    }
    Ok(())
}

// ── DeliveryHook ─────────────────────────────────────────────────────────────

/// Single interface implemented by all notify/bridge adapters.
///
/// `on_deliver` is called once per outer-envelope delivery attempt, after the
/// Reticulum packet has been queued.  Implementations MUST return quickly;
/// any blocking I/O should be dispatched on a background thread.
pub trait DeliveryHook: Send + Sync {
    /// Fire a wake-up ping toward `subscriber_pubkey`.
    ///
    /// `inner_blob` is available for metadata extraction but MUST NOT be
    /// forwarded as notify payload content (privacy-by-design requirement).
    fn on_deliver(&self, subscriber_pubkey: &[u8], inner_blob: &[u8]);
}

// ── Notify registration ───────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct NotifyRegistration {
    /// 16-byte truncated RNS destination hash of the subscriber.
    pub subscriber_hash: Vec<u8>,
    /// 32-char lowercase hex destination hash of the notify relay node.
    pub relay_hash: String,
    /// When the registration was last updated (Unix timestamp).
    pub registered: f64,
}

// ── NotifyRegistry ────────────────────────────────────────────────────────────

/// Per-node notify registration table.  Never synced between peers.
pub struct NotifyRegistry {
    registrations: Vec<NotifyRegistration>,
    file_path: PathBuf,
}

impl NotifyRegistry {
    pub fn load(file_path: PathBuf) -> Self {
        let registrations = if file_path.exists() {
            std::fs::read(&file_path)
                .ok()
                .and_then(|b| rmp_serde::from_slice::<Vec<NotifyRegistration>>(&b).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        NotifyRegistry { registrations, file_path }
    }

    /// Register or refresh a notify relay for a subscriber.
    ///
    /// If the subscriber already has a registration for this exact relay hash
    /// the timestamp is refreshed.  Otherwise a new entry is appended.
    /// A subscriber may register multiple relay hashes simultaneously.
    pub fn register(&mut self, subscriber_hash: Vec<u8>, relay_hash: String) {
        if let Some(existing) = self.registrations.iter_mut().find(|r| {
            r.subscriber_hash == subscriber_hash && r.relay_hash == relay_hash
        }) {
            existing.registered = now();
        } else {
            self.registrations.push(NotifyRegistration {
                subscriber_hash,
                relay_hash,
                registered: now(),
            });
        }
        let _ = self.save();
    }

    /// Remove a specific relay registration for a subscriber.
    pub fn unregister(&mut self, subscriber_hash: &[u8], relay_hash: &str) {
        let before = self.registrations.len();
        self.registrations.retain(|r| {
            !(r.subscriber_hash.as_slice() == subscriber_hash && r.relay_hash == relay_hash)
        });
        if self.registrations.len() != before {
            let _ = self.save();
        }
    }

    /// Remove ALL relay registrations for a subscriber.
    pub fn clear(&mut self, subscriber_hash: &[u8]) {
        let before = self.registrations.len();
        self.registrations.retain(|r| r.subscriber_hash.as_slice() != subscriber_hash);
        if self.registrations.len() != before {
            let _ = self.save();
        }
    }

    /// Lookup all registrations for a subscriber.
    pub fn get(&self, subscriber_hash: &[u8]) -> Vec<&NotifyRegistration> {
        self.registrations
            .iter()
            .filter(|r| r.subscriber_hash.as_slice() == subscriber_hash)
            .collect()
    }

    pub fn save(&self) -> Result<(), String> {
        let bytes = rmp_serde::to_vec(&self.registrations)
            .map_err(|e| format!("NotifyRegistry serialize: {e}"))?;
        std::fs::write(&self.file_path, &bytes)
            .map_err(|e| format!("NotifyRegistry write: {e}"))?;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.registrations.len()
    }
}

// ── HookRegistry ─────────────────────────────────────────────────────────────

/// Ordered registry of delivery hooks.
///
/// Hooks are registered at startup; the node itself has zero application-
/// specific logic.  Each hook is called for every delivery event in
/// registration order.
pub struct HookRegistry {
    hooks: Vec<Box<dyn DeliveryHook>>,
}

impl HookRegistry {
    pub fn new() -> Self {
        HookRegistry { hooks: Vec::new() }
    }

    /// Register a new delivery hook.
    pub fn register(&mut self, hook: Box<dyn DeliveryHook>) {
        self.hooks.push(hook);
    }

    /// Fire all registered hooks for a delivery event.
    pub fn on_deliver(&self, subscriber_pubkey: &[u8], inner_blob: &[u8]) {
        for hook in &self.hooks {
            hook.on_deliver(subscriber_pubkey, inner_blob);
        }
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Notify dispatch ───────────────────────────────────────────────────────────

/// Send a notify wake-up for `reg` via the RNS adapter.
///
/// Called by `lxmf_propagation_notification::on_packet` when a message arrives
/// for a notify-registered destination.  Dispatch is fire-and-forget; the
/// adapter MUST NOT block the calling thread.
pub fn dispatch_notify(
    reg: &NotifyRegistration,
    sender: Option<&[u8]>,
    channel: Option<&[u8]>,
) {
    rns::dispatch(reg, sender, channel);
}
