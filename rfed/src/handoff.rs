//! The hand-off for a delivery rfed could not confirm.
//!
//! A fan-out confirms a delivery only by its proof: the rfed.link response,
//! the stream link's proof, or the proof of an rfed.delivery packet (RFed SPEC
//! §7 "Live delivery and its proof"). Everything else is handed off here: the
//! blob is queued for the pull route, and then the recipient is pushed
//! through its notify registrations so that it pulls. Queue first: the push
//! makes the recipient pull, and a pull that comes before the blob is queued
//! finds nothing (DESIGN_PRINCIPLES §5).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use reticulum_rust::packet::PacketReceipt;
use reticulum_rust::{hexrep, log, LOG_NOTICE, LOG_WARNING};

use crate::deferred_queue::DeferredQueue;
use crate::notify::rns::RelayStack;
use crate::notify::{dispatch_notify_via, NotifyRegistration, NotifyRegistry};
use crate::stream_registry::{tie_receipt, PushOutcome};

/// What the proof of an `rfed.delivery` packet (the channel fan-out's
/// packet, and the announce flush of queued channel blobs) decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketProof {
    /// Delivered only on the proof; on the receipt timeout the blob is
    /// handed off (queued for the pull and pushed).
    Required,
    /// Sent once and counted delivered, as before 2026-09-26. The receipt is
    /// still requested, and whether a proof came is logged: that shows how
    /// many devices run an app that proves.
    Observed,
}

/// OBSERVED UNTIL THE APPS THAT PROVE ARE ON MOST DEVICES (James, 2026-09-26:
/// "we will reenable it in a month or so", so about 2026-10-26). Apps prove
/// rfed.delivery from Retichat-android 21e520b, Retichat-ios fbc2e83 and
/// Retichat-js 15f9ac5. Against an app that never proves, `Required` hands off
/// every packet, and the announce flush then sends the queued copy again on
/// each announce, again and again. To re-enable: set `Required` here and in
/// `tests::the_packet_proof_is_observed_until_the_apps_are_updated`.
pub const DELIVERY_PACKET_PROOF: PacketProof = PacketProof::Observed;

/// Tie an `rfed.delivery` packet's receipt to its verdict under `mode`.
/// `Required`: delivered on the proof, `hand_off` on the receipt timeout.
/// `Observed`: sent once either way, and the proof or its absence is logged
/// only.
pub fn await_packet_proof(
    receipt: &PacketReceipt,
    label: String,
    mode: PacketProof,
    hand_off: Arc<dyn Fn() + Send + Sync>,
) {
    match mode {
        PacketProof::Required => {
            let outcome = PushOutcome::new(label, Some(hand_off));
            outcome.receipt_pending();
            tie_receipt(receipt, &outcome);
            outcome.dispatch_done();
        }
        PacketProof::Observed => {
            // One verdict per packet: a proof after the timeout is not logged twice.
            let concluded = Arc::new(AtomicBool::new(false));
            let (proved_label, proved_done) = (label.clone(), Arc::clone(&concluded));
            receipt.set_delivery_callback(Arc::new(move |_| {
                if !proved_done.swap(true, Ordering::SeqCst) {
                    log(format!("[push] {proved_label} proved"), LOG_NOTICE, false, false);
                }
            }));
            receipt.set_timeout_callback(Arc::new(move |_| {
                if !concluded.swap(true, Ordering::SeqCst) {
                    log(
                        format!("[push] {label} unproven; sent once (the proof is observed, not yet required)"),
                        LOG_NOTICE,
                        false,
                        false,
                    );
                }
            }));
        }
    }
}

/// A recipient a fan-out could not confirm a delivery to, under both of the
/// keys its hand-off needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unconfirmed {
    /// The deferred-queue bucket the pull drains: a distro device's identity
    /// hash, a channel subscriber's hash.
    pub queue_key: Vec<u8>,
    /// The key its notify registrations are stored under: a distro device's
    /// `lxmf.delivery` hash (destinations.rs `notify/register stored lxmf`),
    /// a channel subscriber's hash.
    pub wake_key: Vec<u8>,
}

/// What a fan-out does with a recipient it could not confirm. Build it with
/// [`defer_then_wake`].
pub type OnUnconfirmed = Arc<dyn Fn(Unconfirmed) + Send + Sync>;

/// The one hand-off for a recipient a fan-out could not confirm: queue
/// `blob` under `routing_hash` (a distro's `lxmf.delivery` hash, or a
/// channel's hash) for the pull route, then push the recipient through its
/// notify registrations for `wake_channel` (None: its LXMF registrations,
/// which a distro device's push uses; Some: a channel's).
///
/// Until 2026-09-26 no distro fan-out pushed anyone, and a channel push that
/// a subscriber never answered was queued but not pushed.
pub fn defer_then_wake(
    stack: Arc<dyn RelayStack + Send + Sync>,
    deferred_queue: Arc<Mutex<DeferredQueue>>,
    notify_registry: Arc<Mutex<NotifyRegistry>>,
    limit_for: Arc<dyn Fn(&[u8]) -> usize + Send + Sync>,
    routing_hash: &[u8],
    blob: &[u8],
    wake_channel: Option<&[u8]>,
) -> OnUnconfirmed {
    let routing_hash = routing_hash.to_vec();
    let blob = blob.to_vec();
    let wake_channel = wake_channel.map(<[u8]>::to_vec);
    Arc::new(move |recipient: Unconfirmed| {
        let queued = match deferred_queue.lock() {
            Ok(mut queue) => {
                let limit = limit_for(&recipient.queue_key);
                queue.enqueue(recipient.queue_key.clone(), routing_hash.clone(), blob.clone(), limit);
                true
            }
            Err(_) => false,
        };
        // Snapshot, then wake with the registry released: a wake is a send.
        let registrations: Vec<NotifyRegistration> = match notify_registry.lock() {
            Ok(registry) => registry
                .get_for_channel(&recipient.wake_key, wake_channel.as_deref())
                .into_iter()
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        };
        let woken = registrations
            .iter()
            .filter(|registration| {
                dispatch_notify_via(&*stack, registration, None, wake_channel.as_deref()).is_sent()
            })
            .count();
        log(
            format!(
                "[handoff] {} unconfirmed for {}: {} for pull, woken via {} of {} notify registration(s)",
                hexrep(&recipient.wake_key, false),
                hexrep(&routing_hash, false),
                if queued { "queued" } else { "NOT queued (deferred queue poisoned)" },
                woken,
                registrations.len(),
            ),
            if queued { LOG_NOTICE } else { LOG_WARNING },
            false,
            false,
        );
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The intermediary step (James, 2026-09-26): the rfed.delivery packet's
    /// proof is observed, not required, until the apps that prove are on
    /// most devices (about 2026-10-26). Re-enabling is a deliberate change
    /// to this test and to DELIVERY_PACKET_PROOF together.
    #[test]
    fn the_packet_proof_is_observed_until_the_apps_are_updated() {
        assert_eq!(DELIVERY_PACKET_PROOF, PacketProof::Observed);
    }
}
