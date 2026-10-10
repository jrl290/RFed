//! The hand-off for a delivery rfed could not confirm.
//!
//! A fan-out confirms a delivery only by its proof: the rfed.link response,
//! the stream link's proof, or the proof of an rfed.delivery packet (RFed SPEC
//! §7 "Live delivery and its proof"). Everything else is handed off here: the
//! blob is queued for the pull route, and then the recipient is pushed
//! through its notify registrations so that it pulls. Queue first: the push
//! makes the recipient pull, and a pull that comes before the blob is queued
//! finds nothing (DESIGN_PRINCIPLES §5).
//!
//! A distro hand-off is built by [`distro_hand_off`], at both of its entry
//! points (propagation ingest and FedSync), so the class has one builder. A
//! blob that came with an accepted §17.13 sync proof is queued and not pushed
//! ([`Wake::QueueOnly`]), within two count bounds; everything else is pushed
//! ([`Wake::Push`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use reticulum_rust::packet::PacketReceipt;
use reticulum_rust::{hexrep, log, LOG_NOTICE, LOG_WARNING};

use crate::deferred_queue::{DeferredQueue, EnqueueOutcome};
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
    /// The deferred-queue bucket the pull drains: the identity hash of a
    /// distro device or a channel subscriber.
    pub queue_key: Vec<u8>,
    /// The key its notify registrations are stored under: its
    /// `lxmf.delivery` hash (crate::notify::notify_key), for distro devices
    /// and channel subscribers alike.
    pub wake_key: Vec<u8>,
}

/// What a fan-out does with a recipient it could not confirm. Build it with
/// [`defer_then_wake`] (a channel's), or [`distro_hand_off`] (a distro's).
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
                let outcome = queue.enqueue(recipient.queue_key.clone(), routing_hash.clone(), blob.clone(), limit);
                Queueing::Done(outcome)
            }
            Err(_) => Queueing::Poisoned,
        };
        wake_after_queueing(&*stack, &notify_registry, &recipient, &routing_hash, wake_channel.as_deref(), &queued);
    })
}

/// What a hand-off's attempt to queue its blob came to.
enum Queueing {
    Done(EnqueueOutcome),
    /// The deferred queue's mutex is poisoned: nothing was queued.
    Poisoned,
}

impl Queueing {
    /// The `{} for pull` slot of the pinned `[handoff]` line. "queued" is
    /// what the staging harnesses match (test-harnesses distro_channels.mjs
    /// `handoffsFor`); a blob that was not queued must never read as queued.
    fn for_pull(&self) -> &'static str {
        match self {
            Queueing::Done(outcome) if outcome.queued() => "queued",
            Queueing::Done(_) => "NOT queued: global limit",
            Queueing::Poisoned => "NOT queued (deferred queue poisoned)",
        }
    }

    fn queued(&self) -> bool {
        matches!(self, Queueing::Done(outcome) if outcome.queued())
    }

    /// The entry the enqueue evicted to make room, if it evicted one.
    fn evicted(&self) -> Option<&[u8]> {
        match self {
            Queueing::Done(EnqueueOutcome::QueuedEvictingOldest { evicted_routing_hash }) => Some(evicted_routing_hash),
            _ => None,
        }
    }
}

/// Say that queueing `routing_hash`'s blob for `recipient` evicted its
/// oldest entry, when it did: that entry is lost to the pull (RFed SPEC §7
/// "Limits"). One NOTICE, naming whose entry and what it was routed to.
fn log_eviction(recipient: &Unconfirmed, routing_hash: &[u8], queued: &Queueing) {
    if let Some(evicted) = queued.evicted() {
        log(
            format!(
                "[handoff] {} bucket full: its oldest entry, for {}, evicted to queue one for {}",
                hexrep(&recipient.wake_key, false),
                hexrep(evicted, false),
                hexrep(routing_hash, false),
            ),
            LOG_NOTICE,
            false,
            false,
        );
    }
}

/// The push of a hand-off, once its blob is queued (or could not be): wake
/// `recipient` through its notify registrations for `wake_channel`, then
/// write the one `[handoff]` line saying what was queued and who was woken.
/// The line's format is pinned by the staging harnesses
/// (test-harnesses staging/lib/distro_channels.test.mjs).
fn wake_after_queueing(
    stack: &dyn RelayStack,
    notify_registry: &Mutex<NotifyRegistry>,
    recipient: &Unconfirmed,
    routing_hash: &[u8],
    wake_channel: Option<&[u8]>,
    queued: &Queueing,
) {
    log_eviction(recipient, routing_hash, queued);
    // Snapshot, then wake with the registry released: a wake is a send.
    let registrations: Vec<NotifyRegistration> = match notify_registry.lock() {
        Ok(registry) => registry
            .get_for_channel(&recipient.wake_key, wake_channel)
            .into_iter()
            .cloned()
            .collect(),
        Err(_) => Vec::new(),
    };
    let woken = registrations
        .iter()
        .filter(|registration| dispatch_notify_via(stack, registration, None, wake_channel).is_sent())
        .count();
    log(
        format!(
            "[handoff] {} unconfirmed for {}: {} for pull, woken via {} of {} notify registration(s)",
            hexrep(&recipient.wake_key, false),
            hexrep(routing_hash, false),
            queued.for_pull(),
            woken,
            registrations.len(),
        ),
        if queued.queued() { LOG_NOTICE } else { LOG_WARNING },
        false,
        false,
    );
}

/// Whether a distro hand-off pushes the device (RFed SPEC §17.3, §17.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    /// Queue, then push through the device's notify registrations: every
    /// distro blob but one with an accepted sync proof, and every blob
    /// FedSync delivers.
    Push,
    /// Queue and do not push: a blob that came with an accepted §17.13 sync
    /// proof, the device's own sync, which it collects at its next pull of
    /// any cause. Pushed after all at the [`DISTRO_SYNC_UNWOKEN_LIMIT`]th
    /// un-pulled blob of the distro, or with the queue at three quarters of
    /// its global limit.
    QueueOnly,
}

/// A device holds at most this many queued blobs of one distro without a
/// push: the hand-off that queues the 64th pushes. Three `/rfed/pull` pages
/// of 25, well inside the 8-round pulls of Android and the iOS NSE, so a real
/// message behind a sync backlog comes in the wake it causes.
pub const DISTRO_SYNC_UNWOKEN_LIMIT: usize = 64;

/// The one hand-off builder for a distro fan-out, at both of its entry points
/// (propagation ingest and FedSync): what the fan-out does with a device it
/// could not confirm, for `blob`, a message to the distro `distro_hash`.
///
/// [`Wake::Push`] is [`defer_then_wake`] with the device's LXMF registrations,
/// unchanged. [`Wake::QueueOnly`] counts, under the one acquisition of the
/// queue lock that enqueues, the device's queued blobs of the distro and the
/// whole queue. The hand-off pushes after all, as `Push` does, when the
/// device then holds [`DISTRO_SYNC_UNWOKEN_LIMIT`] or more, or when the queue
/// held three quarters of its global limit or more: both counts, read at the
/// hand-off, never a clock. Otherwise it logs, with the lock released, that
/// the device was not woken, and never reads the notify registry.
pub fn distro_hand_off(
    stack: Arc<dyn RelayStack + Send + Sync>,
    deferred_queue: Arc<Mutex<DeferredQueue>>,
    notify_registry: Arc<Mutex<NotifyRegistry>>,
    limit_for: Arc<dyn Fn(&[u8]) -> usize + Send + Sync>,
    distro_hash: &[u8],
    blob: &[u8],
    wake: Wake,
) -> OnUnconfirmed {
    if wake == Wake::Push {
        return defer_then_wake(stack, deferred_queue, notify_registry, limit_for, distro_hash, blob, None);
    }
    let distro_hash = distro_hash.to_vec();
    let blob = blob.to_vec();
    Arc::new(move |device: Unconfirmed| {
        // One acquisition: the counts and the enqueue, so no other hand-off
        // comes between them.
        let counted = match deferred_queue.lock() {
            Ok(mut queue) => {
                let held = queue.count_matching(&device.queue_key, &distro_hash);
                let total = queue.total_len();
                let global_limit = queue.global_limit;
                let limit = limit_for(&device.queue_key);
                let outcome = queue.enqueue(device.queue_key.clone(), distro_hash.clone(), blob.clone(), limit);
                Some((held, total, global_limit, outcome))
            }
            Err(_) => None,
        };
        let Some((held, total, global_limit, outcome)) = counted else {
            // Nothing could be queued, so a silence would lose the blob: push,
            // and say it was not queued, as `Push` does.
            wake_after_queueing(&*stack, &notify_registry, &device, &distro_hash, None, &Queueing::Poisoned);
            return;
        };
        let un_pulled = un_pulled_after(held, &outcome, &distro_hash);
        let mut why = Vec::new();
        if un_pulled >= DISTRO_SYNC_UNWOKEN_LIMIT {
            why.push(format!("{un_pulled} un-pulled"));
        }
        if total >= global_limit * 3 / 4 {
            why.push(format!("queue at {total} of {global_limit}"));
        }
        let queued = Queueing::Done(outcome);
        if !why.is_empty() {
            log(
                format!(
                    "[handoff] distro sync for {} of {} woken anyway: {}",
                    hexrep(&device.wake_key, false),
                    hexrep(&distro_hash, false),
                    why.join(", "),
                ),
                LOG_NOTICE,
                false,
                false,
            );
            wake_after_queueing(&*stack, &notify_registry, &device, &distro_hash, None, &queued);
            return;
        }
        log_eviction(&device, &distro_hash, &queued);
        log(
            format!(
                "[handoff] {} unconfirmed for {}: queued for pull, NOT woken (distro sync, {} of {} un-pulled)",
                hexrep(&device.wake_key, false),
                hexrep(&distro_hash, false),
                un_pulled,
                DISTRO_SYNC_UNWOKEN_LIMIT,
            ),
            LOG_NOTICE,
            false,
            false,
        );
    })
}

/// The device's queued blobs of `distro_hash` after an enqueue that found
/// `held` of them: one more if it was queued, one fewer if the entry it
/// evicted was one of them.
fn un_pulled_after(held: usize, outcome: &EnqueueOutcome, distro_hash: &[u8]) -> usize {
    match outcome {
        EnqueueOutcome::Queued => held + 1,
        EnqueueOutcome::QueuedEvictingOldest { evicted_routing_hash } if evicted_routing_hash == distro_hash => held,
        EnqueueOutcome::QueuedEvictingOldest { .. } => held + 1,
        EnqueueOutcome::RefusedGlobalLimit => held,
    }
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

    // ── The distro hand-off and its bounds (DISTRO-SYNC-PROOF-DESIGN §6.3) ─

    use crate::notify::rns::fake::FakeStack;
    use reticulum_rust::destination::Destination;
    use reticulum_rust::identity::Identity;

    /// A queue, a notify registry, and a relay stack that records every wake.
    struct Rig {
        dir: std::path::PathBuf,
        queue: Arc<Mutex<DeferredQueue>>,
        notify: Arc<Mutex<NotifyRegistry>>,
        relay_hash: Vec<u8>,
        stack: Arc<FakeStack>,
    }

    impl Rig {
        fn new(tag: &str) -> Rig {
            let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let dir = std::env::temp_dir().join(format!("rfed_handoff_{tag}_{unique}"));
            std::fs::create_dir_all(&dir).expect("temp dir");
            let relay = Identity::new(true);
            let relay_hash = Destination::hash(relay.hash.as_deref(), "rfed", &["notify"]);
            let recalled = Identity::from_public_key(&relay.get_public_key().unwrap()).unwrap();
            Rig {
                queue: Arc::new(Mutex::new(DeferredQueue::load(dir.join("deferred.rmp")))),
                notify: Arc::new(Mutex::new(NotifyRegistry::load(dir.join("notify.rmp")))),
                stack: Arc::new(FakeStack::new(&relay_hash, Some(recalled))),
                relay_hash,
                dir,
            }
        }

        /// A device with one notify registration under its wake key.
        fn device(&self, byte: u8) -> Unconfirmed {
            let device = Unconfirmed { queue_key: vec![byte; 16], wake_key: vec![byte ^ 0xFF; 16] };
            self.notify.lock().unwrap().register(device.wake_key.clone(), None, hexrep(&self.relay_hash, false));
            device
        }

        fn hand_off(&self, distro: &[u8], blob: &[u8], wake: Wake) -> OnUnconfirmed {
            distro_hand_off(
                Arc::clone(&self.stack) as Arc<dyn RelayStack + Send + Sync>,
                Arc::clone(&self.queue),
                Arc::clone(&self.notify),
                Arc::new(|_| 256),
                distro,
                blob,
                wake,
            )
        }

        fn wakes(&self) -> usize {
            self.stack.packets.lock().unwrap().len()
        }

        /// Fill the queue to `total` entries under subscribers no test wakes.
        fn fill_to(&self, total: usize) {
            let mut queue = self.queue.lock().unwrap();
            let mut n = 0usize;
            while queue.total_len() < total {
                let filler = [&[0xEE, 0xEE][..], &n.to_be_bytes()[..], &[0xEE; 6][..]].concat();
                queue.enqueue(filler, vec![0xCC; 16], vec![0], 256);
                n += 1;
            }
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// `Push` is the hand-off as it was: one enqueue, one wake per
    /// registration, the pinned line (test-harnesses distro_channels.test.mjs).
    #[test]
    fn push_queues_then_wakes_every_registration() {
        let rig = Rig::new("push");
        let device = rig.device(0x11);
        rig.notify.lock().unwrap().register(device.wake_key.clone(), None, hexrep(&rig.relay_hash, false));
        let other_relay = Destination::hash(Identity::new(true).hash.as_deref(), "rfed", &["notify"]);
        rig.notify.lock().unwrap().register(device.wake_key.clone(), None, hexrep(&other_relay, false));
        let distro = vec![0xD1; 16];
        let mark = crate::test_log::mark();

        rig.hand_off(&distro, b"blob", Wake::Push)(device.clone());

        assert_eq!(rig.queue.lock().unwrap().count_matching(&device.queue_key, &distro), 1);
        assert_eq!(rig.wakes(), 1, "the registration whose relay has a path is woken");
        let lines = mark.containing("[handoff] ");
        assert_eq!(lines.len(), 1, "one line per hand-off: {lines:?}");
        let line = &lines[0];
        assert!(line.contains("[Notice]"), "{line}");
        assert!(
            line.ends_with(&format!(
                "[handoff] {} unconfirmed for {}: queued for pull, woken via 1 of 2 notify registration(s)",
                hexrep(&device.wake_key, false),
                hexrep(&distro, false),
            )),
            "{line}"
        );
    }

    /// The staging harnesses parse the Push line; its format string is
    /// pinned there (distro_channels.test.mjs) and must not change.
    #[test]
    fn the_pinned_handoff_format_is_unchanged() {
        let source = include_str!("handoff.rs");
        assert!(source.contains(concat!(
            "\"[handoff] {} unconfirmed for {}: {} for pull, ",
            "woken via {} of {} notify registration(s)\","
        )));
        assert!(source.contains(concat!(
            "\"[handoff] {} unconfirmed for {}: queued for pull, ",
            "NOT woken (distro sync, {} of {} un-pulled)\","
        )));
    }

    /// An accepted sync proof: queued, nobody woken, and the line says so.
    #[test]
    fn queue_only_queues_and_wakes_no_one() {
        let rig = Rig::new("queue_only");
        let device = rig.device(0x21);
        let distro = vec![0xD2; 16];
        let mark = crate::test_log::mark();

        rig.hand_off(&distro, b"sync", Wake::QueueOnly)(device.clone());

        assert_eq!(rig.queue.lock().unwrap().count_matching(&device.queue_key, &distro), 1, "one enqueue");
        assert_eq!(rig.wakes(), 0, "no wake");
        let lines = mark.containing("[handoff] ");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].ends_with(&format!(
                "[handoff] {} unconfirmed for {}: queued for pull, NOT woken (distro sync, 1 of 64 un-pulled)",
                hexrep(&device.wake_key, false),
                hexrep(&distro, false),
            )),
            "{}",
            lines[0]
        );
    }

    /// The 63rd un-pulled blob of the distro does not wake; the 64th does,
    /// and says why. Pulling lowers the count again.
    #[test]
    fn the_64th_unpulled_sync_blob_wakes_the_device() {
        let rig = Rig::new("bound_64");
        let device = rig.device(0x31);
        let distro = vec![0xD3; 16];
        let hand_off = rig.hand_off(&distro, b"sync", Wake::QueueOnly);
        // Another distro's blobs and channel posts in the same bucket do not count.
        rig.queue.lock().unwrap().enqueue(device.queue_key.clone(), vec![0xC3; 16], b"post".to_vec(), 256);
        for _ in 0..62 {
            hand_off(device.clone());
        }
        let mark = crate::test_log::mark();
        hand_off(device.clone());
        assert_eq!(rig.wakes(), 0, "63 un-pulled: not woken");
        assert!(mark.lines().iter().any(|l| l.contains("NOT woken (distro sync, 63 of 64 un-pulled)")));

        let mark = crate::test_log::mark();
        hand_off(device.clone());
        assert_eq!(rig.wakes(), 1, "the 64th wakes");
        let lines = mark.containing("[handoff] ");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].ends_with(&format!(
            "[handoff] distro sync for {} of {} woken anyway: 64 un-pulled",
            hexrep(&device.wake_key, false),
            hexrep(&distro, false),
        )), "{}", lines[0]);
        assert!(lines[1].contains("queued for pull, woken via 1 of 1 notify registration(s)"), "{}", lines[1]);

        hand_off(device.clone());
        assert_eq!(rig.wakes(), 2, "and every one after it while the backlog stands");
        let pulled = rig.queue.lock().unwrap().drain_channel_batch(&device.queue_key, &distro, 25);
        assert_eq!(pulled.len(), 25);
        hand_off(device.clone());
        assert_eq!(rig.wakes(), 2, "41 un-pulled after a pull: quiet again");
        assert_eq!(rig.queue.lock().unwrap().count_matching(&device.queue_key, &distro), 41);
    }

    /// With the queue at three quarters of its global limit, a sync hand-off
    /// wakes as `Push` does, so a live device drains.
    #[test]
    fn a_queue_at_three_quarters_of_its_limit_wakes_sync_hand_offs() {
        let rig = Rig::new("bound_3_4");
        let device = rig.device(0x41);
        let distro = vec![0xD4; 16];
        assert_eq!(rig.queue.lock().unwrap().global_limit, 4096);
        rig.fill_to(3071);
        let hand_off = rig.hand_off(&distro, b"sync", Wake::QueueOnly);

        hand_off(device.clone());
        assert_eq!(rig.wakes(), 0, "3071 queued: under three quarters");

        let mark = crate::test_log::mark();
        hand_off(device.clone());
        assert_eq!(rig.wakes(), 1, "3072 queued: woken");
        let lines = mark.containing("[handoff] ");
        assert!(lines[0].ends_with("woken anyway: queue at 3072 of 4096"), "{}", lines[0]);
        assert_eq!(rig.queue.lock().unwrap().count_matching(&device.queue_key, &distro), 2, "both queued");
    }

    /// The review's case: at 4095, a QueueOnly enqueue followed by a Push
    /// enqueue for another subscriber does exactly what two Push enqueues do.
    #[test]
    fn at_4095_queue_only_then_push_is_two_pushes() {
        let run = |first: Wake| -> (Vec<String>, usize, usize) {
            let rig = Rig::new("at_4095");
            let a = rig.device(0x51);
            let b = rig.device(0x52);
            let distro = vec![0xD5; 16];
            rig.fill_to(4095);
            let mark = crate::test_log::mark();
            rig.hand_off(&distro, b"one", first)(a.clone());
            rig.hand_off(&distro, b"two", Wake::Push)(b.clone());
            let lines: Vec<String> = mark
                .lines()
                .into_iter()
                .filter(|l| l.contains("[handoff] ") && l.contains("unconfirmed for"))
                .map(|l| l[l.find("[handoff] ").unwrap()..].to_string())
                .collect();
            let queued = {
                let queue = rig.queue.lock().unwrap();
                queue.count_matching(&a.queue_key, &distro) + queue.count_matching(&b.queue_key, &distro)
            };
            (lines, rig.wakes(), queued)
        };
        let (sync_lines, sync_wakes, sync_queued) = run(Wake::QueueOnly);
        let (push_lines, push_wakes, push_queued) = run(Wake::Push);
        assert_eq!(sync_wakes, 2);
        assert_eq!(sync_queued, 1, "the first fills the queue, the second is refused");
        assert_eq!((sync_wakes, sync_queued), (push_wakes, push_queued));
        assert_eq!(sync_lines.len(), 2);
        assert!(sync_lines[1].contains(": NOT queued: global limit for pull, woken via 1 of 1"), "{}", sync_lines[1]);
        assert_eq!(sync_lines, push_lines, "the same hand-off lines, word for word");
    }

    /// A refused enqueue is a WARNING and never reads as queued; the device
    /// is still woken, so it drains what is queued for it.
    #[test]
    fn a_refused_enqueue_is_a_warning_and_still_wakes() {
        let rig = Rig::new("refused");
        let device = rig.device(0x61);
        rig.queue.lock().unwrap().global_limit = 2;
        rig.fill_to(2);
        let mark = crate::test_log::mark();
        rig.hand_off(&[0xD6; 16], b"blob", Wake::Push)(device.clone());
        assert_eq!(rig.wakes(), 1);
        let lines = mark.containing("[handoff] ");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("[Warning]"), "{}", lines[0]);
        assert!(lines[0].contains(": NOT queued: global limit for pull, woken via 1 of 1"), "{}", lines[0]);
    }

    /// An eviction at the per-device limit is said, naming what was lost.
    #[test]
    fn an_eviction_is_a_notice_naming_what_was_lost() {
        let rig = Rig::new("evict");
        let device = rig.device(0x71);
        let lost = vec![0xC7; 16];
        let distro = vec![0xD7; 16];
        rig.queue.lock().unwrap().enqueue(device.queue_key.clone(), lost.clone(), b"old".to_vec(), 1);
        let hand_off = distro_hand_off(
            Arc::clone(&rig.stack) as Arc<dyn RelayStack + Send + Sync>,
            Arc::clone(&rig.queue),
            Arc::clone(&rig.notify),
            Arc::new(|_| 1),
            &distro,
            b"new",
            Wake::QueueOnly,
        );
        let mark = crate::test_log::mark();
        hand_off(device.clone());
        let lines = mark.containing("[handoff] ");
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("[Notice]"));
        assert!(lines[0].ends_with(&format!(
            "[handoff] {} bucket full: its oldest entry, for {}, evicted to queue one for {}",
            hexrep(&device.wake_key, false),
            hexrep(&lost, false),
            hexrep(&distro, false),
        )), "{}", lines[0]);
        assert!(lines[1].contains("NOT woken (distro sync, 1 of 64 un-pulled)"), "{}", lines[1]);
    }

    /// Both eviction arms of the 64 bound, with the device's bucket full at a
    /// per-device limit of 64. When the evicted oldest entry was one of D's
    /// own, the count stays at 64 (one in, one of D's out); when it was
    /// another routing hash's, the 63 of D become 64. Both wake, and the
    /// line says 64. (Until 2026-10-10 only the second arm ran in a test, so
    /// counting `held + 1` for the first went unseen.)
    #[test]
    fn a_full_bucket_pins_both_eviction_arms_of_the_64_bound() {
        let run = |oldest_is_distro: bool| -> (usize, Vec<String>, usize) {
            let rig = Rig::new("evict_bound");
            let device = rig.device(0x91);
            let distro = vec![0xD9; 16];
            {
                let mut queue = rig.queue.lock().unwrap();
                let first = if oldest_is_distro { distro.clone() } else { vec![0xC9; 16] };
                queue.enqueue(device.queue_key.clone(), first, b"oldest".to_vec(), 64);
                for n in 0..63u8 {
                    queue.enqueue(device.queue_key.clone(), distro.clone(), vec![n], 64);
                }
            }
            let hand_off = distro_hand_off(
                Arc::clone(&rig.stack) as Arc<dyn RelayStack + Send + Sync>,
                Arc::clone(&rig.queue),
                Arc::clone(&rig.notify),
                Arc::new(|_| 64),
                &distro,
                b"sync",
                Wake::QueueOnly,
            );
            let mark = crate::test_log::mark();
            hand_off(device.clone());
            let held = rig.queue.lock().unwrap().count_matching(&device.queue_key, &distro);
            (rig.wakes(), mark.containing("[handoff] "), held)
        };

        for oldest_is_distro in [true, false] {
            let (wakes, lines, held) = run(oldest_is_distro);
            assert_eq!(held, 64, "oldest is the distro's: {oldest_is_distro}");
            assert_eq!(wakes, 1, "the 64th un-pulled wakes (oldest is the distro's: {oldest_is_distro})");
            assert_eq!(lines.len(), 3, "bound, eviction, push: {lines:?}");
            assert!(lines[0].ends_with("woken anyway: 64 un-pulled"), "oldest is the distro's: {oldest_is_distro}: {}", lines[0]);
            assert!(lines[1].contains("bucket full: its oldest entry, for "), "{}", lines[1]);
            assert!(lines[2].contains("queued for pull, woken via 1 of 1"), "{}", lines[2]);
        }

        // Below the bound the count shows in the quiet line: 10 of D's
        // blobs fill a bucket of 10, and an eleventh evicts one of them.
        let rig = Rig::new("evict_quiet");
        let device = rig.device(0x92);
        let distro = vec![0xDA; 16];
        for n in 0..10u8 {
            rig.queue.lock().unwrap().enqueue(device.queue_key.clone(), distro.clone(), vec![n], 10);
        }
        let hand_off = distro_hand_off(
            Arc::clone(&rig.stack) as Arc<dyn RelayStack + Send + Sync>,
            Arc::clone(&rig.queue),
            Arc::clone(&rig.notify),
            Arc::new(|_| 10),
            &distro,
            b"sync",
            Wake::QueueOnly,
        );
        let mark = crate::test_log::mark();
        hand_off(device.clone());
        assert_eq!(rig.wakes(), 0);
        assert!(mark.lines().iter().any(|l| l.contains("NOT woken (distro sync, 10 of 64 un-pulled)")), "{:?}", mark.lines());
    }

    /// A poisoned queue cannot hold the blob, so a QueueOnly hand-off pushes
    /// and says it was not queued, as Push does.
    #[test]
    fn queue_only_with_a_poisoned_queue_pushes_and_says_so() {
        let rig = Rig::new("poisoned");
        let device = rig.device(0x81);
        let queue = Arc::clone(&rig.queue);
        let _ = std::thread::spawn(move || {
            let _guard = queue.lock().unwrap();
            panic!("poison the queue");
        })
        .join();
        let mark = crate::test_log::mark();
        rig.hand_off(&[0xD8; 16], b"sync", Wake::QueueOnly)(device.clone());
        assert_eq!(rig.wakes(), 1);
        let lines = mark.containing("[handoff] ");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("NOT queued (deferred queue poisoned) for pull, woken via 1 of 1"), "{}", lines[0]);
    }
}
