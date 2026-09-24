//! Legacy stream sessions (`rfed.channel.stream`, `rfed.propagation.stream`):
//! live pushes as link DATA packets.
//!
//! A push is proof-driven (RFed SPEC §7): each packet goes out with a
//! PacketReceipt, and the device's link proof is what makes it delivered.
//! Until 2026-09-24 a push was `send_packet` and an `Ok` counted as
//! delivered. A device that died without closing its link (iOS app killed or
//! suspended, Android frozen) kept an ACTIVE-looking link until keepalive
//! staleness, and every blob fanned out in that window was "streamed" into
//! nothing and kept nowhere for pull. The clients were proving every one of
//! those packets all along; rfed logged "Link PROOF no matching receipt".

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use reticulum_rust::link::LinkHandle;
use reticulum_rust::packet::PacketReceipt;
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_WARNING};

#[derive(Default, Debug, Clone, Copy)]
pub struct StreamDispatchResult {
    pub matched: usize,
    pub sent: usize,
}

impl StreamDispatchResult {
    pub fn had_sessions(&self) -> bool {
        self.matched > 0
    }

    /// On the wire on at least one link. For the stream registries that
    /// means "sent with a receipt": whether the device got it is decided
    /// later by the proof, and a push nobody proves reaches the caller's
    /// [`OnUnproven`] hook. The caller must not fall through to another tier
    /// here — that tier change happens in the hook, once, if it is needed.
    pub fn delivered(&self) -> bool {
        self.sent > 0
    }
}

/// What a stream push does when no link proves it before its receipt
/// concludes: the caller's move to the next delivery route — the deferred
/// queue for `/distro/pull` or `/channel/pull`, or the notify wake for a
/// directly-addressed LXMF message that stays in the messagestore. A tier
/// change, not a retry (DESIGN_PRINCIPLES §3). Runs at most once per push,
/// on a thread of its own, so it holds none of the fan-out's locks.
pub type OnUnproven = Arc<dyn Fn() + Send + Sync>;

/// One stream push across the matching session's live links (normally one:
/// there is one stream link per subscriber or delivery hash).
///
/// Delivered as soon as any link's receipt is proved. Unproven once every
/// receipt has concluded without a proof — the RNS receipt timeout (the
/// link's RTT × traffic timeout factor, RNS/Packet.py) is the failure event,
/// and a link that closes before proving also concludes there, because
/// receipts live in Transport and time out whatever the link's state.
pub(crate) struct PushOutcome {
    label: String,
    /// Receipts not yet concluded, plus one held by the dispatch until it has
    /// tried every link: a receipt that times out before the next link is
    /// tried must not end the push early.
    pending: AtomicUsize,
    any_sent: AtomicBool,
    proved: AtomicBool,
    /// Set when the push is handed to `on_unproven` (decided synchronously in
    /// `conclude_one`, before the hook's thread is spawned).
    handed_off: AtomicBool,
    on_unproven: Option<OnUnproven>,
}

impl PushOutcome {
    pub(crate) fn new(label: String, on_unproven: Option<OnUnproven>) -> Arc<Self> {
        Arc::new(Self {
            label,
            pending: AtomicUsize::new(1),
            any_sent: AtomicBool::new(false),
            proved: AtomicBool::new(false),
            handed_off: AtomicBool::new(false),
            on_unproven,
        })
    }

    /// A receipt was obtained on one link. Called before that receipt's
    /// callbacks are installed, so it is counted before it can conclude.
    pub(crate) fn receipt_pending(&self) {
        self.any_sent.store(true, Ordering::SeqCst);
        self.pending.fetch_add(1, Ordering::SeqCst);
    }

    /// A link proved its packet: the device holds it. Runs on the thread
    /// that received the proof (an interface's inbound thread), so it touches
    /// atomics and the log only — no registry, queue or Transport — and
    /// never holds up that interface's traffic.
    pub(crate) fn proved(&self) {
        if !self.proved.swap(true, Ordering::SeqCst) {
            log(format!("[stream] {} proved", self.label), LOG_DEBUG, false, false);
        }
        self.conclude_one();
    }

    /// A link's receipt timed out without a proof.
    pub(crate) fn timed_out(&self) {
        self.conclude_one();
    }

    /// The dispatch has tried every matching link.
    pub(crate) fn dispatch_done(&self) {
        self.conclude_one();
    }

    #[cfg(test)]
    pub(crate) fn is_proved(&self) -> bool {
        self.proved.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn was_handed_off(&self) -> bool {
        self.handed_off.load(Ordering::SeqCst)
    }

    /// Every receipt concluded and the dispatch done: the verdict is final.
    #[cfg(test)]
    pub(crate) fn is_settled(&self) -> bool {
        self.pending.load(Ordering::SeqCst) == 0
    }

    fn conclude_one(&self) {
        if self.pending.fetch_sub(1, Ordering::SeqCst) != 1 {
            return;
        }
        // Everything concluded. Nothing sent: the caller already fell
        // through synchronously. Proved: delivered.
        if !self.any_sent.load(Ordering::SeqCst) || self.proved.load(Ordering::SeqCst) {
            return;
        }
        // `pending` reaches zero once, so this runs at most once per push.
        self.handed_off.store(true, Ordering::SeqCst);
        match self.on_unproven.clone() {
            Some(hook) => {
                log(
                    format!("[stream] {} unproven — no link proved it before its receipt timed out; handing it to the next route", self.label),
                    LOG_WARNING,
                    false,
                    false,
                );
                // Its own thread: the hook takes queue locks and may send, and
                // the thread that concluded the push may be an interface's
                // inbound thread or a fan-out thread holding registry locks.
                std::thread::spawn(move || hook());
            }
            None => log(
                format!("[stream] {} unproven and this caller has no other route — the device did not get it", self.label),
                LOG_WARNING,
                false,
                false,
            ),
        }
    }
}

/// Why one link did not take a push.
enum NotSent {
    /// The link is gone or no longer ACTIVE: its session is stale.
    LinkGone,
    /// The link is fine but this packet could not go out (too large for the
    /// link MDU, no interface took it). The session stays.
    Packet(String),
}

/// Send `payload` on `link` as a link DATA packet with a receipt, and tie the
/// receipt's outcome to `outcome`.
///
/// `LinkHandle::send_packet_with_receipt` is `send_packet` (encrypted and
/// packed on the link, so a push over the link MDU still goes out as one
/// packet, as it always has on this tier) plus the receipt.
fn send_with_receipt(link: &LinkHandle, payload: &[u8], outcome: &Arc<PushOutcome>) -> Result<(), NotSent> {
    let receipt = match link.send_packet_with_receipt(payload) {
        Ok(Some(receipt)) => receipt,
        Ok(None) => return Err(NotSent::Packet("no interface transmitted it".to_string())),
        // Gone, or no longer ACTIVE (Link::send_packet's gate).
        Err(_) => return Err(NotSent::LinkGone),
    };
    outcome.receipt_pending();
    tie_receipt(&receipt, outcome);
    Ok(())
}

/// Conclude `outcome` for this receipt once: proved on its delivery
/// callback, unproven on its timeout callback. A proof that lands after the
/// timeout (or any second callback) does not count again. The receipt shares
/// its state with the one Transport tracks, and a callback set after the
/// receipt concluded — a proof faster than this call — still runs, once
/// (Reticulum-rust B37).
pub(crate) fn tie_receipt(receipt: &PacketReceipt, outcome: &Arc<PushOutcome>) {
    let concluded = Arc::new(AtomicBool::new(false));
    let (on_proof, proof_done) = (Arc::clone(outcome), Arc::clone(&concluded));
    let delivery: Arc<dyn Fn(&PacketReceipt) + Send + Sync> = Arc::new(move |_| {
        if !proof_done.swap(true, Ordering::SeqCst) {
            on_proof.proved();
        }
    });
    let (on_timeout, timeout_done) = (Arc::clone(outcome), concluded);
    let timeout: Arc<dyn Fn(&PacketReceipt) + Send + Sync> = Arc::new(move |_| {
        if !timeout_done.swap(true, Ordering::SeqCst) {
            on_timeout.timed_out();
        }
    });
    receipt.set_delivery_callback(delivery);
    receipt.set_timeout_callback(timeout);
}

/// Push `payload` on every matching link; collect the links whose sessions
/// are stale. Shared by both registries.
fn push_on_links(
    label: String,
    matches: Vec<(Vec<u8>, LinkHandle)>,
    payload: &[u8],
    on_unproven: Option<OnUnproven>,
    stale_links: &mut Vec<Vec<u8>>,
) -> StreamDispatchResult {
    let mut result = StreamDispatchResult { matched: matches.len(), sent: 0 };
    if matches.is_empty() {
        return result;
    }
    let outcome = PushOutcome::new(label, on_unproven);
    for (link_id, link) in matches {
        if !link.is_alive() {
            stale_links.push(link_id);
            continue;
        }
        match send_with_receipt(&link, payload, &outcome) {
            Ok(()) => result.sent += 1,
            Err(NotSent::LinkGone) => stale_links.push(link_id),
            Err(NotSent::Packet(reason)) => log(
                format!(
                    "[stream] {} not sent on link {}: {reason}",
                    outcome.label,
                    hexrep(&link_id, false),
                ),
                LOG_WARNING,
                false,
                false,
            ),
        }
    }
    outcome.dispatch_done();
    result
}

#[derive(Clone)]
struct ChannelStreamSession {
    link: LinkHandle,
    subscriber_hash: Vec<u8>,
    channel_hashes: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct ChannelStreamRegistry {
    sessions: HashMap<Vec<u8>, ChannelStreamSession>,
}

impl ChannelStreamRegistry {
    /// One stream link per subscriber (Link.md "Binding the link for push"):
    /// a new link for a subscriber hash replaces its earlier links.
    pub fn configure(
        &mut self,
        link: LinkHandle,
        subscriber_hash: Vec<u8>,
        channel_hashes: Vec<Vec<u8>>,
    ) {
        let link_id = link.link_id();
        crate::link_session::evict_others(&mut self.sessions, &link_id, |session| {
            session.subscriber_hash == subscriber_hash
        });
        self.sessions.insert(
            link_id,
            ChannelStreamSession {
                link,
                subscriber_hash,
                channel_hashes,
            },
        );
    }

    pub fn remove(&mut self, link_id: &[u8]) -> bool {
        self.sessions.remove(link_id).is_some()
    }

    /// Push to the subscriber's stream link. `on_unproven` runs if no link
    /// proves the packet (see [`PushOutcome`]).
    pub fn dispatch(
        &mut self,
        subscriber_hash: &[u8],
        channel_hash: &[u8],
        payload: &[u8],
        on_unproven: Option<OnUnproven>,
    ) -> StreamDispatchResult {
        let matches: Vec<(Vec<u8>, LinkHandle)> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.subscriber_hash.as_slice() == subscriber_hash
                    && session
                        .channel_hashes
                        .iter()
                        .any(|configured| configured.as_slice() == channel_hash)
            })
            .map(|(link_id, session)| (link_id.clone(), session.link.clone()))
            .collect();

        let mut stale_links = Vec::new();
        let label = format!(
            "channel stream push of {} to subscriber {}",
            hexrep(channel_hash, false),
            hexrep(subscriber_hash, false),
        );
        let result = push_on_links(label, matches, payload, on_unproven, &mut stale_links);

        for link_id in stale_links {
            self.sessions.remove(link_id.as_slice());
        }

        result
    }
}

#[derive(Clone)]
struct PropagationStreamSession {
    link: LinkHandle,
    delivery_hash: Vec<u8>,
}

#[derive(Default)]
pub struct PropagationStreamRegistry {
    sessions: HashMap<Vec<u8>, PropagationStreamSession>,
}

impl PropagationStreamRegistry {
    pub fn register(&mut self, link: LinkHandle, delivery_hash: Vec<u8>) -> Result<(), &'static str> {
        let link_id = link.link_id();
        if self.sessions.contains_key(&link_id) {
            return Err("already_open");
        }
        // One stream link per delivery hash (Link.md "Binding the link for push").
        crate::link_session::evict_others(&mut self.sessions, &link_id, |session| {
            session.delivery_hash == delivery_hash
        });
        self.sessions
            .insert(link_id, PropagationStreamSession { link, delivery_hash });
        Ok(())
    }

    pub fn remove(&mut self, link_id: &[u8]) -> bool {
        self.sessions.remove(link_id).is_some()
    }

    /// Push to the delivery hash's stream link. `on_unproven` runs if no
    /// link proves the packet (see [`PushOutcome`]).
    pub fn dispatch(
        &mut self,
        delivery_hash: &[u8],
        payload: &[u8],
        on_unproven: Option<OnUnproven>,
    ) -> StreamDispatchResult {
        let matches: Vec<(Vec<u8>, LinkHandle)> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.delivery_hash.as_slice() == delivery_hash)
            .map(|(link_id, session)| (link_id.clone(), session.link.clone()))
            .collect();

        let mut stale_links = Vec::new();
        let label = format!("propagation stream push to {}", hexrep(delivery_hash, false));
        let result = push_on_links(label, matches, payload, on_unproven, &mut stale_links);

        for link_id in stale_links {
            self.sessions.remove(link_id.as_slice());
        }

        result
    }
}
#[cfg(test)]
mod tests {
    use super::{tie_receipt, OnUnproven, PushOutcome};
    use reticulum_rust::destination::{Destination, DestinationType};
    use reticulum_rust::identity::Identity;
    use reticulum_rust::packet::PacketReceipt;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    /// A push whose hook reports each run on a channel (the hook runs on its
    /// own thread). Whether it was handed off is read synchronously from
    /// `was_handed_off`; `recv_timeout` only bounds the wait for a hand-off
    /// that must happen (a test failure, never a pass, when it expires).
    fn outcome() -> (Arc<PushOutcome>, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        let hook: OnUnproven = Arc::new(move || {
            let _ = tx.send(());
        });
        (PushOutcome::new("test push".to_string(), Some(hook)), rx)
    }

    fn hook_ran(rx: &mpsc::Receiver<()>) {
        rx.recv_timeout(Duration::from_secs(5)).expect("the handed-off push reaches the caller's route");
    }

    /// Wait until every conclusion has run (callbacks may run on their own
    /// threads). The bound is only the test's failure mechanism.
    fn settle(push: &PushOutcome) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !push.is_settled() {
            assert!(std::time::Instant::now() < deadline, "the push never settled");
            std::thread::yield_now();
        }
    }

    /// A SENT receipt the test can prove (with `signer`) or time out, with
    /// no network: the same object `Packet::send` hands back.
    fn receipt(signer: &Identity, byte: u8) -> PacketReceipt {
        let destination = Destination::new_outbound(
            Some(signer.clone()),
            DestinationType::Single,
            "rfedtest".to_string(),
            vec!["stream".to_string()],
        )
        .expect("destination");
        PacketReceipt::from_parts(vec![byte; 32], vec![byte; 16], destination, 3600.0)
    }

    fn prove(receipt: &mut PacketReceipt, signer: &Identity) {
        let mut proof = receipt.hash.clone();
        proof.extend_from_slice(&signer.sign(&receipt.hash));
        assert!(receipt.validate_proof(&proof), "the device's proof validates");
    }

    fn time_out(receipt: &mut PacketReceipt) {
        receipt.set_timeout(0.0);
        receipt.check_timeout();
    }

    /// The repro, on a real receipt: the packet went out to a device that
    /// had died with its link still up, and nobody proved it. The push moves
    /// to the caller's next route, once.
    #[test]
    fn an_unproven_receipt_hands_the_push_off_once() {
        let device = Identity::new(true);
        let (push, rx) = outcome();
        let mut r = receipt(&device, 0x11);
        push.receipt_pending();
        tie_receipt(&r, &push);
        push.dispatch_done();
        time_out(&mut r);
        hook_ran(&rx);
        assert!(push.was_handed_off());
        // A proof after the timeout changes nothing: Reticulum-rust will not
        // deliver a concluded receipt, and the push has already moved on.
        let mut late = r.clone();
        let mut proof = late.hash.clone();
        proof.extend_from_slice(&device.sign(&late.hash));
        assert!(!late.validate_proof(&proof));
        assert!(!push.is_proved());
    }

    #[test]
    fn a_proved_receipt_delivers_the_push() {
        let device = Identity::new(true);
        let (push, _rx) = outcome();
        let mut r = receipt(&device, 0x12);
        push.receipt_pending();
        tie_receipt(&r, &push);
        push.dispatch_done();
        prove(&mut r, &device);
        assert!(push.is_proved());
        assert!(!push.was_handed_off(), "a proved push is never handed off");
    }

    /// The proof beat `tie_receipt` (a fast device on a LAN): the late
    /// registration still counts it, and the push is not handed off.
    #[test]
    fn a_proof_before_the_callbacks_are_tied_still_counts() {
        let device = Identity::new(true);
        let (push, _rx) = outcome();
        let mut r = receipt(&device, 0x13);
        push.receipt_pending();
        prove(&mut r, &device);
        tie_receipt(&r, &push);
        push.dispatch_done();
        // The late registration runs on its own thread.
        settle(&push);
        assert!(push.is_proved(), "the late-registered delivery callback ran");
        assert!(!push.was_handed_off());
    }

    #[test]
    fn one_proving_link_is_enough() {
        let device = Identity::new(true);
        let (push, _rx) = outcome();
        let mut a = receipt(&device, 0x14);
        let mut b = receipt(&device, 0x15);
        push.receipt_pending();
        tie_receipt(&a, &push);
        push.receipt_pending();
        tie_receipt(&b, &push);
        push.dispatch_done();
        time_out(&mut a);
        prove(&mut b, &device);
        // a's timeout callback runs on its own thread; whichever conclusion
        // comes last decides, and b proved.
        settle(&push);
        assert!(!push.was_handed_off(), "the device got it on the other link");
    }

    /// A receipt that times out while the dispatch is still trying the next
    /// link must not end the push: the next link may prove it.
    #[test]
    fn a_timeout_during_dispatch_does_not_end_the_push_early() {
        let (push, _rx) = outcome();
        push.receipt_pending();
        push.timed_out();
        assert!(!push.was_handed_off(), "the dispatch still holds the push open");
        push.receipt_pending();
        push.dispatch_done();
        push.proved();
        assert!(!push.was_handed_off());
    }

    /// Nothing went out: the caller fell through to its next tier at once,
    /// so the hook must not move the blob a second time.
    #[test]
    fn nothing_sent_means_no_hand_off() {
        let (push, _rx) = outcome();
        push.dispatch_done();
        assert!(!push.was_handed_off());
    }

    #[test]
    fn the_stream_registries_never_push_without_a_receipt() {
        let source = include_str!("stream_registry.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(!production.contains(".send_packet("), "a receipt-less link.send_packet cannot tell a live device from a dead one");
        assert_eq!(production.matches("send_with_receipt(&link, payload, &outcome)").count(), 1, "one push path");
        assert_eq!(production.matches("push_on_links(label, matches, payload, on_unproven, &mut stale_links)").count(), 2, "both registries push through it");
    }
}
