//! Reticulum-native notify wake-up dispatch.
//!
//! Sends a msgpack-encoded wake packet to a notify relay node identified by
//! a 32-char lowercase hex destination hash stored in `NotifyRegistration`.
//!
//! The relay is a Reticulum node operated by the app developer and is
//! responsible for forwarding the wake-up to the device via FCM, APNs, SMS,
//! or any other out-of-band channel.  rfed never makes an outbound IP
//! connection — the entire notify path stays within the Reticulum mesh.
//!
//! # Wake packet payload
//! A msgpack-encoded Map sent to the relay containing:
//!   - `receiver`: Binary(16) — subscriber destination hash (always present)
//!   - `sender`:   Binary(16) — publisher destination hash (when available)
//!   - `channel`:  Binary(16) — channel hash (rfed.channel only, omitted for LXMF)
//!
//! No message content is included.
//!
//! # Addressing
//! The wake goes to exactly the registered relay hash, encrypted to the
//! identity that announced it (and to its ratchet, when it announced one).
//! The destination is rebuilt under whichever known relay name derives that
//! hash from that identity: `apns.relay` (apns-bridge) or `rfed.notify`
//! (fcm-bridge). See [`relay_wake_destination`]. Until 2026-09-25 every wake
//! was built as `rfed.notify` under the relay's identity, so iOS wakes went
//! to a hash apns-bridge has not hosted since 61b4f21.
//!
//! # Outcome
//! [`dispatch`] reports whether a packet left. No path, no identity, no
//! matching relay name, and a packet no interface took are drops, logged at
//! NOTICE or WARNING and not retried (DESIGN_PRINCIPLES §3). The first three
//! issue a path request, whose response brings the route and the relay's
//! key for the subscriber's next wake.

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{self, Packet, PacketReceipt};
use reticulum_rust::transport::{self, Transport};
use reticulum_rust::{decode_hex, hexrep, log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use super::NotifyRegistration;

/// The names a notify relay hosts its wake endpoint under, as
/// `(app_name, aspect)`. `apns.relay` is apns-bridge's (since 61b4f21);
/// `rfed.notify` is fcm-bridge's and the original name. A relay under any
/// other name is reported and not woken until it is added here.
const RELAY_WAKE_NAMES: [(&str, &str); 2] = [("apns", "relay"), ("rfed", "notify")];

/// Where a wake went, or why it did not leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WakeOutcome {
    /// An interface took the packet. Holds the packet's own destination hash.
    Sent(Vec<u8>),
    /// Nothing left, and the reason was logged.
    Dropped(LoggedDrop),
}

impl WakeOutcome {
    pub fn is_sent(&self) -> bool {
        matches!(self, WakeOutcome::Sent(_))
    }

    /// Why the wake did not leave, if it did not.
    pub fn drop_reason(&self) -> Option<WakeDrop> {
        match self {
            WakeOutcome::Sent(_) => None,
            WakeOutcome::Dropped(drop) => Some(drop.reason()),
        }
    }
}

pub use logged::LoggedDrop;

mod logged {
    use reticulum_rust::{hexrep, log};

    use super::WakeDrop;

    /// A drop whose log line has been written. [`LoggedDrop::log`] is the only
    /// way to make one, from anywhere in this file too, so no early return in
    /// `dispatch` can drop a wake without saying so (X7).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct LoggedDrop(WakeDrop);

    impl LoggedDrop {
        pub(super) fn log(reason: WakeDrop, relay: &str, sub_hash: &[u8], detail: &str) -> Self {
            log(
                format!(
                    "[notify/rns] wake NOT sent to relay={} for subscriber={}: {}",
                    relay,
                    hexrep(sub_hash, false),
                    detail,
                ),
                reason.log_level(),
                false,
                false,
            );
            LoggedDrop(reason)
        }

        pub fn reason(self) -> WakeDrop {
            self.0
        }
    }
}

/// Why a wake did not leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeDrop {
    /// The registration's relay hash is not 32 hex chars.
    InvalidRelayHash,
    /// No path to the relay. A path request was issued.
    NoPath,
    /// A path, but no identity recalled for the relay hash. A path request
    /// was issued.
    NoIdentity,
    /// The recalled identity derives the relay hash under none of
    /// [`RELAY_WAKE_NAMES`]: a relay under another name, or a recalled key
    /// that is not the relay's. A path request was issued.
    NoMatchingDestination,
    /// The packet could not be packed, or no interface took it.
    NotTransmitted,
}

impl WakeDrop {
    /// The level the drop is logged at. All of them show at rfed's default
    /// level (NOTICE): until 2026-09-25 no path and no identity were DEBUG
    /// lines and still counted as notified (X7). The routing drops are
    /// NOTICE; the rest are faults.
    pub fn log_level(self) -> i32 {
        match self {
            WakeDrop::NoPath | WakeDrop::NoIdentity => LOG_NOTICE,
            WakeDrop::InvalidRelayHash
            | WakeDrop::NoMatchingDestination
            | WakeDrop::NotTransmitted => LOG_WARNING,
        }
    }
}

/// What a wake needs from the running Reticulum stack: [`LiveStack`] in
/// production, a fake in the tests.
pub trait RelayStack {
    fn has_path(&self, destination_hash: &[u8]) -> bool;
    fn request_path(&self, destination_hash: &[u8]);
    fn recall(&self, destination_hash: &[u8]) -> Option<Identity>;
    /// Hand the packet to Transport. `Ok(true)` only if an interface took it:
    /// `Packet::send` also returns `Ok(None)` when none did.
    fn send(&self, packet: &mut Packet) -> Result<bool, String>;
    /// Hand the packet to Transport with a delivery receipt. `Ok(Some)` only
    /// if an interface took it; the receipt then concludes on the
    /// recipient's proof or on the RNS receipt timeout.
    fn send_with_receipt(&self, packet: &mut Packet) -> Result<Option<PacketReceipt>, String>;
}

pub struct LiveStack;

impl RelayStack for LiveStack {
    fn has_path(&self, destination_hash: &[u8]) -> bool {
        Transport::has_path(destination_hash)
    }

    fn request_path(&self, destination_hash: &[u8]) {
        Transport::request_path(destination_hash, None, None, None, None);
    }

    fn recall(&self, destination_hash: &[u8]) -> Option<Identity> {
        Identity::recall(destination_hash)
    }

    fn send(&self, packet: &mut Packet) -> Result<bool, String> {
        packet.send().map(|_| packet.sent)
    }

    fn send_with_receipt(&self, packet: &mut Packet) -> Result<Option<PacketReceipt>, String> {
        packet.create_receipt = true;
        let receipt = packet.send()?;
        Ok(if packet.sent { receipt } else { None })
    }
}

/// Send a msgpack wake packet to the registered notify relay and report
/// whether it left.
///
/// Runs on the caller's thread and never waits on the network (§7): the
/// lookups are local and `Transport::outbound` hands the packet to the
/// interface's writer. Until 2026-09-25 this spawned a thread and returned
/// nothing, so a wake counted as sent whenever a registration existed (X7).
/// It is a packet send: do not call it holding a registry lock.
pub fn dispatch(
    stack: &dyn RelayStack,
    reg: &NotifyRegistration,
    sender: Option<&[u8]>,
    channel: Option<&[u8]>,
) -> WakeOutcome {
    let relay = reg.relay_hash.as_str();
    let sub_hash = reg.subscriber_hash.as_slice();

    let relay_hash = match decode_hex(relay) {
        Some(hash) if hash.len() == 16 => hash,
        _ => return dropped(WakeDrop::InvalidRelayHash, relay, sub_hash, "invalid relay hash"),
    };

    if !stack.has_path(&relay_hash) {
        stack.request_path(&relay_hash);
        return dropped(WakeDrop::NoPath, relay, sub_hash, "no path to relay, path request issued");
    }

    let identity = match stack.recall(&relay_hash) {
        Some(identity) => identity,
        None => {
            stack.request_path(&relay_hash);
            return dropped(
                WakeDrop::NoIdentity,
                relay,
                sub_hash,
                "relay identity not known, path request issued",
            );
        }
    };

    let destination = match relay_wake_destination(&identity, &relay_hash) {
        Some(destination) => destination,
        None => {
            // Usually a stale key, not a strange relay: until 2026-09-25
            // registration stored the subscriber's key for every relay hash,
            // and known_destinations persists it. The path response is the
            // relay's announce, and Reticulum-rust stores the announced key
            // over the old one, so the next wake can derive the hash. This
            // wake is still dropped: the request is not a retry (§3).
            stack.request_path(&relay_hash);
            let names: Vec<String> = RELAY_WAKE_NAMES
                .iter()
                .map(|(app_name, aspect)| format!("{app_name}.{aspect}"))
                .collect();
            return dropped(
                WakeDrop::NoMatchingDestination,
                relay,
                sub_hash,
                &format!(
                    "recalled identity {} derives this hash under none of {}, path request issued",
                    identity.hash.as_deref().map(|h| hexrep(h, false)).unwrap_or_default(),
                    names.join(", "),
                ),
            );
        }
    };

    let mut packet = Packet::new(
        Some(destination),
        encode_wake_payload(sub_hash, sender, channel),
        packet::DATA,
        packet::NONE,
        transport::BROADCAST,
        packet::HEADER_1,
        None,
        None,
        false,
        packet::FLAG_UNSET,
    );

    match stack.send(&mut packet) {
        Ok(true) => {
            // The hash the packet was packed with, not the registration's:
            // the two differed for every iOS wake until 2026-09-25.
            let sent_to = packet.destination_hash.clone().unwrap_or_default();
            log(
                format!(
                    "[notify/rns] wake sent to {} (registered relay={}) for subscriber={}",
                    hexrep(&sent_to, false),
                    relay,
                    hexrep(sub_hash, false),
                ),
                LOG_DEBUG,
                false,
                false,
            );
            WakeOutcome::Sent(sent_to)
        }
        Ok(false) => dropped(WakeDrop::NotTransmitted, relay, sub_hash, "no interface took the packet"),
        Err(e) => dropped(WakeDrop::NotTransmitted, relay, sub_hash, &format!("send failed: {e}")),
    }
}

fn dropped(reason: WakeDrop, relay: &str, sub_hash: &[u8], detail: &str) -> WakeOutcome {
    WakeOutcome::Dropped(LoggedDrop::log(reason, relay, sub_hash, detail))
}

/// The wake destination for `relay_hash`, built from the relay's recalled
/// identity under whichever of [`RELAY_WAKE_NAMES`] derives exactly that hash.
///
/// Why a name, not the registered hash forced onto a destination: an RNS
/// destination hash is derived from a name and an identity (RNS/Destination.py
/// never takes one), and that derivation is the only check that the recalled
/// key is the relay's. A forced hash would encrypt to whatever key was
/// recalled, including the subscriber's key that registration stored for the
/// relay hash until 2026-09-25, and the relay could not read the wake.
/// Requiring an exact match fails closed instead, and loudly.
///
/// The ratchet follows the hash: `Destination::encrypt` looks it up by the
/// destination's own hash, which is now the registered one.
pub fn relay_wake_destination(identity: &Identity, relay_hash: &[u8]) -> Option<Destination> {
    RELAY_WAKE_NAMES.iter().find_map(|(app_name, aspect)| {
        Destination::new_outbound(
            Some(identity.clone()),
            DestinationType::Single,
            app_name.to_string(),
            vec![aspect.to_string()],
        )
        .ok()
        .filter(|destination| destination.hash == relay_hash)
    })
}

/// At registration, record the registrant's key as the relay's only when the
/// registrant hosts the relay itself: its key derives `relay_hash` under a
/// relay name. Such a relay need not have announced. Returns whether the key
/// was recorded.
///
/// Until 2026-09-25 registration stored the registrant's key for every relay
/// hash. For a bridge relay (apns-bridge, fcm-bridge) that is the
/// subscriber's key, not the relay's, and rfed recalled it for the relay
/// until the relay's next announce replaced it.
pub fn remember_self_hosted_relay(relay_hash: &[u8], registrant_pubkey: &[u8]) -> bool {
    let registrant = match Identity::from_public_key(registrant_pubkey) {
        Ok(identity) => identity,
        Err(_) => return false,
    };
    if relay_wake_destination(&registrant, relay_hash).is_none() {
        return false;
    }
    let _ = Identity::remember_destination(relay_hash, registrant_pubkey, None);
    true
}

fn encode_wake_payload(
    sub_hash: &[u8],
    sender: Option<&[u8]>,
    channel: Option<&[u8]>,
) -> Vec<u8> {
    let mut entries = vec![
        (
            rmpv::Value::String("receiver".into()),
            rmpv::Value::Binary(sub_hash.to_vec()),
        ),
    ];
    if let Some(s) = sender {
        entries.push((
            rmpv::Value::String("sender".into()),
            rmpv::Value::Binary(s.to_vec()),
        ));
    }
    if let Some(c) = channel {
        entries.push((
            rmpv::Value::String("channel".into()),
            rmpv::Value::Binary(c.to_vec()),
        ));
    }
    let mut payload = Vec::new();
    let _ = rmpv::encode::write_value(&mut payload, &rmpv::Value::Map(entries));
    payload
}

/// A [`RelayStack`] that knows one relay hash, for this module's tests and the
/// notify counting tests in `lxmf_propagation`.
#[cfg(test)]
pub(crate) mod fake {
    use std::sync::Mutex;

    use reticulum_rust::identity::Identity;
    use reticulum_rust::packet::{Packet, PacketReceipt};

    use super::RelayStack;

    pub(crate) struct FakeStack {
        relay_hash: Vec<u8>,
        path: bool,
        identity: Option<Identity>,
        transmits: bool,
        pub(crate) path_requests: Mutex<Vec<Vec<u8>>>,
        /// Every packet handed to `send`, packed: `(raw, ratchet_id)`.
        pub(crate) packets: Mutex<Vec<(Vec<u8>, Option<Vec<u8>>)>>,
        /// The receipt of every packet `send_with_receipt` transmitted, for
        /// the test to prove or time out.
        pub(crate) receipts: Mutex<Vec<PacketReceipt>>,
    }

    impl FakeStack {
        /// A path to `relay_hash`, `identity` recalled for it, and an
        /// interface that takes whatever is sent.
        pub(crate) fn new(relay_hash: &[u8], identity: Option<Identity>) -> Self {
            FakeStack {
                relay_hash: relay_hash.to_vec(),
                path: true,
                identity,
                transmits: true,
                path_requests: Mutex::new(Vec::new()),
                packets: Mutex::new(Vec::new()),
                receipts: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn without_path(mut self) -> Self {
            self.path = false;
            self
        }

        pub(crate) fn without_interface(mut self) -> Self {
            self.transmits = false;
            self
        }
    }

    impl RelayStack for FakeStack {
        fn has_path(&self, destination_hash: &[u8]) -> bool {
            self.path && destination_hash == self.relay_hash.as_slice()
        }

        fn request_path(&self, destination_hash: &[u8]) {
            self.path_requests.lock().unwrap().push(destination_hash.to_vec());
        }

        fn recall(&self, destination_hash: &[u8]) -> Option<Identity> {
            if destination_hash == self.relay_hash.as_slice() {
                self.identity.clone()
            } else {
                None
            }
        }

        fn send(&self, packet: &mut Packet) -> Result<bool, String> {
            packet.pack()?;
            self.packets
                .lock()
                .unwrap()
                .push((packet.raw.clone(), packet.ratchet_id.clone()));
            Ok(self.transmits)
        }

        fn send_with_receipt(&self, packet: &mut Packet) -> Result<Option<PacketReceipt>, String> {
            if !self.send(packet)? {
                return Ok(None);
            }
            let receipt = PacketReceipt::new_with_timeout(packet, 3600.0);
            self.receipts.lock().unwrap().push(receipt.clone());
            Ok(Some(receipt))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    use reticulum_rust::destination::Destination;
    use reticulum_rust::identity::Identity;
    use reticulum_rust::{hexrep, LOG_NOTICE, LOG_STDOUT};
    use rmpv::decode::read_value;
    use rmpv::Value;

    use super::fake::FakeStack;
    use super::{
        dispatch, encode_wake_payload, remember_self_hosted_relay, WakeDrop, WakeOutcome,
    };
    use crate::notify::NotifyRegistration;

    const SUBSCRIBER: [u8; 16] = [0x55; 16];
    const SENDER: [u8; 16] = [0x66; 16];
    /// Header 1 packet: flags, hops, destination hash, context, ciphertext.
    const DEST_HASH_AT: std::ops::Range<usize> = 2..18;
    const CIPHERTEXT_AT: usize = 19;

    fn map_entry<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
        map.iter()
            .find(|(candidate, _)| candidate.as_str() == Some(key))
            .map(|(_, value)| value)
    }

    fn relay_hash(identity: &Identity, app_name: &str, aspect: &str) -> Vec<u8> {
        Destination::hash(identity.hash.as_deref(), app_name, &[aspect])
    }

    /// What rfed recalls for a relay: its public key only, as an announce
    /// leaves it in the known destinations.
    fn recalled(identity: &Identity) -> Identity {
        Identity::from_public_key(&identity.get_public_key().expect("public key"))
            .expect("identity from public key")
    }

    fn registration(relay_hash: &[u8]) -> NotifyRegistration {
        NotifyRegistration {
            subscriber_hash: SUBSCRIBER.to_vec(),
            channel_hash: None,
            relay_hash: hexrep(relay_hash, false),
            registered: 0.0,
        }
    }

    fn only_packet(stack: &FakeStack) -> (Vec<u8>, Option<Vec<u8>>) {
        let packets = stack.packets.lock().unwrap();
        assert_eq!(packets.len(), 1, "exactly one wake packet");
        packets[0].clone()
    }

    fn assert_receiver_is_subscriber(plaintext: &[u8]) {
        let map = match read_value(&mut Cursor::new(plaintext)).expect("decode wake payload") {
            Value::Map(map) => map,
            other => panic!("expected map, got {other:?}"),
        };
        assert_eq!(map_entry(&map, "receiver"), Some(&Value::Binary(SUBSCRIBER.to_vec())));
    }

    /// U1: the wake is addressed to exactly the hash the device registered,
    /// and the relay that registered it can read it.
    fn assert_wake_reaches_the_registered_hash(app_name: &str, aspect: &str) {
        let mut relay = Identity::new(true);
        let registered = relay_hash(&relay, app_name, aspect);
        let stack = FakeStack::new(&registered, Some(recalled(&relay)));

        let outcome = dispatch(&stack, &registration(&registered), Some(&SENDER), None);

        assert_eq!(
            outcome,
            WakeOutcome::Sent(registered.clone()),
            "a wake for a {app_name}.{aspect} registration must be addressed to the registered hash",
        );
        let (raw, _) = only_packet(&stack);
        assert_eq!(&raw[DEST_HASH_AT], registered.as_slice(), "the packet header's destination hash");
        let plaintext = relay
            .decrypt(&raw[CIPHERTEXT_AT..])
            .expect("the relay decrypts its wake");
        assert_receiver_is_subscriber(&plaintext);
    }

    /// apns-bridge hosts only apns.relay: every iOS wake went to rfed.notify
    /// under its identity instead until 2026-09-25.
    #[test]
    fn wake_packet_is_addressed_to_the_registered_relay_hash_apns_relay() {
        assert_wake_reaches_the_registered_hash("apns", "relay");
    }

    /// fcm-bridge hosts rfed.notify, the name the wake was always built under.
    #[test]
    fn wake_packet_is_addressed_to_the_registered_relay_hash_rfed_notify() {
        assert_wake_reaches_the_registered_hash("rfed", "notify");
    }

    /// Ratchets are looked up by destination hash, so a wake addressed to the
    /// registered hash is encrypted to the ratchet that relay announced.
    #[test]
    fn wake_uses_the_ratchet_the_registered_relay_announced() {
        let mut relay = Identity::new(true);
        let registered = relay_hash(&relay, "apns", "relay");
        let ratchet_prv = Identity::new(true).get_private_key().expect("key")[..32].to_vec();
        let ratchet_pub = Identity::ratchet_public_bytes(&ratchet_prv).expect("ratchet public key");
        Identity::remember_ratchet(&registered, &ratchet_pub).expect("remember ratchet");
        let stack = FakeStack::new(&registered, Some(recalled(&relay)));

        let outcome = dispatch(&stack, &registration(&registered), None, None);

        assert!(outcome.is_sent(), "{outcome:?}");
        let (raw, ratchet_id) = only_packet(&stack);
        assert_eq!(
            ratchet_id,
            Some(Identity::ratchet_id_from_pub(&ratchet_pub)),
            "encrypted to the relay's announced ratchet",
        );
        let plaintext = relay
            .decrypt_with_ratchets(&raw[CIPHERTEXT_AT..], Some(&[ratchet_prv]))
            .expect("the relay decrypts with its ratchet");
        assert_receiver_is_subscriber(&plaintext);
    }

    /// A relay under a name rfed does not know: reported, never sent to a
    /// destination it cannot derive.
    #[test]
    fn a_relay_under_an_unknown_name_is_reported_and_not_sent() {
        let relay = Identity::new(true);
        let registered = relay_hash(&relay, "someapp", "push");
        let stack = FakeStack::new(&registered, Some(recalled(&relay)));

        let outcome = dispatch(&stack, &registration(&registered), None, None);

        assert_eq!(outcome.drop_reason(), Some(WakeDrop::NoMatchingDestination));
        assert!(stack.packets.lock().unwrap().is_empty(), "nothing is sent");
    }

    /// The key recalled for an apns.relay hash is someone else's (the
    /// subscriber's, as registration stored it until 2026-09-25): not sent,
    /// and a path request fetches the relay's announce, whose key replaces it.
    #[test]
    fn a_recalled_key_that_is_not_the_relays_is_not_sent_to() {
        let relay = Identity::new(true);
        let subscriber = Identity::new(true);
        let registered = relay_hash(&relay, "apns", "relay");
        let stack = FakeStack::new(&registered, Some(recalled(&subscriber)));

        let outcome = dispatch(&stack, &registration(&registered), None, None);

        assert_eq!(outcome.drop_reason(), Some(WakeDrop::NoMatchingDestination));
        assert!(stack.packets.lock().unwrap().is_empty(), "nothing is sent");
        assert_eq!(
            *stack.path_requests.lock().unwrap(),
            vec![registered],
            "the path response carries the relay's own key",
        );
    }

    /// X7: no path is a drop with a path request for the registered hash.
    #[test]
    fn no_path_is_a_drop_with_a_path_request() {
        let relay = Identity::new(true);
        let registered = relay_hash(&relay, "apns", "relay");
        let stack = FakeStack::new(&registered, Some(recalled(&relay))).without_path();

        let outcome = dispatch(&stack, &registration(&registered), None, None);

        assert_eq!(outcome.drop_reason(), Some(WakeDrop::NoPath));
        assert!(stack.packets.lock().unwrap().is_empty(), "nothing is sent");
        assert_eq!(*stack.path_requests.lock().unwrap(), vec![registered]);
    }

    /// X7: a path but no identity is a drop with a path request.
    #[test]
    fn no_identity_is_a_drop_with_a_path_request() {
        let relay = Identity::new(true);
        let registered = relay_hash(&relay, "apns", "relay");
        let stack = FakeStack::new(&registered, None);

        let outcome = dispatch(&stack, &registration(&registered), None, None);

        assert_eq!(outcome.drop_reason(), Some(WakeDrop::NoIdentity));
        assert!(stack.packets.lock().unwrap().is_empty(), "nothing is sent");
        assert_eq!(*stack.path_requests.lock().unwrap(), vec![registered]);
    }

    /// X7: `Packet::send` returns `Ok` when no interface took the packet.
    /// That is not a wake.
    #[test]
    fn a_packet_no_interface_took_is_not_a_wake() {
        let relay = Identity::new(true);
        let registered = relay_hash(&relay, "rfed", "notify");
        let stack = FakeStack::new(&registered, Some(recalled(&relay))).without_interface();

        let outcome = dispatch(&stack, &registration(&registered), None, None);

        assert_eq!(outcome.drop_reason(), Some(WakeDrop::NotTransmitted));
    }

    /// Puts the log back on stdout when the capturing test ends, pass or fail.
    struct LogToStdoutOnDrop;

    impl Drop for LogToStdoutOnDrop {
        fn drop(&mut self) {
            reticulum_rust::set_logdest(LOG_STDOUT);
        }
    }

    /// X7: every drop writes a line rfed shows at its default level, NOTICE:
    /// the routing drops at NOTICE, the faults at WARNING. Until 2026-09-25
    /// no path and no identity were DEBUG lines.
    ///
    /// The only test that captures the log, because the log is process-wide.
    /// Lines from tests running alongside are told apart by relay hash.
    #[test]
    fn every_drop_is_logged_at_a_level_shown_by_default() {
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&lines);
        reticulum_rust::set_loglevel(LOG_NOTICE);
        reticulum_rust::ffi::set_log_callback(move |line| {
            if let Ok(mut lines) = sink.lock() {
                lines.push(line);
            }
        });
        let _restore = LogToStdoutOnDrop;

        let wake_line = |registration: &NotifyRegistration| -> Vec<String> {
            let marker = format!("wake NOT sent to relay={} ", registration.relay_hash);
            let captured = lines.lock().unwrap().clone();
            captured.into_iter().filter(|line| line.contains(&marker)).collect()
        };
        let a_relay = |app_name: &str, aspect: &str| {
            let relay = Identity::new(true);
            let hash = relay_hash(&relay, app_name, aspect);
            (recalled(&relay), hash)
        };

        let (identity, hash) = a_relay("apns", "relay");
        let no_path = (FakeStack::new(&hash, Some(identity)).without_path(), registration(&hash));
        let (_, hash) = a_relay("apns", "relay");
        let no_identity = (FakeStack::new(&hash, None), registration(&hash));
        let (identity, hash) = a_relay("someapp", "push");
        let no_name = (FakeStack::new(&hash, Some(identity)), registration(&hash));
        let (identity, hash) = a_relay("rfed", "notify");
        let no_interface = (
            FakeStack::new(&hash, Some(identity)).without_interface(),
            registration(&hash),
        );
        let (_, hash) = a_relay("apns", "relay");
        let mut invalid = registration(&hash);
        invalid.relay_hash = format!("{}zz", &invalid.relay_hash[2..]);
        let invalid = (FakeStack::new(&hash, None), invalid);

        for ((stack, registration), reason, tag) in [
            (no_path, WakeDrop::NoPath, "[Notice]"),
            (no_identity, WakeDrop::NoIdentity, "[Notice]"),
            (no_name, WakeDrop::NoMatchingDestination, "[Warning]"),
            (no_interface, WakeDrop::NotTransmitted, "[Warning]"),
            (invalid, WakeDrop::InvalidRelayHash, "[Warning]"),
        ] {
            let outcome = dispatch(&stack, &registration, None, None);

            assert_eq!(outcome.drop_reason(), Some(reason));
            let logged = wake_line(&registration);
            assert_eq!(logged.len(), 1, "{reason:?} writes exactly one line at NOTICE or above: {logged:?}");
            assert!(logged[0].contains(tag), "{reason:?} is logged at {tag}: {}", logged[0]);
        }
    }

    /// Registration signs with the subscriber's key. That key is the relay's
    /// only when the subscriber hosts the relay itself.
    #[test]
    fn registration_records_the_registrants_key_only_for_a_relay_it_hosts() {
        let subscriber = Identity::new(true);
        let subscriber_pubkey = subscriber.get_public_key().expect("public key");

        let bridge = Identity::new(true);
        let bridge_relay = relay_hash(&bridge, "apns", "relay");
        assert!(!remember_self_hosted_relay(&bridge_relay, &subscriber_pubkey));
        assert!(
            Identity::recall(&bridge_relay).is_none(),
            "a bridge relay's hash must not be bound to the subscriber's key",
        );

        let own_relay = relay_hash(&subscriber, "rfed", "notify");
        assert!(remember_self_hosted_relay(&own_relay, &subscriber_pubkey));
        assert_eq!(
            Identity::recall(&own_relay).and_then(|identity| identity.hash),
            subscriber.hash,
            "a relay the subscriber hosts is recalled with its key",
        );
    }

    #[test]
    fn wake_payload_uses_binary_hash_fields() {
        let receiver = [0x11u8; 16];
        let sender = [0x22u8; 16];
        let channel = [0x33u8; 16];

        let payload = encode_wake_payload(&receiver, Some(&sender), Some(&channel));
        let value = read_value(&mut Cursor::new(payload)).expect("decode wake payload");
        let map = match value {
            Value::Map(map) => map,
            other => panic!("expected map, got {other:?}"),
        };

        assert_eq!(map_entry(&map, "receiver"), Some(&Value::Binary(receiver.to_vec())));
        assert_eq!(map_entry(&map, "sender"), Some(&Value::Binary(sender.to_vec())));
        assert_eq!(map_entry(&map, "channel"), Some(&Value::Binary(channel.to_vec())));
    }

    #[test]
    fn wake_payload_omits_optional_fields_when_absent() {
        let receiver = [0x44u8; 16];

        let payload = encode_wake_payload(&receiver, None, None);
        let value = read_value(&mut Cursor::new(payload)).expect("decode wake payload");
        let map = match value {
            Value::Map(map) => map,
            other => panic!("expected map, got {other:?}"),
        };

        assert_eq!(map.len(), 1);
        assert_eq!(map_entry(&map, "receiver"), Some(&Value::Binary(receiver.to_vec())));
        assert_eq!(map_entry(&map, "sender"), None);
        assert_eq!(map_entry(&map, "channel"), None);
    }
}
