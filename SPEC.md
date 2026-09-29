# rfed — Reticulum Federation Node

> **Version 0.1.0** · Protocol version 1
>
> **AI-Assisted Development**: This project was developed with significant
> assistance from AI language models (Claude / GitHub Copilot). Architecture
> decisions, implementation, code review, and this specification were produced
> through an iterative human–AI collaboration. All code has been reviewed and
> tested by the human author.

## Overview

**rfed** is a store-and-forward federation node for the
[Reticulum](https://reticulum.network) network. It provides named **channel**
messaging with offline delivery, cross-node synchronisation, notify
wake-ups, and subscriber backup failover — all running over Reticulum's
encrypted transport layer.

Nodes form a loosely-coupled mesh: each node independently accepts blobs,
fans them out to local subscribers, and synchronises with peers. There is no
central coordinator. Any node can join or leave the federation at any time.

### Design Principles

- **Dumb store, smart clients** — the node never interprets blob content.
  Channels exist by virtue of blobs stored against their hash.
- **Sender anonymity** — Reticulum Single destinations carry no sender identity
  in the wire header. LXMF optionally embeds sender inside the encrypted
  envelope.
- **Zero server-side channel registration** — any party that knows a channel
  name can independently derive its hash and publish/subscribe.
- **Encrypted at every hop** — all data packets use `DestinationType::Single`
  (asymmetric encryption). No plaintext broadcasts.

---

### TL-DR Summary
- Channel participants get the plaintext address which translates into the public and private keys
- Sender creates an LXMF packet addressed to and encrypted for the channel. Now it includes the prelude for ID verification
- Sender wraps that packet in a Reticulum packet addressed to his RFed node
- RFed node unwraps the packet and rewraps it in a Reticulum packet addressed to each subscriber
- The subscriber unwraps the packet and gets the LXMF packet addressed to the channel
- The subscriber uses the Channel credentials to decrypt the message. He has the prelude and signing from the sender to verify the identity of the sender

---

## CANONICAL WIRE FORMAT — ULTIMATE AUTHORITY

> **THIS SECTION IS THE ONE TRUE SOURCE OF TRUTH FOR THE CHANNEL
> MESSAGE FORMAT. If any other section, comment, or document
> disagrees with this one, this section wins and the other one is a
> bug. Update this section *first*, then propagate.**

### The four nested envelopes (sender → subscriber)

A channel message is a propagation-style LXMF message wrapped in two
Reticulum hops (sender → RFed node, RFed node → each subscriber). All
encryption is asymmetric (`DestinationType::Single`); RFed is dumb and
never decrypts the payload.

```
Layer 4 (innermost — application):
    plaintext = [ "RTID"(4) | sender_identity_pub(64) | LXMF_tail ]
    where
        sender_identity_pub = Identity::get_public_key()           (32 X25519 enc || 32 Ed25519 sign)
        LXMF_tail           = source_hash(16) | signature(64) | msgpack_payload
        source_hash         = the sender's lxmf.delivery DESTINATION hash
                            = truncated_hash( name_hash("lxmf.delivery") || identity_hash )
                              — NOT truncated_hash(sender_identity_pub).
        msgpack_payload     = the LXMF payload; its fields map may carry the
                              Retichat field 0xD1 (FIELD_RETICHAT, a map) whose
                              key 0 is the poster's Channel Display Name (see
                              "Display name" below).

Layer 3 (LXMF EC envelope, addressed to the CHANNEL identity):
    inner_blob = EC_encrypt( channel_identity.X25519_pub , plaintext )
               = ephemeral_pub(32) | ciphertext | hmac
    Channel identity is derived deterministically from the channel name —
    see §1. Channel Hash Derivation. All subscribers + the sender hold
    the channel private key.

Layer 2 (RFed wire payload, what the sender PUTs to /rfed/send):
    rfed_payload = [ channel_hash(16) | inner_blob | stamp(32) ]
    channel_hash = the channel's identity hash (16 B), used by RFed
                   purely as a routing label; subscribers proved knowledge
                   of it via signed /rfed/subscribe.
    stamp        = LXMF PoW stamp over
                   sha256( channel_hash(16) || inner_blob ), with
                   STAMP_EXPAND_ROUNDS = 16 (see PoW STAMP CONTRACT below).

Layer 1 (Reticulum transport — first hop):
    Reticulum DATA packet, DestinationType::Single, addressed to
    rfed.send (the RFed node's send endpoint). RFed decrypts the outer
    Reticulum envelope with its node identity, validates the stamp,
    strips it, and stores `inner_blob` keyed by channel_hash.

Layer 1' (Reticulum transport — fanout hop, one per subscriber):
    For every subscriber S of channel_hash, RFed sends a Reticulum
    DATA packet, DestinationType::Single, addressed to S's
    rfed.delivery endpoint, with payload:
        [ channel_hash(16) | inner_blob ]
    (No stamp on the fanout hop — stamp was already validated at ingest.)
```

### Subscriber decode (exact inverse)

1. Reticulum decrypts the outer packet with the subscriber's node
   identity → exposes `[ channel_hash(16) | inner_blob ]`.
2. Look up `channel_hash` in the subscriber's local channel table to
   find the matching channel name and re-derive the channel identity
   (private key + public key) per §1.
3. EC-decrypt `inner_blob` with the **channel** private key → recover
   the Layer-4 plaintext.
4. Verify magic `"RTID"` and split off the 64-byte
   `sender_identity_pub`. **Do NOT compare
   `truncated_hash(sender_identity_pub)` against `source_hash` — those
   are different hashes.** `source_hash` is the lxmf.delivery
   destination hash; the bare identity hash is just one of its inputs.
5. **Key binding (MUST, before step 6).** Compute the `lxmf.delivery`
   destination hash of `sender_identity_pub`
   (`truncated_hash(name_hash("lxmf.delivery") || truncated_hash(sender_identity_pub))`)
   and compare it with `source_hash`. On mismatch reject the post and
   remember nothing (LXMF-rust/DISPLAY_NAMES.md §2.3).
6. Call `Identity::remember_destination(source_hash, sender_identity_pub, None)`
   to populate Reticulum's known-destinations cache.
7. Prepend the channel's `lxmf.delivery` destination hash to the
   LXMF tail and feed to
   `LXMessage::unpack_from_bytes(_, Some(PROPAGATED))`.
8. LXMF Ed25519 signature validation runs against the just-cached
   `sender_identity_pub`. **This is the integrity check of the post** —
   a forged `sender_identity_pub` produces `SIGNATURE_INVALID`. It does
   **not** protect the cache: the channel private key is derived from the
   channel name, so anyone who knows the name reaches step 3, and without
   step 5 a post claiming a contact's `source_hash` would overwrite that
   contact's stored key. Step 5 is what prevents that.
9. Only if steps 5 and 8 passed, read key 0 of `0xD1` from the fields (below).

`lxmf_rust::channel::unpack` implements steps 2–9 (and `pack` the
sender side) for both Retichat bridges.

### Display name (key 0 of field 0xD1)

The LXMF message may carry the Retichat field `0xD1` (`FIELD_RETICHAT`),
a msgpack map. Its key 0 is the poster's Channel Display Name as msgpack
bin (receivers accept bin or str), or a zero-length value meaning "no
name now": `{0xD1: {0: <name or empty>}}`. A `0xD1` that is not a map is
ignored whole. No key 0 means the post carries no name. Receivers use it only after the key binding and the
signature pass, and store it per `(channel, sender)`. The contract,
including when a client includes it, is LXMF-rust/DISPLAY_NAMES.md
(§2.3, §4.2, §5.2). RFed never sees it.

### Why the prelude exists

Without it, `LXMessage::unpack(PROPAGATED)` rejects the message as
`SOURCE_UNKNOWN` whenever the sender's `lxmf.delivery` announce hasn't
recently traversed the receiver — the same announce-timing flakiness
that plagues regular LXMF ("have to be online at the right moment").
The prelude embeds the sender pubkey inside the EC envelope, so
signature validation works on the very first message a receiver ever
sees, period.

### Invariants you may NOT break

- **Magic** is the four ASCII bytes `"RTID"`. Not `"RTI "`, not
  little-endian, not length-prefixed.
- **`sender_identity_pub` is 64 bytes** in `Identity::get_public_key()`
  layout. `Identity::from_public_key` is its inverse.
- **`source_hash` is the destination hash, not the identity hash.**
  Repeat: `truncated_hash(name_hash || identity_hash)`, not
  `truncated_hash(public_key)`.
- **The prelude is mandatory.** No legacy fallback path. Receivers
  MUST refuse blobs without `"RTID"`.
- **The prelude key must bind to `source_hash`** (its `lxmf.delivery`
  destination hash equals `source_hash`), checked before it is
  remembered. Receivers MUST reject posts that fail.
- **RFed never inspects the prelude** — it lives inside the EC
  envelope. RFed only sees `[ channel_hash | inner_blob | stamp ]`.
- **`STAMP_EXPAND_ROUNDS = 16`** on every implementation, forever.
  Bumping it silently invalidates every cached `stamp_cost` and
  every in-flight stamp.
- **`stamp_cost` is owned exclusively by `/rfed/subscribe`'s
  `[true, cost_or_nil]` reply.** `Some(0)` means disabled, identical
  to `None`. Re-subscribe per session and on every SEND rejection.

### Bytes-on-the-wire reference (typical)

```
sizeof channel_hash      = 16
sizeof prelude magic     =  4   ("RTID")
sizeof sender_id_pub     = 64
sizeof source_hash       = 16
sizeof signature         = 64
sizeof stamp             = 32
→ inner_blob = ECC overhead(~48) + 4 + 64 + 16 + 64 + msgpack_payload
→ rfed_payload = 16 + inner_blob + 32
```

A "hello" message of ~7 bytes UTF-8 produces `inner_blob ≈ 256`,
`rfed_payload ≈ 304` — confirmed in retichat.log April 25 2026.

---

## Table of Contents

1. [Channel Hash Derivation](#1-channel-hash-derivation)
2. [RNS Destinations & Request Paths](#2-rns-destinations--request-paths)
3. [Wire Formats](#3-wire-formats)
4. [Sync Protocol](#4-sync-protocol)
5. [Blob Storage](#5-blob-storage)
6. [Subscription Table](#6-subscription-table)
7. [Deferred Delivery](#7-deferred-delivery)
8. [Fanout & Double Envelope](#8-fanout--double-envelope)
9. [Notify System](#9-notify-system)
10. [LXMF Propagation Relationship](#10-lxmf-propagation-relationship)
11. [Backup Failover](#11-backup-failover)
12. [Announce Format](#12-announce-format)
13. [Configuration](#13-configuration)
14. [CLI Reference](#14-cli-reference)
15. [Test Suite](#15-test-suite)
16. [Dependencies](#16-dependencies)
17. [Distro](#17-distro)

---

## 1. Channel Hash Derivation

Channels are identified by a deterministic 16-byte hash derived from a
plain-text channel name. Any party that knows the name can independently
compute the same hash — no server-side registration is needed.

### Algorithm

```
seed          = SHA-256(channel_name)                        → 32 bytes
x25519_pub    = X25519_public_key_from(seed)                 → 32 bytes
ed25519_pub   = Ed25519_public_key_from(seed)                → 32 bytes
bundle        = x25519_pub ‖ ed25519_pub                     → 64 bytes
channel_hash  = SHA-256(bundle)[0..16]                       → 16 bytes
```

This mirrors Reticulum's own `Identity` hash derivation: the hash is
computed over the 64-byte public key bundle, then truncated to the first
16 bytes (`TRUNCATED_HASHLENGTH / 8`).

### Rust Implementation

```rust
use sha2::{Digest, Sha256};
use x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519Public};
use ed25519_dalek::{SecretKey as Ed25519Secret, PublicKey as Ed25519Public};

fn channel_hash(name: &str) -> Vec<u8> {
    let seed: [u8; 32] = Sha256::digest(name.as_bytes()).into();

    let x_secret = X25519Secret::from(seed);
    let x_public = X25519Public::from(&x_secret);

    let e_secret = Ed25519Secret::from_bytes(&seed).unwrap();
    let e_public = Ed25519Public::from(&e_secret);

    let mut bundle = Vec::with_capacity(64);
    bundle.extend_from_slice(x_public.as_bytes());
    bundle.extend_from_slice(e_public.as_bytes());

    Sha256::digest(&bundle)[..16].to_vec()
}
```

### Python Implementation

```python
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def compute_channel_hash(name: str) -> bytes:
    seed = hashlib.sha256(name.encode("utf-8")).digest()      # 32 bytes

    x_priv = X25519PrivateKey.from_private_bytes(seed)
    x_pub  = x_priv.public_key().public_bytes_raw()           # 32 bytes

    e_priv = Ed25519PrivateKey.from_private_bytes(seed)
    e_pub  = e_priv.public_key().public_bytes_raw()            # 32 bytes

    bundle = x_pub + e_pub                                     # 64 bytes
    return hashlib.sha256(bundle).digest()[:16]
```

### Naming Convention

| Pattern | Visibility | Example |
|---------|-----------|---------|
| `public.<segments>` | Discoverable by name | `public.news.tech` |
| `<hash>.<segments>` | Private; hash acts as access control | `a1b2c3d4e5f6....<segments>` |

Segments are dot-separated, mirroring Reticulum's aspect notation:

```python
channel_path("public", "news", "tech")           # → "public.news.tech"
channel_path("a1b2c3d4e5f6", "team", "ops")      # → "a1b2c3d4e5f6.team.ops"
```

For **public** channels the first segment is the literal string `"public"`.
Anyone who learns the name can subscribe and decrypt.

For **private** channels, the first segment (the root) is any segment other
than `"public"`: lowercase letters, digits and `-`, no `.`. Clients default
it to 16 lowercase hex characters (64 bits from a CSPRNG) and let the user
edit it, so a shared private channel can be joined by typing or pasting its
full name; entering `root.name` in the name field fills the root and the
name. Since possession of the channel name equals possession of the
decryption key, the random root makes the name impractical to guess.
Distribute the full channel name out-of-band to intended members only.
Existing channels keep their roots (older clients generated 8 hex
characters); nothing in the protocol depends on the root's length.

---

## 2. RNS Destinations & Request Paths

rfed exposes four logical Reticulum service groups under the `rfed` app
namespace. Modern clients should discover and use the split announced
destinations `rfed.channel.subscribe`, `rfed.channel.unsubscribe`,
`rfed.channel.publish`, `rfed.channel.pull`, `rfed.notify.register`, and
`rfed.notify.unregister`. The legacy combined `rfed.channel`, `rfed.delivery`,
and `rfed.notify` surfaces remain wired for compatibility while clients
migrate.

In official Reticulum terminology, these are two separate notations:

- **Destinations** are named by app and aspects, commonly rendered in dot
  notation such as `rfed.channel.subscribe`.
- **Request handlers** on an established link use a separate request-path
  string. RFed follows the slash-prefixed convention used in upstream
  Reticulum examples and built-in handlers, such as `/random/text`, `/status`,
  `/list`, and therefore `/rfed/subscribe`.

| Destination | Aspects | Purpose |
|-------------|---------|---------|
| `rfed.node` | `["node"]` | Peer sync, announces, backup push |
| `rfed.channel` | `["channel"]` | Channel publish / subscribe / pull service family |
| `rfed.delivery` | `["delivery"]` | Live subscriber delivery plus legacy aggregate pull |
| `rfed.notify` | `["notify"]` | Notify relay registration service family |
| `rfed.distro.register` | `["distro", "register"]` | Distro device registration |
| `rfed.distro.unregister` | `["distro", "unregister"]` | Distro device removal |
| `rfed.distro.list` | `["distro", "list"]` | Distro device listing |
| `rfed.link` | `["link"]` | Every operation above, both directions, over one link |

All destinations use `DestinationType::Single` (asymmetric encryption,
multi-hop routed).

### Request Paths

**rfed.node** (peer-to-peer):
| Path | Caller | Payload | Response |
|------|--------|---------|----------|
| `/rfed/offer` | Peer | `msgpack [message_id, ...]` | `msgpack [(channel_hash, message_id), ...]` |
| `/rfed/get` | Peer | `msgpack [message_id, ...]` | Binary blob stream (see §3) |
| `/rfed/backup/push` | Owner node | `msgpack [(sub_hash, ch_hash), ...]` | `msgpack bool` |
| `/rfed/capabilities` | Any | *(ignored)* | `msgpack Map` (see §17) |

**rfed.channel.*** (modern split service destinations):
| Destination | Path | Caller | Payload | Response |
|-------------|------|--------|---------|----------|
| `rfed.channel.subscribe` | `/rfed/subscribe` | Subscriber | `msgpack [bin(16) channel_hash, bin(64) subscriber_pubkey, bin(64) sig(channel_hash)]` | `msgpack [bool ok, uint stamp_cost \| nil]` |
| `rfed.channel.unsubscribe` | `/rfed/unsubscribe` | Subscriber | `msgpack [bin(16) channel_hash, bin(64) subscriber_pubkey, bin(64) sig(channel_hash)]` | `msgpack bool` |
| `rfed.channel.publish` | *(fire-and-forget SEND)* | Publisher | `channel_hash(16) \| inner_blob \| stamp` | *(none)* |
| `rfed.channel.pull` | `/rfed/pull` | Subscriber | `bin(16) channel_hash` or `msgpack bin(16)` | `msgpack [ [[bin(16) channel_hash, bin blob], …], bool more_pending ]` |

**rfed.distro.*** (distro service destinations):
| Destination | Path | Caller | Payload | Response |
|-------------|------|--------|---------|----------|
| `rfed.distro.register` | `/rfed/distro/register` | Device | `msgpack [bin(64) device_pubkey, bin(64) distro_pubkey, bin(64) sig(device_pubkey)]` | `msgpack bool` |
| `rfed.distro.register` | `/rfed/pull` | Device | `msgpack nil` (packed `None`, `0xc0` — a request with no data is still one msgpack value; zero bytes is malformed and unparseable). Caller authenticated by link identity | `msgpack [ [[bin(16) distro_hash, bin blob], …], bool more_pending ]` |
| `rfed.distro.unregister` | `/rfed/distro/unregister` | Device | `msgpack [bin(64) device_pubkey, bin(64) distro_pubkey, bin(64) sig(device_pubkey)]` | `msgpack bool` |
| `rfed.distro.list` | `/rfed/distro/list` | Device | `msgpack [bin(16) distro_identity_hash, bin(64) distro_pubkey, bin(64) sig(distro_identity_hash)]` | `msgpack [bin(16) device_lxmf_hash, ...]` |

**rfed.delivery** (live fanout destination + legacy aggregate pull):
| Path | Caller | Payload | Response |
|------|--------|---------|----------|
| `/rfed/pull` | Subscriber | `msgpack nil` (packed `None`, `0xc0` — a request with no data is still one msgpack value; zero bytes is malformed and unparseable). Caller authenticated by link identity | `msgpack [ [[bin(16) channel_hash, bin blob], …], bool more_pending ]` |

**PULL paging** (user-initiated; mirrors chat-history "Load earlier
messages"): each call drains at most one page (`deferred_pull_batch_limit`
or `DEFAULT_PULL_PAGE_SIZE = 25`) and returns `more_pending = true` when
additional entries remain for the caller. The client offers another
page-load action while `more_pending` is true and stops once it is false.
Drain is destructive on the server side — once a page has been returned
those blobs are gone from this node and will only re-arrive via fanout
from another session or sync from the origin.

**PULL error responses.** PULL is the one rfed request family authenticated
by the caller's **link identity** rather than a signed payload, which exposes
it to the LINKIDENTIFY race: identify is fire-and-forget, so a request can
reach the node before the identify has (the race that moved every other
endpoint to signed payloads in the first place). Error handling therefore
follows the reference LXMF Propagation protocol exactly:

- Unidentified caller → response is a bare msgpack integer `0xF0`
  (`ERROR_NO_IDENTITY`, LXMF/LXMPeer.py) — **never silence**. A node must
  not answer an unidentified PULL by sending nothing: the client cannot
  distinguish that from a dead node and burns its full timeout budget.
  (rfed did exactly this until 2026-08-17.)
- Malformed payload (channel-scoped PULL only) → `0xF4` (`ERROR_INVALID_DATA`).
- Client reaction, per LXMF/LXMRouter.py `message_list_response`: on `0xF0`
  or `0xF1`, **tear the link down** and re-identify on a fresh link at the
  next attempt. No in-place retry.

Success responses remain the `[[pairs...], more_pending]` array, so a client
distinguishes refusal from success by type: integer = error code, array =
page. This matches how the propagation `/get` path already behaves on both
node and client.

**rfed.notify** (subscriber → node):
| Path | Caller | Payload | Response |
|------|--------|---------|----------|
| `/rfed/notify/register` | Subscriber | `msgpack string` (32-char hex relay hash) | `msgpack bool` |
| `/rfed/notify/unregister` | Subscriber | `msgpack string` (32-char hex relay hash) | `msgpack bool` |
| `/rfed/notify/clear` | Subscriber | *(empty)* | `msgpack bool` |

### `rfed.link` — one destination for all of it

Normative spec: **[RFed-spec/Link.md](../RFed-spec/Link.md)**. Path table in
code: `rfed/src/link_session.rs::paths`.

Every destination above is also reachable on the single `rfed.link`
destination, addressed by request path instead of by destination hash. The
path is the destination's aspect chain with `.` replaced by `/`, plus the
operation verb when the aspect chain does not already name it —
`rfed.channel.pull` `/rfed/pull` becomes `/channel/pull`. Payloads and
responses are byte-identical to the tables above; only the routing differs.

Two things are genuinely new rather than relocated:

- **`/channel/publish` answers.** The legacy publish is a fire-and-forget
  packet, so a rejected stamp is indistinguishable from a lost one. As a
  request it responds `msgpack [bool, str|nil]` with `too_short`,
  `stamp_too_short`, `stamp_invalid`, `stamp_legacy`, or `store_failed`.
  A publish over the link MDU is still a request — RNS carries it as a request
  Resource — and is answered the same way. A bare Resource on the link is also
  ingested, but gets no answer.
- **Node → client requests.** After `/channel/stream/open` or
  `/propagation/stream/open` binds the link, the node pushes back over it:
  `/delivery` (`channel_hash(16) | inner_blob`), `/lxmf/delivery` (packed
  LXMF), `/notify` (wake map). The client's `msgpack bool` response is the
  delivery proof. An unanswered channel `/delivery` or distro `/lxmf/delivery`
  push moves the blob to the deferred queue, and the client collects it with
  `/channel/pull` or `/distro/pull`. An unanswered `/lxmf/delivery` of a
  directly-addressed message is not deferred: the message stays in the
  messagestore and propagation sync finds it. See §7 "Live delivery and its
  proof".

`rfed.link` is additive. Every destination above stays registered, announced,
and answering, and no deployed client has to move.

---

## 3. Wire Formats

### SEND Packet (fire-and-forget)

```
┌──────────────────┬──────────────────────┬──────────────┐
│ channel_hash(16) │     inner_blob       │   stamp      │
└──────────────────┴──────────────────────┴──────────────┘
```

- **channel_hash**: 16-byte channel **identity hash** of the target
  channel — the routing label RFed uses (subscribers signed it during
  `/rfed/subscribe`).
- **inner_blob**: **The EC-encrypted authentication payload from
  `lxmf_rust::LXMessage::pack(PROPAGATED)` — byte-identical to what an
  LXMF propagation node carries:**

  ```
  inner_blob = EC_encrypted( source-identity prelude || source_hash(16) || signature(64) || msgpack_payload )
  ```

  Immutable — RFed treats it OPAQUELY and never decrypts, parses or
  modifies it.

  **SOURCE-IDENTITY PRELUDE (Retichat extension, application-layer,
  RFed-agnostic, MANDATORY):** The EC plaintext starts with the 4-byte
  ASCII magic `"RTID"` followed by 64 bytes of sender identity public
  key (the format produced by Reticulum-rust's
  `Identity::get_public_key()` — 32 X25519 enc pub || 32 Ed25519 sign
  pub), then the LXMF tail. Receivers MUST first check the key
  binding: the `lxmf.delivery` destination hash of `identity_pub`
  must equal `source_hash` taken verbatim from the LXMF tail, or the
  post is rejected and nothing is remembered. Only then call
  `Identity::remember_destination(source_hash, identity_pub, None)`
  and invoke `LXMessage::unpack_from_bytes`. **Do NOT compare
  `truncated_hash(identity_pub)` itself with `source_hash`** — that is
  the bare identity hash, not the lxmf.delivery DESTINATION hash, so
  the equality never holds and would reject every legitimate message.
  LXMF's Ed25519 signature validation authenticates the post (forged
  `identity_pub` → `SIGNATURE_INVALID`); the key binding protects the
  known-destinations cache, which the channel key alone does not,
  since anyone who knows the channel name holds it. The LXMF fields
  may carry key 0 of the Retichat field `0xD1`, the poster's Channel
  Display Name, used only once both checks pass (see "Display name
  (key 0 of field 0xD1)" above).
  RFed never sees the prelude (it's inside the EC envelope). See the
  **CANONICAL WIRE FORMAT** section at the top of this file for the
  full layered diagram and decode procedure — that section is
  authoritative.

  **Why this exists:** Channel pub/sub means the sender and receivers
  may have no prior history — the sender's `lxmf.delivery` identity is
  not in the receiver's known-destinations cache, so
  `LXMessage::unpack_from_bytes(PROPAGATED)` would emit
  `unverified_reason = SOURCE_UNKNOWN` for every message until/unless
  the sender's announce coincidentally arrived. The prelude removes
  the announce-timing dependency entirely: signature validates on the
  very first message a receiver sees, period.

  The channel identity (which holds both the X25519 encryption key and
  the Ed25519 verification baseline) is derived deterministically from
  the channel name as
  `seed = sha256(name); private_key_bundle = seed || seed`. Any subscriber
  holding the channel name can re-derive the channel identity, EC-decrypt
  the inner_blob, and reconstruct the canonical LXMF block by prepending
  the `lxmf.delivery` destination_hash for the channel identity (= the
  hash a receiver sees if they treat the channel identity as an LXMF
  delivery destination), then feed the result to
  `LXMessage::unpack_from_bytes(_, Some(PROPAGATED))`, which validates
  the Ed25519 signature against the cached source identity.
- **stamp**: Proof-of-work stamp appended by the sender. Validated and
  stripped on ingest; only the clean inner_blob (= LXMF lxmf_data tail) is
  stored and synced.

  **PoW STAMP CONTRACT (must hold across rfed + retichat-ffi + iOS forever):**
  * Material that the stamp is bound to:
    `material = channel_id_hash(16) || inner_blob`
    (i.e. `data[..data.len() - LXStamper::STAMP_SIZE]` as the SEND
    handler sees it).
  * `transient_id = identity::full_hash(material)`
  * `workblock    = LXStamper::stamp_workblock(transient_id, 16)`
    — `STAMP_EXPAND_ROUNDS` MUST stay 16 on both sides.  Bumping it
    silently invalidates every previously-cached client `stamp_cost`
    and every in-flight stamp.  Don't.
  * Required PoW value: `LXStamper::stamp_value(workblock, stamp) >= cost`
    where `cost = stamp_cost - stamp_flexibility` (clamped at 0).
  * `stamp_cost` is advertised by `/rfed/subscribe`'s response
    `[true, stamp_cost_or_nil]`. There is no other authoritative source;
    rfed announces do not currently carry it.
  * `Some(0)` in node config == disabled (same as `None`). Both subscribe
    response and SEND validation MUST honor this.
  * Clients MUST refresh their cached `stamp_cost` by re-issuing
    `/rfed/subscribe` at least once per app session AND on every SEND
    rejection, to recover from operator-side cost changes.

  See `RFed-rust/rfed/src/config.rs` (TierPolicy section, *HISTORICAL
  FAILURE MODES*), `Retichat-ios/rust/retichat-ffi/src/lib.rs`
  (`retichat_compute_channel_stamp`), and
  `Retichat-ios/Retichat/Services/RfedChannelClient.swift`
  (`refreshStampCost`, `trySend`).

### MESSAGE_GET Response (blob stream)

```
┌──────────────────┬──────────────────┬────────────┬──────────────┐
│ channel_hash(16) │ message_id(16)   │ length(4BE)│ blob(length) │
├──────────────────┼──────────────────┼────────────┼──────────────┤
│ channel_hash     │ message_id       │ length     │ blob         │
│       ...        │       ...        │    ...     │    ...       │
└──────────────────┴──────────────────┴────────────┴──────────────┘
```

Each record in the response:
- **channel_hash**: 16 bytes (padded/truncated)
- **message_id**: 16 bytes (padded/truncated)
- **length**: 4 bytes, big-endian `u32`
- **blob**: `length` bytes of raw inner blob (no stamp)

Records repeat until the response is complete or a transfer/sync limit is
reached.

### Notify Wake Packet

Sent as a msgpack Map:

```
{
  "receiver": bin(16),    // subscriber's lxmf.delivery hash (always present)
  "sender":   bin(16),    // optional — present when known (e.g. LXMF)
  "channel":  bin(16),    // optional — present for rfed.channel fanout
}
```

Only destination hashes are included. No message content ever leaves the
node via the notify path.

---

## 4. Sync Protocol

Federation nodes exchange blobs through a three-step manifest-based sync
protocol:

### Step 1: OFFER

The initiating node (A) opens a Reticulum `Link` to the target node (B)
and sends an OFFER request containing the message IDs it already holds:

```
A → B: /rfed/offer  payload = msgpack [msg_id₁, msg_id₂, ...]
B → A: response     payload = msgpack [(ch_hash₁, msg_id₁), (ch_hash₂, msg_id₂), ...]
```

B returns its **entire** store manifest (channel hash + message ID pairs).

### Step 2: Gap Computation

A filters B's manifest to only IDs for channels A has local subscribers
for, minus IDs A already holds. This produces the "gap" — blobs A needs.

### Step 3: MESSAGE_GET

A requests the gap from B:

```
A → B: /rfed/get  payload = msgpack [wanted_id₁, wanted_id₂, ...]
B → A: response   payload = binary blob stream (see §3)
```

The response is subject to two caps, always set:
- **`channel_transfer_limit_mb`** (`[storage]`, default 100): the most one
  response carries (per peer request)
- **`channel_sync_limit_mb`** (`[storage]`, default 1000): the most sent to
  all peers together per hour

B builds the response for A's whole gap while holding the FedSync and
BlobStore locks and reading every blob from disk, so it is never uncapped.
What a response leaves out is in the gap of A's next sync. Until 2026-09-28
the caps were `transfer_limit_mb` / `sync_limit_mb`, which are also the
`lxmf.propagation` node's announced limits (§10); left unset for that
announce (the shipped templates since then), channel sync had no cap at all.

### Step 4: Ingest & Fanout

A parses the blob stream, stores each blob, and immediately fans out to
local subscribers (see §8). Deferred queuing occurs for offline subscribers.

### Timing

| Constant | Value | Description |
|----------|-------|-------------|
| `SYNC_BACKOFF_MIN` | 10 s | Minimum interval between sync attempts |
| `SYNC_BACKOFF_MAX` | 3600 s | Maximum backoff (1 hour) |
| Stale peer cutoff | 7200 s | Peers not heard from in 2× max backoff are pruned |

Backoff doubles on failure and resets on success or announce heard.
Static peers are never pruned.

---

## 5. Blob Storage

Blobs are stored on the filesystem under `<config_dir>/blobs/`:

```
blobs/
  <channel_hash_hex>/
    <message_id_hex>      ← raw inner blob, no envelope
```

### Metadata

Each blob has an in-memory metadata entry rebuilt from disk on startup:

| Field | Type | Description |
|-------|------|-------------|
| `message_id` | `[u8; 16]` | Random 16-byte ID assigned at ingest |
| `destination_hash` | `[u8; 16]` | Channel hash |
| `received` | `f64` | Unix timestamp |
| `size` | `usize` | Byte length of blob |

### Eviction

| Policy | Value | Trigger |
|--------|-------|---------|
| TTL | 30 days | Hourly check |
| Capacity | `storage_limit_bytes` (default 2 GB) | On new blob ingest |

When capacity is exceeded, the oldest blobs by `received` timestamp are
evicted first.

---

## 6. Subscription Table

Subscriptions map subscribers to channels and are persisted to disk in
SQLite (`subscriptions.sqlite3`, one row per entry; see §13 Data Files).

### Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `subscriber_hash` | `[u8; 16]` | Subscriber's identity hash |
| `channel_hash` | `[u8; 16]` | Channel hash |
| `added` | `f64` | Unix timestamp |
| `owner_node_hash` | `Option<[u8; 16]>` | Non-None = backup subscription |
| `last_refreshed` | `f64` | Backup TTL tracking |

### Primary vs. Backup Subscriptions

- **Primary** (`owner_node_hash = None`): Created via `/rfed/subscribe`.
  Fanout always delivers.
- **Backup** (`owner_node_hash = Some(hash)`): Created via
  `/rfed/backup/push`. Delivery is **suppressed** while the owner node is
  online. When the owner's Reticulum path decays, the backup node activates
  delivery (failover).

Stale backup entries (not refreshed within `2 × owner_offline_secs`) are
automatically pruned.

---

## 7. Deferred Delivery

When a subscriber is offline during fanout, or a live push to it is never
confirmed, blobs are queued in the deferred delivery queue and persisted to
disk (`deferred_delivery.sqlite3`, one row per blob, in queue order).

### Live delivery and its proof

Channel and distro fan-out try the subscriber's live routes in order, and
stop at the first one that takes the push:

1. **`rfed.link`** — a `/delivery` (channel) or `/lxmf/delivery` (distro)
   request on the subscriber's bound link. The client's `msgpack bool`
   response is the proof.
2. **Legacy stream link** (`rfed.channel.stream`, `rfed.propagation.stream`)
   — a link DATA packet sent **with a packet receipt**. The client's link
   proof of that packet is the proof. A client MUST prove every DATA packet
   it receives on a stream link (the Reticulum-rust link proves each one
   when it has a packet callback); a client that does not will see each push
   handed off and delivered again by pull.
3. **`rfed.delivery` packet** (channels only; distro never uses it, §17.3) —
   a single DATA packet to the subscriber's delivery destination, sent **with
   a packet receipt**. The client's proof of that packet is the proof. A
   client MUST prove every packet it receives on `rfed.delivery` (PROVE_ALL);
   Retichat Android, iOS and web do since 2026-09-26.

   **Interim (from 2026-09-26, about a month):** the packet's proof is
   *observed*, not required (`handoff::DELIVERY_PACKET_PROOF`). The packet is
   sent once and counts as delivered; the node logs `[push] … proved` or
   `[push] … unproven; sent once`, which shows how many devices run an app
   that proves. Required against apps that never prove, every packet would be
   handed off and the announce flush would send the queued copy again on each
   announce. When most devices prove, the proof becomes required as below.
4. Otherwise the blob is handed off at once.

A push that is **never confirmed** is not lost and is not re-sent on another
live tier: it is **handed off** once (`handoff::defer_then_wake`). The blob
moves to the deferred queue, and then the subscriber is pushed through its
notify registrations (§9) so that it collects the blob with `/channel/pull`
or `/rfed/pull`. That is a change of route, not a retry. Tier 1 is
unconfirmed when the request fails (no response before the request
timeout, or the link closes first); tiers 2 and 3 when no proof arrives
before the receipt concludes — the RNS receipt timeout (for a link packet
the link's RTT × traffic timeout factor; for a packet to a destination
6 s plus 6 s per hop) is the failure event, and a link that closes before
the proof ends there too. The hand-off runs at most once per push per
subscriber. The `rfed.delivery` announce flush of queued channel blobs sends
with a receipt too, and, once the packet proof is required, hands off what
is not proved.

Until 2026-09-26 a tier-3 packet counted as delivered once it left, an
unconfirmed tier-1 or tier-2 push was deferred but no one was pushed, and
distro fan-out pushed no one at all: a subscriber whose app had died, its
path still held, lost the message or learnt of it only at its next pull.

Before 2026-09-24 tier 2 counted a packet the link accepted as delivered. A
device that died without closing its link (an iOS app killed or suspended,
an Android app frozen) kept an ACTIVE-looking link until keepalive
staleness, and every blob pushed in that window was lost.

A proof can arrive after the receipt has timed out. It still counts as
delivery (Reticulum-rust B35): a push that is still open when it lands is
delivered and not deferred, but a push already deferred stays deferred, so a
client can receive the same blob live and again by pull. Clients dedupe: distro blobs by a seen
key of `source + LXMF timestamp`, and a stored distro message by an id of
source, timestamp and content (§17.11 rule 5); channel blobs by their own
message identity.

One deferred bucket holds everything for an identity, and one identity is
often both a channel subscriber and a distro device. Each pull takes only its
own kind: `/distro/pull` (and `/rfed/pull` on `rfed.distro.register`) returns
only blobs for distros registered at this node, `/channel/pull` only the
requested channel's, and `/rfed/pull` on `rfed.delivery` returns both, for
the client to route by the leading hash.

A directly-addressed LXMF message streamed on `rfed.propagation.stream`
stays in the messagestore either way, so an unconfirmed push is not
deferred: the recipient is sent its notify wake instead (the same wake a
message gets when no live route took it), and fetches the message by
propagation sync.

### Limits

| Scope | Default | Configurable |
|-------|---------|-------------|
| Per subscriber (default tier) | 256 blobs | `policy.default.deferred_queue_limit` |
| Per subscriber (VIP tier) | 2048 blobs | `policy.vip.deferred_queue_limit` |
| Global | 4096 entries | Hard cap |

When a per-subscriber limit is exceeded, the oldest entry is evicted.
When the global limit is reached, new entries are silently dropped.

### Delivery Triggers

1. **Subscriber comes online** — delivery destination announces; node
   drains deferred queue and sends each blob.
2. **PULL request** — subscriber explicitly requests pending blobs via
   `/rfed/pull` (or `/channel/pull`, `/distro/pull` on `rfed.link`); queue is
   drained and returned as a msgpack array.
3. **Periodic eviction** — entries older than 7 days are pruned hourly.

---

## 8. Fanout & Double Envelope

### Fanout Process

When a blob is ingested (via SEND or sync), `fanout_blob()` iterates over
all subscribers for the channel:

1. Skip backup subscriptions where the owner is still online.
2. Look up the subscriber's identity and current path.
3. Build an outbound Reticulum packet to the subscriber's `rfed.delivery`
   destination, containing the inner blob as payload.
4. Send the packet.
5. If the subscriber is unreachable, add to the "missed" list for deferred
   queuing.

### Double Envelope

```
┌─── Outer Envelope (rfed → subscriber) ───────────────────────────┐
│  Reticulum HEADER_1 packet                                       │
│  Destination: subscriber's rfed.delivery (Single, encrypted)     │
│  Payload: [ inner_blob ]                                         │
│                                                                  │
│  ┌─── Inner Blob (sender → channel) ─────────────────────────┐  │
│  │  Encrypted to channel X25519 pubkey                        │  │
│  │  Signed by sender                                          │  │
│  │  Content: application-defined (opaque to rfed)             │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

The node **never modifies** the inner blob. It is stored, synced, and
delivered verbatim.

---

## 9. Notify System

The notify system sends lightweight wake-up signals to relay nodes when a
blob arrives for an offline subscriber.  These wake packets carry no message
content and can be used for mobile push notifications (APNs, FCM,
UnifiedPush) or any other out-of-band alerting mechanism, without the rfed
node holding platform credentials.

### 9.1 Registration

Subscribers register notify relay hashes via `/rfed/notify/register`.
The relay hash is the **32-character lowercase hex** representation of the
relay's 16-byte RNS destination hash.

```python
# Register a relay node for wake-ups
relay_hash = "aabbccdd11223344aabbccdd11223344"  # exactly 32 hex chars
# → /rfed/notify/register  payload = msgpack string("aabbccdd...")
# ← response: msgpack bool (true = accepted)
```

**Validation:** The hash must be exactly 32 ASCII hex digits (`[0-9a-f]`).
Any other value is rejected.

**Persistence:** Registrations are stored on disk in
`~/.rfed/notify_registrations.sqlite3` and survive node restarts.

#### NotifyRegistration Record

Each registration is stored as:

| Field | Type | Description |
|-------|------|-------------|
| `subscriber_hash` | `bin(16)` | Subscriber's `lxmf.delivery` destination hash, derived from the identity hash of the key that signed the registration, for LXMF and channel registrations alike. It is the key the device registers its push token under with the bridge. (Until 2026-09-26 channel registrations used the identity hash, which no bridge had a token for; stored rows are re-keyed once on load.) |
| `relay_hash` | `string(32)` | Hex-encoded relay destination hash |
| `registered` | `f64` | Unix timestamp of registration (for expiry/refresh) |

A subscriber may register multiple relays.  Each relay receives wake
packets independently.

### 9.2 Relay Destination Addressing

The rfed node sends each wake to **exactly the registered relay hash**, as a
**Reticulum Single destination**:

| Component | Value |
|-----------|-------|
| Destination hash | The registered relay hash, unchanged |
| Name | Whichever of `apns.relay` (apns-bridge) or `rfed.notify` (fcm-bridge) derives the registered hash from the identity |
| Destination type | `Single` (asymmetric encryption, multi-hop routed) |
| Identity | Recalled from Reticulum transport by the 16-byte relay hash |
| Ratchet | The one the relay announced for that hash, if any |

The relay must announce the registered destination so that Reticulum
transport can route packets to it and rfed can recall its identity. A
registration whose hash neither name derives from the recalled identity is
logged as a WARNING and not woken. Until 2026-09-25 rfed built every wake
as `rfed.notify` under the relay's identity, whatever hash was registered.

### 9.3 Wake Packet Wire Format

The wake packet payload is a **msgpack Map** with string keys and binary
values.  It contains only destination hashes — never message content.

| Key | Type | Present | Description |
|-----|------|---------|-------------|
| `"receiver"` | `bin(16)` | **Always** | Subscriber's `lxmf.delivery` destination hash: the key its registration and its push token are stored under, for LXMF, channel and distro wakes alike |
| `"sender"` | `bin(16)` | Optional | Sender's RNS destination hash (LXMF path only) |
| `"channel"` | `bin(16)` | Optional | Channel hash (rfed.channel fanout path only) |

The map contains **at most 3 entries**.  Clients must tolerate unknown keys
in future versions.

**Encoding:** `rmpv::Value::Map` (msgpack fixmap or map16).

#### Example: Channel Fanout Wake

When a blob arrives on `rfed.channel.publish` for a subscribed channel:

```
msgpack Map {
  "receiver" → bin(16)   ← subscriber's lxmf.delivery hash
  "channel"  → bin(16)   ← channel hash the blob was published to
}
```

`"sender"` is absent because fire-and-forget SEND packets carry no sender
identity.

#### Example: LXMF Propagation Notification Wake

When an LXMF message arrives for a notify-registered destination:

```
msgpack Map {
  "receiver" → bin(16)   ← recipient destination hash
  "sender"   → bin(16)   ← sender destination hash (from LXMF payload)
}
```

`"channel"` is absent because LXMF messages are not channel-scoped.

### 9.4 Dispatch Flow

1. Blob arrives for a subscriber who has registered notify relays.
2. rfed snapshots the subscriber's registrations, releases the registry (and
   any node lock), and for each relay, on the calling thread (no network wait):
   a. Decodes the 32-char hex relay hash to 16 bytes.
   b. Checks for a path to that hash; if none, requests one and drops the wake.
   c. Recalls the relay's identity; if unknown, requests a path and drops the wake.
   d. Builds the Single destination for the registered hash (§9.2); if no
      known name derives it, requests a path and drops the wake. The path
      response is the relay's announce, and its key replaces a stale one.
   e. Sends the msgpack wake packet as a Reticulum packet.
3. A wake counts as sent only when an interface took the packet. Drops are
   logged at NOTICE (no path, no identity) or WARNING (anything else) and are
   **not retried** (DESIGN_PRINCIPLES §3). The subscriber still receives the
   message via deferred queue pull or live fanout on their next connection.
4. A registration stores the registrant's key for the relay hash only when
   that key derives it (a relay the subscriber hosts itself).

### 9.5 Relay Implementation Guide (e.g. Retichat iOS)

A relay is a service that:

1. **Announces** a Reticulum identity on its wake destination, `apns.relay`
   or `rfed.notify` (`DestinationType::Single`), and registers that
   destination's hash with rfed (§9.2).
2. **Receives** incoming Reticulum packets on that destination.
3. **Decodes** the msgpack Map payload (see §9.3).
4. **Maps** the `"receiver"` hash to a platform-specific device token
   (APNs, FCM, etc.) using a relay-side database.
5. **Sends** a platform push notification to the device.

```
┌─────────┐   SEND blob    ┌──────────┐  wake packet   ┌───────────┐  APNs/FCM  ┌──────────┐
│ Publisher│───────────────→│ rfed node│───────────────→│   Relay   │───────────→│  Device  │
└─────────┘                 └──────────┘                └───────────┘            └──────────┘
                                 │                           │
                         stores blob,                 maps receiver
                         checks subs,                 hash → device
                         dispatches wake              token, sends
                                                      platform push
```

**The rfed node never holds APNs/FCM credentials.**  The relay operator
manages all platform integrations independently.

#### Relay-Side Requirements

| Responsibility | Owner | Notes |
|---------------|-------|-------|
| `subscriber_hash → device_token` mapping | Relay | Relay must maintain this; rfed does not provide it |
| APNs/FCM/UnifiedPush credentials | Relay | Stored on relay infrastructure, never shared with rfed |
| Rate limiting outbound pushes | Relay | rfed imposes no backpressure on the relay |
| Delivery confirmation | N/A | No ack path from relay back to rfed (fire-and-forget) |

### 9.6 Privacy

- The relay sees only which `subscriber_hash` should be woken, and
  optionally which `sender` or `channel` triggered the wake.
- The relay **never** sees message content, channel names, or any
  encrypted payload.
- The rfed node **never** sees device tokens, APNs certificates, or any
  platform credentials.

---

## 10. LXMF Propagation Relationship

RFed is intentionally LXMF-adjacent, but the relationship has three separate
layers that are easy to conflate if they are not spelled out explicitly:

1. **Channel payload format**: the recommended RFed inner blob is an LXMF
   `PROPAGATED` message, with the required source-identity prelude, encrypted
   to the channel identity.
2. **Federation mechanics**: RFed reuses LXMF-style OFFER/GET manifest sync and
   LXMF stamp-validation machinery.
3. **Optional full propagation service**: rfed can also announce a standard
  `lxmf.propagation` destination and act as a full LXMF propagation node.

### What RFed reuses from LXMF propagation

- propagated LXMF blob semantics for sender authentication inside the encrypted
  inner payload
- manifest-based OFFER / GET sync between store-and-forward peers
- proof-of-work stamp validation rules and announce metadata conventions
- the core idea that a node can store opaque ciphertext keyed by a hash without
  being able to decrypt the content it forwards

### What RFed changes

- the stored key is a **channel hash**, not a recipient delivery hash
- delivery is **fanout to subscribers**, not one mailbox per recipient
- peer sync is filtered to channels with local subscriber interest
- subscribers prove channel membership by signing subscribe requests rather
  than by owning a delivery mailbox on the propagation node

### Optional full `lxmf.propagation` service

When `[node].lxmf_propagation = yes`, rfed announces an `lxmf.propagation`
destination and runs the standard LXMF propagation service in parallel with
its channel federation surfaces. This is full propagation support, not a
notify-only shim.

### Behaviour

1. Client sends an LXMF propagated message to rfed's propagation destination.
2. rfed validates the propagation-node stamp against the configured
  cost/flexibility.
3. rfed stores the LXMF message on disk, indexes it, and queues it for
  eligible propagation peers. A sync Resource from a peer (the sender's
  identity on the link maps to a peer's `lxmf.propagation` hash) is handled
  for that peer, every message in it including ones rfed already held, and is
  queued for the other peers only (LXMF 1.1.1
  `propagation_resource_concluded`, `from_peer`). A client's PUT goes to
  every peer. The reference reads the identity off the link when the
  Resource concludes; rfed records it when the Resource is advertised,
  because by the time the Resource concludes the proof has gone out and the
  sender may already have closed the link, which rfed can then no longer
  ask. The per-batch log line names the origin: a peer, a non-peer identity,
  or a sender with no identity.
4. Recipients retrieve stored messages with the standard LXMF `GET` path, and
  peers exchange OFFER / GET sync with LXMF-rust `lxmd` instances and other
  rfed nodes.
5. If the recipient has notify relays registered, rfed also dispatches wake
  packets with `receiver` and optional `sender` hashes.

`lxmf_propagation_autopeer` controls announce-based discovery, while
`[peering].propagation_peers` pins static propagation peers.

### Outbound peer sync

rfed pushes stored messages to its propagation peers as the Python reference
does (LXMF 1.1.1 `LXMRouter.sync_peers`, `LXMPeer.sync` / `offer_response` /
`resource_concluded`); code in `rfed/src/lxmf_propagation.rs`, "Outbound peer
sync".

1. **Choice.** Every 24 s (the reference's `JOB_PEERSYNC_INTERVAL` × 4 s) one
   IDLE peer with unhandled messages is chosen: at random among the 2 fastest
   alive peers (by the rate of their last completed sync) plus as many of
   unknown speed; only when no alive peer waits, at random among unresponsive
   peers whose backoff has run out. Sessions already running continue on
   their own events, so several peers sync at once. (While the outbound
   budget binds, the choice is the least recently served, alive or
   unresponsive: see "Sharing the budget" below.)
2. **Link.** The session opens a held link to the peer's `lxmf.propagation`
   destination through AppLinks. Each attempt adds 12 min to the peer's
   backoff; an established link clears it.
3. **Offer.** On the link: identify, then `/offer` `[peering_key, [id, ...]]`,
   back to back. Ids go lightest first (age × size); an id over the peer's
   per-message transfer limit is marked handled unsent; the batch stays under
   the peer's sync limit (KB, estimated as size + 16 B per message + 24 B).
4. **Response.** `false`: all offered ids handled. `true` / `[ids]`: the
   unwanted ones handled, the wanted ones sent. Errors: `0xF0` identify again,
   `0xF1` unpeer, `0xF3` regenerate the peering key once per announced cost,
   `0xF6` no sync for 180 s (the peer stays alive).
5. **Transfer.** The wanted messages (each stored file: message + stamp) go as
   ONE `RNS.Resource` of msgpack `[time, [lxm, ...]]` (float, array of bin) —
   the format the reference and rfed's own inbound path ingest. They are
   marked handled **only when the Resource concludes COMPLETE**. A failed
   offer, a failed Resource or a lost link returns the peer to IDLE with every
   id still unhandled.
6. **Persistent strategy.** After a COMPLETE the session carries on with the
   next batch while the peer still lacks messages (while the outbound budget
   binds and other ready peers wait, only until it has sent its fair share:
   see "Sharing the budget").

Departures from the reference, each for a reason:

- **Links through AppLinks**, never built by rfed (Reticulum-rust
  `SUBSYSTEMS.md` §1). AppLinks' path race replaces the reference's path
  request and 7.5 s sleep; its DISCONNECTED report is the failure event. The
  held link is released (`AppLinks::close`) wherever the reference tears its
  link down, except that the persistent strategy's next batch goes on the
  still-up link instead of a new one. A session runs only on a link it opened
  with `open_persistent`, so that AppLinks reports its loss: a link already
  held when a session starts from IDLE, one that comes up for an IDLE peer or
  for a destination that is no longer a peer, are closed; a second link that
  comes up mid-session (it replaced the session's link in AppLinks) is closed
  and the session ends with its ids unhandled. A report of a link AppLinks no
  longer holds (one already closed) is stale and ignored.
- **Not-ready peers are never chosen.** A peer whose stamp costs are unknown
  or whose peering key is still being generated is skipped; keys are ground
  in the background. The reference chooses such a peer and only postpones,
  and rfed used to choose the first IDLE peer every tick, so one peer grinding
  its key held up every peer (3.5 min, staging 2026-09-27). An alive peer
  still in link-attempt backoff is marked unresponsive when found, as the
  reference's `sync()` does when it chooses one.
- **Per-minute outbound budget** (`DEFAULT_OUTBOUND_SYNC_MSGS_PER_MIN`, 600).
  Guarantee: for every moment t, the messages in sync Resources handed to a
  link in (t − 60 s, t] number at most the budget, all peers together,
  across a restart too. A message counts from the moment its Resource is
  handed to the link (just before the `sending N message(s) to peer X as a
  Resource` log line), whether or not the Resource then completes; spans are
  measured on a monotonic clock. The window rolls — it is not a calendar
  minute: an offer may take only the budget less what was handed over in the
  last 60 s, less what running sessions reserve (a session reserves its whole
  offer until the answer, then the wanted ids until their Resource is handed
  over, when the reservation becomes the send). Restart: the send record is
  not persisted; instead nothing is offered for the first 60 s after start,
  as if the last run had spent the whole budget the moment this one started.
  The last run's final send came before it stopped, so no second budget
  opens within 60 s of it. That holds after a crash or a kill, which a record
  written at shutdown would not, puts no disk write in the send path, and
  never compares two runs' wall clocks. (Until 2026-09-28 the budget was a
  fixed minute started lazily and reset by a restart: 1200 left in 26 s in
  one process and 1200 in 58 s across a restart, staging.) Offers are also
  capped at 500 ids.
- **Sharing the budget.** The budget is rfed's own departure, and the
  reference's choice was never made to share one: its persistent strategy
  keeps a session going while the peer lacks messages, and its pool favours
  the fastest peers. Under the budget that starved peers (staging
  2026-09-28): one session took the whole 600 (500 on the offer, 100 more on
  the held link), so one peer was served per ~73 s, and the pool chose the
  same fast peers again (one peer 7 sessions in a phase) while 7 of 20 got
  nothing in 30 minutes. So while the budget **binds** — the ready peers
  step 1 could choose now, alive (waiting) or unresponsive with their
  backoff run out, each counted up to one offer, want more than is left of
  it — three rules apply, and none otherwise:
  - a session's **turn** is a **fair share** of messages **sent**: the
    budget divided by those ready peers (this one included), but never
    less than one tick's worth of it (budget × 24 s / 60 s, 240 of 600). A
    new session starts only on a tick, so at most 2.5 start in a minute; a
    smaller share would leave the budget unspent and serve no peer sooner.
    Each offer is cut to what is left of the share (and of the budget), so
    no turn sends more than its share and no batch takes the whole budget
    while another ready peer waits;
  - until its share is sent the session takes its next batch on the held
    link; once it is sent (or the budget is spent, or the link is gone) the
    session ends (the link is released) while other ready peers wait, and
    waits for its turn like them. A turn used to be one batch, and a batch
    is often far smaller than the share: ~52 messages of 20 KB fill a
    Resource, and a peer that already holds most of an offer (normal in a
    mesh) wants only part of it. With 20 peers for 8 minutes, turns of one
    batch sent 1040 and 480 of a budget of 4800 (review, 2026-09-28); turns
    of a share send 4080 and 3996 (tests
    `the_budget_is_spent_while_it_binds_when_batches_are_byte_limited`,
    `..._when_peers_want_part_of_each_offer`);
  - the choice (step 1) is the ready peer whose last turn
    (`last_sync_attempt`) is **oldest**, at random among equals, instead of
    the fastest-peer pool — unresponsive peers past their backoff included,
    and they count in the share and make a running session yield like
    alive ones. The reference chooses an unresponsive peer only when no
    alive peer waits, which relies on the waiting set draining quickly;
    under the budget it does not, so one failed link attempt (12 min of
    backoff, then the next tick marks the peer unresponsive) left a peer
    with nothing until its next announce, every 6 h from lxmd by default
    (review, 2026-09-28: 0 of 3000 in 30 minutes). Now its last turn is
    the oldest once its backoff has run out, and it is chosen within a tick
    or two (test `an_unresponsive_peer_takes_its_turn_while_the_budget_binds`).
    An unreachable peer costs one link attempt per turn, and its backoff
    grows by 12 min with each.

  With 20 ready peers each lacking many messages, one peer is served per
  tick, all 20 within ceil(20 / 2.5) = 8 minutes, in turns of 240 / 240 /
  120 per 72 s (the budget spent, never exceeded): test
  `every_ready_peer_gets_a_turn_while_the_budget_binds`.
- **One Resource segment per batch** (`MAX_SYNC_RESOURCE_BYTES`, ~1 MiB).
  Reticulum-rust sends an in-memory Resource as one segment of any size, and
  receivers refuse a segment over ~3 MiB; the rest goes in the next batch. A
  message larger than a segment is marked handled for the peer unsent, and
  logged.
- **`0xF0` (no identity)** is answered with one more identify per link, not
  one per answer, so a peer that never records the identity cannot loop the
  session. **`0xF6` (throttled)** ends the session at once (the reference
  leaves it waiting for its link to close) and holds the peer for 180 s
  (`throttled_until`) WITHOUT marking it unresponsive: the reference never
  chooses or demotes a peer it holds on its link, and that peer is alive and
  waiting again when the link closes. A 1.1.1 PN throttles any offer that
  arrives while it validates a batch, so this is routine; demoted, the peer
  waited behind every alive peer until its next announce. **`0xF3`
  (invalid key)** discards the peering key and grinds a new one at the
  announced cost, once per announced cost: that repairs a key ground under
  another rfed identity or persisted from an older stamper. If the peer
  refuses that key too, it validates against a cost rfed has not heard yet,
  and another key at the same cost cannot fare better, so the peer is not
  chosen again until it announces a different peering cost. (The reference
  has no `0xF3` branch: it ends the session with the key kept and offers
  again at every choice. rfed used to regrind at the same cost after every
  refusal: a full PoW grind, a link and an offer per cycle.)
- **A lost link ends the session at once**, even with a Resource in flight:
  a Resource not yet advertised when its link closed never concludes in
  Reticulum-rust. Its ids stay unhandled; if it had in fact completed, the
  next offer finds the peer has them. Callbacks of an ended session are
  recognised by a session number and ignored.
- **Message files that cannot be read.** A file that is gone (`NotFound`)
  takes its message out of the store index and out of every peer's queues,
  with a warning: nothing can be sent or served from it again, and left
  queued it was offered, with a link opened for it, to every peer lacking it
  until it expired (7 days). The reference skips a missing file silently and
  marks it handled for that peer on COMPLETE. Any other read error (a
  permission problem, EIO) leaves the id unhandled, with a warning, as the
  reference's failed `open()` does.
- **Backoff is not reset by announces**, and the **startup backlog** (messages
  stored before start) is held back from sync for an hour; both predate this.
- **No 5-second assertion on the Resource** (DESIGN_PRINCIPLES §1): its
  completion scales with size and RTT (as for app-links' Resources). The
  offer's round trip keeps its assertion.

Known departures not yet fixed, both outside rfed:

- **AppLinks re-opens a lost sync link once** (Reticulum-rust `SUBSYSTEMS.md`
  §1: "one automatic re-open attempt"). `open_persistent` is the only
  AppLinks mode that holds a link, and it re-arms that re-open on every
  establishment, so when the peer closes the sync link, or it goes stale,
  AppLinks expires the path, requests it and builds a new link that no
  session asked for (DESIGN_PRINCIPLES §3); the reference's
  `LXMPeer.link_closed` only returns to IDLE. rfed ends the session on the
  DISCONNECTED and closes the stray link when it comes up (above). Because
  `AppLinks::close` does not cancel an attempt already in flight, a session
  started while that re-open is still racing can run a second attempt beside
  it, and the one overwritten in AppLinks' registry is never torn down
  locally (a Python peer drops it after 180 s idle; an rfed peer keeps
  it). The fix belongs in AppLinks: a held-link mode without the
  close-triggered re-open, and a per-registration generation that `close`
  bumps and an attempt checks before it registers its link.
- **A sync Resource whose link closes before it is advertised is leaked.**
  Reticulum-rust's `Resource::advertise_shared` thread waits on
  `ready_for_new_resource`, which is false for ever once the link's actor
  has exited, so it spins every 250 ms for the life of the process, holding
  the batch (up to ~1 MiB) and its callback, and never concludes. RNS 1.5.2
  cancels such a Resource (`ensure_link`), which concludes it FAILED. rfed's
  session does not wait on it (the DISCONNECTED ends it, ids unhandled); the
  leaked thread and buffer are Reticulum-rust's to fix.

### Announce Metadata

The LXMF propagation destination announces with app_data:

```
[
  false,                            // protocol version marker
  unix_timestamp,                   // announce time
  true,                             // is active propagation node
  transfer_limit_kb,                // per-message limit, KB of 1000 B
  sync_limit_kb,                    // per-sync limit, KB of 1000 B
  [stamp_cost, flexibility, cost],  // PoW parameters
  {0x01: node_name}                 // metadata map
]
```

Both limits are integers in the reference's kilobytes of 1000 bytes, as LXMF
1.1.1 announces them and as every reader (`LXMPeer.sync`, rfed's own offer
planning) multiplies them back by 1000. `[storage] transfer_limit_mb` /
`sync_limit_mb` stay in MB (× 1024² bytes) and are divided by 1000 for the
announce; unset they are 256 and 10240 (LXMF's `PROPAGATION_LIMIT` and
`SYNC_LIMIT`). The sync limit is never below the per-message limit, as in
`LXMRouter.__init__`. Until 2026-09-28 rfed announced MB here, truncated, so a
default rfed announced `0` and `10`: every peer, Python or rfed, read a 0 KB
per-message limit and marked every message for rfed handled without sending
it. The shipped templates (`config.txt.example`, `rfed-nas.config`, the
first-run sample) leave both keys unset: their old 100 / 1000, announced for
real, said 100 MB per message and ~1 GB per sync, ~410× and ~100× the
reference; whole MB cannot express 256 KB. (`rfed.node` channel sync has
caps of its own, `channel_transfer_limit_mb` / `channel_sync_limit_mb`, §4.)

rfed holds senders to what it announces, as LXMF 1.1.1
`LXMRouter.propagation_resource_advertised` does: a propagation Resource
whose data size (the advertisement's `d`) is larger than the announced
per-sync limit × 1000 B is refused at its advertisement, with a log line
naming the size, the limit and the link. As in the reference there is no
per-message size limit on receipt — the per-transfer limit is the sender's
to apply (`LXMPeer.sync`, rfed's `plan_offer`); the reference's one
per-message check on receipt, `LXStamper.validate_pn_stamp` (a message no
longer than LXMF_OVERHEAD + STAMP_SIZE, or with a stamp under the cost, is
dropped), runs in rfed through the same stamper, and each batch's log line
counts those drops as `bad-stamp`.

---

## 11. Backup Failover

rfed implements chain-of-custody backup delivery for subscriber resilience.

### Architecture

```
              ┌─────────────┐
              │   Primary    │   ── owns subscriptions
              │   rfed node  │
              └──────┬───────┘
                     │  /rfed/backup/push (subscription pairs)
                     ▼
              ┌─────────────┐
              │   Backup     │   ── holds backup subscriptions
              │   rfed node  │   ── suppresses delivery while primary online
              └──────────────┘
                     │
                     ▼  primary path decays → activate delivery
              ┌─────────────┐
              │  Subscriber  │   ── receives blobs from backup
              └─────────────┘
```

### Configuration

```ini
[peering]
primary_node       = aabbccdd...    # first-choice backup target
secondary_nodes    = 11223344...    # ordered fallback list
owner_offline_secs = 90             # silence before failover activates
```

### Failover Sequence

1. Primary periodically pushes `(subscriber_hash, channel_hash)` pairs to
   its designated backup node via `/rfed/backup/push`.
2. Backup stores these as backup subscriptions (`owner_node_hash = primary`).
3. Backup monitors the primary's announce freshness.
4. When primary has been silent for `owner_offline_secs`, backup activates
   delivery for adopted subscribers.
5. Backup re-pushes adopted entries to **its own** backup (chain of custody).
6. Entries not refreshed within `2 × owner_offline_secs` are pruned.

### Backup Selection

The active backup is selected in priority order:

1. `primary_node` (if alive and reachable)
2. First alive node in `secondary_nodes`
3. Auto-selected from alive federation peers

Only **one** node receives pushes at a time.

---

## 12. Announce Format

### rfed.node Announce

Encoded as a msgpack array in the announce `app_data`:

```
[
  bin(display_name),        // UTF-8 node name
  uint(stamp_cost) | nil,   // PoW cost (nil = disabled)
  uint(1)                    // protocol version
]
```

RFed's channel-federation destinations are described in §2. `rfed.node`
carries RFed app_data, and when propagation is enabled `lxmf.propagation`
carries the standard LXMF app_data shown above.

---

## 13. Configuration

### Reticulum Native Config File

Located at `<config_dir>/config`. The file uses Reticulum's native config
format, not TOML. All settings are optional; a commented sample is written on
first run, and `config.txt.example` is a ready-to-edit starting point.

```ini
[node]
name                         = rfed
announce_interval_minutes    = 360
announce_at_start            = yes
lxmf_propagation             = no
lxmf_propagation_autopeer    = no

[storage]
limit_mb          = 2000
# transfer_limit_mb = 1     # unset: LXMF's 256 KB per message (§10)
# sync_limit_mb     = 10    # unset: LXMF's 10240 KB per sync (§10)
channel_transfer_limit_mb = 100   # /rfed/get per response (§4); unset: 100
channel_sync_limit_mb     = 1000  # /rfed/get per hour, all peers; unset: 1000

[peering]
static_peers         = aabbccdd...
from_static_only     = no
peering_cost         = 18
trusted_backup_peers = aabbccdd...
primary_node         = aabbccdd...
secondary_nodes      = 11223344...
owner_offline_secs   = 90
propagation_peers    = aabbccdd...

[policy.default]
stamp_cost                = 16
stamp_flexibility         = 3
deferred_queue_limit      = 256
allow_notify_registration = yes
allow_subscription        = yes
trusted_backup_only       = no

[policy.vip]
stamp_cost                = 4
stamp_flexibility         = 2
deferred_queue_limit      = 2048
allow_notify_registration = yes
allow_subscription        = yes
trusted_backup_only       = no

[vip]
subscribers = aabbccdd..., 11223344...
```

The `[reticulum]` and `[interfaces]` sections live in the same file and use
standard Reticulum syntax. List values are comma-separated hashes, and
booleans use Reticulum-style `yes` / `no`.

### Merge Order

CLI flags → config values → compiled defaults.

### Data Files

All persisted to `<config_dir>/`:

| File | Format | Contents |
|------|--------|----------|
| `identity` | Reticulum identity | Node X25519 + Ed25519 keypair |
| `subscriptions.sqlite3` | SQLite | Subscription table |
| `notify_registrations.sqlite3` | SQLite | Notify relay registrations |
| `deferred_delivery.sqlite3` | SQLite | Offline blob queue |
| `distro.sqlite3` | SQLite | Distro device registrations (§17.6) |
| `distro_announces.sqlite3` | SQLite | Pre-signed distro announces |
| `peers.rmp` | msgpack | Peer sync state & backoff timers |
| `blobs/<ch_hex>/<id_hex>` | raw bytes | Stored inner blobs (written as `<id_hex>.tmp`, then renamed) |
| `lxmf_propagation/messagestore/<message_id_hex>` | raw bytes | Stored LXMF propagated messages (when enabled) |
| `lxmf_propagation/peers` | msgpack | Propagation peer state and sync backoff |
| `lxmf_propagation/node_stats` | msgpack map | Propagation message counters |

The SQLite stores run in WAL mode (each has `-wal` and `-shm` files beside
it) and write one row per change, so a node stopped at any moment keeps every
committed change. Until 2026-09-26 they were msgpack files of the same name
with `.rmp`, each rewritten whole on every change, and one that did not decode
loaded as empty and was overwritten. On first start a node imports each
`.rmp` file once and renames it `<name>.rmp.imported-<unix secs>`; a file that
cannot be read is renamed `<name>.rmp.unreadable-<unix secs>` and logged
(`[store]`), never overwritten. Neither is deleted.

---

## 14. CLI Reference

```
rfed [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config <DIR>` | `~/.rfed` | Config & storage directory |
| `--rnsconfig <DIR>` | *(system)* | Reticulum config directory |
| `--identity <FILE>` | `<config>/identity` | Node identity file |
| `--name <NAME>` | `"rfed"` | Display name |
| `--announce-interval <MIN>` | `360` | Announce interval (minutes) |
| `--no-announce-at-start` | *(announce)* | Skip initial announce |
| `--stamp-cost <BITS>` | `16` | PoW stamp cost |
| `--stamp-flexibility <BITS>` | `3` | Stamp flexibility |
| `--peering-cost <BITS>` | `18` | Peering PoW cost |
| `--storage-limit <MB>` | `2000` | Blob storage limit |
| `--static-peer <HASH>` | *(none)* | Add static peer (repeatable) |
| `--from-static-only` | `false` | Only accept from static peers |
| `-v, --verbose` | | Increase log verbosity |
| `-q, --quiet` | | Decrease log verbosity |
| `-h, --help` | | Show usage |

---

## 15. Test Suite

The integration test suite lives in `cli-tests/rfed_tests/` and covers:

| # | Scenario | Description |
|---|----------|-------------|
| 1 | `live_fanout` | Subscribe → publish → verify immediate delivery |
| 2 | `deferred` | Publish while offline → come online → verify flush |
| 3 | `pull` | Publish while offline → explicit PULL → verify return |
| 4 | `notify` | Register relay → publish offline → verify wake packet |
| 5 | `sync` | Two-node: publish on A, subscribe on B, verify sync |
| 6 | `backup_failover` | Primary dies → backup activates → subscriber receives |
| 7 | `prop_notify` | Register via rfed.notify → send LXMF propagation → relay woken |
| 9 | `nse_timing` | Full propagation store-forward with tight NSE-like sync budget |
| — | `distro_e2e` | Distro register → propagate → PULL via rmap.world |

```bash
# Run all tests
./run_tests.sh all

# Run a specific scenario
./run_tests.sh 3

# Run distro E2E test (requires seeded identity, see seed_test_identity.sh)
RFED_TEST_HOST=rmap.world \
RFED_TEST_CONFIG_DIR=/tmp/rfed-local-rmap-client \
RFED_TEST_RUN_DIR=/tmp/rfed-actual-local-harness \
RFED_UPLINK_PORT=4242 \
RFED_LOCAL_CONFIG=/tmp/rfed-actual-local-rmap-only \
RFED_LOCAL_IDENTITY=... \
RFED_IDENTITY_HASH=... \
RFED_PUBLIC_KEY=... \
PYTHONPATH=... python distro_e2e_test.py
```

Test clients are Python scripts that use the reference Reticulum library
and the `channel_hash.py` utility module for deterministic hash computation.

---

## 16. Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `reticulum_rust` | local | Rust Reticulum transport layer |
| `lxmf_rust` | local | LXMF message handling & PN stamps |
| `rmp` / `rmpv` / `rmp-serde` | 0.8 / 1.0 / 1.1 | MessagePack serialisation |
| `serde` | 1.0 | Derive serialisation traits |
| `configparser` | 3 | Reticulum-native config parsing |
| `sha2` | 0.10 | SHA-256 hashing |
| `x25519-dalek` | 1.1.1 | X25519 key derivation |
| `ed25519-dalek` | 1.0.1 | Ed25519 key derivation |
| `rand` | 0.8 | Random message ID generation |
| `ctrlc` | 3.4 | Graceful shutdown (SIGINT) |

---

## 17. Capabilities Query

The `/rfed/capabilities` request path on `rfed.node` returns a msgpack Map
describing features, protocol version, and anti-spam parameters advertised by
this node.  Any caller may issue the request; the payload is ignored.

### Response Fields

| Key | Type | Description |
|-----|------|-------------|
| `protocol_version` | Integer | Wire-format version (currently `1`). Bump on breaking changes. |
| `display_name` | String | Human-readable node name from config. |
| `subscription` | Boolean | Whether the default policy allows subscription. |
| `notify` | Boolean | Whether the default policy allows notify registration. |
| `lxmf_propagation` | Boolean | Whether the full `lxmf.propagation` service is enabled. |
| `channel_stream` | Boolean | Whether live per-channel streaming is available. |
| `propagation_stream` | Boolean | Whether propagation streaming support is available (currently mirrors `lxmf_propagation`). |
| `distro` | Boolean | Whether distro (multi-device fanout) is available. Always `true` on current rfed. |
| `backup` | Boolean | Whether backup failover is configured (primary or secondary nodes set). |
| `stamp_cost` | Integer / Nil | Required PoW leading-zero bits, or Nil if stamping is disabled. |

The map is intentionally extensible — clients must tolerate unknown keys.
Future versions may add fields such as `storage_available`, `peer_count`,
or feature-specific sub-maps.

### Example Response (decoded)

```
{
  "protocol_version": 1,
  "display_name": "my-rfed-node",
  "subscription": true,
  "notify": true,
  "lxmf_propagation": false,
  "channel_stream": true,
  "propagation_stream": false,
  "distro": true,
  "backup": true,
  "stamp_cost": 16
}
```

---

## 17. Distro

Distro (Distribution List) provides personal multi-device message fanout for a
shared LXMF identity.  A user with multiple devices (phone, laptop, LoRa
messenger) registers each device's `lxmf.delivery` address under a single
"distro identity."  Any LXMF message sent to the distro identity is
automatically fanned out to all registered devices.

### 17.1 Architecture

Distro is a **double-wrap, server-blind** relay (same trust model as channels):

```
Sender → LXMF message encrypted to distro identity
       → lxmf.propagation PUT (standard LXMF path)
       → RFed intercepts, stores in BlobStore (NOT messagestore)
       → RFed fans out to each registered device via rfed.delivery
       → Device receives on rfed.delivery, decrypts with shared distro key
```

**Key differences from channels:**

| | Channel | Distro |
|---|---|---|
| Identity model | Derived from channel name | Standard LXMF identity, shared out-of-band |
| Registration | Self-service (know name → join) | Owner-managed (distro key proves ownership) |
| Sender experience | Must know channel name, derive keys | Sends normal LXMF to a normal address |
| Reply identity | Each sender signs with own identity | All devices reply as the distro identity |
| Ingress | `rfed.channel.publish` (DATA) | `lxmf.propagation` (intercepted) |

### 17.2 Cross-Node Distribution

Distro messages are stored in **BlobStore** (not the LXMF propagation
messagestore) and synced between RFed nodes via **FedSync** (the same
`rfed.node` OFFER/MESSAGE_GET engine channels use).  This avoids polluting
the vanilla `lxmd` propagation mesh with messages those nodes can never
deliver.

Each RFed node maintains its own **DistroTable** — a per-node registry of
which devices have registered locally.  A node pulls distro blobs from
peers when it has at least one local device registered for that distro hash.

### 17.3 Delivery

A distro message reaches each registered device the way a propagated
message reaches its recipient (§7 "Live delivery and its proof"):

1. `/lxmf/delivery` on the device's bound `rfed.link`: the bare LXMF blob,
   confirmed by the response;
2. else its `rfed.propagation.stream` link: the bare LXMF blob, confirmed by
   the link proof;
3. else, and whenever 1 or 2 goes unconfirmed, a **hand-off**: the blob is
   queued in the **DeferredQueue** under the device's identity hash, and then
   the device is pushed through its LXMF notify registrations (§9), stored
   under its `lxmf.delivery` hash, so that it collects the blob with
   `/rfed/pull` (`distro::defer_then_wake`). Queue first: the push makes the
   device pull. The push carries no sender and no channel.

The leading 16 bytes of the blob are its destination, the distro's
`lxmf.delivery` hash, which is how the device tells a distro message from
one addressed to itself. The blob is a standard LXMF propagation message,
encrypted to the distro identity's X25519 key; RFed never decrypts it.
`/rfed/pull` returns `[distro_lxmf_hash, lxmf_blob]` pairs (§17.8).

No distro message is sent as an `rfed.delivery` packet, and the
`rfed.delivery` announce flush leaves distro blobs queued: nothing confirms
such a packet. Until 2026-09-26 a device with no live session was sent one
and it counted as delivered, and no distro fan-out pushed anyone: an Android
or iOS device whose app was closed got no push for its distro, and a device
whose app had died, but whose path rfed still held, lost the message.

### 17.4 RNS Destinations & Request Paths

| Destination | Aspects | Request Path | Purpose |
|---|---|---|---|
| `rfed.distro.register` | `["distro", "register"]` | `/rfed/distro/register` | Register a device |
| `rfed.distro.unregister` | `["distro", "unregister"]` | `/rfed/distro/unregister` | Remove a device |
| `rfed.distro.list` | `["distro", "list"]` | `/rfed/distro/list` | List registered devices |

All three use `DestinationType::Single`.

### 17.5 Registration Protocol

The distro owner proves possession of the distro private key by signing the
registration payload.  The protocol mirrors the channel subscription format:

**Register / Unregister:**
```
Payload: msgpack [ bin(64) device_pubkey, bin(64) distro_pubkey, bin(64) sig(device_pubkey) ]
```

`verify_signed_payload` extracts `(device_pubkey, distro_identity_hash, distro_pubkey)`
and validates `sig(device_pubkey)` against `distro_pubkey`.  The server derives:
- `distro_lxmf_hash` = `Destination::hash(app="lxmf", aspects=["delivery"], identity_hash=distro_identity_hash)`
- `device_lxmf_hash` = same derivation from `device_pubkey`

**List:**
```
Payload: msgpack [ bin(16) distro_identity_hash, bin(64) distro_pubkey, bin(64) sig(distro_identity_hash) ]
Response: msgpack [ bin(16) device_lxmf_hash, ... ]
```

### 17.6 DistroTable Schema

Per-node table persisted to `distro.sqlite3` (one row per device registration):

| Field | Type | Description |
|---|---|---|
| `distro_lxmf_hash` | `[u8; 16]` | Distro identity's `lxmf.delivery` hash (routing key) |
| `device_lxmf_hash` | `[u8; 16]` | Device's `lxmf.delivery` hash |
| `device_pubkey` | `[u8; 64]` | Device identity public key (for outbound delivery) |
| `added` | `f64` | Unix timestamp of registration |
| `owner_node_hash` | `Option<[u8; 16]>` | Reserved for backup failover (future) |
| `last_refreshed` | `f64` | Backup TTL tracking (future) |

### 17.7 Sync Engine Integration

The FedSync engine treats channel and distro blobs uniformly:

- **Manifest building** (`local_manifest`): includes blobs for channels with
  local subscribers AND distros with local devices.
- **Gap filtering** (`gap_from_peer`): pulls blobs for subscribed channels
  OR registered distros that the node doesn't already hold.
- **Post-ingest dispatch**: calls `fanout_blob()` for channel hashes and
  `distro_fanout()` for distro hashes, then enqueues missed subscribers/devices
  in the DeferredQueue.

### 17.8 Deferred PULL on distro.register

In addition to `rfed.delivery`, the `/rfed/pull` request path is also
registered on `rfed.distro.register`. This allows a client to reuse an
existing distro.register link for PULL without establishing a separate
link to `rfed.delivery`.

This is important for relay nodes (e.g., rmap.world) that may drop rapid
successive link requests from the same client. By reusing the register
link, the client avoids a third LINKREQUEST that the relay might drop.

| Destination | Path | Caller | Payload | Response |
|-------------|------|--------|---------|----------|
| `rfed.distro.register` | `/rfed/pull` | Subscriber | `msgpack nil` (packed `None`, `0xc0` — a request with no data is still one msgpack value; zero bytes is malformed and unparseable). Caller authenticated by link identity | `msgpack [ [[bin(16) distro_hash, bin blob], …], bool more_pending ]` |

The response format is identical to the `rfed.delivery` PULL response.
The `distro_hash` field contains the distro's `lxmf.delivery` hash
(the routing key), and `blob` is the raw LXMF propagation message.

### 17.10 Distro Announce

RFed rebroadcasts the pre-signed `lxmf.delivery` announce a device hands it
on `/rfed/distro/announce` (§17.4). Its `app_data` is the LXMF 0.5.0+ list
and marks the address as a distro:

```
[ announce_name,  // bin, or nil: the user's Announce Display Name, empty by
                  // default (LXMF-rust/DISPLAY_NAMES.md §2.2); other names
                  // travel inside encrypted messages, in key 0 of
                  // the Retichat field 0xD1
  nil,            // stamp_cost: none
  [ 0xD0 ] ]      // supported_functionality: SF_RFED_DISTRO
```

`SF_RFED_DISTRO = 0xD0` is an entry in the supported-functionality list
next to LXMF's `SF_COMPRESSION = 0x00`. The list has no custom range, so
the value sits far above what upstream counts up from zero and outside the
one-byte msgpack range it would fill first. Readers check membership only,
so the reference ignores it, and a device that also wants to claim
compression may list both.

This is the only way an address is known to be a distro. No device answers
a direct link to a distro address, so a sender that has seen the flag sends
PROPAGATED at once (LXMF-rust `LXMRouter::handle_outbound`, Retichat-js
`isDistro` contacts). The flag is learned from the announce a sender needs
anyway to encrypt to the address; nothing is queried, and a contact link
(`lxma://hash:pubkey`) carries a key, not this fact. `lxmf_rust::distro::
announce_payload` always writes the flag; `lxmf_rust::lxmf::
distro_from_app_data` reads it.

### 17.11 Sent-message sync

A message a device sends *as the distro* (§17.1: "all devices reply as the
distro identity") reaches its recipient but, without this section, none of
the distro's other devices: the conversation on each sibling shows only the
other side's half. The sending device therefore also sends a copy to the
distro itself, and every sibling files it as a message it sent.

**Who sends it.** A device holding distro identity D that sends an LXMF
direct message M as the distro (source = D's `lxmf.delivery` hash, signed
with D's key) to a recipient R, where R != D, also sends a copy C:

| | Copy C |
|---|---|
| Destination | D's `lxmf.delivery` |
| Source / signature | D, signed with D's key (the same "send as distro" path as M) |
| Title, content | Identical to M's. Text only: attachments are **not** copied; if M carried attachments, C's content is M's content unchanged and C carries none |
| `fields[0xFB]` (FIELD_CUSTOM_TYPE) | `"rfed.distro.sent"` |
| `fields[0xFC]` (FIELD_CUSTOM_DATA) | R's `lxmf.delivery` address, 32 lowercase hex characters |
| `fields[0xFD]` (FIELD_CUSTOM_META) | The **sending device's own** `lxmf.delivery` address, 32 lowercase hex characters |
| Method | PROPAGATED at once (D is a distro, §17.10); RFed intercepts it on `lxmf.propagation` like any distro message (§17.1) and fans it out to every registered device of D, the sender included |

C is sent exactly once per message the user sent, not once per delivery
attempt or method: a DIRECT attempt of M followed by a propagated fallback
is still one message and one copy. C is fire-and-forget. Its state never
changes M's delivery state, and it creates no message of its own on the
sending device.

**No copy is sent for:** identity transfers (`"rfed.distro.transfer"`,
§17.9), delivery notifications and ticket-only messages, group messages,
channel messages, messages whose destination is D itself, or when the device
holds no distro identity.

**Receiving.** A device unwraps a fan-out blob with its distro key (§17.3).
A message whose `fields[0xFB]` is `"rfed.distro.sent"` is a copy, and the
device applies these receive rules to it in order; the first rule that drops
the copy ends the check. A message from D without the marker keeps its
existing behaviour.

1. **Source.** If the unwrapped source is **not** the device's own distro
   D, the copy is ignored and logged: a genuine copy always comes from D,
   and anyone else claiming the marker is filing words into the user's
   conversations.
2. **Signature.** A copy whose source is D MUST carry a valid LXMF
   signature by D's key. A copy that fails the check is dropped with a log
   line and is never stored or shown. Rule 1 alone proves nothing: the
   LXMF source hash is plaintext inside the encrypted body, and D's public
   key is announced (§17.10), so anyone can encrypt a message to D that
   claims source D. Only the distro key can produce a genuine copy, and
   that holds only because of this check. The check is the one LXMF makes
   on every message it unpacks (`LXMessage.unpack_from_bytes`): with `dest`
   D's 16-byte `lxmf.delivery` hash that prefixes the blob, `src` and
   `signature` the first 16 and the next 64 bytes of the decrypted
   plaintext, and `payload` the msgpack bytes after them, the signature
   must be D's Ed25519 signature over
   `dest || src || payload || SHA-256(dest || src || payload)`. If the
   payload array carries a fifth element (a stamp), `payload` is instead
   the first four elements, `[timestamp, title, content, fields]`,
   re-packed with msgpack, because LXMF builds the signed data before it
   appends the stamp.
   `lxmf_rust::distro::unwrap_blob` enforces this rule for both native
   bridges: it returns an error for a copy that claims source D without
   D's signature, so Android's `nativeDistroUnwrap` and iOS's
   `retichat_distro_unwrap` return no message and the client logs the
   rejection.
3. **Own echo.** If `fields[0xFD]` equals this device's own
   `lxmf.delivery` address, the copy is this device's own echo. It is
   dropped silently, but still recorded for deduplication.
4. **Recipient.** `fields[0xFC]` must be exactly 32 hex characters and
   must not be D itself (a sender never copies a message addressed to D,
   so such a copy is malformed); anything else is dropped with a log line.
5. **Store.** A copy that passes rules 1-4 is stored as an **outgoing**
   message in the direct conversation with R:
   - sender D (it came from the distro, i.e. from "me");
   - state SENT, never DELIVERED: this device cannot know whether R
     received M;
   - timestamp = C's LXMF timestamp;
   - message id derived exactly as for any other distro fan-out message
     (source + timestamp + content), so a copy arriving twice (live fan-out
     and `/rfed/pull`, §17.8) is stored once;
   - the conversation with R is created if it does not exist, with no
     contact request and no stranger filter, since the user wrote to R;
   - no push or local notification: it is the user's own sent message.

`lxmf_rust::distro::unwrap_blob` reads the marker for both native bridges:
`DistroMessage.sent_to` is `fields[0xFC]` lowercased, and is set only when
the type matches and the value is 32 hex characters. `DistroMessage.sent_by`
is `fields[0xFD]` lowercased, and is set whenever the type matches (empty
when 0xFD is absent), so the client can still apply rule 1 to a marker from
another source. A set `sent_by` with no `sent_to` is therefore a copy with a
malformed 0xFC, which rule 4 drops. The unwrap JSON of Android's
`nativeDistroUnwrap` and iOS's `retichat_distro_unwrap` carries them as
`"sent_to"` and `"sent_by"` (string or null).

**Older clients.** A client that predates this section does not know the
marker and shows each copy as an incoming message from the distro address,
in a conversation with D. That remains so until the client is updated. It is
not worked around on the sending side or in RFed: RFed never decrypts the
copy, and suppressing copies to hide it would take the feature away from
updated siblings.

**Privacy.** `fields[0xFD]` reveals which device sent M. C is encrypted to D,
so only holders of the distro key can read it, and they are the user's own
devices, which already know one another's addresses from
`/rfed/distro/list` (§17.5). RFed and relays see only an ordinary distro
blob.

### 17.9 Distro Identity Transfer

The distro identity (64-byte private key) is shared between devices
using a URI format or encrypted LXMF transfer.

**URI format:**

```
rfed-distro-id://<128_hex_chars>
```

The 128 hex characters encode the 64-byte private key
(X25519_priv(32) || Ed25519_priv(32)). The public key is derived from
the private key on import.

**LXMF transfer:**

The sender addresses an ordinary LXMF message to the recipient's
`lxmf.delivery` address (signed as the sending *device*, not as the distro,
so the recipient can judge the offer by who sent it) and carries the key in
LXMF's custom-payload pair:

```
fields[0xFB] (FIELD_CUSTOM_TYPE) = "rfed.distro.transfer"
fields[0xFC] (FIELD_CUSTOM_DATA) = <128 hex chars, the private key>
```

A receiver treats a message as a transfer only when `FIELD_CUSTOM_TYPE`
equals that string. Field `0x0D`, used before 2026-09-24, is LXMF 1.1.1's
`FIELD_EVENT` and is neither written nor read.

**User flow:**

1. Device A generates a new distro identity (button press in Retichat).
2. Device A shares via LXMF to Device B (or shows QR code with URI).
3. Device B receives the encrypted private key, prompts user to import.
4. Device B imports identity and registers with RFed.

**Security model:**

- The private key is never displayed to the user.
- The URI is only shown ephemerally (QR code) or sent encrypted (LXMF).
- The identity is stored in the platform's secure enclave
  (iOS Keychain / Android Keystore).
- Possession of the private key = full access to all distro traffic.
  There is no revocation mechanism — a compromised key requires
  generating a new distro identity and re-registering all devices.

---

## License

See [LICENSE](rfed/LICENSE).

---

*This specification and the rfed codebase were developed through human–AI
collaboration using Claude (Anthropic) and GitHub Copilot. Architecture
decisions, code review, security audits, and testing were conducted by the
human author with AI assistance throughout the development process.*
