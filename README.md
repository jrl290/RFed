# RFed — Reticulum Federation Node

A subscriber federation node for the [Reticulum](https://reticulum.network) network. RFed provides named **channel** messaging with deferred delivery, cross-node synchronisation, notify wake-ups, and subscriber backup failover — all running over Reticulum's encrypted transport layer.

> **AI-Assisted Development**: This project was developed with significant
> assistance from AI language models. Architecture, implementation, code review,
> and documentation were produced through iterative human–AI collaboration.

## Built on LXMF

RFed's core transport is modelled directly on the [LXMF](https://github.com/markqvist/LXMF) (Lightweight Extensible Message Format) store-and-forward architecture. The following mechanisms are carried over from LXMF and adapted for channel-based messaging:

| Mechanism | LXMF Origin | RFed Adaptation |
|-----------|-------------|-----------------|
| **Propagation node model** | Messages stored by destination hash, retrieved by recipients on demand | Blobs stored by channel hash, fanned out to subscribers |
| **OFFER / GET sync protocol** | Peer sends manifest of IDs → gap computed → missing blobs fetched | Identical wire protocol (`/rfed/offer`, `/rfed/get`), filtered to channels with local subscribers |
| **Proof-of-work stamps** | Sender stamps validated at configurable bit difficulty (msg / PN / peering tiers) | Reuses LXMF stamp validation via `lxmf_rust`; same cost/flexibility model |
| **Peering cost** | Propagation nodes advertise a PoW cost for incoming peers | Parsed from peer announces; used in sync backoff scheduling |
| **Destination hash routing** | First 16 bytes of wire format = recipient hash (plaintext, for routing) | Channel hash occupies the same position in the SEND packet |
| **Exponential backoff** | Sync retry with increasing delay on failure, reset on success | Same pattern: 10 s min → 1 hour max, reset on announce heard |
| **Announce metadata** | Msgpack array with node state, limits, stamp params, metadata map | Simplified RFed node announce plus standard LXMF propagation metadata on the optional full `lxmf.propagation` service |

RFed extends beyond LXMF with **named channels**, **explicit subscriptions**, **double-envelope encryption**, **notify relays**, **deferred per-subscriber queuing**, and **backup failover with chain-of-custody** — none of which exist in LXMF.

## RFed and LXMF Propagation

RFed now exposes two distinct LXMF-related surfaces:

| Service | Stored unit | Retrieval model | Sync model | End goal |
|---------|-------------|-----------------|------------|----------|
| RFed channel federation (`rfed.channel.*`) | Channel-addressed opaque blobs | Subscribers receive live fanout or pull deferred pages from rfed | OFFER / GET between rfed peers, filtered to channels with local subscribers | Named-channel messaging |
| Optional `lxmf.propagation` service | Recipient-addressed LXMF messages | Standard LXMF clients pull with GET | Standard LXMF OFFER / GET between propagation peers | Full LXMF mailbox / propagation compatibility |

RFed's channel federation is still a separate service from LXMF mailbox storage, but the binary can host both. When `lxmf_propagation = yes`, rfed announces `lxmf.propagation`, stores inbound LXMF messages, serves client GETs, peers with LXMF-rust `lxmd` instances and other rfed nodes, and fires notify wake-ups for registered destinations.

## Features

- **Named channels** — derive a 16-byte channel hash from any plain-text name; no server registration needed
- **Subscriber delivery** — blobs are stored on disk and delivered to subscribers when they come online
- **Federation sync** — manifest-based gap-pull protocol between peer nodes (LXMF OFFER/GET)
- **Deferred delivery** — offline subscribers receive queued blobs on reconnect or explicit pull
- **Notify relays** — lightweight wake packets to registered relays; can be used for mobile push notifications (APNs, FCM, UnifiedPush) without exposing message content
- **Backup failover** — chain-of-custody handoff when a primary node goes silent
- **LXMF propagation node** — when enabled, rfed announces `lxmf.propagation`, stores inbound LXMF messages, serves client GETs, peers with other propagation nodes, and also fires notify wake-ups for registered destinations
- **Proof-of-work stamps** — configurable PoW difficulty per subscriber tier (default / VIP)
- **Double-envelope encryption** — node never sees inner blob content; encrypted end-to-end

## Install and Run

RFed can be installed from prebuilt release binaries. Manual source builds are still supported and are documented further down in this section.

### 1. Download a release binary

Download the matching archive from the project's GitHub releases page:

- `rfed-vX.Y.Z-linux-x86_64.tar.gz` for Linux x86_64
- `rfed-vX.Y.Z-linux-arm64.tar.gz` for Linux ARM64
- `rfed-vX.Y.Z-darwin-arm64.tar.gz` for macOS Apple Silicon

Each release archive contains the `rfed` binary, `config.txt.example`, and a copy of this README. A matching `.sha256` file is published alongside each archive.

Example for Linux x86_64:

```bash
VERSION=v0.1.0
PACKAGE_DIR="rfed-${VERSION}-linux-x86_64"
curl -L -o rfed.tar.gz \
    "https://github.com/jrl290/RFed-rust/releases/download/${VERSION}/rfed-${VERSION}-linux-x86_64.tar.gz"
tar -xzf rfed.tar.gz
sudo install -m 755 "${PACKAGE_DIR}/rfed" /usr/local/bin/rfed
```

On macOS, extract `rfed-${VERSION}-darwin-arm64.tar.gz` and move `rfed` into a directory on your `PATH`.

If you do not see a matching binary for your platform yet, use the manual build path in step 4.

### 2. Create a config directory

`rfed --config` expects a directory that contains a file named `config`, not a direct path to the file itself. The file uses Reticulum's native config format rather than TOML.

```bash
mkdir -p ~/.rfed
cp "${PACKAGE_DIR}/config.txt.example" ~/.rfed/config
```

If you downloaded manually instead of using the Linux snippet above, replace `${PACKAGE_DIR}` with the extracted release directory. If you are installing from a macOS archive, copy `config.txt.example` out of that extracted directory instead.

On first run, rfed will also write a commented sample config to `<config_dir>/config` if none exists yet.

### 3. Start the node

```bash
# Minimal — defaults, stores data in ~/.rfed/
rfed

# Explicit config directory
rfed --config ~/.rfed

# Override selected settings for one run
rfed --config ~/.rfed --name "my-node"
```

### 4. Build from source (manual)

If you prefer to build locally, or need a platform without a published release binary, use the source-build path below.

From the `RFed-rust/` checkout:

```bash
./scripts/bootstrap-sibling-deps.sh
```

That script fetches the required sibling crates into the parent directory of `RFed-rust`, which is the layout Cargo expects today.

You still need:

- Rust 1.70+ toolchain

If you are actively developing across all four repositories, the manual sibling layout remains supported:

```text
parent/
├── Reticulum-rust/
├── LXMF-rust/
├── app-links/
└── RFed-rust/
```

#### Build the node binary

From the `RFed-rust/` workspace root:

```bash
cargo build --release -p rfed
```

The node binary will be written to `target/release/rfed`.

#### Start the manually built node

```bash
# Development run from Cargo
cargo run --release -p rfed -- --config ~/.rfed

# Or run the built binary directly
./target/release/rfed --config ~/.rfed
```

### 5. Operator checklist

Before treating the node as production-ready, make sure you have explicitly reviewed:

- `[node].name` so peers and operators can identify the node in announces
- `[storage]` limits so sync and blob retention stay bounded
- `[peering].static_peers` if you want deterministic bootstrap peers
- `[policy.default]` and `[policy.vip]` so send cost, deferred limits, and backup policy match your threat model
- `[node].lxmf_propagation` if you want rfed to run the full `lxmf.propagation` service alongside channel federation
- `[node].lxmf_propagation_autopeer` and `[peering].propagation_peers` so propagation peering matches your discovery model

For the full configuration reference, see [SPEC.md](SPEC.md#13-configuration) and the annotated [config.txt.example](config.txt.example).

## Channels Are Reticulum Destinations

A channel is derived using the same cryptographic primitives as a Reticulum identity — X25519 for encryption and Ed25519 for signing — but it is **not** a registered or announced identity on the network. The keypair is deterministically computed from the channel name, so anyone who knows the name independently derives the same keys and the same 16-byte destination hash:

```
"public.news.tech"
        │
        ▼
  seed = SHA-256("public.news.tech")            → 32 bytes
        │
        ├─► X25519 public key (from seed)       → 32 bytes  (encryption)
        └─► Ed25519 public key (from seed)      → 32 bytes  (signing)
                │
                ▼
  bundle = X25519_pub ‖ Ed25519_pub             → 64 bytes
        │
        ▼
  channel_hash = SHA-256(bundle)[0..16]         → 16 bytes  (destination hash)
```

**Possession of the channel name = possession of the private keys = ability to decrypt.**

RFed nodes only ever see the 16-byte `channel_hash`. They store and route opaque blobs encrypted to the channel's public key. The nodes are **cryptographically blind** — they cannot decrypt any message content.

### Channels Are Virtual — Not Announced, Not Routed

Although a channel hash is derived using the same cryptographic primitives as a Reticulum identity (X25519 + Ed25519 → destination hash), **channels are never announced or routed on the Reticulum network**. No Reticulum destination is registered for a channel, and no packets are addressed *to* the channel hash as a transport destination.

Instead, a channel only comes into existence when a sender publishes a blob to the rfed node's `rfed.channel.publish` destination with the channel hash embedded in the payload. The node treats the hash as an opaque storage key — it has no awareness that the hash corresponds to a keypair, only that blobs should be filed under it and fanned out to matching subscribers.

This is directly analogous to how LXMF propagation works: an LXMF propagation node stores messages keyed by the recipient's destination hash without that recipient being registered or announced on the node itself. The node is a mailbox, not a router. RFed applies the same principle to channels.

### Channel Hash Utilities

Utilities for computing channel hashes are provided in both Rust and Python:

```python
# Python
from channel_hash import compute_channel_hash
h = compute_channel_hash("public.news.tech")
print(h.hex())
```

```rust
// Rust
let kp = ChannelKeypair::from_name("public.news.tech");
let hash: Vec<u8> = kp.hash();
```

### Naming Conventions

| Pattern | Visibility | Example |
|---------|-----------|--------|
| `public.<segments>` | Discoverable by name | `public.news.tech` |
| `<hash>.<segments>` | Private; hash acts as access control | `a1b2c3d4e5f6.team.ops` |

For **public** channels the first segment is the literal string `"public"`. Anyone who learns the name can subscribe and decrypt.

For **private** channels, use a cryptographically random hex string (e.g. 32+ characters from a CSPRNG) as the first segment. Possession of the full channel name equals membership — the random prefix makes it computationally infeasible to guess. Distribute the name out-of-band to intended members only.

See [SPEC.md §1](SPEC.md#1-channel-hash-derivation) for the full derivation algorithm.

## Writing Applications Around RFed

Application code talks to an rfed node, not to a channel as an announced network destination. The channel name stays local to the application and is used to derive the channel identity, encrypt/decrypt the inner blob, and prove that the user is a member of the channel.

### Modern client surface

New clients should use the split service destinations announced by rfed:

Reticulum destination names are rendered in dot notation, like
`rfed.channel.subscribe`. Request handlers on an established link use a
separate request-path string. Following the convention used in the official
Reticulum examples and built-in services, RFed writes those request paths with
a leading slash, like `/rfed/subscribe` or `/rfed/pull`.

| Purpose | Destination | Operation |
|---------|-------------|-----------|
| Publish channel data | `rfed.channel.publish` | Fire-and-forget SEND payload `[channel_hash | inner_blob | stamp]` |
| Subscribe to a channel | `rfed.channel.subscribe` | Request path `/rfed/subscribe` |
| Unsubscribe from a channel | `rfed.channel.unsubscribe` | Request path `/rfed/unsubscribe` |
| Pull deferred data for one channel | `rfed.channel.pull` | Request path `/rfed/pull` with `bin(16)` channel hash |
| Receive live fanout | `rfed.delivery` | Inbound Reticulum Single packets addressed to the subscriber |
| Register or remove wake relays | `rfed.notify.register` / `rfed.notify.unregister` | Notify relay management |

The older combined `rfed.channel`, `rfed.delivery`, and `rfed.notify` surfaces still exist for transition compatibility, but new client code should target the split destinations above.

### Publisher flow

1. Discover or configure the destination hash of the rfed node you want to publish through.
2. Derive the channel identity and 16-byte `channel_hash` from the channel name.
3. Build the inner blob locally. The interoperable choice is to pack an LXMF `PROPAGATED` message, prepend the required source-identity prelude, and encrypt that payload to the channel identity.
4. Learn the node's current SEND stamp policy. The authoritative application-facing contract today is the `/rfed/subscribe` response shape `[ok_bool, stamp_cost_or_nil]`.
5. Append the RFed stamp over `channel_hash || inner_blob` when stamping is enabled, then send `[channel_hash | inner_blob | stamp]` to `rfed.channel.publish`.

### Subscriber flow

1. Create or load the subscriber's Reticulum identity.
2. Open a link to `rfed.channel.subscribe` and send a **signed** subscribe request carrying `[channel_hash, subscriber_pubkey, signature(channel_hash)]`.
3. Store the returned `stamp_cost` if the node requires SEND proof of work.
4. Announce or otherwise make your `rfed.delivery` destination reachable for live fanout.
5. Optionally register notify relays so offline wakeups can be triggered without exposing message content.
6. When data arrives, use the channel name to re-derive the channel identity and decrypt the inner blob locally.

### What your application owns

RFed handles blob storage, deferred queues, peer sync, and per-subscriber fanout. Your application still owns:

- channel naming and distribution
- subscriber identity lifecycle
- message plaintext schema
- decryption and sender verification on the client side
- any UX around retries, paging, or showing `more_pending`

If you already have an LXMF-capable application stack, the cleanest integration is usually to keep using LXMF for the inner authenticated message format and let RFed provide the outer channel fanout and deferred-delivery layer.

## Architecture: Message Journey

### Step-by-Step: Sender to Subscriber

```
 ┌──────────┐         ┌──────────────┐         ┌─────────────┐
 │  Sender  │────1───►│  rfed node A │────4───►│ Subscriber  │
 └──────────┘         └──────┬───────┘         └─────────────┘
                             │
                          2  │  3
                             ▼
                      ┌──────────────┐
                      │  rfed node B │────4───► (other subscribers)
                      └──────────────┘
```

#### Step 1 — Sender publishes to rfed node

The sender derives the channel's X25519 public key from the channel name and encrypts the message content to it (ephemeral ECDH + HKDF + AES-CBC-HMAC — the same scheme Reticulum uses for `Identity.encrypt()`). This produces an **inner blob** — opaque to anyone who doesn't know the channel name.

> **Note:** RFed itself does not add a separate server-side sender-auth layer,
> but the interoperable channel payload format does carry sender identity and
> authenticity inside the encrypted inner blob. The recommended format is an
> LXMF-rust `LXMessage::pack(PROPAGATED)` block plus the required source-identity
> prelude, which gives subscribers the same signature-verification semantics used
> by LXMF propagation without exposing plaintext to the rfed node.

The sender transmits to the node's `rfed.channel.publish` destination
(`rfed.channel` remains as a legacy compatibility alias during transition):

```
[ channel_hash (16 bytes) | inner_blob | PoW stamp ]
```

**channel_hash is the channel _identity hash_** — the routing label
RFed uses (subscribers signed it during `/rfed/subscribe`). **inner_blob
is the EC-encrypted authentication payload** from
`LXMessage::pack(PROPAGATED)` — byte-identical to what an LXMF
propagation node carries:

```
inner_blob = EC_encrypted(
    source_hash (16) || signature (64) || msgpack_payload
)
```

The channel identity (which holds both the X25519 encryption key and the
Ed25519 verification baseline) is derived deterministically from the
channel name. Subscribers re-derive the channel identity, EC-decrypt the
inner_blob, and reconstruct the canonical LXMF block by prepending the
`lxmf.delivery` destination_hash for the channel identity, then feed the
result to `LXMessage::unpack_from_bytes(_, Some(PROPAGATED))`, which
validates the signature against the cached sender identity. If the sender
has not announced and isn't in the cache, the message is rejected as
`SOURCE_UNKNOWN`.

| Data | Encrypted? | Visible to rfed node? |
|------|-----------|----------------------|
| Channel hash | No (routing label) | **Yes** — used for storage and fanout lookup |
| Inner blob (LXMF EC ciphertext) | Yes (to channel X25519 key) | **No** — opaque ciphertext |
| Sender identity / signature | Yes (inside LXMF EC ciphertext) | **No** |
| PoW stamp | No | **Yes** — validated then stripped before storage |

#### Step 2 — Node stores the blob

The node validates the PoW stamp, strips it, and writes the raw inner blob to disk under `blobs/<channel_hash_hex>/<message_id_hex>`. The `message_id` is randomly generated by the node. The node never modifies the inner blob.

| Data at rest | Visible to node operator? |
|-------------|--------------------------|
| Channel hash | **Yes** — directory name |
| Message ID | **Yes** — filename (random, reveals nothing) |
| Blob content | **No** — still encrypted to channel pubkey |
| Sender identity | **No** — not stored anywhere |

#### Step 3 — Federation sync (OFFER / GET)

Peer nodes exchange manifests and gap-pull missing blobs. Only blobs for channels that have **local subscribers** are requested — preventing unbounded storage growth.

| Data on the wire | Visible to either peer? |
|-----------------|------------------------|
| Message IDs | **Yes** — used for gap computation |
| Channel hashes | **Yes** — used to filter relevant blobs |
| Blob content | **No** — still encrypted to channel pubkey |
| Subscriber list | **No** — never shared between peers |

#### Step 4 — Fanout to subscribers (double envelope)

The node wraps each inner blob in a second Reticulum envelope addressed to the subscriber's `rfed.delivery` destination:

```
┌─── Outer Envelope (rfed node → subscriber) ──────────────────┐
│  Reticulum Single packet (encrypted to subscriber's pubkey)  │
│                                                              │
│  ┌─── Inner Blob (sender → channel) ─────────────────────┐  │
│  │  Encrypted to channel's X25519 pubkey                  │  │
│  │  Content: opaque to rfed node                          │  │
│  │  (sender auth carried by LXMF inner format)            │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

| Data | Visible to rfed node? | Visible to subscriber? |
|------|----------------------|----------------------|
| Outer envelope (routing) | **Yes** — the node created it | Decrypted by subscriber |
| Inner blob ciphertext | **Yes** — but cannot decrypt | **Yes** — then decrypts with channel privkey |
| Inner blob plaintext | **No** — lacks channel privkey | **Yes** — knows channel name |

If the subscriber is offline, the blob enters the **deferred queue** and is delivered on reconnect or explicit pull.

### Encryption Summary

| Party | Knows | Can decrypt content? | Sees |
|-------|-------|---------------------|------|
| **Sender** | Channel name, own keys | Yes | Only what they send |
| **rfed node** | Channel hash only | **No** | Opaque blobs, routing hashes |
| **Subscriber** | Channel name | **Yes** | Decrypted content |
| **Federation peer** | Channel hash only | **No** | Opaque blobs during sync |
| **Network observer** | Nothing | **No** | Reticulum-encrypted packets |

The rfed node is a **courier, not a reader**. It repackages and propagates channel messages in a fanout manner without ever accessing the content.

## Documentation

- **[README.md](README.md)** — Installation, operator onboarding, application integration, and architecture overview
- **[SPEC.md](SPEC.md)** — Full protocol and operational specification
- **[config.txt.example](config.txt.example)** — Example Reticulum-native configuration copied to `<config_dir>/config`
- **[rfed/TESTS.md](rfed/TESTS.md)** — Automated and manual test entry points

## Dependencies

RFed currently builds against three sibling local crates: `reticulum_rust`, `lxmf_rust`, and `app_links`. For normal installs, `./scripts/bootstrap-sibling-deps.sh` clones them into the correct parent-directory layout automatically. If you are working across the repos directly, the manual layout is:

```
parent/
├── Reticulum-rust/    ← reticulum_rust crate
├── LXMF-rust/         ← lxmf_rust crate
├── app-links/         ← app_links crate
└── RFed-rust/  ← this repo (RFed)
    ├── Cargo.toml
    ├── rfed/
    │   ├── Cargo.toml
    │   └── src/
    ├── SPEC.md
    └── config.txt.example
```

| Crate | Purpose |
|-------|---------|
| `reticulum_rust` | Rust Reticulum transport layer |
| `lxmf_rust` | LXMF message handling & PN stamps |
| `app_links` | Shared app-link types used transitively by `lxmf_rust` |

All other dependencies are pulled from crates.io automatically by Cargo.

## License

See [LICENSE](rfed/LICENSE).

---

*Built with Rust, Reticulum, and a healthy dose of AI-assisted engineering.*
