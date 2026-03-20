# RFed — Reticulum Federation Node

A store-and-forward federation node for the [Reticulum](https://reticulum.network) network. RFed provides named **channel** messaging with offline delivery, cross-node synchronisation, mobile push wake-ups, and subscriber backup failover — all running over Reticulum's encrypted transport layer.

> **AI-Assisted Development**: This project was developed with significant
> assistance from AI language models. Architecture, implementation, code review,
> and documentation were produced through iterative human–AI collaboration.

## Features

- **Named channels** — derive a 16-byte channel hash from any plain-text name; no server registration needed
- **Store-and-forward** — blobs are stored on disk and delivered when subscribers come online
- **Federation sync** — manifest-based gap-pull protocol between peer nodes
- **Deferred delivery** — offline subscribers receive queued blobs on reconnect or explicit pull
- **Notify relays** — lightweight wake packets enable mobile push without exposing message content
- **Backup failover** — chain-of-custody handoff when a primary node goes silent
- **LXMF propagation** — optional inbound LXMF acceptance for push-notification wake-ups
- **Proof-of-work stamps** — configurable PoW difficulty per subscriber tier (default / VIP)
- **Double-envelope encryption** — node never sees inner blob content; encrypted end-to-end

## Quick Start

### Prerequisites

- Rust 1.70+ toolchain
- [reticulum_rust](https://github.com/your-org/reticulum-rust) and [lxmf_rust](https://github.com/your-org/lxmf-rust) cloned alongside this repo (see [Dependencies](#dependencies))

### Build

```bash
cargo build --release
```

The binary is at `target/release/rfed`.

### Run

```bash
# Minimal — uses defaults, stores data in ~/.rfed/
rfed

# With a config file
rfed --config /path/to/config/dir

# Override settings via CLI
rfed --name "my-node" --stamp-cost 12 --storage-limit 5000
```

On first run, rfed writes a commented sample config to `<config_dir>/rfed.toml` if none exists.

### Configuration

Copy `rfed.toml.example` to your config directory and edit:

```bash
cp rfed.toml.example ~/.rfed/rfed.toml
```

See the [Specification](SPEC.md#13-configuration) for all options.

## Channel Hash Utilities

Any party that knows a channel name can independently derive its 16-byte hash. Utilities are provided in both Rust and Python.

### Python

```python
from channel_hash import compute_channel_hash

h = compute_channel_hash("public.news.tech")
print(h.hex())  # deterministic 16-byte hash
```

### Rust

```rust
use rfed::channel::ChannelKeypair;

let kp = ChannelKeypair::from_name("public.news.tech");
let hash: Vec<u8> = kp.hash();
println!("{}", hex::encode(&hash));
```

See [SPEC.md §1](SPEC.md#1-channel-hash-derivation) for the full algorithm.

## Architecture

```
Publishers ──► rfed node A ◄──sync──► rfed node B ◄── Subscribers
                  │                       │
                  ├── blob storage         ├── blob storage
                  ├── subscription table   ├── subscription table
                  ├── deferred queue       ├── deferred queue
                  └── notify relays        └── notify relays
```

Nodes form a loosely-coupled mesh with no central coordinator. Each node independently:
1. Accepts blobs from publishers
2. Stores and fans out to local subscribers
3. Synchronises with peers via manifest-based gap-pull
4. Queues deferred delivery for offline subscribers
5. Sends notify wake packets to registered relays

## Documentation

- **[SPEC.md](SPEC.md)** — Full protocol and operational specification
- **[rfed.toml.example](rfed.toml.example)** — Annotated configuration template

## Dependencies

RFed depends on two local Rust crates that must be cloned as siblings:

```
parent/
├── Reticulum-rust/    ← reticulum_rust crate
├── LXMF-rust/         ← lxmf_rust crate
└── ReticulumFederation/  ← this repo (RFed)
    ├── Cargo.toml
    ├── rfed/
    │   ├── Cargo.toml
    │   └── src/
    ├── SPEC.md
    └── rfed.toml.example
```

| Crate | Purpose |
|-------|---------|
| `reticulum_rust` | Rust Reticulum transport layer |
| `lxmf_rust` | LXMF message handling & PN stamps |

All other dependencies are pulled from crates.io automatically by Cargo.

## License

See [LICENSE](rfed/LICENSE).

---

*Built with Rust, Reticulum, and a healthy dose of AI-assisted engineering.*
