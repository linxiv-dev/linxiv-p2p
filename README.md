# linxiv-p2p

P2P project sharing for linXiv: iroh transport + Keyhive capabilities +
Beelay encrypted sync. The full protocol stack is implemented and tested
**behind feature flags** so linXiv is ready the day Keyhive stabilizes.

> [!WARNING]
> This code is a personal implementation of a pre-alpha technology, always review code yourself 
> before relying on it for any confidentiality or security reasons.
## Layers

| Module | Flag | What |
|---|---|---|
| `sync` | (default) | Persistent device identity, ALPN `linxiv/sync/0`, pasteable share tickets, plain automerge sync. Ship-quality fallback path. |
| `auth` | `auth-keyhive` | keyhive_core 0.5.0: per-project groups, signed delegations (`Role::{Relay,Read,Edit,Admin}`), revocation + PCS rotation, dual cross-signed device keys, access-check hook. |
| `beelay` | `sync-beelay` | beelay-core alpha moves keyhive-encrypted automerge changes as opaque commits over iroh, plus an iroh-blobs path for encrypted file transfer. |

## Test

```sh
cargo test                            # phase 1 (3)
cargo test --features auth-keyhive    # + capability layer (15)
cargo test --features sync-beelay     # + encrypted sync e2e (14, +1 ignored)
cargo test --features sync-beelay --release -- --ignored   # 5/25 MiB blob timings
```

Tests are offline (no relay/discovery). `tests/beelay.rs::e2e_toy_project` is
the gate: create → delegate → sync → edit both sides → revoke → new content
"undecryptable". 

## Acknowledgements

Built on top of [Ink & Switch](https://www.inkandswitch.com/)'s
[Keyhive](https://github.com/inkandswitch/keyhive) and
[Beelay](https://github.com/inkandswitch/beelay) research, and
[n0's iroh](https://github.com/n0-computer/iroh) transport. Thank you both
for generously open-sourcing incredible software.
