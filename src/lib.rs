//! linXiv P2P sharing: iroh transport + (flagged) keyhive capabilities + beelay sync.
//!
//! App code uses only this root interface; `auth`/`sync` internals never leak.

pub mod api;
pub mod sync;

pub use api::{
    ALPN as API_ALPN, ApiClientError, ApiHandlerFn, ApiProtocol, ApiResponse, ApiSlot, ByteLane,
    KnockLogFn, MemberCheckFn, NodeAddress, TransferLogFn, TransferOutcome,
};
pub use sync::{ALPN, AccessCheckFn, CustomRelay, DeviceIdentity, ShareNode, ShareTicket};

// Remote Query Mode gives app crates protocol handlers to mount
// ([`ShareNode::set_api_protocol`]) and a [`NodeAddress`] to mint — the iroh
// types those touch, so callers need no direct iroh dependency.
pub use iroh::{EndpointId, RelayUrl, protocol::DynProtocolHandler};

// vendor-edit: encrypted key store at rest (write-enforcement spec §8).
#[cfg(feature = "encrypted-store")]
pub use sync::KeyStoreError;

#[cfg(feature = "auth-keyhive")]
pub mod auth;

#[cfg(feature = "auth-keyhive")]
pub use auth::{
    AuthIdentity, DecryptError, DeviceBinding, MemberId, ProjectAuth, Role, SetRoleError,
};

#[cfg(feature = "sync-beelay")]
pub mod beelay;

#[cfg(feature = "sync-beelay")]
pub use beelay::{
    BEELAY_ALPN, BeelayNode, ProjectInvite, SyncOutcome, bind_stack, bind_stack_custom_relay,
    bind_stack_local,
};

// vendor-edit: the crate's fallible surface returns `n0_error::AnyError`;
// re-exported so callers can name it (e.g. to downcast `beelay::BlobError`).
pub use n0_error::AnyError;
