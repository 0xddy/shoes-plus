//! Replay-protection state whose lifetime is the lifetime of one inbound.
//!
//! A TCP handler is only one immutable generation of an inbound. There may be one
//! handler per bind IP, and dynamic reload replaces all of them. Keeping replay
//! filters inside those handlers therefore splits the protection across addresses
//! and forgets it on every reload. This scope is instead owned by `ServerHandle` and
//! cloned into every handler generation belonging to that handle.

use std::sync::OnceLock;
use std::sync::{Arc, Weak};
use std::time::Duration;

use parking_lot::Mutex;

use crate::replay_filter::ReplayFilter;
use crate::shadowsocks::salt_checker::SaltChecker;

/// A VMess auth id can be fresh for 120 seconds on either side of its timestamp.
/// Remembering it for the whole 240-second admissible interval leaves no replay gap.
pub(crate) const VMESS_AUTH_ID_WINDOW: Duration = Duration::from_secs(240);

/// SIP022 only requires an AEAD salt to be retained for 60 seconds.
pub(crate) const SHADOWSOCKS_SALT_WINDOW: Duration = Duration::from_secs(60);

pub(crate) type VmessAuthIdFilter = Arc<Mutex<ReplayFilter>>;
pub(crate) type ShadowsocksSaltFilter = Arc<Mutex<dyn SaltChecker>>;

/// The replay namespace for exactly one configured inbound.
///
/// VMess and Shadowsocks deliberately have separate filters: their wire values and
/// freshness windows are unrelated. Two configured inbounds deliberately get two
/// instances, while all bind addresses and reload generations of one inbound clone
/// these same two handles.
#[derive(Clone, Default)]
pub struct InboundReplayState {
    inner: Arc<InboundReplayStateInner>,
}

/// Strong live-generation owner for a replay namespace.
///
/// Rollback leases intentionally retain only [`InboundReplayState`]. Handlers and
/// listener handles retain this separate scope, allowing the engine to distinguish
/// "an old connection can still authenticate" from "only a rollback lease remains".
#[derive(Clone)]
pub struct InboundReplayScope {
    inner: Arc<InboundReplayScopeInner>,
}

struct InboundReplayScopeInner {
    state: InboundReplayState,
    lineage: Arc<()>,
}

/// Non-owning registry reference to the live handlers of one replay namespace.
#[derive(Clone)]
pub struct InboundReplayScopeWeak {
    inner: Weak<InboundReplayScopeInner>,
}

impl PartialEq for InboundReplayState {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for InboundReplayState {}

#[derive(Default)]
struct InboundReplayStateInner {
    vmess_auth_ids: OnceLock<VmessAuthIdFilter>,
    shadowsocks_salts: OnceLock<ShadowsocksSaltFilter>,
}

impl InboundReplayState {
    pub(crate) fn vmess_auth_ids(&self) -> VmessAuthIdFilter {
        Arc::clone(
            self.inner
                .vmess_auth_ids
                .get_or_init(new_vmess_auth_id_filter),
        )
    }

    pub(crate) fn shadowsocks_salts(&self) -> ShadowsocksSaltFilter {
        Arc::clone(
            self.inner
                .shadowsocks_salts
                .get_or_init(new_shadowsocks_salt_filter),
        )
    }
}

impl InboundReplayScope {
    pub fn new(state: InboundReplayState) -> Self {
        Self::with_lineage(state, Arc::new(()))
    }

    #[doc(hidden)]
    pub fn with_lineage(state: InboundReplayState, lineage: Arc<()>) -> Self {
        Self {
            inner: Arc::new(InboundReplayScopeInner { state, lineage }),
        }
    }

    pub fn state(&self) -> InboundReplayState {
        self.inner.state.clone()
    }

    #[doc(hidden)]
    pub fn lineage(&self) -> Arc<()> {
        Arc::clone(&self.inner.lineage)
    }

    pub fn downgrade(&self) -> InboundReplayScopeWeak {
        InboundReplayScopeWeak {
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub(crate) fn vmess_auth_ids(&self) -> VmessAuthIdFilter {
        self.inner.state.vmess_auth_ids()
    }

    pub(crate) fn shadowsocks_salts(&self) -> ShadowsocksSaltFilter {
        self.inner.state.shadowsocks_salts()
    }
}

impl InboundReplayScopeWeak {
    pub fn upgrade(&self) -> Option<InboundReplayScope> {
        self.inner
            .upgrade()
            .map(|inner| InboundReplayScope { inner })
    }
}

pub(crate) fn new_vmess_auth_id_filter() -> VmessAuthIdFilter {
    Arc::new(Mutex::new(ReplayFilter::new(VMESS_AUTH_ID_WINDOW)))
}

pub(crate) fn new_shadowsocks_salt_filter() -> ShadowsocksSaltFilter {
    Arc::new(Mutex::new(ReplayFilter::new(SHADOWSOCKS_SALT_WINDOW)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_one_inbound_but_new_scopes_are_isolated() {
        let inbound = InboundReplayState::default();
        let another_handler = inbound.clone();
        let another_inbound = InboundReplayState::default();

        assert!(inbound.inner.vmess_auth_ids.get().is_none());
        assert!(inbound.inner.shadowsocks_salts.get().is_none());

        let vmess = inbound.vmess_auth_ids();
        let shadowsocks = inbound.shadowsocks_salts();
        assert!(Arc::ptr_eq(&vmess, &another_handler.vmess_auth_ids()));
        assert!(Arc::ptr_eq(
            &shadowsocks,
            &another_handler.shadowsocks_salts()
        ));
        assert!(!Arc::ptr_eq(
            &inbound.vmess_auth_ids(),
            &another_inbound.vmess_auth_ids()
        ));
        assert!(!Arc::ptr_eq(
            &inbound.shadowsocks_salts(),
            &another_inbound.shadowsocks_salts()
        ));
    }
}
