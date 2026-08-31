//! The registry used when an inbound gets its users from a config file.
//!
//! Immutable once built, so lookups need no synchronisation at all. This is the
//! fallback path: when nothing injects a registry, each protocol handler builds one
//! of these from the credentials in its own config section, which reproduces the
//! single-user comparison the handlers did before the registry existed.

use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};
use subtle::ConstantTimeEq;

use super::credential::{
    VmessAuthKey, naive_basic_credential, password_sha256, password_sha256_prefix,
};
use super::registry::{TuicIdentity, UserRegistry, VmessIdentity};
use super::user::UserContext;
use crate::trojan_handler::create_password_hash;
use crate::uuid_util::parse_uuid;

/// Identity reported for users that came from a config file rather than an API.
///
/// Password-based protocols have no name in their config, and the password itself
/// must never be used as an identity, so they all share this label.
const CONFIG_USER_ID: &str = "config";

struct Entry {
    context: Arc<UserContext>,
    /// The credential exactly as it arrives on the wire, retained so that a hit can
    /// be confirmed in constant time. The hash probe that found this entry is not
    /// constant time and is not treated as proof of anything.
    credential: Box<[u8]>,
    /// Present only for uuid entries, since VMess is the one protocol here that
    /// cannot be indexed on. Held inside the entry rather than in a list of its own
    /// so that a user has exactly one record: re-registering a uuid replaces it
    /// whole, with no second table left pointing at the superseded context.
    vmess: Option<VmessAuthKey>,
    /// Present only for TUIC entries, where the uuid alone is not the credential: the
    /// token beside it is keyed with this password. Not indexed on, and not a
    /// credential in its own right -- a TUIC user cannot authenticate by password.
    tuic_password: Option<Arc<str>>,
}

impl Entry {
    fn new(id: &str, credential: impl Into<Box<[u8]>>) -> Self {
        Self {
            context: UserContext::new_untracked(id),
            credential: credential.into(),
            vmess: None,
            tuic_password: None,
        }
    }

    fn uuid(id: &str, uuid: [u8; 16]) -> Self {
        Self {
            vmess: Some(VmessAuthKey::new(&uuid)),
            ..Self::new(id, uuid)
        }
    }

    fn tuic(id: &str, uuid: [u8; 16], password: &str) -> Self {
        Self {
            tuic_password: Some(password.into()),
            ..Self::new(id, uuid)
        }
    }

    fn verify(&self, presented: &[u8]) -> Option<Arc<UserContext>> {
        if self.credential.ct_eq(presented).unwrap_u8() == 0 || !self.context.is_enabled() {
            return None;
        }
        Some(self.context.clone())
    }

    /// Whether this entry's user sealed `auth_id`.
    ///
    /// No constant-time comparison here, and none is called for: unlike `verify`,
    /// nothing is being compared against a stored secret. A valid checksum means the
    /// sixteen bytes were produced by somebody holding the uuid -- which is not the
    /// same as the *sender* holding it, since those bytes cross the wire in the
    /// clear and can be copied. Like every registry lookup this only resolves a
    /// candidate; the handler admits it once the header AEAD proves possession. See
    /// [`UserRegistry::find_vmess_auth_id`].
    fn verify_vmess(&self, auth_id: &[u8; 16]) -> Option<VmessIdentity> {
        let key = self.vmess.as_ref()?;
        let timestamp = key.open(auth_id)?;
        if !self.context.is_enabled() {
            return None;
        }
        Some(VmessIdentity {
            user: self.context.clone(),
            instruction_key: *key.instruction_key(),
            timestamp,
        })
    }

    /// This entry's user and TUIC password, if the uuid is theirs.
    ///
    /// The token that proves the client holds the password has not been checked yet,
    /// and cannot be checked from in here. See
    /// [`UserRegistry::find_tuic_uuid`](super::registry::UserRegistry::find_tuic_uuid).
    fn verify_tuic(&self, uuid: &[u8; 16]) -> Option<TuicIdentity> {
        let password = self.tuic_password.clone()?;
        if self.credential.ct_eq(&uuid[..]).unwrap_u8() == 0 || !self.context.is_enabled() {
            return None;
        }
        Some(TuicIdentity {
            user: self.context.clone(),
            password,
        })
    }
}

#[derive(Default)]
pub struct StaticUserRegistry {
    by_uuid: FxHashMap<[u8; 16], Entry>,
    by_trojan_hash: FxHashMap<Box<[u8]>, Entry>,
    by_password: FxHashMap<Box<str>, Entry>,
    by_anytls_hash: FxHashMap<[u8; 32], Entry>,
    by_naive_encoded: FxHashMap<Box<[u8]>, Entry>,
    /// The 8-byte prefixes of everything in `by_anytls_hash`, for the probe AnyTLS
    /// makes before it has read a whole credential. A set rather than a count,
    /// because this map is immutable once built and nothing is ever removed from it.
    anytls_prefixes: FxHashSet<[u8; 8]>,
}

impl std::fmt::Debug for StaticUserRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticUserRegistry")
            .field("num_users", &self.user_count())
            .finish()
    }
}

impl StaticUserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a uuid credential, identified by its own canonical form.
    ///
    /// A uuid is not a secret in the sense a password is: it is what VLESS puts on
    /// the wire in cleartext, and it is already the identity every operator uses to
    /// refer to the user, so it is safe and useful as the reported id.
    pub fn add_uuid(&mut self, uuid_str: &str) -> std::io::Result<&mut Self> {
        let bytes = parse_uuid(uuid_str)?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes);
        self.by_uuid.insert(uuid, Entry::uuid(uuid_str, uuid));
        Ok(self)
    }

    pub fn add_trojan_password(&mut self, password: &str) -> &mut Self {
        let hash = create_password_hash(password);
        self.by_trojan_hash
            .insert(hash.clone(), Entry::new(CONFIG_USER_ID, hash));
        self
    }

    pub fn add_password(&mut self, id: &str, password: &str) -> &mut Self {
        self.by_password.insert(
            password.into(),
            Entry::new(id, password.as_bytes().to_vec()),
        );
        self
    }

    /// Register a TUIC credential: a uuid and the password its token is keyed with.
    ///
    /// The uuid is the reported id, for the same reason as [`add_uuid`](Self::add_uuid)
    /// -- TUIC sends it in cleartext and operators already refer to the user by it.
    /// The password never serves as an id and is not registered as a credential of its
    /// own, so this user cannot authenticate anywhere but TUIC.
    pub fn add_tuic(&mut self, uuid_str: &str, password: &str) -> std::io::Result<&mut Self> {
        let bytes = parse_uuid(uuid_str)?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes);
        self.by_uuid
            .insert(uuid, Entry::tuic(uuid_str, uuid, password));
        Ok(self)
    }

    /// Registry for a config that declares exactly one uuid.
    pub fn single_uuid(uuid_str: &str) -> std::io::Result<Arc<dyn UserRegistry>> {
        let mut registry = Self::new();
        registry.add_uuid(uuid_str)?;
        Ok(Arc::new(registry))
    }

    /// Registry for a config that declares exactly one Trojan password.
    pub fn single_trojan_password(password: &str) -> Arc<dyn UserRegistry> {
        let mut registry = Self::new();
        registry.add_trojan_password(password);
        Arc::new(registry)
    }

    /// Registry for a config that declares exactly one cleartext password, as
    /// Hysteria2 does.
    ///
    /// Named like the Trojan one and for the same reason: the password is the whole
    /// credential, so there is nothing else that could serve as an id.
    pub fn single_password(password: &str) -> Arc<dyn UserRegistry> {
        let mut registry = Self::new();
        registry.add_password(CONFIG_USER_ID, password);
        Arc::new(registry)
    }

    /// Register an AnyTLS credential, indexed by the SHA-256 of the password that
    /// crosses the wire.
    ///
    /// Not registered as a plain password as well: AnyTLS never sends the cleartext,
    /// so a `find_password` hit on this value would mean some *other* protocol on the
    /// same inbound had accepted an AnyTLS user's secret in a form they never send.
    pub fn add_anytls_password(&mut self, id: &str, password: &str) -> &mut Self {
        let hash = password_sha256(password);
        self.anytls_prefixes.insert(password_sha256_prefix(&hash));
        self.by_anytls_hash.insert(hash, Entry::new(id, hash));
        self
    }

    /// Registry for a config that declares exactly one AnyTLS user.
    ///
    /// Takes the name from the config, unlike the password-only builders: an AnyTLS
    /// user config has a `name` field, so there is a real identity to report rather
    /// than [`CONFIG_USER_ID`].
    pub fn single_anytls_password(name: &str, password: &str) -> Arc<dyn UserRegistry> {
        let mut registry = Self::new();
        let id = if name.is_empty() {
            CONFIG_USER_ID
        } else {
            name
        };
        registry.add_anytls_password(id, password);
        Arc::new(registry)
    }

    /// Register a NaiveProxy credential: a username and password, indexed by the
    /// base64 pair the client actually sends.
    ///
    /// `name` is the config's display name, kept apart from `username` because
    /// NaiveProxy has both and only the latter is part of the credential.
    pub fn add_naive_user(&mut self, name: &str, username: &str, password: &str) -> &mut Self {
        let encoded = naive_basic_credential(username, password);
        let id = if name.is_empty() { username } else { name };
        self.by_naive_encoded
            .insert(encoded.clone(), Entry::new(id, encoded));
        self
    }

    /// Registry for a config that declares exactly one TUIC uuid and password.
    pub fn single_tuic(uuid_str: &str, password: &str) -> std::io::Result<Arc<dyn UserRegistry>> {
        let mut registry = Self::new();
        registry.add_tuic(uuid_str, password)?;
        Ok(Arc::new(registry))
    }
}

impl UserRegistry for StaticUserRegistry {
    fn find_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<UserContext>> {
        self.by_uuid.get(uuid)?.verify(uuid)
    }

    fn find_trojan_hash(&self, hash: &[u8]) -> Option<Arc<UserContext>> {
        self.by_trojan_hash.get(hash)?.verify(hash)
    }

    fn find_password(&self, password: &str) -> Option<Arc<UserContext>> {
        self.by_password.get(password)?.verify(password.as_bytes())
    }

    fn find_vmess_auth_id(&self, auth_id: &[u8; 16]) -> Option<VmessIdentity> {
        // A trial over every uuid entry, because there is nothing to index on. A
        // config-built registry holds one, so the loop is a formality here; it is the
        // dynamic registry that pays the linear cost.
        self.by_uuid.values().find_map(|e| e.verify_vmess(auth_id))
    }

    fn find_tuic_uuid(&self, uuid: &[u8; 16]) -> Option<TuicIdentity> {
        self.by_uuid.get(uuid)?.verify_tuic(uuid)
    }

    fn find_password_sha256(&self, hash: &[u8; 32]) -> Option<Arc<UserContext>> {
        self.by_anytls_hash.get(hash)?.verify(&hash[..])
    }

    fn find_naive_basic(&self, encoded: &[u8]) -> Option<Arc<UserContext>> {
        self.by_naive_encoded.get(encoded)?.verify(encoded)
    }

    fn has_password_sha256_prefix(&self, prefix: &[u8; 8]) -> bool {
        // Deliberately no `is_enabled` check: see the trait method's docs. A
        // suspended user's connections must reach the same place a live user's do,
        // or the fallback becomes an oracle for who has been suspended.
        self.anytls_prefixes.contains(prefix)
    }

    fn user_count(&self) -> usize {
        self.by_uuid.len()
            + self.by_trojan_hash.len()
            + self.by_password.len()
            + self.by_anytls_hash.len()
            + self.by_naive_encoded.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

    fn seal_auth_id(uuid: &str, time_secs: u64, padding: [u8; 4]) -> [u8; 16] {
        VmessAuthKey::new(&uuid_bytes(uuid)).seal(time_secs, padding)
    }

    fn uuid_bytes(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&parse_uuid(s).unwrap());
        out
    }

    #[test]
    fn finds_a_registered_uuid_and_rejects_others() {
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();

        let found = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        assert_eq!(&**found.id(), UUID);
        assert_eq!(found.total_conns(), 0);

        assert!(
            registry
                .find_uuid(&uuid_bytes("11111111-1111-4111-8111-111111111111"))
                .is_none()
        );
    }

    #[test]
    fn accepts_a_uuid_without_dashes() {
        // VLESS carries raw bytes, so the wire form of both spellings is identical.
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        assert!(
            registry
                .find_uuid(&uuid_bytes(&UUID.replace('-', "")))
                .is_some()
        );
    }

    #[test]
    fn rejects_an_invalid_uuid_at_build_time() {
        assert!(StaticUserRegistry::single_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn shares_one_context_across_lookups() {
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        let a = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        let b = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "each user must have one shared record");

        a.add_rx(100);
        b.add_tx(40);
        assert_eq!((b.rx(), a.tx()), (100, 40));
    }

    #[test]
    fn a_disabled_user_looks_absent() {
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        let user = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        user.set_enabled(false);
        assert!(registry.find_uuid(&uuid_bytes(UUID)).is_none());
        user.set_enabled(true);
        assert!(registry.find_uuid(&uuid_bytes(UUID)).is_some());
    }

    #[test]
    fn finds_a_trojan_password_by_its_wire_hash() {
        let registry = StaticUserRegistry::single_trojan_password("hunter2");
        let hash = create_password_hash("hunter2");
        assert_eq!(hash.len(), 56);
        assert!(registry.find_trojan_hash(&hash).is_some());
        assert!(
            registry
                .find_trojan_hash(&create_password_hash("hunter3"))
                .is_none()
        );
        // A short read must not panic or match.
        assert!(registry.find_trojan_hash(b"").is_none());
        assert!(registry.find_trojan_hash(&hash[..55]).is_none());
    }

    #[test]
    fn finds_a_cleartext_password_without_admitting_it() {
        let registry = StaticUserRegistry::single_password("hunter2");
        let found = registry
            .find_password("hunter2")
            .expect("the config's own password should authenticate");
        assert_eq!(&**found.id(), CONFIG_USER_ID);
        assert_eq!(found.total_conns(), 0);

        assert!(registry.find_password("hunter3").is_none());
        // A prefix must not match: the comparison is over the whole value.
        assert!(registry.find_password("hunter").is_none());
        assert!(registry.find_password("").is_none());
        // Trojan hashes its password; this one is compared as sent, so the hash of
        // the same password is a different credential and must not match either.
        assert!(
            registry
                .find_trojan_hash(&create_password_hash("hunter2"))
                .is_none()
        );
    }

    #[test]
    fn a_disabled_password_user_looks_absent() {
        let registry = StaticUserRegistry::single_password("hunter2");
        let user = registry.find_password("hunter2").unwrap();
        user.set_enabled(false);
        assert!(registry.find_password("hunter2").is_none());
        assert_eq!(user.total_conns(), 0, "a lookup is not a connection");
        user.set_enabled(true);
        assert!(registry.find_password("hunter2").is_some());
    }

    #[test]
    fn an_empty_registry_denies_everyone() {
        let registry = StaticUserRegistry::new();
        assert_eq!(registry.user_count(), 0);
        assert!(registry.find_uuid(&uuid_bytes(UUID)).is_none());
        assert!(
            registry
                .find_trojan_hash(&create_password_hash("x"))
                .is_none()
        );
        assert!(registry.find_password("x").is_none());
        assert!(registry.find_vmess_auth_id(&[0u8; 16]).is_none());
        assert!(registry.find_tuic_uuid(&uuid_bytes(UUID)).is_none());
        assert!(
            registry
                .find_password_sha256(&password_sha256("x"))
                .is_none()
        );
        assert!(registry.find_naive_basic(b"").is_none());
        assert!(!registry.has_password_sha256_prefix(&[0u8; 8]));
    }

    #[test]
    fn recognises_a_vmess_auth_id_from_the_same_uuid() {
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        let auth_id = seal_auth_id(UUID, 1_700_000_000, [1, 2, 3, 4]);

        let found = registry
            .find_vmess_auth_id(&auth_id)
            .expect("the config's uuid should recognise its own auth id");
        assert_eq!(&**found.user.id(), UUID);
        assert_eq!(found.timestamp, 1_700_000_000);
        // The handshake cannot continue without this, so a zeroed key would be a
        // silent failure much later.
        assert_ne!(found.instruction_key, [0u8; 16]);

        let other = seal_auth_id(
            "11111111-1111-4111-8111-111111111111",
            1_700_000_000,
            [1, 2, 3, 4],
        );
        assert!(registry.find_vmess_auth_id(&other).is_none());
    }

    #[test]
    fn vmess_shares_the_uuid_users_record() {
        // One user, one set of counters, whichever of the two protocols they arrived
        // over. If VMess had its own table these would be separate records and half
        // the traffic would be invisible.
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        let by_uuid = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        let by_auth_id = registry
            .find_vmess_auth_id(&seal_auth_id(UUID, 1, [0; 4]))
            .unwrap()
            .user;
        assert!(Arc::ptr_eq(&by_uuid, &by_auth_id));

        // Neither lookup admits a connection. VLESS can admit immediately after its
        // lookup; VMess waits until the header AEAD proves the sender holds the key.
        assert_eq!(by_uuid.total_conns(), 0);
    }

    #[test]
    fn a_disabled_user_looks_absent_to_vmess_too() {
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        let auth_id = seal_auth_id(UUID, 1, [0; 4]);
        let user = registry.find_vmess_auth_id(&auth_id).unwrap().user;

        user.set_enabled(false);
        assert!(registry.find_vmess_auth_id(&auth_id).is_none());

        user.set_enabled(true);
        assert!(registry.find_vmess_auth_id(&auth_id).is_some());

        // Not once, across all three lookups. The handler admits only after the
        // header AEAD opens, so nothing here is billable however many times it is
        // asked.
        assert_eq!(user.total_conns(), 0);
    }

    #[test]
    fn a_password_only_registry_has_nothing_for_vmess() {
        // Trojan and AnyTLS users have no uuid, so there is no key to try. The trial
        // must come up empty rather than fall over.
        let registry = StaticUserRegistry::single_trojan_password("hunter2");
        assert!(
            registry
                .find_vmess_auth_id(&seal_auth_id(UUID, 1, [0; 4]))
                .is_none()
        );
    }

    #[test]
    fn finds_a_tuic_uuid_without_counting_an_authentication() {
        let registry = StaticUserRegistry::single_tuic(UUID, "hunter2").unwrap();

        let found = registry
            .find_tuic_uuid(&uuid_bytes(UUID))
            .expect("the config's uuid should be found");
        assert_eq!(&**found.user.id(), UUID);
        assert_eq!(&*found.password, "hunter2");
        // The whole point: the token has not been checked yet, so nothing may be
        // billed. The handler counts it once it has.
        assert_eq!(found.user.total_conns(), 0);

        assert!(
            registry
                .find_tuic_uuid(&uuid_bytes("11111111-1111-4111-8111-111111111111"))
                .is_none()
        );
    }

    #[test]
    fn a_disabled_tuic_user_looks_absent() {
        let registry = StaticUserRegistry::single_tuic(UUID, "hunter2").unwrap();
        let user = registry.find_tuic_uuid(&uuid_bytes(UUID)).unwrap().user;
        user.set_enabled(false);
        assert!(registry.find_tuic_uuid(&uuid_bytes(UUID)).is_none());
        user.set_enabled(true);
        assert!(registry.find_tuic_uuid(&uuid_bytes(UUID)).is_some());
    }

    #[test]
    fn half_a_tuic_credential_authenticates_nothing() {
        // A TUIC user's password is not a password credential, and a plain uuid user
        // has no password for a token to be keyed with. Neither half stands alone.
        let tuic = StaticUserRegistry::single_tuic(UUID, "hunter2").unwrap();
        assert!(tuic.find_password("hunter2").is_none());

        let vless = StaticUserRegistry::single_uuid(UUID).unwrap();
        assert!(vless.find_tuic_uuid(&uuid_bytes(UUID)).is_none());
    }

    #[test]
    fn rejects_an_invalid_tuic_uuid_at_build_time() {
        assert!(StaticUserRegistry::single_tuic("not-a-uuid", "hunter2").is_err());
    }

    #[test]
    fn finds_an_anytls_user_by_the_hash_they_send() {
        let registry = StaticUserRegistry::single_anytls_password("alice", "hunter2");
        let hash = password_sha256("hunter2");

        let found = registry
            .find_password_sha256(&hash)
            .expect("the config's own password should authenticate");
        assert_eq!(&**found.id(), "alice");
        assert_eq!(found.total_conns(), 0);

        assert!(
            registry
                .find_password_sha256(&password_sha256("hunter3"))
                .is_none()
        );
    }

    #[test]
    fn an_anytls_user_falls_back_to_the_config_id_without_a_name() {
        let registry = StaticUserRegistry::single_anytls_password("", "hunter2");
        let found = registry
            .find_password_sha256(&password_sha256("hunter2"))
            .unwrap();
        assert_eq!(&**found.id(), CONFIG_USER_ID);
    }

    #[test]
    fn the_anytls_prefix_probe_answers_for_a_disabled_user_too() {
        // The whole point of the probe: it says "keep reading", not "this user
        // exists". Answering `false` here would send a suspended user's connections
        // to the fallback while a live user's went to the handler -- an observable
        // difference that leaks who has been suspended.
        let registry = StaticUserRegistry::single_anytls_password("alice", "hunter2");
        let hash = password_sha256("hunter2");
        let prefix = password_sha256_prefix(&hash);

        assert!(registry.has_password_sha256_prefix(&prefix));

        let user = registry.find_password_sha256(&hash).unwrap();
        user.set_enabled(false);
        assert!(
            registry.find_password_sha256(&hash).is_none(),
            "the lookup denies"
        );
        assert!(
            registry.has_password_sha256_prefix(&prefix),
            "but the probe must not"
        );

        assert!(!registry.has_password_sha256_prefix(&[0u8; 8]));
    }

    #[test]
    fn finds_a_naive_user_by_the_basic_credential_they_send() {
        let mut registry = StaticUserRegistry::new();
        registry.add_naive_user("alice", "alice-user", "hunter2");
        let registry: Arc<dyn UserRegistry> = Arc::new(registry);

        let encoded = naive_basic_credential("alice-user", "hunter2");
        let found = registry
            .find_naive_basic(&encoded)
            .expect("the config's own credential should authenticate");
        assert_eq!(&**found.id(), "alice");
        assert_eq!(found.total_conns(), 0);

        // The username alone is not the credential, nor is the password.
        assert!(
            registry
                .find_naive_basic(&naive_basic_credential("alice-user", "hunter3"))
                .is_none()
        );
        assert!(
            registry
                .find_naive_basic(&naive_basic_credential("bob-user", "hunter2"))
                .is_none()
        );
        // Garbage off a header must not panic or match.
        assert!(registry.find_naive_basic(b"not base64 at all").is_none());
        assert!(registry.find_naive_basic(&[0xff, 0xfe]).is_none());
    }

    #[test]
    fn a_naive_credential_survives_a_colon_in_the_password() {
        // Base64 hides it, and the server never splits the decoded pair -- it
        // compares the encoding -- so a password containing the separator is fine.
        let mut registry = StaticUserRegistry::new();
        registry.add_naive_user("bob", "user", "p@ss:w0rd!");
        registry.add_naive_user("empty", "user2", "");

        assert!(
            registry
                .find_naive_basic(&naive_basic_credential("user", "p@ss:w0rd!"))
                .is_some()
        );
        assert!(
            registry
                .find_naive_basic(&naive_basic_credential("user2", ""))
                .is_some(),
            "an empty password is still a credential, and must not match a missing one"
        );
        // And the naive reading -- split on the first colon -- must not authenticate.
        assert!(
            registry
                .find_naive_basic(&naive_basic_credential("user", "p@ss"))
                .is_none()
        );
    }

    #[test]
    fn a_naive_user_without_a_name_is_reported_by_their_username() {
        // Their username, never their password: the config's `name` is optional and
        // the username is the half of the credential that is not a secret.
        let mut registry = StaticUserRegistry::new();
        registry.add_naive_user("", "alice-user", "hunter2");
        let found = registry
            .find_naive_basic(&naive_basic_credential("alice-user", "hunter2"))
            .unwrap();
        assert_eq!(&**found.id(), "alice-user");
    }

    #[test]
    fn a_disabled_naive_user_looks_absent() {
        let mut registry = StaticUserRegistry::new();
        registry.add_naive_user("alice", "alice-user", "hunter2");
        let encoded = naive_basic_credential("alice-user", "hunter2");

        let user = registry.find_naive_basic(&encoded).unwrap();
        user.set_enabled(false);
        assert!(registry.find_naive_basic(&encoded).is_none());
        assert_eq!(user.total_conns(), 0, "a lookup is not a connection");
        user.set_enabled(true);
        assert!(registry.find_naive_basic(&encoded).is_some());
    }

    #[test]
    fn an_anytls_password_is_not_a_plain_or_trojan_credential() {
        // Three derivations of one cleartext value, and each protocol only ever sees
        // its own. A hit on another would mean accepting a secret in a form its owner
        // never sends.
        let registry = StaticUserRegistry::single_anytls_password("alice", "hunter2");
        assert!(registry.find_password("hunter2").is_none());
        assert!(
            registry
                .find_trojan_hash(&create_password_hash("hunter2"))
                .is_none()
        );

        let plain = StaticUserRegistry::single_password("hunter2");
        assert!(
            plain
                .find_password_sha256(&password_sha256("hunter2"))
                .is_none()
        );
        assert!(
            !plain.has_password_sha256_prefix(&password_sha256_prefix(&password_sha256("hunter2")))
        );
    }
}
