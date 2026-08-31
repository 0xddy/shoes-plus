use std::fmt::Debug;

pub trait SaltChecker: Send + Sync + Debug {
    fn insert_and_check(&mut self, salt: &[u8]) -> bool;
}

/// The crate's shared [`ReplayFilter`] is what actually backs this for every cipher
/// mode that wants replay protection. The trait stays because the field is an
/// `Option<Arc<Mutex<dyn SaltChecker>>>` -- some modes deliberately have none -- and
/// this is the one line that connects the two.
impl SaltChecker for crate::replay_filter::ReplayFilter {
    fn insert_and_check(&mut self, salt: &[u8]) -> bool {
        self.check_and_insert(salt)
    }
}
