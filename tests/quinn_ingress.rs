// Cargo cannot run a non-workspace dependency's private unit tests with `-p`.
// Include the same patched source so CI exercises it with this project's lockfile.
#[path = "../vendor/quinn/src/connection_events.rs"]
mod connection_events;
