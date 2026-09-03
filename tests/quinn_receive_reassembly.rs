// Cargo cannot run a non-workspace dependency's dev-tests with `-p quinn-proto`.
// Compile its original modules here so the backport regressions use our root lockfile.

#[allow(dead_code)]
#[path = "../vendor/quinn-proto/src/range_set/btree_range_set.rs"]
mod range_set;

#[allow(dead_code)]
#[path = "../vendor/quinn-proto/src/connection/assembler.rs"]
mod assembler;
