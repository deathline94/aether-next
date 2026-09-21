//! Binary shim.
//!
//! Every line of real logic lives in `aether::cli`, which is compiled and tested
//! exactly once. This file used to carry its own private `mod` list of all 30
//! engine modules, which meant `aether/tests/*` exercised a *different
//! compilation* from the executable users actually ran — and any module added to
//! `lib.rs` stayed invisible to the binary until it was added here too (which is
//! how `route_repair`/`trust` broke the integration tests). See `src/cli.rs`.
#![allow(unstable_name_collisions)]

#[tokio::main]
async fn main() -> aether::Result<()> {
    aether::cli::run().await
}
