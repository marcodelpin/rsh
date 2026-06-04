//! mrsh top-level library crate.
//!
//! Historically `mrsh` was a binary-only crate (`src/main.rs`). The library
//! surface is intentionally **minimal** — it re-exports only the constants
//! that external consumers need to keep in lockstep with the CLI's command
//! taxonomy (`LOCAL_COMMANDS`, `CLIENT_SUBCOMMANDS`).
//!
//! ## Why this exists
//!
//! `mrsh-desk` ships a merged binary (`mrsh.exe`) that combines the rustdesk
//! GUI with mrsh's CLI surface. To dispatch correctly on `argv[1]` *before*
//! handing off to either subsystem, the dispatcher (in
//! `mrsh-desk/src/mrsh_bin/dispatcher.rs`) needs the canonical lists of
//! mrsh subcommands. Hard-coding those lists in two places would drift; this
//! `pub use` makes mrsh the single source of truth.
//!
//! ## What is NOT exposed
//!
//! The full `fn main()` body (server-mode detection, tokio runtime, tracing
//! init, SCM dispatch) is **not** re-exported as `pub fn run`. That refactor
//! is tracked separately and lands in a follow-up cycle. For now, mrsh-desk's
//! merged binary either re-execs the bundled `mrsh.exe` (cycle 1) or — once
//! `pub fn run` is extracted — calls it directly in-process (cycle 2).
//!
//! ## Stability
//!
//! Only `consts` is part of the public API. Everything else (modules like
//! `dispatch`, `server_mode`, etc.) stays binary-private.

pub mod consts {
    //! Re-exported command-name lists, for external dispatchers.
    //!
    //! These are the same `&'static [&'static str]` slices consumed by mrsh's
    //! own CLI (`src/cli.rs`). Keeping them re-exported here means downstream
    //! crates always see the exact same taxonomy mrsh itself uses.
    pub use crate::cli::{CLIENT_SUBCOMMANDS, LOCAL_COMMANDS};
}

// `cli` declared here so `pub use crate::cli::...` works above. It is
// otherwise the same module the binary uses (declared in `src/main.rs` as
// `mod cli;`). Rust allows the same source file to be referenced by both
// the bin and the lib crates, which keeps the constants in one place.
mod cli;

/// Pure MAC-form detection helper used by the `wake` command. Exposed at
/// the library surface so integration tests can exercise the boundary
/// conditions without spawning the binary.
pub mod mac_form;
