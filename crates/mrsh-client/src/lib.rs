//! Cross-platform client — exec, push, pull, shell, fleet, browse, sftp, recording.

pub mod browse;
pub mod client;
pub mod commands;
pub mod config_tui;
pub mod dashboard;
pub mod fleet;
pub mod host_picker;
pub mod install_pack;
pub mod launch;
pub mod log_viewer;
pub mod mux;
pub mod pull_via_batch;
pub mod push_via_batch;
#[cfg(feature = "quic")]
pub mod quic;
pub mod recording;
pub mod relay_connect;
pub mod session_log;
pub mod sftp;
pub mod shell;
pub mod socks;
pub mod ssh_client;
pub mod sync;
pub mod tunnel;
pub mod via_batch_common;
