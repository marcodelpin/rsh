//! Regression test for solved/2026-03-19-003: tracing-appender PermissionDenied panic.
//!
//! Verifies that RollingFileAppender::builder().build() returns Err instead of
//! panicking when the log directory is not writable. The fix replaced the panicking
//! `rolling::daily()` with the builder API that returns Result.

#[test]
fn tracing_appender_builder_does_not_panic_on_unwritable_dir() {
    // Use a path that does not exist and cannot be created
    let bad_dir = if cfg!(windows) {
        "Z:\\nonexistent\\impossible\\path"
    } else {
        "/proc/nonexistent/impossible/path"
    };

    let result = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("audit")
        .build(bad_dir);

    // Must return Err, not panic
    assert!(result.is_err(), "builder should return Err for unwritable directory, not panic");
}

#[test]
fn tracing_appender_builder_ok_maps_to_none_gracefully() {
    let bad_dir = if cfg!(windows) {
        "Z:\\nonexistent\\path"
    } else {
        "/proc/nonexistent/path"
    };

    // This is the exact pattern from main.rs — .ok() converts Err to None
    let layer = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("audit")
        .build(bad_dir)
        .ok();

    assert!(layer.is_none(), "unwritable dir should produce None via .ok()");
}
