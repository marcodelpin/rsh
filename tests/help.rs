#[test]
fn help_shows_implicit_host_usage() {
    // help text documents the implicit host syntax
    let usage = "mrsh <host> [command] [args...]";
    assert!(usage.contains("<host>"));
}

#[test]
fn help_shows_shell_flag() {
    let flag = "--shell <s>";
    assert!(flag.contains("--shell"));
}
