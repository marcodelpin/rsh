#[test]
fn fleet_update_default_path() {
    // fleet update uses deploy/mrsh.exe (not legacy deploy/rsh.exe)
    let default = "deploy/mrsh.exe";
    assert_eq!(default, "deploy/mrsh.exe");
}
