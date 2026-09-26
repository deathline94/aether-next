//! Spawns the shipped binary the way the shells do and pins the startup
//! contract around the CLI parser. The v1.3.14 regression lived exactly here:
//! the rewritten parser received argv[0] (the binary's own path) and refused
//! it, so every session — Windows and Android — died before the key handoff.
//! Unit tests fed the parser clean argument lists and could not see it.

use std::process::Command;

#[test]
fn the_binary_starts_and_reports_its_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_aether"))
        .arg("--version")
        .output()
        .expect("spawn the engine binary");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("aether"), "version line missing: {stdout}");
}

#[test]
fn an_unknown_flag_is_refused_by_name_not_by_the_program_path() {
    // Reaching the parser at all requires a flag that is not short-circuited by
    // the --version/--diagnostics entry points; an unknown flag fails fast and
    // names ITSELF. When argv[0] leaked into the parser, this stderr named the
    // binary's path instead — the exact startup kill shipped in v1.3.14.
    let out = Command::new(env!("CARGO_BIN_EXE_aether"))
        .arg("--definitely-not-a-flag")
        .output()
        .expect("spawn the engine binary");
    assert!(!out.status.success(), "an unknown flag must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--definitely-not-a-flag"),
        "the refusal must name the offending flag, got: {stderr}"
    );
    assert!(
        !stderr.contains("aether.exe") && !stderr.contains("aether\""),
        "the program path must never be parsed as a flag, got: {stderr}"
    );
}
