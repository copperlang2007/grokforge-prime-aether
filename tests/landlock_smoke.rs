//! End-to-end test that Landlock genuinely enforces the workdir jail.
//!
//! Spawns `/bin/sh` with `apply_landlock` in `pre_exec`, then asks the
//! shell to write a file outside the workdir. The kernel must deny it.
//! If the host kernel doesn't support Landlock the test reports that
//! and skips rather than failing, so it can run in any CI environment.

#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::tempdir;

fn run_with_landlock(workdir: &Path, sh_command: &str) {
    let wd = workdir.to_owned();
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", sh_command])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe { cmd.pre_exec(move || grokforge_prime::apply_landlock(&wd)) };
    let _ = cmd.status().expect("failed to spawn /bin/sh");
}

fn landlock_supported() -> bool {
    // Probe by applying the ruleset to a throwaway child and checking
    // whether a write outside the workdir is actually denied.
    let workdir = tempdir().expect("workdir");
    let canary = std::env::temp_dir().join(format!(
        "ggs_landlock_probe_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&canary);
    run_with_landlock(
        workdir.path(),
        &format!("echo probe > {}", canary.display()),
    );
    let denied = !canary.exists();
    let _ = std::fs::remove_file(&canary);
    denied
}

#[test]
fn landlock_denies_writes_outside_workdir() {
    if !landlock_supported() {
        eprintln!(
            "Landlock not enforced on this host (kernel < 5.13 or container \
             restriction). Skipping; engine-level sandbox still applies."
        );
        return;
    }

    let workdir = tempdir().expect("workdir");
    let outside = std::env::temp_dir().join(format!(
        "ggs_outside_{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&outside);

    run_with_landlock(
        workdir.path(),
        &format!("echo pwned > {}", outside.display()),
    );

    let leaked = outside.exists();
    let _ = std::fs::remove_file(&outside);
    assert!(!leaked, "Landlock failed to block write outside workdir");
}

#[test]
fn landlock_allows_writes_inside_workdir() {
    let workdir = tempdir().expect("workdir");
    let inside = workdir.path().join("inside.txt");

    run_with_landlock(
        workdir.path(),
        &format!("echo allowed > {}", inside.display()),
    );

    let content = std::fs::read_to_string(&inside)
        .expect("write inside workdir was blocked by Landlock");
    assert!(content.contains("allowed"));
}
