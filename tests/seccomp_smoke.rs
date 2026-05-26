//! End-to-end test that seccomp denies the syscalls we filter out.
//!
//! Spawns `python3 -c` with `apply_seccomp` in `pre_exec`, asks Python
//! to open an `AF_INET` socket, and asserts the kernel returns `EPERM`.
//! Self-skips on hosts where the BPF filter can't be installed.

#![cfg(target_os = "linux")]

use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

fn run_with_seccomp(python_code: &str) -> std::process::Output {
    let mut cmd = Command::new("python3");
    cmd.args(["-c", python_code])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: pre_exec runs between fork and exec; seccompiler only calls
    // async-signal-safe operations from this closure.
    unsafe { cmd.pre_exec(grokforge_prime::apply_seccomp) };
    cmd.output().expect("failed to spawn python3")
}

fn seccomp_supported() -> bool {
    let out = run_with_seccomp("print('hi')");
    out.status.success() && out.stdout.starts_with(b"hi")
}

#[test]
fn seccomp_denies_inet_socket() {
    if !seccomp_supported() {
        eprintln!(
            "seccomp filter could not be installed on this host \
             (likely a restricted container). Skipping."
        );
        return;
    }

    let out = run_with_seccomp(
        "import socket\n\
         try:\n\
         \x20   socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         \x20   print('OPENED')\n\
         except PermissionError:\n\
         \x20   print('BLOCKED')\n",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("BLOCKED"),
        "seccomp did not block AF_INET socket; stdout={stdout:?} stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn seccomp_allows_unix_socket() {
    if !seccomp_supported() {
        return;
    }
    // AF_UNIX is deliberately left allowed so the interpreter's internal
    // machinery (and the engine's pipes to subprocesses) keep working.
    let out = run_with_seccomp(
        "import socket\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n\
         s.close()\n\
         print('OK')\n",
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK"), "AF_UNIX socket was unexpectedly blocked");
}
