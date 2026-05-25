//! GrokForge Prime — Rust shell library.
//!
//! Spawns the Python GGS engine in a per-call tempdir and, on Linux,
//! applies a Landlock ruleset to the child so only that tempdir is
//! writable. The engine's own path-jail / command allowlist still
//! applies; Landlock is a kernel-enforced second layer.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

/// Locate the GGS engine script.
///
/// Resolution order:
///   1. an explicit `GGS_ENGINE_PATH` environment override;
///   2. a copy bundled next to the executable (packaged builds);
///   3. the source tree, for dev builds via `cargo tauri dev`.
pub fn engine_path() -> PathBuf {
    if let Ok(path) = std::env::var("GGS_ENGINE_PATH") {
        return PathBuf::from(path);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let bundled = dir.join("python").join("ggs_engine.py");
            if bundled.is_file() {
                return bundled;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("python")
        .join("ggs_engine.py")
}

/// Apply a Landlock ruleset to the current process: read on the system
/// library / interpreter paths the engine needs, read-write only on
/// `workdir`. Even if the Python engine had a path-jail bug, the kernel
/// would deny writes outside `workdir`.
///
/// Designed to be called from `Command::pre_exec`, which runs *after*
/// fork but *before* exec — the parent keeps full access; only the child
/// engine is restricted. On a kernel without Landlock support the
/// `add_rule` calls are silently no-ops (best-effort mode); the engine's
/// own user-space sandbox still applies.
#[cfg(target_os = "linux")]
pub fn apply_landlock(workdir: &Path) -> std::io::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };

    let abi = ABI::V2;
    let read = AccessFs::from_read(abi);
    let read_write = AccessFs::from_all(abi);

    // System roots the Python interpreter and its subprocesses must read or
    // exec from. Missing entries (e.g. `/lib64` on merged-usr distros) are
    // skipped without failing the call.
    let system_roots = ["/usr", "/bin", "/lib", "/lib64", "/etc", "/proc", "/dev"];

    let mut ruleset = Ruleset::default()
        .handle_access(read_write)
        .map_err(std::io::Error::other)?
        .create()
        .map_err(std::io::Error::other)?;

    for root in system_roots {
        if let Ok(fd) = PathFd::new(root) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read))
                .map_err(std::io::Error::other)?;
        }
    }

    let workdir_fd = PathFd::new(workdir).map_err(std::io::Error::other)?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(workdir_fd, read_write))
        .map_err(std::io::Error::other)?;

    ruleset.restrict_self().map_err(std::io::Error::other)?;
    Ok(())
}

/// Execute a GGS graph: create a per-call tempdir, hand it to the Python
/// engine via `GGS_WORKDIR`, apply Landlock to the child on Linux, and
/// return the engine's parsed JSON result.
pub fn run_ggs(graph: serde_json::Value) -> Result<serde_json::Value, String> {
    let workdir = tempfile::Builder::new()
        .prefix("ggs_run_")
        .tempdir()
        .map_err(|e| format!("failed to create workdir: {e}"))?;
    let workdir_path = workdir.path().to_owned();

    let payload = serde_json::to_vec(&graph).map_err(|e| e.to_string())?;

    let mut cmd = Command::new("python3");
    cmd.arg(engine_path())
        .env("GGS_WORKDIR", &workdir_path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(target_os = "linux")]
    {
        let wd = workdir_path.clone();
        // SAFETY: pre_exec runs between fork and exec; the landlock crate
        // only calls async-signal-safe operations from this closure.
        unsafe { cmd.pre_exec(move || apply_landlock(&wd)) };
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to start GGS engine: {e}"))?;

    child
        .stdin
        .take()
        .ok_or("could not open engine stdin")?
        .write_all(&payload)
        .map_err(|e| format!("failed to send graph to engine: {e}"))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("engine did not complete: {e}"))?;

    if output.stdout.is_empty() {
        return Err(format!(
            "GGS engine produced no output (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let result: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid engine output: {e}"))?;

    // The engine exits non-zero for a *verification failure* (a valid
    // result the caller still wants, ledger included) as well as for a
    // hard error. The JSON `status` field is the source of truth: only
    // "error" is a genuine failure of the command itself.
    if result.get("status").and_then(|s| s.as_str()) == Some("error") {
        return Err(result
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown GGS engine error")
            .to_string());
    }

    Ok(result)
}
