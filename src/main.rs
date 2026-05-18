use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Locate the GGS engine script.
///
/// Resolution order:
///   1. an explicit `GGS_ENGINE_PATH` environment override;
///   2. a copy bundled next to the executable (packaged builds);
///   3. the source tree, for dev builds via `cargo tauri dev`.
fn engine_path() -> PathBuf {
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

/// Grok-Grounded Synthesis entrypoint.
///
/// Takes a GGS graph (a DAG of action/verifier/rollback nodes) and runs it
/// through the Python engine, which sandboxes execution, verifies each node,
/// rolls back on failure, and returns a hash-chained provenance ledger.
#[tauri::command]
fn execute_ggs(graph: serde_json::Value) -> Result<serde_json::Value, String> {
    let payload = serde_json::to_vec(&graph).map_err(|e| e.to_string())?;

    let mut child = Command::new("python3")
        .arg(engine_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

    // The engine exits non-zero for a *verification failure* (a valid result
    // the caller still wants, ledger included) as well as for a hard error.
    // The JSON `status` field is the source of truth: only "error" is a
    // genuine failure of the command itself.
    if result.get("status").and_then(|s| s.as_str()) == Some("error") {
        return Err(result
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("unknown GGS engine error")
            .to_string());
    }

    Ok(result)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![execute_ggs])
        .run(tauri::generate_context!())
        .expect("GrokForge Prime failed to launch");
}
