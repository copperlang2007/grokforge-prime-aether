use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Locate the GGS engine script that ships with this crate.
fn engine_path() -> PathBuf {
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
            "GGS engine produced no output: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid engine output: {e}"))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![execute_ggs])
        .run(tauri::generate_context!())
        .expect("GrokForge Prime failed to launch");
}
