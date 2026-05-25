/// Tauri command: Grok-Grounded Synthesis entrypoint.
#[tauri::command]
fn execute_ggs(graph: serde_json::Value) -> Result<serde_json::Value, String> {
    grokforge_prime::run_ggs(graph)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![execute_ggs])
        .run(tauri::generate_context!())
        .expect("GrokForge Prime failed to launch");
}
