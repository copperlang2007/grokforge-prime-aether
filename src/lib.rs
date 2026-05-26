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

/// Apply a seccomp BPF filter that denies syscalls the engine never needs:
/// network sockets on AF_INET/AF_INET6, raw debugging (`ptrace`), and
/// mount-table changes. Everything else stays allowed — a denylist suits
/// Python better than an allowlist, which would break the interpreter.
///
/// Layered on top of Landlock: Landlock confines the filesystem, seccomp
/// closes off the non-filesystem syscalls a sandboxed engine should never
/// touch. Called from `Command::pre_exec`, same as `apply_landlock`.
#[cfg(target_os = "linux")]
pub fn apply_seccomp() -> std::io::Result<()> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
        SeccompCondition, SeccompFilter, SeccompRule,
    };

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(std::io::Error::other)?;
    let denied = SeccompAction::Errno(libc::EPERM as u32);
    let allowed = SeccompAction::Allow;

    let inet = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::AF_INET as u64,
    )
    .map_err(std::io::Error::other)?;
    let inet6 = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::AF_INET6 as u64,
    )
    .map_err(std::io::Error::other)?;

    let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
        std::collections::BTreeMap::new();

    // socket(AF_INET, ...) and socket(AF_INET6, ...) — block IP networking.
    // AF_UNIX is intentionally still allowed so Python's internal pipes work.
    rules.insert(
        libc::SYS_socket as i64,
        vec![
            SeccompRule::new(vec![inet]).map_err(std::io::Error::other)?,
            SeccompRule::new(vec![inet6]).map_err(std::io::Error::other)?,
        ],
    );

    // Syscalls with no useful purpose inside a sandboxed engine. An empty
    // rules vec means "match any invocation of this syscall".
    for sys in [
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
    ] {
        rules.insert(sys as i64, vec![]);
    }

    let filter = SeccompFilter::new(rules, allowed, denied, arch)
        .map_err(std::io::Error::other)?;
    let program: BpfProgram = filter.try_into().map_err(std::io::Error::other)?;
    seccompiler::apply_filter(&program).map_err(std::io::Error::other)?;
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
        // SAFETY: pre_exec runs between fork and exec; the landlock and
        // seccompiler crates only call async-signal-safe operations from
        // these closures. Seccomp is applied last so the filter sees the
        // smallest possible set of remaining capabilities.
        unsafe {
            cmd.pre_exec(move || {
                apply_landlock(&wd)?;
                apply_seccomp()
            })
        };
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

/// How much WASM "fuel" a single call may burn. One unit roughly
/// corresponds to one executed instruction; a million is enough for
/// realistic compute and short enough to bound runaway loops.
///
/// Note: fuel is consumed only during exported function *execution*,
/// not during module compilation or instantiation. Memory/table growth
/// is bounded separately by [`WASM_MEMORY_LIMIT`] and
/// [`WASM_TABLE_ELEMENT_LIMIT`].
pub const WASM_FUEL_LIMIT: u64 = 1_000_000;

/// Maximum linear-memory size the module may grow to. Wasmtime's default
/// is 4 GiB per memory; without an explicit cap, a malicious module
/// could request a huge memory at instantiation time and OOM the host.
pub const WASM_MEMORY_LIMIT: usize = 64 * 1024 * 1024; // 64 MiB

/// Maximum number of elements across all tables in the module.
pub const WASM_TABLE_ELEMENT_LIMIT: usize = 10_000;

/// Run a function exported by a WebAssembly module in a no-capability
/// sandbox: no host imports are linked, so the module has no syscalls,
/// no filesystem, and no network. Bounded on three axes:
///
/// - **CPU**: fuel-limited to [`WASM_FUEL_LIMIT`] instructions per call.
/// - **Memory**: linear memory capped at [`WASM_MEMORY_LIMIT`] via a
///   `StoreLimiter`. Modules that request a larger memory fail to
///   instantiate instead of being allowed to OOM the host.
/// - **Tables**: total elements capped at [`WASM_TABLE_ELEMENT_LIMIT`].
///
/// Returns the exported function's i32 results. Only i32 args and
/// results are supported by this primitive — enough to be useful for
/// verifier predicates and arithmetic action handlers without exposing
/// the full Val enum at the API boundary. Engine integration (a `wasm`
/// action / verifier type that lets a graph carry a module) is a
/// follow-up PR.
pub fn run_wasm_module(
    module_bytes: &[u8],
    func_name: &str,
    args: &[i32],
) -> Result<Vec<i32>, String> {
    use wasmtime::{
        Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
        Val, ValType,
    };

    let mut config = Config::new();
    config.consume_fuel(true);
    // Wasmtime errors are anyhow chains; `{:#}` flattens the chain into a
    // single string so callers (and tests) see the real trap reason, not
    // just the top-level "error while executing" line.
    let engine = Engine::new(&config).map_err(|e| format!("{e:#}"))?;
    let module = Module::new(&engine, module_bytes).map_err(|e| format!("{e:#}"))?;

    // Empty linker → the module cannot import anything from the host.
    let linker: Linker<StoreLimits> = Linker::new(&engine);

    // The store carries a StoreLimits as its data and uses it as a
    // ResourceLimiter — this is what enforces the memory and table caps
    // during instantiation and during memory.grow / table.grow calls.
    let limits = StoreLimitsBuilder::new()
        .memory_size(WASM_MEMORY_LIMIT)
        .table_elements(WASM_TABLE_ELEMENT_LIMIT)
        .build();
    let mut store = Store::new(&engine, limits);
    store.limiter(|s| s);
    store.set_fuel(WASM_FUEL_LIMIT).map_err(|e| format!("{e:#}"))?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("{e:#}"))?;
    let func = instance
        .get_func(&mut store, func_name)
        .ok_or_else(|| format!("module has no export named {func_name:?}"))?;

    let ty = func.ty(&store);
    let mut results: Vec<Val> = ty
        .results()
        .map(|t| match t {
            ValType::I32 => Ok(Val::I32(0)),
            other => Err(format!("unsupported result type {other:?}; only i32 is supported")),
        })
        .collect::<Result<_, _>>()?;
    let wasm_args: Vec<Val> = args.iter().map(|a| Val::I32(*a)).collect();

    func.call(&mut store, &wasm_args, &mut results)
        .map_err(|e| format!("{e:#}"))?;

    results
        .into_iter()
        .map(|v| match v {
            Val::I32(n) => Ok(n),
            other => Err(format!("non-i32 result {other:?}")),
        })
        .collect()
}
