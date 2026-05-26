//! End-to-end tests for the WASM compute primitive.
//!
//! WAT (the WebAssembly text format) is compiled to bytes inline by the
//! `wat` crate, so the tests need no precompiled fixture files.

use grokforge_prime::run_wasm_module;

fn wasm(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).expect("WAT failed to parse")
}

#[test]
fn wasm_adds_two_integers() {
    let module = wasm(
        r#"(module
              (func (export "add") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add))"#,
    );
    let result = run_wasm_module(&module, "add", &[2, 3]).expect("call failed");
    assert_eq!(result, vec![5]);
}

#[test]
fn wasm_missing_export_is_an_error() {
    let module = wasm(r#"(module (func (export "ok")))"#);
    let err = run_wasm_module(&module, "absent", &[]).expect_err("should fail");
    assert!(err.contains("absent"), "expected the error to name the missing export: {err}");
}

#[test]
fn wasm_runaway_loop_is_bounded_by_fuel() {
    // An infinite loop. Without fuel limiting this would hang forever;
    // with our budget it must run out and return a trap.
    let module = wasm(
        r#"(module
              (func (export "spin")
                (loop $l br $l)))"#,
    );
    let err = run_wasm_module(&module, "spin", &[]).expect_err("should trap on fuel exhaustion");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("fuel") || lower.contains("trap"),
        "expected fuel/trap error, got: {err}"
    );
}

#[test]
fn wasm_memory_growth_is_bounded() {
    // The module declares a memory whose initial size exceeds the host's
    // configured 64 MiB cap (one page = 64 KiB, so >1024 pages overshoots).
    // Without a StoreLimiter wasmtime would happily allocate gigabytes;
    // with it, instantiation must fail.
    let module = wasm(
        r#"(module
              (memory (export "mem") 2048))"#,
    );
    let err = run_wasm_module(&module, "missing", &[])
        .expect_err("oversized memory must be refused");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("memor") || lower.contains("limit") || lower.contains("instantiat"),
        "expected a memory/limit/instantiation error, got: {err}"
    );
}

#[test]
fn wasm_small_memory_is_allowed() {
    // A modest 1 MiB (16 pages) module must instantiate fine — confirms
    // the limit is at the cap, not "no memory at all".
    let module = wasm(
        r#"(module
              (memory 16)
              (func (export "ok") (result i32) i32.const 1))"#,
    );
    let result = run_wasm_module(&module, "ok", &[]).expect("small memory should be allowed");
    assert_eq!(result, vec![1]);
}

#[test]
fn wasm_no_host_imports_available() {
    // The module declares an import the host does not provide. The
    // empty linker must refuse to instantiate it — exactly the property
    // that makes this a sandbox.
    let module = wasm(
        r#"(module
              (import "env" "syscall" (func $syscall (param i32) (result i32)))
              (func (export "go") (result i32)
                i32.const 0
                call $syscall))"#,
    );
    let err = run_wasm_module(&module, "go", &[]).expect_err("should fail to instantiate");
    let lower = err.to_lowercase();
    assert!(
        lower.contains("import") || lower.contains("syscall") || lower.contains("unknown"),
        "expected an instantiation error, got: {err}"
    );
}
