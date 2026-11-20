# Stealth, Symbol & Toolchain Scrubbing Checklist

This reference guides remediation for findings reported by `area_audit.py stealth`.

---

## 1. Symbol Table Exposure (`nm` / `readelf`)

- **macOS (`Mach-O`)**:
  - Local and internal symbols survive default Release builds unless explicitly stripped.
  - Run `strip -x <binary>` (strips local/non-global symbols while preserving dynamic linking) or `strip <binary>` for standalone executables.
  - Verify with `nm -gU <binary>`: only expected public entry points (e.g., `_main` or exported C ABI functions) should remain.
- **Linux (`ELF`)**:
  - Build with `-fvisibility=hidden` (C/C++) and link with `strip --strip-all <binary>`.
  - Verify with `readelf -Ws <binary>` / `nm -D <binary>`.
- **Rust (`Cargo.toml`)**:
  ```toml
  [profile.release]
  opt-level = 3
  lto = true
  codegen-units = 1
  strip = "symbols"
  panic = "abort"
  ```

---

## 2. Plaintext Obfuscator & Hint Strings

Reverse engineers always run `strings <binary> | grep -iE "license|vm|opcode|debug|error|secret"` in the first 30 seconds.
- Remove diagnostic banners, UI debug labels, and `"Debugger detected"` messages from protected code paths.
- Never store plaintext function-lookup tables (`"verify_license"`, `"calc_price"`); hash function identifiers at compile time (e.g., FNV-1a / SplitMix64 XORed with runtime key material).

---

## 3. Compiler & Toolchain Fingerprints (`/rustc/`, `.llvm.`, Host Paths)

Even with `strip = "symbols"` and `panic = "abort"`, Rust and LLVM embed diagnostic strings inside read-only `__cstring` / `.rodata` sections:
- `/rustc/<commit-hash>/library/core/src/...`
- `/rust/deps/gimli-...` and `rustc-demangle`
- `RUST_BACKTRACE`, `RUST_LIB_BACKTRACE`, `__rust_begin_short_backtrace`, `__rust_end_short_backtrace`
- `.llvm.<digits>` suffix markers
- Build-machine home directories (`/Users/alice/projects/...`, `/home/ci/...`)

### Remediation
1. **Compile-time path remapping**:
   - Rust: `RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/src"`
   - Clang/GCC: `-ffile-prefix-map=$PWD=/src -fdebug-prefix-map=$HOME=/build`
2. **Post-build same-length byte scrubbing** (when targeting zero toolchain strings):
   - Replace non-imported read-only literal markers in-place with equal-length neutral ASCII bytes (never changing binary length or Mach-O/ELF section offsets!).
   - **Critical safety rule**: Always verify with `nm -u <binary>` (imported undefined symbols) that you do NOT overwrite dynamic linker symbol names such as `__Unwind_Backtrace`! Match exact case (e.g., lowercase `backtrace`, `/rustc/`, `RUST_BACKTRACE`).
   - Re-sign Mach-O binaries (`codesign --force --options runtime --sign ...`) **after** any byte-level scrubbing, because modifying bytes invalidates the existing code signature.

---

## 4. Interpreting Shannon Entropy

- **Plaintext / Standard Native Code**: `~4.8 – 6.2 bits/byte` (with many low-entropy zero-padding blocks).
- **Polymorphic VM / Encrypted Bytecode + Code**: `~6.3 – 7.3 bits/byte`.
- **Full-Binary Packed / Encrypted Blob**: `> 7.5 bits/byte` (note: extremely uniform `> 7.9` entropy across the whole file can trigger heuristic antivirus false positives; targeting high entropy specifically inside encrypted bytecode/data tables is often preferable for commercial apps).
