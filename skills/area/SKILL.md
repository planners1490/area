---
name: area
description: >-
  AREA (Anti-Reverse Engineering Anything) — Universal defensive reverse-engineering
  (Anti-REA) and binary obfuscation verification skill ("Guard Your Perimeter").
  Use when auditing protected or obfuscated Mach-O, ELF, or PE binaries (C, C++, Rust,
  Swift, Go, OLLVM, VMProtect, custom VMs, scLock) to check symbol/string/toolchain
  stealth, detect LLVM constant-folding or stack-spill regressions in ARM64/x86_64
  disassembly, verify code signing and hardware-binding portability, run differential
  equivalence tests, and audit security documentation claims against binary reality.
---

# AREA — Anti-Reverse Engineering Anything

> **Guard Your Perimeter**: Universal Defensive Reverse-Engineering (Anti-REA) & Binary Obfuscation Verification Skill for **Codex**, **Antigravity**, **Claude Code**, **Gemini CLI**, and **OpenCode**.

## Overview

`AREA` turns hard-won reverse-engineering defense lessons into a repeatable, automated 5-pillar verification workflow for any native binary (Mach-O `arm64`/`x86_64`, ELF `x86_64`/`aarch64`, PE). Instead of trusting source-level obfuscation macros or marketing claims, `AREA` inspects the **actual compiled machine code, symbol tables, strings, signing/hardware-binding metadata, runtime behavior, and public documentation** to catch silent regressions before release.

The 5 verification pillars:
1. **Stealth (`stealth`)**: Symbol leaks (`nm`/`readelf`), plaintext obfuscator/VM hints, compiler/toolchain fingerprints (`/rustc/`, `.llvm.`, `RUST_BACKTRACE`), build-host paths (`/Users/...`, `/home/...`), code section size, and Shannon entropy.
2. **Disassembly Hardening (`disasm`)**: Real machine-code inspection (`llvm-objdump`/`objdump`/`otool`) for LLVM `-O3` constant-folding regressions (`mov/movk -> eor`, `movabs -> xor`), `std::hint::black_box` stack-spill bloat (`str [sp, #imm] + add sp, #imm`), MBA (Mixed Boolean-Arithmetic) survival density, indirect dispatch counts, and patchable branch-and-exit anti-debug checks.
3. **Binding & Portability (`binding`)**: Code signing, Hardened Runtime (`runtime`) / ELF `NX` & `RELRO`, Gatekeeper quarantine (`xattr`), and accidental single-host hardware lock detection (e.g., Apple Secure Enclave `rk1`/`dacl` blobs without a portable envelope).
4. **Differential Verification (`diff`)**: Semantic equivalence verification (stdout & exit codes across test vectors) and size/latency overhead comparison between an unprotected baseline and the protected binary.
5. **Truth-vs-Claims (`claims`)**: Cross-checks `README.md`, landing pages, and release notes against actual binary audit results to catch exaggerated `"Zero-Key"` or `"0 leaks"` claims and cross-document benchmark drift.

## Dependencies

- **Runtime**: Python 3.9+ standard library only (`uv run` preferred; direct `python3` execution also supported — zero third-party packages required).
- **Optional Platform Tools** (auto-detected with graceful `SKIP` fallback if absent):
  - **macOS**: `objdump` / `llvm-objdump` / `otool`, `nm`, `size`, `codesign`, `xattr`, `file`
  - **Linux**: `llvm-objdump` / `objdump`, `nm` / `readelf`, `ldd`, `file`
- **Network**: None (100% offline / air-gap safe).

## Quick Start

Run the full perimeter audit on any compiled binary and write structured JSON output to a file:

```bash
uv run ./scripts/area_audit.py full /path/to/protected_binary \
  --max-insns 25000 \
  --output /tmp/area_report.json
```

Run a complete A/B audit including unprotected baseline comparison and documentation Truth-vs-Claims verification:

```bash
uv run ./scripts/area_audit.py full /path/to/protected_binary \
  --max-insns 30000 \
  --unprotected /path/to/unprotected_binary \
  --cases /path/to/test_cases.json \
  --iters 10 \
  --docs README.md,docs/index.html \
  --output /tmp/area_full_report.json
```

Read only the fields you need from the JSON report (do not dump entire disassembly logs into context):

```bash
uv run python3 -c "import json; d=json.load(open('/tmp/area_full_report.json')); print(d['perimeter_grade'], d['severity_counts']); [print(f) for f in d['all_findings']]"
```

## Utility Scripts (`scripts/area_audit.py`)

Every subcommand writes full structured JSON to `--output` and prints only a one-line status summary to stdout.

### 1. `stealth` — Symbols, Strings, Toolchain Paths & Entropy
```bash
uv run ./scripts/area_audit.py stealth <binary> \
  --extra-patterns "my_secret_func,internal_key" \
  --output stealth.json
```

### 2. `disasm` — Disassembly Folding, Stack-Spill & MBA Verification
`--max-insns` is required so the audit explicitly reports how many instructions were scanned and whether scanning was truncated.
```bash
uv run ./scripts/area_audit.py disasm <binary> \
  --max-insns 25000 \
  --output disasm.json
```

### 3. `binding` — Signing, Mitigations & Hardware Portability
```bash
uv run ./scripts/area_audit.py binding <binary> \
  --output binding.json
```

### 4. `diff` — Differential Equivalence & Overhead Benchmark
Create a JSON test-case file (e.g. `[{"name": "default", "args": ["20", "1234"]}, {"name": "edge", "args": ["20", "7777"]}]`) and run:
```bash
uv run ./scripts/area_audit.py diff \
  --unprotected ./app_plain \
  --protected ./app_locked \
  --cases ./cases.json \
  --iters 10 \
  --output diff.json
```

### 5. `claims` — Truth-vs-Claims Documentation Audit
```bash
uv run ./scripts/area_audit.py claims \
  --audit full.json \
  --docs README.md,docs/index.html \
  --output claims.json
```

### 6. `full` — Consolidated 5-Pillar Perimeter Audit
Combines `stealth`, `disasm`, `binding`, and optionally `diff` (`--unprotected` + `--cases`) and `claims` (`--docs`), returning an overall `perimeter_grade` (`A`–`F`).

## Agent Verification Protocol

When a user asks to verify, audit, or harden an obfuscated binary or protector compiler:

1. **Run `full` first** via `uv run ./scripts/area_audit.py full ... --output <file>` (always specify `--max-insns`, e.g., `25000`–`50000`, and include `--docs` if the repo has a README or landing page).
2. **Inspect `all_findings` in severity order** (`CRITICAL` → `HIGH` → `MEDIUM` → `INFO`).
3. **Spot-check actual disassembly on suspicious addresses**: If `disasm` flags `folded_const_xor_sample` or `blackbox_stack_spill_sample`, inspect ~25 lines around 1–2 reported addresses with `objdump -d --start-address=...` to confirm whether an obfuscated constant was truly folded or is an encoded affine parameter.
4. **Consult the detailed reference manuals** when remediating specific findings:
   - [Disassembly Hardening Patterns](./references/disassembly_patterns.md) — fixing LLVM constant folding, `InstCombine` MBA collapse, and `black_box` stack-spill bloat with zero-spill register barriers.
   - [Stealth & Toolchain Scrubbing Checklist](./references/stealth_checklist.md) — removing `/rustc/`, `.llvm.`, host paths, and internal symbols safely.
   - [Truth-vs-Claims & Hardware Portability Guide](./references/truth_vs_claims.md) — avoiding accidental build-machine hardware locks and overclaimed documentation.
5. **Re-run `area_audit.py full` after applying fixes** and present a concise before/after comparison table (`perimeter_grade`, `__text` size, MBA density, leaks, and differential equivalence).

## Common Mistakes

- **Trusting source-level MBA expressions without checking disassembly**: At `-O3`, LLVM's `InstCombine` routinely collapses identities like `(x | y) - (x & y)` right back into a single `eor`/`xor` instruction and folds constant affine expressions into `mov/movk` literals. Always verify compiled machine code with `disasm`.
- **Using `std::hint::black_box` in hot VM handlers**: On `arm64`, `black_box` takes a stack pointer (`str [sp, #off] + add sp, #off`), inflating `.text` by 50–90% and hurting latency. Use a register-only inline assembly barrier (`options(nomem, nostack, preserves_flags)`) instead.
- **Accidentally shipping a host-locked hardware key**: Sealing a key directly in the build machine's Secure Enclave / TPM UID breaks execution on every end-user machine. Always run `binding` and test on a separate machine when distributing public binaries or CrackMes.
- **Forgetting to sync docs after security architecture changes**: Leaving stale `"Zero-Key"` claims on a landing page after switching to a portable offline KDF invites immediate public rebuttal from reverse engineers. Always run `claims`.
