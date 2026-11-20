<div align="center">

# `AREA` — Anti-Reverse Engineering Anything

**Guard Your Perimeter: Universal Defensive Reverse-Engineering (Anti-REA) & Binary Obfuscation Verification AI Skill**

*Built for **OpenAI Codex**, **Google Antigravity**, **Claude Code**, **Gemini CLI**, and **OpenCode***

[![License: MIT](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)
[![Agent Skills Spec](https://img.shields.io/badge/Agent%20Skills-Codex%20%7C%20Antigravity%20%7C%20Claude%20Code-38BDF8?style=for-the-badge)](#installation)
[![Zero Dependencies](https://img.shields.io/badge/Python%203-Zero%20Dependencies%20(Offline)-A855F7?style=for-the-badge)](#cli-subcommands)

[**Install in 1 Command**](#installation) · [**5-Pillar Audit Architecture**](#5-pillar-perimeter-audit) · [**CLI Reference**](#cli-subcommands) · [**한국어 안내 (Korean)**](#part-ii--한국어-안내-korean)

</div>

---

## Why `AREA`?

Source-level obfuscation macros and compiler flags frequently fail silently in the compiled machine code:
- **`LLVM -O3` (`InstCombine` & Constant Folding)** collapses Mixed Boolean-Arithmetic (MBA) expressions and affine constant decoders right back into single `mov/movk + eor` or `movabs + xor` literals.
- **`std::hint::black_box`** on ARM64 spills every constant to the stack (`str [sp, #off] + add sp, #off`), bloating `.text` by 50–90% and degrading hot-path latency.
- **Toolchain & host paths** (`/rustc/<hash>/...`, `.llvm.`, `RUST_BACKTRACE`, `/Users/<name>/...`) survive `strip` inside read-only data sections.
- **Accidental build-host hardware locks** (e.g., Apple Secure Enclave `rk1`/`dacl` blobs without a portable envelope) pass every test on the developer's Mac while crashing on every end-user machine.
- **Documentation drift** leaves stale `"Zero-Key"` or `"0 leaks"` claims on READMEs and landing pages that reverse engineers immediately disprove.

**`AREA` (Anti-Reverse Engineering Anything)** packages a universal, zero-dependency verification CLI ([`skills/area/scripts/area_audit.py`](skills/area/scripts/area_audit.py)) and expert disassembly/stealth runbooks ([`skills/area/SKILL.md`](skills/area/SKILL.md)) into a portable **Agent Skill** that works across **Codex**, **Antigravity**, and **Claude Code** on any Mach-O, ELF, or PE binary (C, C++, Rust, Swift, Go, OLLVM, VMProtect, custom VMs, or [`scLock`](https://github.com/planners1490/sclock)).

---

## 5-Pillar Perimeter Audit

| Pillar | Subcommand | What `AREA` Verifies Automatically |
| :--- | :--- | :--- |
| **1. Stealth & Fingerprints** | `stealth` | Symbol leaks (`nm`/`readelf`), plaintext obfuscator/VM hints, `/rustc/`·`.llvm.`·`RUST_BACKTRACE` fingerprints, build-host paths, `.text` size, and block/overall Shannon entropy. |
| **2. Disassembly Hardening** | `disasm` | Real ARM64 & x86_64 disassembly (`llvm-objdump`/`objdump`/`otool`) checks for LLVM constant folding (`mov/movk -> eor`, `movabs -> xor`), `black_box` stack-spill bloat, MBA interleaving density, indirect dispatch counts, and patchable branch-and-exit anti-debug checks. |
| **3. Binding & Portability** | `binding` | Code signing (`codesign`), macOS Hardened Runtime (`runtime`) / Linux ELF `NX` & `RELRO`, Gatekeeper quarantine (`xattr`), and hardware-binding portability risk (host-locked SEP UID vs. portable envelope). |
| **4. Differential Verification** | `diff` | Runs unprotected vs. protected binaries across JSON test vectors to prove exact stdout & exit-code semantic equivalence while measuring binary size & wall-clock latency overhead. |
| **5. Truth-vs-Claims Audit** | `claims` | Cross-checks `README.md`, `docs/index.html`, and release notes against actual binary audit JSON to flag unscoped `"Zero-Key"` claims, `"0 leaks"` contradictions, and cross-doc benchmark drift. |

---

## Installation

### Global Install (Codex + Antigravity + Claude Code)

```bash
git clone https://github.com/planners1490/area.git
cd area
./install.sh
```

This installs the `area` skill simultaneously into:
- **OpenAI Codex**: `~/.agents/skills/area/`
- **Google Antigravity**: `~/.gemini/config/skills/area/`
- **Claude Code**: `~/.claude/skills/area/`

Need Gemini CLI, OpenCode, or project-local installation?
```bash
./install.sh --all                     # Also installs to ~/.gemini/skills/area & ~/.config/opencode/skills/area
./install.sh --local /path/to/project  # Installs into <project>/.agents/skills/area & .claude/skills/area
```

### Triggering the Skill in Your AI Agent

Once installed, simply prompt Codex, Antigravity, or Claude Code naturally:
- *"Use the `area` skill to run a full Anti-REA obfuscation audit on `./build/my_app` and check `README.md` for overclaims."*
- *"Audit `./challenge_protected` with `area` to check if LLVM constant-folded our MBA handlers or leaked `/rustc/` paths."*
- *"Run an A/B `area` differential and disassembly verification comparing `./plain` vs `./protected`."*

---

## CLI Subcommands

All commands are **100% offline (zero network calls)** and write full structured JSON reports to `--output` so your AI agent never overflows its context window:

```bash
# Full 5-pillar perimeter audit (standalone)
uv run skills/area/scripts/area_audit.py full ./my_protected_bin \
  --max-insns 25000 \
  --docs README.md,docs/index.html \
  --output /tmp/area_report.json

# Full A/B audit with differential equivalence check
uv run skills/area/scripts/area_audit.py full ./my_protected_bin \
  --max-insns 25000 \
  --unprotected ./my_plain_bin \
  --cases ./test_cases.json \
  --iters 10 \
  --docs README.md \
  --output /tmp/area_ab_report.json

# Individual targeted audits
uv run skills/area/scripts/area_audit.py stealth ./my_bin --output stealth.json
uv run skills/area/scripts/area_audit.py disasm  ./my_bin --max-insns 25000 --output disasm.json
uv run skills/area/scripts/area_audit.py binding ./my_bin --output binding.json
uv run skills/area/scripts/area_audit.py claims  --audit full.json --docs README.md --output claims.json
```

---

<br />

## Part II — 한국어 안내 (Korean)

### `AREA` (Anti-Reverse Engineering Anything) 소개

**`AREA`**(*"Guard Your Perimeter — 네 코드의 영역을 지켜라"*)는 C, C++, Rust, Swift, Go, OLLVM, VMProtect, 커스텀 VM, [`scLock`](https://github.com/planners1490/sclock) 등 **모든 네이티브 바이너리(Mach-O / ELF / PE)의 난독화 품질과 방어적 리버스 엔지니어링(Anti-REA) 내성을 자동 검증하는 범용 AI 스킬**입니다.

소스 코드 수준에서 난독화를 적용했더라도 실제 컴파일된 바이너리에서는 다음과 같은 치명적 회귀가 흔히 발생합니다:
1. **`LLVM -O3` 상수 접힘 & `InstCombine` 단순화**: MBA 수식이나 암호화된 상수가 기계어에서 `mov/movk + eor` 평문 즉시값으로 접혀버리는 문제
2. **`std::hint::black_box` 스택 스필 비대화**: 상수마다 스택 왕복(`str [sp, #off] + add sp, #off`)이 발생해 `.text` 크기가 50~90% 폭증하고 성능이 저하되는 문제
3. **심볼·툴체인 지문 누출**: `strip` 이후에도 `/rustc/`, `.llvm.`, `RUST_BACKTRACE`, 빌드 머신 경로(`/Users/...`)가 남는 문제
4. **호스트 하드웨어 잠금 실수**: 배포용 바이너리에 빌드 Mac 전용 Secure Enclave(`rk1`/`dacl`) 키가 묶여 다른 기기에서 전부 깨지는 문제
5. **문서 과장 및 불일치(Truth-vs-Claims)**: 포터블 모드 바이너리를 배포하면서 README·랜딩 페이지에 `"Zero-Key"`나 `"0 leaks"`가 그대로 남아 리버서에게 반박당하는 문제

`AREA`는 **외부 의존성 0개·100% 오프라인 Python CLI (`area_audit.py`)**와 **실전 ARM64/x86_64 디스어셈블리·스텔스 레퍼런스**를 통해 **Codex, Antigravity, Claude Code** 어디서나 5대 영역(`stealth`, `disasm`, `binding`, `diff`, `claims`)을 원클릭으로 검증합니다.

### 설치 방법
```bash
git clone https://github.com/planners1490/area.git
cd area
./install.sh
```
실행 즉시 **Codex (`~/.agents/skills/area`)**, **Antigravity (`~/.gemini/config/skills/area`)**, **Claude Code (`~/.claude/skills/area`)** 글로벌 경로에 자동 설치됩니다.

---

<div align="center">
  <sub>© 2026 <b>relay</b> (<code>relay // SYSTEMS</code>). Born from real-world red-team audits on <a href="https://github.com/planners1490/sclock">scLock</a>. Released under the <a href="LICENSE">MIT License</a>.</sub>
</div>
