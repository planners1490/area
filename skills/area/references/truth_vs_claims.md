# Truth-vs-Claims & Hardware Portability Audit Guide

Reverse engineers and security auditors routinely test public claims in `README.md`, landing pages, and release notes directly against the shipped binary. A single disprovable claim undermines credibility even when the underlying obfuscation is strong.

---

## 1. The Fundamental Trade-Off: Portability vs. Zero-Key Hardware Sealing

Any protected binary must choose between two fundamentally distinct threat models:

| Deployment Model | Where Can It Run? | Can Key Material Be Truly Absent From Binary? | Honest Threat Model Description |
| :--- | :--- | :--- | :--- |
| **Portable Multi-Machine Mode** (e.g., end-user apps, games, public CrackMes) | Any compatible end-user machine offline (no remote key server) | **No.** Because every user's CPU must derive the same decryption key offline, deterministic key-derivation inputs must exist in the binary. | Describe as **White-Box / Code-Anchor KDF + MBA Salt Shattering + Live Hardware Anti-Emulation Gate**. Offline static defense rests on MBA complexity, trajectory-entangled masks, and decompiler resistance—not hardware key impossibility. |
| **Hardware UID Node-Locked Mode** (e.g., `--sep-lock`, TPM-sealed server builds, internal anti-leak builds) | **Only** the exact physical machine whose Secure Enclave / TPM sealed the key | **Yes.** Unsealable key material is hardware-wrapped by the chip's physical UID (`0` unsealable keys in binary). | Describe as **Physical Hardware UID Sealing**. Clearly warn users that binaries built in this mode will NOT run on other machines. |

### Common Catastrophic Bug to Catch Early (`area_audit.py binding`)
Shipping a public CrackMe or end-user SDK with **host hardware sealing enabled by default**:
- On the developer's build Mac, every test passes (`exit 0`).
- On every other Mac in the world, `SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation:)` throws an error, causing corrupted keys, wrong outputs, or crashes.
- **Rule**: Default CLI builds for distributable software MUST use Portable Mode; host-locked hardware sealing must be an explicit opt-in flag (`--sep-lock` / `--host-sep-lock`).

---

## 2. Documentation Consistency Checklist (`area_audit.py claims`)

Before publishing a release, run `area_audit.py claims --audit full.json --docs README.md,docs/index.html,...` and verify:

1. **No Unscoped `"Zero-Key"` Claims on Portable Binaries**:
   - If `"Zero-Key"` or `"0 keys in binary"` appears in marketing/README text, it MUST be explicitly scoped to the node-locked hardware mode (`--sep-lock`), never to a portable offline binary.
2. **Scope `"0 Leaks"` Claims Accurately**:
   - Distinguish between `"0 obfuscator/VM symbol & crate-path leaks"` vs. standard OS dynamic imports (`libSystem`, `__Unwind_Backtrace`).
3. **Sync Landing Pages (`docs/index.html`) With `README.md`**:
   - Benchmark latencies (`µs`), throughput (`calls/sec`), CLI flag names, and architecture badges must match across `README.md`, `docs/index.html`, CrackMe READMEs, and Release Notes.
4. **Re-Measure Benchmarks After Any Obfuscation Change**:
   - Adding MBA layers, inline assembly barriers, or trajectory masks changes `.text` size and execution latency. Always re-measure and update published numbers before tagging a release.
5. **macOS Gatekeeper Quarantine Instructions**:
   - For ad-hoc signed open-source binaries downloaded via a browser, always include `xattr -cr ./<binary> && chmod +x ./<binary>` so reviewers can execute the binary immediately without macOS Gatekeeper blocking it.
