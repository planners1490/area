# Disassembly Hardening Patterns (ARM64 & x86_64)

This reference explains the four primary machine-code failure modes detected by `area_audit.py disasm` and how to fix each cleanly at the compiler/source level.

---

## 1. LLVM Constant Folding of Obfuscated Constants & Salts

### What It Looks Like in Disassembly
You wrote an affine or polynomial constant decoder in C/Rust, expecting it to run at runtime, but LLVM (`-O3` / `opt-level=3`) evaluated the constant expression at compile time and emitted a plain 64-bit literal:

**ARM64 (`aarch64`) failure signature:**
```asm
mov  x8, #0x2554
movk x8, #0x7a47, lsl #16
movk x8, #0x0cf6, lsl #32
movk x8, #0x19f6, lsl #48
eor  x8, x1, x8          ; secret salt/mask completely exposed as 1 immediate!
```

**x86_64 failure signature:**
```asm
movabs rax, 0x19f60cf67a472554
xor    rdi, rax
```

### Root Cause
All inputs to the decoding formula (`enc`, `a_inv`, `b`, `k`) are compile-time constants, or the same SSA register is referenced on both sides of an algebraic identity so LLVM `InstCombine` simplifies `(x | y) - (x & y) -> x ^ y` and `((x ^ y) + 2*(x & y)) - ((x | y) + (x & y)) -> 0`.

### Fix: Zero-Spill Register-Only Inline Assembly Barrier + Dynamic State Entanglement
1. **Separate SSA values in registers without stack spills**:
   - **Rust (`aarch64` / `x86_64`)**:
     ```rust
     #[inline(always)]
     fn reg_barrier(mut v: u64) -> u64 {
         unsafe {
             core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
         }
         v
     }
     ```
   - **C / C++ (Clang / GCC)**:
     ```c
     static inline uint64_t reg_barrier(uint64_t v) {
         __asm__ volatile("" : "+r"(v));
         return v;
     }
     ```
2. **Split operands inside MBA and opaque zero expressions**:
   Instead of `(x | y) - (x & y)`, compute `let mx = reg_barrier(x); (mx | y).wrapping_sub(x & y)`. LLVM sees `mx` and `x` as unrelated opaque registers and cannot simplify the expression.
3. **Entangle with live runtime state**:
   Pre-mask handler salts with a runtime code-integrity anchor (`vm.anchor`) and mix live trajectory state (`vm.sigma`, `vm.pc`) into per-instruction operand masks so no handler's masks are static constants.

---

## 2. `std::hint::black_box` Stack-Spill Bloat

### What It Looks Like in Disassembly
**ARM64 failure signature (`area_audit.py` flags `blackbox_stack_spill_count`):**
```asm
str  x8, [sp, #0x20]
add  x8, sp, #0x20       ; black_box took &mut dummy on the stack!
...
ldp  x8, x9, [sp, #0x20] ; redundant memory reload
```

### Impact
Spilling every obfuscated constant and MBA subterm to the stack inflates `.text` / `__text` by **50–90%** and adds significant L1D stack-traffic latency in tight VM handler loops.

### Fix
Replace `std::hint::black_box(x)` with `reg_barrier(x)` (`inout(reg)` + `options(nomem, nostack, preserves_flags)`). It emits **0 extra instructions** and **0 stack spills** while remaining a total optimization barrier to LLVM.

---

## 3. Patchable Branch-and-Exit Anti-Debug Checks

### What It Looks Like in Disassembly
```asm
bl   _sysctl             ; or _ptrace / IsDebuggerPresent
...
cbz  w8, 0x100004120     ; single conditional branch!
bl   _exit               ; attacker flips cbz -> cbnz or NOPs 4 bytes -> bypassed
```

### Fix: Branchless State Entanglement
Never branch directly to `exit()`/`abort()` on a debugger flag or breakpoint scan (`0xD4200000` ARM64 `BRK` / `0xCC` x86 `INT3`). Instead, convert the check into a 64-bit bitmask or non-zero poison word (`0` when clean, non-zero constant when traced) and XOR/add it directly into the live decryption keystream, sponge accumulator, or runtime anchor. Patching requires reverse-engineering the entire key schedule rather than flipping one jump instruction.

---

## 4. Interpreting `mba_window_density`
- **Unprotected `clang -O3` binaries**: Typically `< 0.03` (`< 3%` of 12-instruction windows contain dense interleaved boolean + arithmetic ops).
- **Heavily virtualized / MBA-hardened binaries**: Typically `0.15`–`0.60+` (`15%–60%+`), accompanied by higher indirect dispatch (`br`/`blr` or `jmp *reg`) counts.
- **Warning sign**: High `folded_const_xor_count` combined with low `mba_window_density` strongly indicates that your MBA pass was silently optimized away by `-O3`.
