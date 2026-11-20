#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
AREA (Anti-Reverse Engineering Anything) — Universal Binary Hardening &
Obfuscation Verification CLI.

Zero-dependency Python 3 auditing tool designed for AI coding agents
(Codex, Antigravity, Claude Code, Gemini CLI, OpenCode) and CI pipelines.

All subcommands write structured JSON reports to --output and print only a
concise summary to stdout to preserve agent context windows.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


VERSION = "1.0.0"

# Default stealth detection patterns (universal across C/C++/Rust/Swift/Go/VMs)
OBFUSCATOR_HINT_PATTERNS = [
    r"\bobfusc\w*",
    r"\bbytecode\b",
    r"\bopcode\b",
    r"\bvm_exec\b",
    r"\bvm_dispatch\b",
    r"\bvm_handler\b",
    r"\bdispatcher\b",
    r"\bchaff_hit\w*",
    r"\bmba_\w+",
    r"\bsclock\b",
    r"\bvmprotect\b",
    r"\bthemida\b",
    r"\bollv[m]?\b",
    r"\banti[_-]?debug\w*",
    r"debugger detected",
    r"tamper detected",
    r"license invalid",
    r"trial expired",
    r"hardware[- ]locked",
    r"polymorphic vm",
]

SYMBOL_LEAK_PATTERNS = [
    r"obfusc",
    r"opcode",
    r"bytecode",
    r"vm_dispatch",
    r"vm_exec",
    r"chaff",
    r"mba_",
    r"anti_debug",
    r"license",
    r"verify_pin",
    r"decrypt_key",
    r"unseal_key",
    r"sclock",
    r"sep_guard",
]

TOOLCHAIN_FINGERPRINT_PATTERNS = [
    r"/rustc/[0-9a-f]{8,}",
    r"/rust/deps/",
    r"rustc-demangle",
    r"\bRUST_BACKTRACE\b",
    r"\bRUST_LIB_BACKTRACE\b",
    r"__rust_begin_short_backtrace",
    r"__rust_end_short_backtrace",
    r"\.llvm\.[0-9]+",
    r"go\.buildid",
    r"/usr/local/go/src/",
    r"XcodeDefault\.xctoolchain",
]

HOST_PATH_PATTERNS = [
    r"/Users/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+",
    r"/home/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+",
    r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\[A-Za-z0-9._\\-]+",
]

ANTIDEBUG_API_KEYWORDS = [
    "sysctl",
    "ptrace",
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "task_get_exception_ports",
    "getppid",
]

TERMINATE_KEYWORDS = [
    "_exit",
    "exit",
    "abort",
    "__stack_chk_fail",
    "raise",
    "kill",
    "brk",
    "ud2",
]


def run_cmd(cmd: List[str], timeout: int = 60) -> Tuple[Optional[int], str, str, Optional[str]]:
    """Run an external command safely; return (returncode, stdout, stderr, error_msg)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, None
    except FileNotFoundError:
        return None, "", "", f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, "", "", f"command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as exc:  # noqa: BLE001
        return None, "", "", f"execution error: {exc}"


def find_tool(candidates: List[str]) -> Optional[str]:
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    length = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def block_entropy_stats(data: bytes, block_size: int = 4096) -> Dict[str, Any]:
    if not data:
        return {
            "block_size": block_size,
            "num_blocks": 0,
            "min_entropy": 0.0,
            "max_entropy": 0.0,
            "mean_entropy": 0.0,
            "high_entropy_blocks_ge_7_0": 0,
            "high_entropy_ratio": 0.0,
            "zero_blocks": 0,
        }
    entropies: List[float] = []
    zero_blocks = 0
    for i in range(0, len(data), block_size):
        chunk = data[i : i + block_size]
        if len(chunk) < 64:
            continue
        if not any(chunk):
            zero_blocks += 1
            entropies.append(0.0)
        else:
            entropies.append(shannon_entropy(chunk))
    if not entropies:
        ent = shannon_entropy(data)
        return {
            "block_size": block_size,
            "num_blocks": 1,
            "min_entropy": round(ent, 4),
            "max_entropy": round(ent, 4),
            "mean_entropy": round(ent, 4),
            "high_entropy_blocks_ge_7_0": 1 if ent >= 7.0 else 0,
            "high_entropy_ratio": 1.0 if ent >= 7.0 else 0.0,
            "zero_blocks": zero_blocks,
        }
    high_cnt = sum(1 for e in entropies if e >= 7.0)
    return {
        "block_size": block_size,
        "num_blocks": len(entropies),
        "min_entropy": round(min(entropies), 4),
        "max_entropy": round(max(entropies), 4),
        "mean_entropy": round(sum(entropies) / len(entropies), 4),
        "high_entropy_blocks_ge_7_0": high_cnt,
        "high_entropy_ratio": round(high_cnt / len(entropies), 4),
        "zero_blocks": zero_blocks,
    }


def extract_ascii_strings(data: bytes, min_len: int = 5) -> List[str]:
    pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_len)
    return [m.group(0).decode("ascii", errors="ignore") for m in pattern.finditer(data)]


def parse_section_sizes(binary_path: Path) -> Dict[str, Any]:
    """Extract code section (.text / __text) size using platform tools with fallback."""
    result: Dict[str, Any] = {"tool": None, "status": "SKIP", "text_bytes": None, "sections": {}}

    size_bin = find_tool(["size"])
    if size_bin and platform.system() == "Darwin":
        rc, out, _, _ = run_cmd([size_bin, "-m", str(binary_path)])
        if rc == 0 and out:
            result["tool"] = "size -m"
            result["status"] = "OK"
            for line in out.splitlines():
                m = re.search(r"Section\s+([A-Za-z0-9_]+):\s+(\d+)", line)
                if m:
                    sec_name, sec_size = m.group(1), int(m.group(2))
                    result["sections"][sec_name] = sec_size
                    if sec_name == "__text":
                        result["text_bytes"] = sec_size
            return result

    readelf_bin = find_tool(["readelf", "greadelf"])
    if readelf_bin:
        rc, out, _, _ = run_cmd([readelf_bin, "-SW", str(binary_path)])
        if rc == 0 and out:
            result["tool"] = f"{Path(readelf_bin).name} -SW"
            result["status"] = "OK"
            for line in out.splitlines():
                m = re.search(r"\[\s*\d+\]\s+(\.[A-Za-z0-9_.-]+)\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)", line)
                if m:
                    sec_name, sec_size = m.group(1), int(m.group(2), 16)
                    result["sections"][sec_name] = sec_size
                    if sec_name == ".text":
                        result["text_bytes"] = sec_size
            return result

    objdump_bin = find_tool(["llvm-objdump", "objdump"])
    if objdump_bin:
        rc, out, _, _ = run_cmd([objdump_bin, "-h", str(binary_path)])
        if rc == 0 and out:
            result["tool"] = f"{Path(objdump_bin).name} -h"
            result["status"] = "OK"
            for line in out.splitlines():
                m = re.search(r"^\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+", line)
                if m:
                    sec_name, sec_size = m.group(1), int(m.group(2), 16)
                    result["sections"][sec_name] = sec_size
                    if sec_name in ("__text", ".text"):
                        result["text_bytes"] = sec_size
            return result

    result["note"] = "No section-size tool (size/readelf/objdump) available; using raw file size only."
    return result


def audit_stealth(binary_path: Path, extra_patterns: List[str]) -> Dict[str, Any]:
    raw = binary_path.read_bytes()
    file_size = len(raw)
    overall_entropy = round(shannon_entropy(raw), 4)
    blk_entropy = block_entropy_stats(raw)
    sec_info = parse_section_sizes(binary_path)

    # 1. Symbol audit (nm -> llvm-nm -> readelf)
    sym_info: Dict[str, Any] = {
        "tool": None,
        "status": "SKIP",
        "defined_symbol_count": 0,
        "exported_symbol_count": 0,
        "leaked_symbol_count": 0,
        "leaked_symbols_sample": [],
        "exported_symbols_sample": [],
    }
    nm_bin = find_tool(["nm", "llvm-nm"])
    readelf_bin = find_tool(["readelf", "greadelf"])
    sym_lines: List[str] = []
    if nm_bin:
        rc, out, err, _ = run_cmd([nm_bin, str(binary_path)])
        if rc == 0:
            sym_info["tool"] = Path(nm_bin).name
            sym_info["status"] = "OK"
            sym_lines = out.splitlines()
        elif "no symbols" in (err + out).lower():
            sym_info["tool"] = Path(nm_bin).name
            sym_info["status"] = "OK"
            sym_info["note"] = "Symbol table fully stripped (no symbols)."
        else:
            rc2, out2, _, _ = run_cmd([nm_bin, "-gU", str(binary_path)])
            if rc2 == 0:
                sym_info["tool"] = f"{Path(nm_bin).name} -gU"
                sym_info["status"] = "OK"
                sym_lines = out2.splitlines()
    elif readelf_bin:
        rc, out, _, _ = run_cmd([readelf_bin, "-Ws", str(binary_path)])
        if rc == 0:
            sym_info["tool"] = f"{Path(readelf_bin).name} -Ws"
            sym_info["status"] = "OK"
            sym_lines = out.splitlines()

    sym_regexes = [re.compile(p, re.IGNORECASE) for p in SYMBOL_LEAK_PATTERNS + extra_patterns]
    defined_syms: List[str] = []
    exported_syms: List[str] = []
    leaked_syms: List[str] = []

    for line in sym_lines:
        parts = line.split()
        if not parts:
            continue
        if sym_info["tool"] and "nm" in sym_info["tool"]:
            if len(parts) >= 3:
                sym_type, sym_name = parts[1], parts[2]
                if sym_type.upper() == "U":
                    continue
                defined_syms.append(sym_name)
                if sym_type in ("T", "D", "S", "B", "R"):
                    exported_syms.append(sym_name)
                if any(rx.search(sym_name) for rx in sym_regexes):
                    leaked_syms.append(sym_name)
        else:
            # readelf -Ws fallback
            if len(parts) >= 8 and parts[6] != "UND":
                sym_name = parts[7]
                defined_syms.append(sym_name)
                if parts[4] == "GLOBAL":
                    exported_syms.append(sym_name)
                if any(rx.search(sym_name) for rx in sym_regexes):
                    leaked_syms.append(sym_name)

    sym_info["defined_symbol_count"] = len(defined_syms)
    sym_info["exported_symbol_count"] = len(exported_syms)
    sym_info["exported_symbols_sample"] = exported_syms[:20]
    sym_info["leaked_symbol_count"] = len(leaked_syms)
    sym_info["leaked_symbols_sample"] = leaked_syms[:25]

    # 2. Pure-Python string & fingerprint scan
    all_strings = extract_ascii_strings(raw, min_len=5)
    hint_rxs = [re.compile(p, re.IGNORECASE) for p in OBFUSCATOR_HINT_PATTERNS]
    tc_rxs = [re.compile(p) for p in TOOLCHAIN_FINGERPRINT_PATTERNS]
    host_rxs = [re.compile(p) for p in HOST_PATH_PATTERNS]
    custom_rxs = [re.compile(p, re.IGNORECASE) for p in extra_patterns]

    hint_hits: List[str] = []
    tc_hits: List[str] = []
    host_hits: List[str] = []
    custom_hits: List[str] = []

    for s in all_strings:
        if any(rx.search(s) for rx in hint_rxs):
            hint_hits.append(s[:160])
        if any(rx.search(s) for rx in tc_rxs):
            tc_hits.append(s[:160])
        if any(rx.search(s) for rx in host_rxs):
            host_hits.append(s[:160])
        if custom_rxs and any(rx.search(s) for rx in custom_rxs):
            custom_hits.append(s[:160])

    findings: List[Dict[str, Any]] = []
    if leaked_syms:
        findings.append({
            "severity": "HIGH",
            "category": "stealth.symbols",
            "message": f"Found {len(leaked_syms)} internal/obfuscator symbol(s) in symbol table (e.g., {', '.join(leaked_syms[:3])}).",
            "remediation": "Strip local and non-exported symbols (`strip -x` on macOS, `strip --strip-all` on Linux) and avoid descriptive names for VM/handler functions.",
        })
    if hint_hits:
        findings.append({
            "severity": "HIGH",
            "category": "stealth.strings",
            "message": f"Found {len(hint_hits)} plaintext obfuscator/VM/security hint string(s) (e.g., {hint_hits[0]!r}).",
            "remediation": "Remove or encrypt plaintext diagnostic banners, error messages, and VM/license hint strings.",
        })
    if tc_hits:
        findings.append({
            "severity": "MEDIUM",
            "category": "stealth.toolchain",
            "message": f"Found {len(tc_hits)} compiler/toolchain fingerprint string(s) (e.g., {tc_hits[0]!r}).",
            "remediation": "Use `--remap-path-prefix` / `-fdebug-prefix-map` and post-build binary string scrubbing to remove `/rustc/`, `.llvm.`, and backtrace markers.",
        })
    if host_hits:
        findings.append({
            "severity": "MEDIUM",
            "category": "stealth.host_paths",
            "message": f"Found {len(host_hits)} build-machine filesystem path(s) (e.g., {host_hits[0]!r}).",
            "remediation": "Strip debug info and remap absolute source paths so build-host usernames and workspace directories are not embedded.",
        })
    if custom_hits:
        findings.append({
            "severity": "HIGH",
            "category": "stealth.custom_patterns",
            "message": f"Matched {len(custom_hits)} user-specified sensitive pattern(s) in binary strings.",
            "remediation": "Encrypt, obfuscate, or scrub all custom secret strings before release.",
        })
    if overall_entropy < 5.5:
        findings.append({
            "severity": "INFO",
            "category": "stealth.entropy",
            "message": f"Overall binary Shannon entropy is relatively low ({overall_entropy} bits/byte), typical of unprotected or sparsely virtualized binaries.",
            "remediation": "Verify that critical logic is actually encrypted/virtualized rather than left in plaintext.",
        })

    return {
        "binary": str(binary_path),
        "file_size_bytes": file_size,
        "overall_shannon_entropy": overall_entropy,
        "block_entropy": blk_entropy,
        "sections": sec_info,
        "symbols": sym_info,
        "strings": {
            "total_extracted": len(all_strings),
            "obfuscator_hint_count": len(hint_hits),
            "obfuscator_hints_sample": hint_hits[:20],
            "toolchain_fingerprint_count": len(tc_hits),
            "toolchain_fingerprints_sample": tc_hits[:20],
            "host_path_count": len(host_hits),
            "host_paths_sample": host_hits[:15],
            "custom_pattern_count": len(custom_hits),
            "custom_patterns_sample": custom_hits[:20],
        },
        "findings": findings,
    }


def disassemble_binary(binary_path: Path, max_insns: int) -> Tuple[Optional[str], str, List[str], bool, Optional[str]]:
    """Disassemble binary with platform fallback. Returns (tool_used, arch, insn_lines, truncated, err)."""
    candidates: List[Tuple[str, List[str]]] = []
    llvm_od = find_tool(["llvm-objdump"])
    od = find_tool(["objdump"])
    otool = find_tool(["otool"])
    if llvm_od:
        candidates.append(("llvm-objdump -d", [llvm_od, "-d", str(binary_path)]))
    if od:
        candidates.append(("objdump -d", [od, "-d", str(binary_path)]))
    if otool and platform.system() == "Darwin":
        candidates.append(("otool -tV", [otool, "-tV", str(binary_path)]))

    if not candidates:
        return None, "unknown", [], False, "No disassembler found (tried llvm-objdump, objdump, otool)."

    last_err = None
    for label, cmd in candidates:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
            continue

        arch = "unknown"
        lines: List[str] = []
        truncated = False
        assert proc.stdout is not None
        insn_re = re.compile(r"^\s*[0-9a-fA-F]+:\s+")
        try:
            for raw_line in proc.stdout:
                low = raw_line.lower()
                if arch == "unknown":
                    if "arm64" in low or "aarch64" in low:
                        arch = "arm64"
                    elif "x86-64" in low or "x86_64" in low or "i386:x86-64" in low:
                        arch = "x86_64"
                if insn_re.match(raw_line):
                    lines.append(raw_line.rstrip("\n"))
                    if len(lines) >= max_insns:
                        truncated = True
                        break
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception as exc:  # noqa: BLE001
            proc.kill()
            last_err = str(exc)
            continue

        if lines:
            if arch == "unknown":
                sample = " ".join(lines[:100]).lower()
                if any(k in sample for k in ("movk", "stp", "ldp", "adrp")):
                    arch = "arm64"
                elif any(k in sample for k in ("movq", "movabs", "%rsp", "rsp")):
                    arch = "x86_64"
            return label, arch, lines, truncated, None
        last_err = f"{label} produced 0 disassembled instructions"

    return None, "unknown", [], False, last_err or "Disassembly failed"


def parse_insn(line: str, arch: str) -> Tuple[str, str, str]:
    """Return (address, mnemonic, operands) from a disassembly line."""
    # Example objdump arm64: "100000d04: d2808c68 \tmov\tx8, #0x463"
    # Example objdump x86_64: " 1149: 48 b8 ... \tmovabs $0x..., %rax"
    # Example otool arm64: "0000000100000d04\tmov\tx8, #0x463"
    m = re.match(r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2,8}\s+)+([A-Za-z][A-Za-z0-9_.]*)(?:\s+(.*))?$", line)
    if m:
        addr, mnem, ops = m.group(1), m.group(2).lower(), (m.group(3) or "").strip()
        ops = ops.split(";")[0].split("# =")[0].strip()
        return addr, mnem, ops
    m2 = re.match(r"^\s*([0-9a-fA-F]+)\s+([A-Za-z][A-Za-z0-9_.]*)(?:\s+(.*))?$", line)
    if m2:
        addr, mnem, ops = m2.group(1), m2.group(2).lower(), (m2.group(3) or "").strip()
        ops = ops.split(";")[0].strip()
        return addr, mnem, ops
    return "", "", ""


def audit_disasm(binary_path: Path, max_insns: int) -> Dict[str, Any]:
    tool_used, arch, raw_lines, truncated, err = disassemble_binary(binary_path, max_insns)
    if not tool_used:
        return {
            "binary": str(binary_path),
            "status": "SKIP",
            "tool": None,
            "arch": arch,
            "error": err,
            "findings": [{
                "severity": "INFO",
                "category": "disasm.skipped",
                "message": f"Disassembly audit skipped: {err}",
                "remediation": "Install `llvm-objdump` / `objdump` (Xcode CLT or binutils) to enable disassembly verification.",
            }],
        }

    parsed = [parse_insn(ln, arch) for ln in raw_lines]
    parsed = [p for p in parsed if p[1]]
    n = len(parsed)

    bool_ops = {"and", "ands", "orr", "eor", "bic", "bics", "orn", "eon", "mvn", "xor", "or", "not", "andq", "orq", "xorq", "notq"}
    arith_ops = {"add", "adds", "sub", "subs", "mul", "madd", "msub", "neg", "adc", "sbc", "addq", "subq", "imul", "imulq", "lea", "leaq"}
    rot_ops = {"ror", "lsl", "lsr", "asr", "extr", "rol", "shl", "shr", "sar", "rorq", "rolq", "shlq", "shrq"}

    bool_cnt = 0
    arith_cnt = 0
    rot_cnt = 0
    indirect_branch_cnt = 0
    direct_cond_branch_cnt = 0
    sp_mem_ops = 0

    folded_const_xor_hits: List[Dict[str, str]] = []
    folded_arg_xor_hits: List[Dict[str, str]] = []
    blackbox_spill_hits: List[Dict[str, str]] = []
    patchable_antidebug_hits: List[Dict[str, str]] = []

    since_prologue = 999
    clobbered_args: set = set()

    # Sliding window MBA density (windows of 12 instructions containing >=2 bool AND >=2 arith)
    mba_windows = 0
    total_windows = max(1, (n - 11) // 6) if n >= 12 else 1

    for i, (addr, mnem, ops) in enumerate(parsed):
        ops_low = ops.lower()
        since_prologue += 1
        if arch == "arm64":
            if (mnem == "stp" and "[sp, #-" in ops_low) or (mnem == "sub" and ops_low.startswith("sp, sp, #")):
                since_prologue = 0
                clobbered_args = set()
            else:
                dst_m = re.match(r"^(x[123]),", ops_low)
                if dst_m and mnem not in ("str", "stp", "cmp", "tst", "cbz", "cbnz", "tbz", "tbnz"):
                    clobbered_args.add(dst_m.group(1))
        if mnem in bool_ops:
            bool_cnt += 1
        if mnem in arith_ops:
            arith_cnt += 1
        if mnem in rot_ops:
            rot_cnt += 1

        # Indirect branches / calls (VM dispatch / jump tables)
        if arch == "arm64":
            if mnem in ("br", "blr", "braa", "blraa", "brab", "blrab"):
                indirect_branch_cnt += 1
            elif mnem.startswith("b.") or mnem in ("cbz", "cbnz", "tbz", "tbnz"):
                direct_cond_branch_cnt += 1
            if mnem in ("str", "ldr", "stp", "ldp") and "[sp" in ops_low:
                sp_mem_ops += 1
        else:
            if mnem in ("jmp", "call", "jmpq", "callq") and ("*" in ops_low or ops_low.startswith("r") or ops_low.startswith("%r")):
                indirect_branch_cnt += 1
            elif mnem in ("je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "ja", "jb"):
                direct_cond_branch_cnt += 1
            if ("rsp" in ops_low or "esp" in ops_low) and mnem.startswith("mov"):
                sp_mem_ops += 1

        # 1. Detect LLVM constant-folded 64-bit immediate -> immediate XOR/masking
        if arch == "arm64" and mnem == "mov" and "#0x" in ops_low:
            reg_m = re.match(r"^(x\d+),", ops_low)
            if reg_m:
                reg = reg_m.group(1)
                movk_cnt = 0
                j = i + 1
                while j < min(n, i + 5) and parsed[j][1] == "movk" and parsed[j][2].lower().startswith(f"{reg},"):
                    movk_cnt += 1
                    j += 1
                if movk_cnt >= 2 and j < min(n, i + 7):
                    # Check if immediately fed into eor/cmp with an argument/live register
                    for k in range(j, min(n, j + 3)):
                        k_addr, k_mnem, k_ops = parsed[k]
                        if k_mnem == "eor" and reg in k_ops.lower() and not re.search(r"lsr|lsl|ror", k_ops.lower()):
                            hit = {
                                "address": f"0x{addr}",
                                "consumer_address": f"0x{k_addr}",
                                "pattern": f"mov+{movk_cnt}*movk {reg} -> {k_mnem} {k_ops}",
                            }
                            folded_const_xor_hits.append(hit)
                            # True prologue folded argument mask: within 24 insns of prologue, immediate reg != x1..x3,
                            # and source operand includes an unclobbered incoming argument register (x1, x2, or x3)
                            if since_prologue <= 24 and reg not in ("x1", "x2", "x3"):
                                eor_parts = [p.strip() for p in k_ops.lower().split(",")]
                                src_regs = eor_parts[1:] if len(eor_parts) >= 3 else []
                                if any(sr in ("x1", "x2", "x3") and sr not in clobbered_args for sr in src_regs):
                                    folded_arg_xor_hits.append(hit)
                            break
        elif arch == "x86_64" and mnem in ("movabs", "movabsq"):
            for k in range(i + 1, min(n, i + 4)):
                k_addr, k_mnem, k_ops = parsed[k]
                if k_mnem in ("xor", "xorq"):
                    folded_const_xor_hits.append({
                        "address": f"0x{addr}",
                        "consumer_address": f"0x{k_addr}",
                        "pattern": f"{mnem} {ops} -> {k_mnem} {k_ops}",
                    })
                    break

        # 2. Detect std::hint::black_box stack-spill anti-pattern:
        # ARM64: str xN, [sp, #imm] followed by add xM, sp, #imm (same stack offset!)
        if arch == "arm64" and mnem == "str" and "[sp, #" in ops_low:
            off_m = re.search(r"\[sp,\s*#(0x[0-9a-f]+|\d+)\]", ops_low)
            if off_m and i + 1 < n:
                off = off_m.group(1)
                n_addr, n_mnem, n_ops = parsed[i + 1]
                if n_mnem == "add" and f"sp, #{off}" in n_ops.lower():
                    blackbox_spill_hits.append({
                        "address": f"0x{addr}",
                        "pattern": f"str [sp, #{off}] + add sp, #{off}",
                    })
        elif arch == "x86_64" and mnem.startswith("mov") and "rsp" in ops_low and i + 1 < n:
            n_addr, n_mnem, n_ops = parsed[i + 1]
            if n_mnem in ("lea", "leaq") and "rsp" in n_ops.lower():
                blackbox_spill_hits.append({
                    "address": f"0x{addr}",
                    "pattern": f"{mnem} {ops} + {n_mnem} {n_ops}",
                })

        # 3. Detect patchable anti-debug branch pattern:
        # call/bl to sysctl/ptrace/IsDebuggerPresent followed closely by conditional branch + exit/abort
        if mnem in ("bl", "call", "callq") and any(api in ops_low for api in ANTIDEBUG_API_KEYWORDS):
            saw_cond = False
            cond_info = ""
            for k in range(i + 1, min(n, i + 18)):
                k_addr, k_mnem, k_ops = parsed[k]
                k_low = k_ops.lower()
                if k_mnem.startswith("b.") or k_mnem in ("cbz", "cbnz", "tbz", "tbnz", "je", "jne", "jz", "jnz"):
                    saw_cond = True
                    cond_info = f"0x{k_addr}: {k_mnem} {k_ops}"
                if saw_cond and (k_mnem in ("bl", "call", "callq", "brk", "ud2") and any(t in k_low or t == k_mnem for t in TERMINATE_KEYWORDS)):
                    patchable_antidebug_hits.append({
                        "api_call": f"0x{addr}: {mnem} {ops}",
                        "branch": cond_info,
                        "terminate": f"0x{k_addr}: {k_mnem} {k_ops}",
                    })
                    break

    for start in range(0, max(0, n - 11), 6):
        win = parsed[start : start + 12]
        wb = sum(1 for _, m, _ in win if m in bool_ops)
        wa = sum(1 for _, m, _ in win if m in arith_ops)
        if wb >= 2 and wa >= 2:
            mba_windows += 1

    mba_density = round(mba_windows / total_windows, 4) if total_windows > 0 else 0.0
    sp_ratio = round(sp_mem_ops / max(1, n), 4)
    folded_per_1k = round((len(folded_const_xor_hits) * 1000.0) / max(1, n), 2)
    spills_per_1k = round((len(blackbox_spill_hits) * 1000.0) / max(1, n), 2)

    findings: List[Dict[str, Any]] = []
    if len(blackbox_spill_hits) >= 20:
        findings.append({
            "severity": "MEDIUM",
            "category": "disasm.stack_spill_bloat",
            "message": f"Detected {len(blackbox_spill_hits)} stack-spill barrier pattern(s) ({spills_per_1k}/1k insns) characteristic of `std::hint::black_box`.",
            "remediation": "Replace `std::hint::black_box` with a zero-spill register-only inline assembly barrier (`asm!(\"/* {0} */\", inout(reg) v, options(nomem, nostack, preserves_flags))`) to shrink `.text` size and boost hot-path latency.",
        })
    if len(folded_arg_xor_hits) >= 5:
        findings.append({
            "severity": "HIGH",
            "category": "disasm.folded_arg_mask",
            "message": f"Detected {len(folded_arg_xor_hits)} 64-bit immediate constant(s) directly XORed into raw argument registers (x1..x3). Handler masks/salts appear constant-folded by LLVM.",
            "remediation": "Insert register-only inline assembly barriers (`reg_barrier`) and entangle masks with runtime state (`anchor`, `sigma`, `pc`) to prevent LLVM constant folding.",
        })
    elif len(folded_const_xor_hits) >= 15 and mba_density < 0.08:
        findings.append({
            "severity": "HIGH",
            "category": "disasm.constant_folding",
            "message": f"Detected {len(folded_const_xor_hits)} 64-bit immediate-constant -> XOR pattern(s) with low MBA density ({mba_density:.2%}). Compiler optimization (-O3 / InstCombine) may have constant-folded obfuscated salts or masks into plaintext literals.",
            "remediation": "Split SSA operands with register-only inline assembly barriers and entangle handler salts/masks with runtime state (`anchor`, `sigma`, `pc`) to prevent LLVM constant folding.",
        })
    elif len(folded_const_xor_hits) >= 10:
        findings.append({
            "severity": "INFO",
            "category": "disasm.immediate_xor_patterns",
            "message": f"Observed {len(folded_const_xor_hits)} 64-bit immediate -> XOR sequence(s) across {n} instructions (direct arg-register XORs: {len(folded_arg_xor_hits)}, MBA window density: {mba_density:.2%}).",
            "remediation": "Spot-check sample addresses in `folded_const_xor_sample` to confirm raw secrets are never reconstructed via a single `mov/movk + eor`.",
        })
    if patchable_antidebug_hits:
        findings.append({
            "severity": "HIGH",
            "category": "disasm.patchable_antidebug",
            "message": f"Detected {len(patchable_antidebug_hits)} classic branch-and-exit anti-debug pattern(s) easily bypassed with a 1-instruction patch.",
            "remediation": "Replace `if (is_debugged) exit()` branches with branchless state entanglement (XOR/mix the debugger flag bit directly into decryption keys or VM accumulator state).",
        })
    if mba_density < 0.03 and indirect_branch_cnt < 5:
        findings.append({
            "severity": "MEDIUM",
            "category": "disasm.low_obfuscation_density",
            "message": f"Low MBA mixing density ({mba_density:.2%}) and low indirect dispatch count ({indirect_branch_cnt}) across {n} scanned instructions.",
            "remediation": "Verify that the intended critical functions were actually compiled through the obfuscation/virtualization pass.",
        })

    return {
        "binary": str(binary_path),
        "status": "OK",
        "tool": tool_used,
        "arch": arch,
        "max_insns_requested": max_insns,
        "scanned_instructions": n,
        "truncated": truncated,
        "metrics": {
            "boolean_insns": bool_cnt,
            "arithmetic_insns": arith_cnt,
            "rotate_shift_insns": rot_cnt,
            "mba_interleaved_windows": mba_windows,
            "total_windows": total_windows,
            "mba_window_density": mba_density,
            "indirect_branches_calls": indirect_branch_cnt,
            "direct_conditional_branches": direct_cond_branch_cnt,
            "stack_mem_ratio": sp_ratio,
            "folded_const_xor_count": len(folded_const_xor_hits),
            "folded_const_xor_per_1k": folded_per_1k,
            "folded_arg_xor_count": len(folded_arg_xor_hits),
            "blackbox_stack_spill_count": len(blackbox_spill_hits),
            "blackbox_stack_spills_per_1k": spills_per_1k,
            "patchable_antidebug_count": len(patchable_antidebug_hits),
        },
        "samples": {
            "folded_const_xor_sample": folded_const_xor_hits[:15],
            "folded_arg_xor_sample": folded_arg_xor_hits[:15],
            "blackbox_stack_spill_sample": blackbox_spill_hits[:15],
            "patchable_antidebug_sample": patchable_antidebug_hits[:10],
        },
        "findings": findings,
    }


def audit_binding(binary_path: Path) -> Dict[str, Any]:
    raw = binary_path.read_bytes()
    sys_os = platform.system()
    findings: List[Dict[str, Any]] = []

    # 1. File type
    file_desc = "unknown"
    file_bin = find_tool(["file"])
    if file_bin:
        rc, out, _, _ = run_cmd([file_bin, "-b", str(binary_path)])
        if rc == 0:
            file_desc = out.strip()

    # 2. Linked dependencies
    deps: List[str] = []
    deps_tool = None
    if sys_os == "Darwin":
        otool = find_tool(["otool"])
        if otool:
            rc, out, _, _ = run_cmd([otool, "-L", str(binary_path)])
            if rc == 0:
                deps_tool = "otool -L"
                for line in out.splitlines()[1:]:
                    lib = line.strip().split(" ")[0]
                    if lib:
                        deps.append(lib)
    else:
        ldd = find_tool(["ldd"])
        if ldd:
            rc, out, _, _ = run_cmd([ldd, str(binary_path)])
            if rc == 0:
                deps_tool = "ldd"
                for line in out.splitlines():
                    deps.append(line.strip())

    # 3. Platform-specific signing / hardening
    signing: Dict[str, Any] = {"status": "SKIP"}
    quarantine: Dict[str, Any] = {"status": "SKIP"}
    elf_mitigations: Dict[str, Any] = {"status": "SKIP"}

    if sys_os == "Darwin":
        codesign = find_tool(["codesign"])
        if codesign:
            rc, out, err, _ = run_cmd([codesign, "-dv", "--verbose=4", str(binary_path)])
            combined = (out + "\n" + err).strip()
            if rc == 0:
                is_adhoc = "Signature=adhoc" in combined
                has_runtime = "flags=0x10000(runtime)" in combined or "(runtime)" in combined
                signing = {
                    "status": "OK",
                    "signed": True,
                    "adhoc": is_adhoc,
                    "hardened_runtime": has_runtime,
                    "summary_lines": [ln for ln in combined.splitlines() if any(k in ln for k in ("Identifier=", "CodeDirectory", "Signature=", "Authority=", "TeamIdentifier="))][:10],
                }
                if is_adhoc:
                    findings.append({
                        "severity": "INFO",
                        "category": "binding.codesign",
                        "message": "Binary is ad-hoc signed (`Signature=adhoc`).",
                        "remediation": "For public macOS distribution, sign with a Developer ID certificate + notarize, or document `xattr -cr <binary>` to clear Gatekeeper quarantine.",
                    })
                if not has_runtime:
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "binding.hardened_runtime",
                        "message": "macOS Hardened Runtime flag (`runtime`) is not enabled on the code signature.",
                        "remediation": "Sign with `codesign --force --options runtime --sign ...` to block DYLD_INSERT_LIBRARIES injection and unsigned debugger attachment.",
                    })
            else:
                signing = {"status": "OK", "signed": False, "detail": combined[:200]}
                findings.append({
                    "severity": "HIGH",
                    "category": "binding.unsigned",
                    "message": "Mach-O binary is unsigned; Apple Silicon macOS refuses to execute unsigned arm64 binaries.",
                    "remediation": "Apply at least an ad-hoc Hardened Runtime signature (`codesign --force --options runtime --sign - <binary>`).",
                })

        xattr_bin = find_tool(["xattr"])
        if xattr_bin:
            rc, out, _, _ = run_cmd([xattr_bin, "-l", str(binary_path)])
            if rc == 0:
                has_q = "com.apple.quarantine" in out
                quarantine = {"status": "OK", "has_quarantine": has_q}
    else:
        readelf = find_tool(["readelf", "greadelf"])
        if readelf:
            rc, out, _, _ = run_cmd([readelf, "-lW", str(binary_path)])
            if rc == 0:
                has_relro = "GNU_RELRO" in out
                nx_enabled = "GNU_STACK" in out and "RWE" not in out
                elf_mitigations = {"status": "OK", "relro": has_relro, "nx": nx_enabled}
                if not nx_enabled:
                    findings.append({
                        "severity": "HIGH",
                        "category": "binding.elf_nx",
                        "message": "ELF binary appears to have an executable stack (NX disabled).",
                        "remediation": "Link with `-Wl,-z,noexecstack`.",
                    })

    # 4. Hardware Key Binding vs. Portability heuristics (Apple SEP / CryptoKit)
    uses_cryptokit = any("cryptokit" in d.lower() or "security.framework" in d.lower() for d in deps) or (b"CryptoKit" in raw)
    has_sep_hw_markers = (b"rk1" in raw and b"dacl" in raw) or (b"kSecAttrTokenIDSecureEnclave" in raw)
    has_portable_scp1 = b"SCP1" in raw

    portability_mode = "standard_software"
    if uses_cryptokit or has_sep_hw_markers or has_portable_scp1:
        if has_portable_scp1:
            portability_mode = "portable_sep_attested_scp1"
            findings.append({
                "severity": "INFO",
                "category": "binding.portability",
                "message": "Detected Portable SEP-Attested (`SCP1`) envelope: runnable across Apple Silicon Macs, with runtime SEP anti-emulation gate (not physically UID-sealed to one host).",
                "remediation": "Ensure public documentation accurately distinguishes Portable Mode (`SCP1`) from single-host hardware UID sealing (`--sep-lock`).",
            })
        elif has_sep_hw_markers:
            portability_mode = "host_hardware_sep_uid_locked"
            findings.append({
                "severity": "HIGH",
                "category": "binding.host_lock_risk",
                "message": "Detected hardware-bound Apple Secure Enclave key representation (`rk1`/`dacl`) WITHOUT a portable envelope. This binary will ONLY unseal on the exact physical Mac that built it.",
                "remediation": "If this binary is meant for end-user distribution or a public CrackMe, rebuild in Portable Mode; if intentionally node-locked, clearly document single-machine hardware binding.",
            })

    return {
        "binary": str(binary_path),
        "os_host": sys_os,
        "file_type": file_desc,
        "dependencies_tool": deps_tool,
        "dependencies": deps[:40],
        "codesign": signing,
        "quarantine": quarantine,
        "elf_mitigations": elf_mitigations,
        "hardware_binding": {
            "uses_cryptokit_or_security": uses_cryptokit,
            "has_sep_hw_blob_markers": has_sep_hw_markers,
            "has_portable_scp1_marker": has_portable_scp1,
            "inferred_mode": portability_mode,
        },
        "findings": findings,
    }


def audit_diff(
    unprotected: Path,
    protected: Path,
    cases_path: Path,
    iters: int,
) -> Dict[str, Any]:
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases JSON must be a non-empty list of objects with 'args' list.")

    findings: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    mismatches = 0

    for idx, case in enumerate(cases):
        name = str(case.get("name", f"case_{idx}"))
        args = [str(a) for a in case.get("args", [])]
        rc_u, out_u, err_u, e_u = run_cmd([str(unprotected)] + args, timeout=30)
        rc_p, out_p, err_p, e_p = run_cmd([str(protected)] + args, timeout=30)

        matched = (e_u is None) and (e_p is None) and (rc_u == rc_p) and (out_u.strip() == out_p.strip())
        if not matched:
            mismatches += 1
        results.append({
            "name": name,
            "args": args,
            "matched": matched,
            "unprotected": {"rc": rc_u, "stdout": out_u.strip()[:200], "stderr": err_u.strip()[:200], "error": e_u},
            "protected": {"rc": rc_p, "stdout": out_p.strip()[:200], "stderr": err_p.strip()[:200], "error": e_p},
        })

    # Wall-clock latency benchmark on case 0
    bench_args = [str(a) for a in cases[0].get("args", [])]
    t0 = time.perf_counter()
    for _ in range(iters):
        run_cmd([str(unprotected)] + bench_args, timeout=30)
    u_ms = ((time.perf_counter() - t0) * 1000.0) / max(1, iters)

    t1 = time.perf_counter()
    for _ in range(iters):
        run_cmd([str(protected)] + bench_args, timeout=30)
    p_ms = ((time.perf_counter() - t1) * 1000.0) / max(1, iters)

    u_size = unprotected.stat().st_size
    p_size = protected.stat().st_size

    if mismatches > 0:
        findings.append({
            "severity": "CRITICAL",
            "category": "diff.semantic_mismatch",
            "message": f"{mismatches}/{len(cases)} differential test case(s) produced divergent outputs or exit codes between unprotected and protected binaries.",
            "remediation": "Inspect the failing test case in `cases_results`; check entry-point symbol resolution, integer width/sign extension, or corrupted key derivation.",
        })

    return {
        "unprotected": str(unprotected),
        "protected": str(protected),
        "total_cases": len(cases),
        "mismatches": mismatches,
        "all_matched": mismatches == 0,
        "size_comparison": {
            "unprotected_bytes": u_size,
            "protected_bytes": p_size,
            "size_ratio": round(p_size / max(1, u_size), 2),
        },
        "process_wall_latency_benchmark": {
            "iterations": iters,
            "args": bench_args,
            "unprotected_avg_ms": round(u_ms, 3),
            "protected_avg_ms": round(p_ms, 3),
            "delta_ms": round(p_ms - u_ms, 3),
            "note": "Includes OS process spawn + cold-start hardware initialization; use in-process harness for hot-path microsecond latency.",
        },
        "cases_results": results,
        "findings": findings,
    }


def audit_claims(audit_data: Dict[str, Any], doc_paths: List[Path]) -> Dict[str, Any]:
    """Cross-check security documentation claims against actual binary audit results."""
    findings: List[Dict[str, Any]] = []
    doc_summaries: List[Dict[str, Any]] = []

    stealth = audit_data.get("stealth", audit_data if "symbols" in audit_data else {})
    disasm = audit_data.get("disasm", audit_data if "metrics" in audit_data else {})
    binding = audit_data.get("binding", audit_data if "hardware_binding" in audit_data else {})

    inferred_mode = binding.get("hardware_binding", {}).get("inferred_mode", "unknown")
    sym_leaks = stealth.get("symbols", {}).get("leaked_symbol_count", 0)
    hint_leaks = stealth.get("strings", {}).get("obfuscator_hint_count", 0)
    tc_leaks = stealth.get("strings", {}).get("toolchain_fingerprint_count", 0)
    folded_cnt = disasm.get("metrics", {}).get("folded_const_xor_count", 0)
    mba_density = disasm.get("metrics", {}).get("mba_window_density", 1.0)

    latency_mentions_by_doc: Dict[str, List[str]] = {}
    flag_mentions_by_doc: Dict[str, List[str]] = {}

    zero_key_re = re.compile(r"\b(zero[- ]key|0 keys|zero decryption keys|no decryption keys exist anywhere)\b", re.IGNORECASE)
    node_lock_scope_re = re.compile(r"(--sep-lock|--host-sep-lock|node-locked|hardware uid|single-machine)", re.IGNORECASE)
    zero_leak_re = re.compile(r"\b(0 leaks|zero leaks|0 hint strings|0 internal symbols)\b", re.IGNORECASE)
    mba_salt_re = re.compile(r"(salt[s]?\s+are\s+never\s+stored|exclusively\s+shattered|mba\s+salt\s+shattering)", re.IGNORECASE)
    latency_re = re.compile(r"~?\d+(?:\.\d+)?(?:\s*[–-]\s*\d+(?:\.\d+)?)?\s*(?:µs|us|μs)")
    flag_re = re.compile(r"--[a-z][a-z0-9-]{2,}")

    for dp in doc_paths:
        if not dp.exists():
            findings.append({
                "severity": "MEDIUM",
                "category": "claims.missing_doc",
                "message": f"Documentation file not found: {dp}",
                "remediation": "Verify path passed to `--docs`.",
            })
            continue
        text = dp.read_text(encoding="utf-8", errors="replace")
        if dp.suffix.lower() in (".html", ".htm"):
            text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
            text = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
        latencies = sorted(set(latency_re.findall(text)))
        flags = sorted(set(flag_re.findall(text)))
        latency_mentions_by_doc[str(dp)] = latencies
        flag_mentions_by_doc[str(dp)] = flags

        has_zero_key = bool(zero_key_re.search(text))
        has_node_scope = bool(node_lock_scope_re.search(text))
        has_zero_leak = bool(zero_leak_re.search(text))
        has_mba_claim = bool(mba_salt_re.search(text))

        doc_summaries.append({
            "doc": str(dp),
            "claims_zero_key": has_zero_key,
            "scopes_zero_key_to_node_lock": has_node_scope,
            "claims_zero_leaks": has_zero_leak,
            "claims_mba_salt_shattering": has_mba_claim,
            "latency_mentions": latencies,
            "cli_flags_mentioned": flags[:20],
        })

        if has_zero_key and inferred_mode == "portable_sep_attested_scp1" and not has_node_scope:
            findings.append({
                "severity": "HIGH",
                "category": "claims.zero_key_overclaim",
                "message": f"{dp.name} claims 'Zero-Key' architecture without scoping it to a hardware node-locked mode, but audited binary uses Portable Mode (`SCP1`) which contains deterministic key derivation inputs.",
                "remediation": "Clarify in docs that Portable Mode uses an offline white-box KDF + runtime anti-emulation gate, while true zero-unsealable-key sealing applies specifically to `--sep-lock` / hardware UID mode.",
            })

        if has_zero_leak and (sym_leaks > 0 or hint_leaks > 0 or tc_leaks > 0):
            findings.append({
                "severity": "HIGH",
                "category": "claims.zero_leak_contradiction",
                "message": f"{dp.name} claims '0 leaks', but binary audit found symbols={sym_leaks}, hint_strings={hint_leaks}, toolchain_fingerprints={tc_leaks}.",
                "remediation": "Scrub the remaining leaked symbols/strings in the binary or qualify the claim in documentation.",
            })

        if has_mba_claim and folded_cnt >= 15 and mba_density < 0.08:
            findings.append({
                "severity": "HIGH",
                "category": "claims.mba_folding_contradiction",
                "message": f"{dp.name} claims MBA salt shattering, but disassembly shows {folded_cnt} folded immediate-XOR patterns with low MBA density ({mba_density:.2%}).",
                "remediation": "Insert register-only inline assembly barriers (`__sc_rb`) to stop LLVM from folding salts into literals.",
            })

    # Cross-doc drift check (e.g., README.md vs docs/index.html)
    if len(doc_summaries) >= 2:
        non_empty_lat = {k: set(v) for k, v in latency_mentions_by_doc.items() if v}
        if len(non_empty_lat) >= 2:
            sets = list(non_empty_lat.values())
            if not set.intersection(*sets):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "claims.cross_doc_latency_drift",
                    "message": f"Latency figures diverge across documentation files with no overlapping metric: {latency_mentions_by_doc}",
                    "remediation": "Synchronize measured benchmark latencies across README, landing pages, and release notes.",
                })

    return {
        "docs_audited": len(doc_summaries),
        "doc_summaries": doc_summaries,
        "findings": findings,
    }


def compute_grade(findings: List[Dict[str, Any]]) -> Tuple[str, Dict[str, int]]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    if counts["CRITICAL"] > 0:
        grade = "F"
    elif counts["HIGH"] >= 3:
        grade = "D"
    elif counts["HIGH"] >= 1:
        grade = "C"
    elif counts["MEDIUM"] >= 2:
        grade = "B"
    else:
        grade = "A"
    return grade, counts


def write_json_report(output_path: Path, payload: Dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="area_audit.py",
        description="AREA (Anti-Reverse Engineering Anything) — Universal Binary Hardening & Obfuscation Auditor",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # stealth
    p_st = sub.add_parser("stealth", help="Audit symbols, plaintext strings, toolchain paths, and Shannon entropy")
    p_st.add_argument("binary", type=Path, help="Target executable or shared library")
    p_st.add_argument("--output", type=Path, required=True, help="Output JSON report path")
    p_st.add_argument("--extra-patterns", type=str, default="", help="Comma-separated custom regex patterns to check")

    # disasm
    p_da = sub.add_parser("disasm", help="Audit disassembly for LLVM constant folding, stack spills, MBA density, and patchable anti-debug")
    p_da.add_argument("binary", type=Path, help="Target executable or shared library")
    p_da.add_argument("--max-insns", type=int, required=True, help="Maximum instructions to disassemble and analyze (e.g., 25000)")
    p_da.add_argument("--output", type=Path, required=True, help="Output JSON report path")

    # binding
    p_bi = sub.add_parser("binding", help="Audit code signing, Hardened Runtime / ELF mitigations, and hardware binding vs portability")
    p_bi.add_argument("binary", type=Path, help="Target executable or shared library")
    p_bi.add_argument("--output", type=Path, required=True, help="Output JSON report path")

    # diff
    p_df = sub.add_parser("diff", help="Run differential equivalence and latency/size overhead checks")
    p_df.add_argument("--unprotected", type=Path, required=True, help="Baseline unprotected binary")
    p_df.add_argument("--protected", type=Path, required=True, help="Protected/obfuscated binary")
    p_df.add_argument("--cases", type=Path, required=True, help="JSON file of test cases: [{\"name\": ..., \"args\": [...]}]")
    p_df.add_argument("--iters", type=int, required=True, help="Timing iterations on first test case (e.g., 10)")
    p_df.add_argument("--output", type=Path, required=True, help="Output JSON report path")

    # claims
    p_cl = sub.add_parser("claims", help="Cross-check security documentation claims against binary audit JSON")
    p_cl.add_argument("--audit", type=Path, required=True, help="Existing JSON report from stealth/disasm/binding/full")
    p_cl.add_argument("--docs", type=str, required=True, help="Comma-separated documentation file paths (README.md, index.html, ...)")
    p_cl.add_argument("--output", type=Path, required=True, help="Output JSON report path")

    # full
    p_fu = sub.add_parser("full", help="Run full 5-pillar AREA perimeter audit")
    p_fu.add_argument("binary", type=Path, help="Target executable or shared library")
    p_fu.add_argument("--max-insns", type=int, required=True, help="Maximum instructions to disassemble and analyze (e.g., 25000)")
    p_fu.add_argument("--output", type=Path, required=True, help="Output JSON report path")
    p_fu.add_argument("--extra-patterns", type=str, default="", help="Comma-separated custom regex patterns")
    p_fu.add_argument("--unprotected", type=Path, default=None, help="Optional baseline unprotected binary for differential check")
    p_fu.add_argument("--cases", type=Path, default=None, help="Optional JSON test cases file (required if --unprotected is set)")
    p_fu.add_argument("--iters", type=int, default=5, help="Timing iterations for differential benchmark (default: 5)")
    p_fu.add_argument("--docs", type=str, default="", help="Optional comma-separated documentation files for Truth-vs-Claims audit")

    args = parser.parse_args()

    try:
        if args.command in ("stealth", "disasm", "binding", "full"):
            if not args.binary.is_file():
                print(f"Error: target binary does not exist or is not a file: {args.binary}", file=sys.stderr)
                return 1

        if args.command == "stealth":
            extra = [p.strip() for p in args.extra_patterns.split(",") if p.strip()]
            res = audit_stealth(args.binary, extra)
            grade, counts = compute_grade(res["findings"])
            payload = {"area_version": VERSION, "command": "stealth", "perimeter_grade": grade, "severity_counts": counts, "stealth": res}
            write_json_report(args.output, payload)
            print(f"[AREA stealth] Grade={grade} | {counts} | Report: {args.output}")
            return 0

        if args.command == "disasm":
            res = audit_disasm(args.binary, args.max_insns)
            grade, counts = compute_grade(res["findings"])
            payload = {"area_version": VERSION, "command": "disasm", "perimeter_grade": grade, "severity_counts": counts, "disasm": res}
            write_json_report(args.output, payload)
            print(f"[AREA disasm] Grade={grade} | Arch={res.get('arch')} | Scanned={res.get('scanned_instructions', 0)} | {counts} | Report: {args.output}")
            return 0

        if args.command == "binding":
            res = audit_binding(args.binary)
            grade, counts = compute_grade(res["findings"])
            payload = {"area_version": VERSION, "command": "binding", "perimeter_grade": grade, "severity_counts": counts, "binding": res}
            write_json_report(args.output, payload)
            print(f"[AREA binding] Grade={grade} | Mode={res['hardware_binding']['inferred_mode']} | {counts} | Report: {args.output}")
            return 0

        if args.command == "diff":
            if not args.unprotected.is_file() or not args.protected.is_file() or not args.cases.is_file():
                print("Error: --unprotected, --protected, and --cases must all be existing files.", file=sys.stderr)
                return 1
            res = audit_diff(args.unprotected, args.protected, args.cases, args.iters)
            grade, counts = compute_grade(res["findings"])
            payload = {"area_version": VERSION, "command": "diff", "perimeter_grade": grade, "severity_counts": counts, "diff": res}
            write_json_report(args.output, payload)
            print(f"[AREA diff] Grade={grade} | Matched={res['all_matched']} ({res['total_cases']} cases) | Report: {args.output}")
            return 0

        if args.command == "claims":
            if not args.audit.is_file():
                print(f"Error: audit JSON not found: {args.audit}", file=sys.stderr)
                return 1
            audit_data = json.loads(args.audit.read_text(encoding="utf-8"))
            doc_paths = [Path(p.strip()) for p in args.docs.split(",") if p.strip()]
            res = audit_claims(audit_data, doc_paths)
            grade, counts = compute_grade(res["findings"])
            payload = {"area_version": VERSION, "command": "claims", "perimeter_grade": grade, "severity_counts": counts, "claims": res}
            write_json_report(args.output, payload)
            print(f"[AREA claims] Grade={grade} | Docs={res['docs_audited']} | {counts} | Report: {args.output}")
            return 0

        if args.command == "full":
            extra = [p.strip() for p in args.extra_patterns.split(",") if p.strip()]
            st = audit_stealth(args.binary, extra)
            da = audit_disasm(args.binary, args.max_insns)
            bi = audit_binding(args.binary)

            combined: Dict[str, Any] = {
                "area_version": VERSION,
                "command": "full",
                "target": str(args.binary),
                "stealth": st,
                "disasm": da,
                "binding": bi,
            }
            all_findings = list(st["findings"]) + list(da["findings"]) + list(bi["findings"])

            if args.unprotected and args.cases:
                df = audit_diff(args.unprotected, args.binary, args.cases, args.iters)
                combined["diff"] = df
                all_findings.extend(df["findings"])
            elif args.unprotected or args.cases:
                print("Error: --unprotected and --cases must be provided together.", file=sys.stderr)
                return 1

            if args.docs:
                doc_paths = [Path(p.strip()) for p in args.docs.split(",") if p.strip()]
                cl = audit_claims(combined, doc_paths)
                combined["claims"] = cl
                all_findings.extend(cl["findings"])

            grade, counts = compute_grade(all_findings)
            combined["perimeter_grade"] = grade
            combined["severity_counts"] = counts
            combined["all_findings"] = all_findings
            write_json_report(args.output, combined)
            print(
                f"[AREA full] Perimeter Grade={grade} | "
                f"CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} INFO={counts['INFO']} | "
                f"Report written to: {args.output}"
            )
            return 0

    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
