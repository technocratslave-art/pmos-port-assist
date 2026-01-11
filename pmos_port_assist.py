#!/usr/bin/env python3
"""
pmos-port-assist (v1.3) — PostmarketOS boot-log forensics assistant + compare/diff.

Safety features:
  - Luhn-validated IMEI redaction
  - Aggressive redaction (--redact-aggressive)
  - Tail suppression (--no-tail)
  - --safe alias (= --redact-aggressive --no-tail)
  - Leak-check before AI (blocks unless --force)

Compare engine:
  - --compare OLD_LOG          : produce .diff.md + .comparison.json
  - Signal delta               : counts up/down
  - New vs resolved errors     : semantic signatures (timestamps/addrs/PIDs normalized away)
  - Boot progress metric       : last dmesg timestamp delta
  - Regression detection       : new panic/init_fail
  - Timeline visualization     : bucketed error counts over boot time

Notes:
  - Compare is performed AFTER redaction.
"""

from __future__ import annotations

import os
import re
import sys
import json
import argparse
import subprocess
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set, Tuple

# ---------------------------
# 1) Offline knowledge base
# ---------------------------

ERRNO_MAP = {
    "-1": "EPERM (Operation not permitted)",
    "-2": "ENOENT (No such file or directory)",
    "-5": "EIO (I/O error)",
    "-11": "EAGAIN (Try again)",
    "-12": "ENOMEM (Out of memory)",
    "-13": "EACCES (Permission denied)",
    "-16": "EBUSY (Device or resource busy)",
    "-19": "ENODEV (No such device - check DT compatible string)",
    "-22": "EINVAL (Invalid argument - check DT properties)",
    "-110": "ETIMEDOUT (Connection timed out)",
    "-517": "EPROBE_DEFER (Waiting for dependency; OK unless persistent)",
}

KNOWN_ISSUES = [
    {"pattern": r"init:.*terminating.*signal 15",
     "advice": "Userspace requested shutdown. During boot, init script may have exited or hit an error path."},
    {"pattern": r"adc_tm:.*probe failed",
     "advice": "Common on Qualcomm. Often harmless if battery/thermal still works."},
    {"pattern": r"dma_alloc_coherent failed",
     "advice": "CMA exhaustion. Consider increasing CMA (kernel cmdline cma=, or config CMA_SIZE_MBYTES)."},
    {"pattern": r"waiting for device /dev/.*partition",
     "advice": "Rootfs partition not found. Check cmdline root= / UUID vs actual partitions."},
    {"pattern": r"VFS: Cannot open root device",
     "advice": "Root device mismatch. Check root=, initramfs modules, storage driver built-in vs module."},
]

# ---------------------------
# 2) Patterns and redaction
# ---------------------------

PANIC_PATTERNS = [
    r"\bKernel panic\b", r"\bUnable to handle kernel\b", r"\bOops:\b",
    r"\bBUG:\b", r"\bpanic\b.*\bnot syncing\b",
]
INIT_FAIL_PATTERNS = [
    r"\binit\b.*\bnot found\b", r"\bNo init found\b",
    r"\bVFS:\b.*\bUnable to mount root fs\b", r"\bFailed to execute\b.*\b/bin/init\b",
    r"\bALERT!\b.*\bdoes not exist\b",
]
FIRMWARE_PATTERNS = [
    r"\bfirmware\b.*\bfailed\b", r"\bfirmware\b.*\bnot found\b",
    r"\bdirect firmware load\b.*\bfailed\b",
]
DT_PATTERNS = [
    r"\bOF:\b", r"\bof_\w+\b", r"\bdevice tree\b",
    r"\bMissing\b.*\bproperty\b", r"\bfailed to parse\b.*\bdt\b",
]
PROBE_FAIL_PATTERNS = [
    r"\bprobe\b.*\bfailed\b", r"\bprobe\b.*\berror\b",
    r"\bfailed\b.*\bwith error\b\s*-?\d+",
]

ERROR_LINE_HINTS = [r"\berror\b", r"\bfailed\b", r"\btimeout\b", r"\bnot responding\b"]
IGNORE_HINTS = [r"\bdeprecated\b", r"\btaint\b", r"\bWARNING:\b"]

# Stricter IPv4 per octet 0-255 (reduces collateral redaction in aggressive mode)
IPV4_STRICT = r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def luhn_ok(number: str) -> bool:
    total = 0
    alt = False
    for ch in reversed(number):
        if not ch.isdigit():
            return False
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return (total % 10) == 0

def redact_text(text: str, aggressive: bool = False) -> str:
    """
    Standard: MACs, serials, UUIDs, androidboot.* ids, Luhn-valid IMEIs.
    Aggressive: IPv4, email-like, USB serial patterns, long hashes, IMSI, ICCID (Luhn).
    """
    # Standard
    text = re.sub(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "[REDACTED_MAC]", text)
    text = re.sub(r"(androidboot\.serialno=)(\S+)", r"\1[REDACTED_SERIAL]", text, flags=re.IGNORECASE)
    text = re.sub(r"(androidboot\.imei=)(\S+)", r"\1[REDACTED_IMEI]", text, flags=re.IGNORECASE)
    text = re.sub(r"(androidboot\.deviceid=)(\S+)", r"\1[REDACTED_DEVICEID]", text, flags=re.IGNORECASE)
    text = re.sub(r"(Serial Number:)\s*(\S+)", r"\1 [REDACTED_SERIAL]", text, flags=re.IGNORECASE)
    text = re.sub(
        r"\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b",
        "[REDACTED_UUID]",
        text
    )

    # Luhn IMEI (15 digits)
    def imei_repl(m: re.Match) -> str:
        s = m.group(0)
        return "[REDACTED_IMEI]" if luhn_ok(s) else s
    text = re.sub(r"\b\d{15}\b", imei_repl, text)

    if aggressive:
        text = re.sub(IPV4_STRICT, "[REDACTED_IP]", text)
        text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]", text)
        text = re.sub(r"(iSerial\s+\d+\s+)(\S+)", r"\1[REDACTED_USB_SERIAL]", text)
        text = re.sub(r"(\bSerialNumber:\s*)(\S+)", r"\1[REDACTED_USB_SERIAL]", text, flags=re.IGNORECASE)
        text = re.sub(r"(\bserial(?:no)?[:=]\s*)(\S+)", r"\1[REDACTED_SERIAL]", text, flags=re.IGNORECASE)
        text = re.sub(r"\b[0-9a-fA-F]{32,}\b", "[REDACTED_HASH]", text)
        text = re.sub(r"(\bIMSI[:=\s]*)(\d{15})\b", r"\1[REDACTED_IMSI]", text, flags=re.IGNORECASE)

        def iccid_repl(m: re.Match) -> str:
            s = m.group(0)
            return "[REDACTED_ICCID]" if luhn_ok(s) else s
        text = re.sub(r"\b\d{19,20}\b", iccid_repl, text)

    return text

def leak_check(text: str) -> List[str]:
    """
    Conservative post-redaction scan. If this triggers, review before AI.
    """
    warnings = []
    if re.search(r"\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", text):
        warnings.append("Possible MAC still present")
    if re.search(r"\bandroidboot\.\w+=\S+", text, re.IGNORECASE):
        warnings.append("androidboot.* param still present (may include unique identifiers)")
    if re.search(r"\b\d{15}\b", text):
        warnings.append("15-digit sequence still present (could be IMEI/IMSI)")
    if re.search(r"\b\d{19,20}\b", text):
        warnings.append("19-20 digit sequence still present (could be ICCID)")
    return warnings

def should_ignore(line: str) -> bool:
    return any(re.search(p, line, re.IGNORECASE) for p in IGNORE_HINTS)

def decode_errno(line: str) -> str:
    m = re.search(r"(?:error\s+|err=|ret=|errno=|failed with error\s+)(-\d+)\b", line, re.IGNORECASE)
    if not m:
        return ""
    return ERRNO_MAP.get(m.group(1), "")

def check_known_issues(text: str) -> List[str]:
    hits = []
    for item in KNOWN_ISSUES:
        if re.search(item["pattern"], text, re.IGNORECASE):
            hits.append(f"MATCH: '{item['pattern']}' -> {item['advice']}")
    return hits

# ---------------------------
# 3) DTS lint
# ---------------------------

def lint_dts_file(dts_path: Path, include_dirs: Optional[List[str]] = None) -> str:
    if not dts_path.exists():
        return f"Error: DTS file {dts_path} not found."
    cmd = ["dtc", "-I", "dts", "-O", "dtb", "-o", os.devnull]
    if include_dirs:
        for inc in include_dirs:
            cmd.extend(["-i", inc])
    cmd.append(str(dts_path))
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            return f"✅ DTC Validated: {dts_path}"
        return f"❌ DTC Errors:\n{(res.stderr or res.stdout).strip()}"
    except FileNotFoundError:
        return "⚠️  dtc not installed."

# ---------------------------
# 4) Signal extraction
# ---------------------------

@dataclass
class Signal:
    kind: str
    line_no: int
    line: str
    errno_hint: str = ""

@dataclass
class SignalsBundle:
    file: str
    total_lines: int
    counts: Dict[str, int]
    signals: Dict[str, List[Signal]]
    tail: List[str]
    offline_advice: List[str]

def extract_signals(lines: List[str], tail_n: int, no_tail: bool) -> SignalsBundle:
    signals: Dict[str, List[Signal]] = {k: [] for k in
        ["panic_oops", "init_fail", "probe_fail", "firmware_missing", "device_tree", "other_errors"]
    }
    full_text = "\n".join(lines)
    advice = check_known_issues(full_text)

    for idx, line in enumerate(lines, start=1):
        if not line.strip() or should_ignore(line):
            continue

        kind = None
        if any(re.search(p, line, re.IGNORECASE) for p in PANIC_PATTERNS):
            kind = "panic_oops"
        elif any(re.search(p, line, re.IGNORECASE) for p in INIT_FAIL_PATTERNS):
            kind = "init_fail"
        elif any(re.search(p, line, re.IGNORECASE) for p in FIRMWARE_PATTERNS):
            kind = "firmware_missing"
        elif any(re.search(p, line, re.IGNORECASE) for p in DT_PATTERNS):
            kind = "device_tree"
        elif any(re.search(p, line, re.IGNORECASE) for p in PROBE_FAIL_PATTERNS):
            kind = "probe_fail"

        if kind:
            signals[kind].append(Signal(kind, idx, line, decode_errno(line)))
            continue

        low = line.lower()
        if any(re.search(p, low) for p in ERROR_LINE_HINTS) and "warning" not in low:
            signals["other_errors"].append(Signal("other_errors", idx, line, decode_errno(line)))

    tail = [] if no_tail else (lines[-tail_n:] if len(lines) > tail_n else lines[:])

    return SignalsBundle(
        file="",
        total_lines=len(lines),
        counts={k: len(v) for k, v in signals.items()},
        signals=signals,
        tail=tail,
        offline_advice=advice
    )

def cluster_context(lines: List[str], hit_line_nos: List[int], radius: int = 12, max_blocks: int = 8):
    if not hit_line_nos:
        return []
    hit_line_nos = sorted(set(hit_line_nos))[:max_blocks]
    blocks = []
    last_end = 0
    for ln in hit_line_nos:
        start = max(1, ln - radius)
        end = min(len(lines), ln + radius)
        if blocks and start <= last_end:
            prev_start, prev_end, _ = blocks[-1]
            new_end = max(prev_end, end)
            blocks[-1] = (prev_start, new_end, lines[prev_start-1:new_end])
            last_end = new_end
        else:
            blocks.append((start, end, lines[start-1:end]))
            last_end = end
    return blocks

# ---------------------------
# 5) Output (analysis)
# ---------------------------

def format_signals_md(bundle: SignalsBundle, blocks: List, dts_report: str = "") -> str:
    md = [f"# pmOS Port Assist v1.3 Report"]
    md.append(f"File: `{bundle.file}` | Lines: {bundle.total_lines} | Counts: `{bundle.counts}`\n")

    if dts_report:
        md.append(f"## DTS Lint\n```text\n{dts_report}\n```\n")

    if bundle.offline_advice:
        md.append("## 🧠 Offline Knowledge Matches")
        for adv in bundle.offline_advice:
            md.append(f"- {adv}")
        md.append("")

    for k, v in bundle.signals.items():
        if not v:
            continue
        md.append(f"## {k} ({len(v)})")
        for s in v[:15]:
            extra = f" **[{s.errno_hint}]**" if s.errno_hint else ""
            md.append(f"- L{s.line_no}: `{s.line}`{extra}")
        if len(v) > 15:
            md.append(f"- ... ({len(v)-15} more)")
        md.append("")

    if blocks:
        md.append("## Critical Context Blocks")
        for s, e, bl in blocks:
            md.append(f"**Lines {s}-{e}**\n```text\n" + "\n".join(bl) + "\n```")

    if bundle.tail:
        md.append("## Tail (Redacted)")
        md.append("```text\n" + "\n".join(bundle.tail) + "\n```")
    else:
        md.append("## Tail\n*(Suppressed via --no-tail)*")

    return "\n".join(md)

# ---------------------------
# 6) AI (optional; not required for porters)
# ---------------------------

def build_ai_prompt(bundle: SignalsBundle, blocks: List, mode: str) -> str:
    def top_lines(kind: str, n: int) -> str:
        items = bundle.signals.get(kind, [])
        out = []
        for s in items[:n]:
            hint = f" [{s.errno_hint}]" if s.errno_hint else ""
            out.append(f"L{s.line_no}: {s.line}{hint}")
        return "\n".join(out) if out else "(none)"

    context_txt = []
    for s, e, bl in blocks[:6]:
        context_txt.append(f"--- CONTEXT {s}-{e} ---\n" + "\n".join(bl))

    base = f"""Expert PostmarketOS porter analysis requested.

Counts: {bundle.counts}

Top Signals:
[panic_oops]
{top_lines("panic_oops", 10)}

[init_fail]
{top_lines("init_fail", 10)}

[probe_fail]
{top_lines("probe_fail", 15)}

[firmware_missing]
{top_lines("firmware_missing", 15)}

[device_tree]
{top_lines("device_tree", 15)}

[other_errors]
{top_lines("other_errors", 15)}

Context (Redacted):
{("\n\n".join(context_txt) if context_txt else "(none)")}

Rules:
1) Don't invent hardware.
2) Focus on DTS/Kconfig/firmware path fixes grounded in evidence.
3) Treat -517 (EPROBE_DEFER) as non-fatal unless clearly persistent and blocking probes.
"""

    if mode == "commands":
        return base + "\nOutput ONLY diagnostic commands (dmesg filters, dtc checks, lsmod/modinfo, firmware search)."
    if mode == "patch":
        return base + "\nOutput ONLY a unified diff patch OR the exact text: INSUFFICIENT EVIDENCE"
    return base + "\nReturn markdown: ## Issue, ## Root Cause, ## Evidence (quote 3-8 lines), ## Fix, ## Verification, ## Confidence."

def call_ai(prompt: str, provider: str, model: str) -> str:
    provider = provider.lower()
    try:
        if provider == "openai":
            from openai import OpenAI
            key = os.getenv("OPENAI_API_KEY")
            if not key:
                return "AI Error: OPENAI_API_KEY not set."
            client = OpenAI(api_key=key)
            resp = client.chat.completions.create(
                model=model,
                temperature=0.2,
                max_tokens=1800,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.choices[0].message.content.strip()

        if provider == "anthropic":
            from anthropic import Anthropic
            key = os.getenv("ANTHROPIC_API_KEY")
            if not key:
                return "AI Error: ANTHROPIC_API_KEY not set."
            client = Anthropic(api_key=key)
            resp = client.messages.create(
                model=model,
                temperature=0.2,
                max_tokens=1800,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text.strip()

    except Exception as e:
        return f"AI Error: {e}"

    return "Unknown Provider"

# ---------------------------
# 7) Compare/Diff Engine
# ---------------------------

@dataclass
class LogComparison:
    old_file: str
    new_file: str

    old_total_lines: int
    new_total_lines: int

    old_last_timestamp_sec: Optional[float]
    new_last_timestamp_sec: Optional[float]
    timestamp_delta_sec: Optional[float]

    count_deltas: Dict[str, int]

    resolved_errors: Dict[str, List[str]]
    new_errors: Dict[str, List[str]]
    persistent_errors: Dict[str, List[str]]

    regressions: List[str]

    timeline: Dict[str, List[Tuple[float, int, int]]]

def extract_boot_timestamp(line: str) -> Optional[float]:
    line = ANSI_RE.sub("", line)
    m = re.match(r"^(?:<\d+>)?\s*\[\s*(\d+(?:\.\d+)?)\s*\]", line)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None

def get_last_timestamp(lines: List[str]) -> Optional[float]:
    window = lines[-800:] if len(lines) > 800 else lines
    ts_max = None
    for line in window:
        ts = extract_boot_timestamp(line)
        if ts is not None:
            ts_max = ts if ts_max is None else max(ts_max, ts)
    return ts_max

def normalize_error_line(line: str) -> str:
    s = ANSI_RE.sub("", line)
    s = re.sub(r"^<\d+>\s*", "", s)
    s = re.sub(r"^\s*\[\s*\d+(?:\.\d+)?\s*\]\s*", "", s)
    s = re.sub(r"\bCPU\d+\b", "CPUx", s)
    s = re.sub(r"\bprocessor\s+\d+\b", "processor x", s, flags=re.IGNORECASE)
    s = re.sub(r"\[\d{2,6}\]", "[PID]", s)
    s = re.sub(r"\[0x[0-9a-fA-F]+\]", "[ADDR]", s)
    s = re.sub(r"\b0x[0-9a-fA-F]{8,}\b", "0xADDR", s)
    s = re.sub(r"\b[0-9a-fA-F]{8,}\b", "HEX", s)
    s = " ".join(s.split())
    return s.strip()

def extract_error_signatures(bundle: SignalsBundle) -> Dict[str, Set[str]]:
    sigs: Dict[str, Set[str]] = {}
    for kind, sig_list in bundle.signals.items():
        st: Set[str] = set()
        for sig in sig_list:
            n = normalize_error_line(sig.line)
            if n:
                st.add(n)
        sigs[kind] = st
    return sigs

def timeline_counts(lines: List[str], bundle: SignalsBundle, bucket_sec: float) -> Dict[str, Dict[int, int]]:
    line_ts: Dict[int, Optional[float]] = {}
    for idx, line in enumerate(lines, start=1):
        line_ts[idx] = extract_boot_timestamp(line)

    out: Dict[str, Dict[int, int]] = {}
    for kind, sig_list in bundle.signals.items():
        buckets: Dict[int, int] = {}
        for s in sig_list:
            ts = line_ts.get(s.line_no)
            if ts is None:
                continue
            b = int(ts // bucket_sec)
            buckets[b] = buckets.get(b, 0) + 1
        out[kind] = buckets
    return out

def compare_logs(old_bundle: SignalsBundle, new_bundle: SignalsBundle,
                 old_lines: List[str], new_lines: List[str],
                 bucket_sec: float = 5.0) -> LogComparison:
    old_sigs = extract_error_signatures(old_bundle)
    new_sigs = extract_error_signatures(new_bundle)

    count_deltas: Dict[str, int] = {}
    for kind in old_bundle.counts.keys():
        delta = new_bundle.counts.get(kind, 0) - old_bundle.counts.get(kind, 0)
        if delta != 0:
            count_deltas[kind] = delta

    resolved: Dict[str, List[str]] = {}
    new_errs: Dict[str, List[str]] = {}
    persistent: Dict[str, List[str]] = {}

    for kind in old_sigs.keys():
        a = old_sigs.get(kind, set())
        b = new_sigs.get(kind, set())
        resolved[kind] = sorted(a - b)
        new_errs[kind] = sorted(b - a)
        persistent[kind] = sorted(a & b)

    regressions: List[str] = []
    for kind in ["panic_oops", "init_fail"]:
        for err in new_errs.get(kind, []):
            regressions.append(f"[{kind}] {err}")

    old_ts = get_last_timestamp(old_lines)
    new_ts = get_last_timestamp(new_lines)
    ts_delta = (new_ts - old_ts) if (old_ts is not None and new_ts is not None) else None

    old_tl = timeline_counts(old_lines, old_bundle, bucket_sec=bucket_sec)
    new_tl = timeline_counts(new_lines, new_bundle, bucket_sec=bucket_sec)

    kinds_for_tl = ["panic_oops", "init_fail", "probe_fail", "firmware_missing", "device_tree", "other_errors"]
    timeline: Dict[str, List[Tuple[float, int, int]]] = {}
    for kind in kinds_for_tl:
        old_b = old_tl.get(kind, {})
        new_b = new_tl.get(kind, {})
        all_idx = sorted(set(old_b.keys()) | set(new_b.keys()))
        rows: List[Tuple[float, int, int]] = []
        for i in all_idx:
            rows.append((i * bucket_sec, old_b.get(i, 0), new_b.get(i, 0)))
        timeline[kind] = rows

    return LogComparison(
        old_file=old_bundle.file,
        new_file=new_bundle.file,
        old_total_lines=old_bundle.total_lines,
        new_total_lines=new_bundle.total_lines,
        old_last_timestamp_sec=old_ts,
        new_last_timestamp_sec=new_ts,
        timestamp_delta_sec=ts_delta,
        count_deltas=count_deltas,
        resolved_errors=resolved,
        new_errors=new_errs,
        persistent_errors=persistent,
        regressions=regressions,
        timeline=timeline,
    )

def progress_bar(old_ts: Optional[float], new_ts: Optional[float], width: int = 40) -> str:
    if old_ts is None or new_ts is None:
        return "Progress: (no timestamps)"
    max_val = max(old_ts, new_ts, 1.0)
    old_w = int((old_ts / max_val) * width)
    new_w = int((new_ts / max_val) * width)

    bar = []
    for i in range(width):
        if i < old_w and i < new_w:
            bar.append("█")
        elif i < new_w:
            bar.append("░")
        elif i < old_w:
            bar.append("▒")
        else:
            bar.append(" ")
    return "Progress:|" + "".join(bar) + "|"

def format_comparison_md(comp: LogComparison, limit_each: int = 12) -> str:
    md: List[str] = ["# 🔄 pmOS Log Comparison Report (v1.3)\n"]
    md.append(f"**Old Log:** `{comp.old_file}` ({comp.old_total_lines} lines)")
    md.append(f"**New Log:** `{comp.new_file}` ({comp.new_total_lines} lines)\n")

    md.append("## 📊 Boot Progress")
    if comp.old_last_timestamp_sec is not None and comp.new_last_timestamp_sec is not None:
        md.append(f"- **Old:** `{comp.old_last_timestamp_sec:.2f}s`")
        md.append(f"- **New:** `{comp.new_last_timestamp_sec:.2f}s`")
        if comp.timestamp_delta_sec is not None:
            emoji = "✅" if comp.timestamp_delta_sec > 0 else ("⚠️" if comp.timestamp_delta_sec < 0 else "➡️")
            md.append(f"- **Delta:** {emoji} `{comp.timestamp_delta_sec:+.2f}s`")
        md.append(f"- **Visual:** `{progress_bar(comp.old_last_timestamp_sec, comp.new_last_timestamp_sec)}`\n")
    else:
        md.append("- *(Could not extract timestamps from one or both logs)*\n")

    md.append("## 📈 Signal Count Changes")
    if comp.count_deltas:
        for kind, delta in sorted(comp.count_deltas.items(), key=lambda kv: kv[1]):
            emoji = "✅" if delta < 0 else ("❌" if delta > 0 else "➡️")
            md.append(f"- {emoji} **{kind}:** `{delta:+d}`")
    else:
        md.append("- *(No changes in error counts)*")
    md.append("")

    if comp.regressions:
        md.append("## 🚨 Regressions Detected")
        md.append("New critical errors not present before:")
        for r in comp.regressions[:25]:
            md.append(f"- ❌ `{r}`")
        if len(comp.regressions) > 25:
            md.append(f"- *...and {len(comp.regressions) - 25} more*")
        md.append("")

    md.append("## 🔍 Detailed Error Changes (Semantic)")
    order = ["panic_oops", "init_fail", "probe_fail", "firmware_missing", "device_tree", "other_errors"]
    for kind in order:
        resolved = comp.resolved_errors.get(kind, [])
        new = comp.new_errors.get(kind, [])
        if not resolved and not new:
            continue

        md.append(f"### {kind}")
        if resolved:
            md.append(f"**✅ Resolved ({len(resolved)}):**")
            for e in resolved[:limit_each]:
                md.append(f"- ~~{e}~~")
            if len(resolved) > limit_each:
                md.append(f"- *...and {len(resolved) - limit_each} more*")
        if new:
            md.append(f"**❌ New ({len(new)}):**")
            for e in new[:limit_each]:
                md.append(f"- {e}")
            if len(new) > limit_each:
                md.append(f"- *...and {len(new) - limit_each} more*")
        md.append("")

    md.append("## 🕒 Timeline (errors per bucket)")
    md.append("Counts are per time bucket (defaults to 5s).")
    for kind in order:
        rows = comp.timeline.get(kind, [])
        if not rows or not any((o or n) for _, o, n in rows):
            continue
        md.append(f"### {kind}")
        md.append("| t_start(s) | old | new |")
        md.append("|---:|---:|---:|")
        shown = 0
        for t0, o, n in rows[:80]:
            if o == 0 and n == 0:
                continue
            md.append(f"| {t0:>8.1f} | {o} | {n} |")
            shown += 1
            if shown >= 60:
                break
        if len(rows) > 80:
            md.append("| … | … | … |")
        md.append("")

    total_resolved = sum(len(v) for v in comp.resolved_errors.values())
    total_new = sum(len(v) for v in comp.new_errors.values())
    md.append("## 📝 Summary")
    if total_resolved > total_new:
        md.append(f"✅ **Net improvement:** {total_resolved - total_new} fewer unique semantic errors")
    elif total_new > total_resolved:
        md.append(f"⚠️ **Net regression:** {total_new - total_resolved} more unique semantic errors")
    else:
        md.append("➡️ **Neutral:** same number of unique semantic errors (composition changed)")
    return "\n".join(md)

# ---------------------------
# 8) Main
# ---------------------------

def read_input(path_str: str) -> str:
    if path_str == "-":
        return sys.stdin.read()
    p = Path(path_str)
    if not p.exists():
        raise FileNotFoundError(path_str)
    return p.read_text(errors="ignore")

def ensure_outdir(outdir: Optional[str]) -> Path:
    if not outdir:
        return Path(".")
    d = Path(outdir)
    d.mkdir(parents=True, exist_ok=True)
    return d

def main():
    ap = argparse.ArgumentParser(description="pmOS Port Assist v1.3 (Compare/Diff Engine)")
    ap.add_argument("logfile", help="Path to log file, or '-' for stdin")

    ap.add_argument("--outdir", help="Directory to write reports into (default: current dir)")

    ap.add_argument("--tail", type=int, default=200)
    ap.add_argument("--no-tail", action="store_true", help="Exclude tail from output entirely")
    ap.add_argument("--redact-aggressive", action="store_true", help="Scrub IPs, hashes, USB serials, IMSI/ICCID")
    ap.add_argument("--safe", action="store_true", help="Alias for --redact-aggressive --no-tail")
    ap.add_argument("--force", action="store_true", help="Force AI send even if leak-check warns")

    ap.add_argument("--radius", type=int, default=12)
    ap.add_argument("--max-blocks", type=int, default=8)

    ap.add_argument("--dts-file", help="Path to .dts to lint")
    ap.add_argument("--dtc-include", action="append", default=[])

    ap.add_argument("--ai", action="store_true")
    ap.add_argument("--provider", default=os.getenv("AI_PROVIDER", "openai"))
    ap.add_argument("--model", default=os.getenv("AI_MODEL", "gpt-4.1-mini"))
    ap.add_argument("--mode", choices=["analysis", "commands", "patch"], default="analysis")

    ap.add_argument("--compare", metavar="OLD_LOG",
                    help="Compare against an older log to show progress/regressions")
    ap.add_argument("--timeline-bucket", type=float, default=5.0,
                    help="Seconds per timeline bucket in diff report (default: 5.0)")

    args = ap.parse_args()

    if args.safe:
        args.redact_aggressive = True
        args.no_tail = True

    outdir = ensure_outdir(args.outdir)

    # ---- Process NEW log ----
    raw = read_input(args.logfile)
    clean = redact_text(raw, aggressive=args.redact_aggressive)
    lines = clean.splitlines()

    bundle = extract_signals(lines, args.tail, args.no_tail)
    bundle.file = args.logfile

    priority_hits: List[int] = []
    for k in ["panic_oops", "init_fail", "probe_fail", "firmware_missing", "device_tree"]:
        priority_hits.extend([s.line_no for s in bundle.signals[k]])
    blocks = cluster_context(lines, priority_hits, radius=args.radius, max_blocks=args.max_blocks)

    dts_report = lint_dts_file(Path(args.dts_file), args.dtc_include) if args.dts_file else ""

    # Base name for output files
    base_name = "stdin.log" if args.logfile == "-" else Path(args.logfile).name

    md_out = format_signals_md(bundle, blocks, dts_report)
    md_path = outdir / (base_name + ".analysis.md")
    md_path.write_text(md_out)
    print(f"Report: {md_path}")

    json_path = outdir / (base_name + ".signals.json")
    json_path.write_text(json.dumps({
        "file": bundle.file,
        "total_lines": bundle.total_lines,
        "counts": bundle.counts,
        "offline_advice": bundle.offline_advice,
        "signals": {k: [asdict(x) for x in v] for k, v in bundle.signals.items()},
    }, indent=2))
    print(f"Signals: {json_path}")

    diff_md = None
    if args.compare:
        old_raw = read_input(args.compare)
        old_clean = redact_text(old_raw, aggressive=args.redact_aggressive)
        old_lines = old_clean.splitlines()

        old_bundle = extract_signals(old_lines, args.tail, args.no_tail)
        old_bundle.file = args.compare

        comp_obj = compare_logs(old_bundle, bundle, old_lines, lines, bucket_sec=args.timeline_bucket)
        diff_md = format_comparison_md(comp_obj)

        diff_path = outdir / (Path(base_name).stem + ".diff.md")
        diff_path.write_text(diff_md)

        comp_json_path = outdir / (Path(base_name).stem + ".comparison.json")
        comp_json_path.write_text(json.dumps(asdict(comp_obj), indent=2))

        print(f"Comparison Report: {diff_path}")
        print(f"Comparison JSON: {comp_json_path}")
        if comp_obj.old_last_timestamp_sec is not None and comp_obj.new_last_timestamp_sec is not None:
            print(progress_bar(comp_obj.old_last_timestamp_sec, comp_obj.new_last_timestamp_sec))

    if args.ai:
        warnings = leak_check(clean)
        if warnings and not args.force:
            print("SECURITY WARNING: leak-check flagged possible identifiers:")
            for w in warnings:
                print(f" - {w}")
            print("Refusing to send to AI. Re-run with --force if you've reviewed output.")
            sys.exit(2)

        base_prompt = build_ai_prompt(bundle, blocks, args.mode)
        if diff_md:
            base_prompt = (
                "## Comparison Context (Redacted)\n\n"
                + diff_md
                + "\n\n---\n\n"
                + base_prompt
                + "\n\nTask: Use the comparison to prioritize next fixes. Be explicit about regressions vs improvements."
            )

        ai_resp = call_ai(base_prompt, args.provider, args.model)
        ai_out = outdir / (base_name + f".{args.mode}.md")
        ai_out.write_text(ai_resp)
        print(f"AI Output: {ai_out}")

if __name__ == "__main__":
    main()
