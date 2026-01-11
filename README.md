# pmos-port-assist
​A hardened dmesg/UART analyzer that redacts sensitive IDs (IMEI/MAC), decodes errnos, and performs semantic diffs between boot attempts to track porting progress.
# pmos-port-assist (v1.3) — pmOS boot-log forensics + compare/diff

A small offline-first helper to triage postmarketOS boot logs and track iterative progress during device porting.

## Goals
- Extract high-signal boot failures (panic/oops, init failures, DT, firmware, probe failures).
- Provide **safe-by-default** redaction controls for sharing logs publicly.
- Compare two logs from successive boots to detect:
  - which errors were fixed
  - which new errors appeared
  - whether boot progressed further (dmesg timestamp delta)
  - regressions (new panic/init_fail)

## Outputs
Given `new.log`:
- `new.log.analysis.md` — human report
- `new.log.signals.json` — machine-readable signals
If `--compare old.log`:
- `new.diff.md` — comparison report
- `new.comparison.json` — machine-readable comparison

## Safety / Redaction
This tool supports:
- Luhn-validated IMEI redaction
- MAC / UUID redaction
- optional aggressive mode: IPv4, emails, IMSI, ICCID, long hashes, USB serials
- `--no-tail` to avoid dumping full tails
- `--safe` = `--redact-aggressive --no-tail`

It also runs a leak-check. If leak-check triggers, AI export (optional) is blocked unless `--force`.

> Note: Compare/diff is performed AFTER redaction.

## Requirements
- Python 3.9+ (no external deps)
- Optional: `dtc` if you use `--dts-file`

## Usage

### Basic analysis
```bash
python3 pmos_port_assist.py boot.log
