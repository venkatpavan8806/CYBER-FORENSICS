# RansomTrace

A local, Python-only tool that ingests Windows forensic artifacts (a disk
image, or a pre-extracted artifact set) and correlates evidence of
ransomware file-encryption, shadow-copy/backup deletion, and suspicious
registry modifications into a human-validated, MITRE ATT&CK-tagged report.

Built as a BTech Cyber Forensics capstone project ("Ransomware Artifact
Analyzer — Trace encryption activity, shadow copy deletion, and registry
modifications from a disk image").

## What this is (and isn't)

RansomTrace is a **post-incident, offline, single-host analysis tool**. It
does not use machine learning, does not touch the network, does not run as a
live agent, and does not include or execute any real ransomware. See
[Scope & limitations](#scope--limitations) below.

## Setup

Requires Python 3.11+ and, for full functionality (registry hive test-fixture
generation, Mode A disk-image test-fixture generation), **Windows** — see
[Platform notes](#platform-notes).

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

This installs the `ransomtrace` command.

## Usage

```bash
# Generate the benign synthetic test fixture (Mode B folder + optional Mode A image)
ransomtrace simulate ./demo_incident --disk-image

# Analyze a pre-extracted artifact folder
ransomtrace analyze ./demo_incident --mode b -o report.html

# Analyze a raw disk image
ransomtrace analyze ./demo_incident/synthetic_incident.raw --mode a -o report.html

# Non-interactive (skips the CLI validation step - for CI/testing)
ransomtrace analyze ./demo_incident --mode b --no-review -o report.html
```

`analyze` walks you through each finding in the terminal
(`[c]onfirm / [f]alse positive / [u]ncertain / [s]kip`) before writing the
HTML report — every finding requires a human decision; nothing is presented
as fact just because a rule fired.

### Web review UI (alternative to the CLI flow)

```bash
streamlit run ransomtrace/validation/web_review.py
```

Same guarantee as the CLI flow (every finding needs an explicit analyst
decision), but as a page in your browser: point it at an artifact folder or
disk image, click Analyze, expand each finding to review its evidence and
set Confirmed/False Positive/Uncertain, then generate and download the
report. See [`validation/web_review.py`](ransomtrace/validation/web_review.py).

## Architecture

```
ransomtrace/
  ingest/
    disk_image.py        Mode A: pytsk3 walk of a raw disk image
    artifact_folder.py   Mode B: read a pre-extracted artifact folder
  extractors/
    filesystem.py         unusual-extension detector, ransom-note filename matcher
    registry.py            Run/RunOnce, service ImagePath, BAM execution evidence
    eventlog_vss.py         VSS-deletion command evidence, Event ID 1102
  correlation/
    rules.py               5 documented rules (see below)
    engine.py               runs all rules, returns sorted Findings
    mitre_map.py             ATT&CK technique ID -> name
  validation/
    cli_review.py           terminal Confirm / False Positive / Uncertain flow
  report/
    templates/report.html.j2
    generate.py              HTML report + SHA-256 chain-of-custody hash
  simulate/
    synthetic_incident.py    benign Mode B fixture generator (Section 6)
    synthetic_disk_image.py  benign Mode A (FAT32 image) fixture generator
    hive_writer.py           Windows-only helper: builds real, empty synthetic
                              registry hives via the Windows Registry API
  models.py                  Event / Finding - the normalization boundary
  cli.py                     `ransomtrace analyze|simulate`
```

Both ingestion modes converge on the same `list[Event]` shape
(`ransomtrace/models.py`) before extraction, and both feed the same
correlation engine — Mode A and Mode B are just two ways of getting the same
question answered.

```
disk image ──┐
             ├─► ingest ─► extractors ─► [Event] ─► correlation/rules.py ─► [Finding]
artifact dir ─┘                                                                │
                                                                                ▼
                                                          CLI review (Confirm/FP/Uncertain)
                                                                                │
                                                                                ▼
                                                                    HTML report (report.html.j2)
```

## The ruleset (v1)

All rules are plain, documented Python functions in
[`ransomtrace/correlation/rules.py`](ransomtrace/correlation/rules.py) — not
a trained model, and every Finding is traceable to specific `Event` evidence.

| Rule | Trigger | MITRE | Confidence |
|---|---|---|---|
| **R1** Mass extension-change burst | ≥15 files share an unrecognized extension within a 10-minute window | T1486 | Low/Medium/High, scales with burst size |
| **R2** Shadow-copy deletion command | `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, or `bcdedit ... recoveryenabled no` evidence | T1490 | High |
| **R3** Persistence registry key | New Run/RunOnce value, or new service with a non-standard `ImagePath` | T1112 + T1547.001/T1543.003 | Medium |
| **R4** Ransomware Execution Sequence | An R1 finding **and** both an R2 and an R3 finding within 30 minutes of it — merged into one composite finding referencing all underlying evidence | T1486, T1490, T1112, ... | High |
| **R5** Anti-forensics signal | Event ID 1102 ("audit log cleared") | T1070.001 | High |

R1's 10-minute/15-file thresholds and R4's 30-minute correlation window are
named constants at the top of `rules.py`, with the reasoning for each value
documented inline (real ransomware incident write-ups referenced in MITRE
ATT&CK T1486/T1490 consistently show file trees touched within single-digit
minutes; the wider R4 window accounts for an attack chain being staged as
separate sequential steps rather than one instant).

R4 is the project's core "novelty": it's what turns three independent,
individually-weak signals into one high-confidence correlated finding — the
cross-artifact correlation the capstone brief asks for.

**Entropy corroboration (R1):** when real file content is available (Mode B's
`files/` tree, or Mode A reading bytes off the disk image via `pytsk3`), R1
samples up to 8KB of each unusually-extensioned file and computes its Shannon
entropy. Real ciphertext sits close to the theoretical maximum of 8 bits/byte;
plain text and most structured formats sit noticeably lower. A cluster whose
average sampled entropy is ≥7.5 bits/byte gets its confidence bumped one level
(capped at High) — independent corroboration that the burst really does look
like encrypted output, not just an unrecognized extension. See
`HIGH_ENTROPY_THRESHOLD` in [`extractors/filesystem.py`](ransomtrace/extractors/filesystem.py).

## Synthetic test data — how it was generated safely

**No real malware, encryption, or destructive capability was used anywhere
in this project.** `ransomtrace simulate` generates a benign fixture that
merely *mimics ransomware artifacts*:

- **Filesystem**: ordinary files are copied/renamed to a fake extension
  (`.locked_demo`) and a clearly-labeled `README_RESTORE_FILES.txt` dummy
  note is dropped alongside them. File "content" is a placeholder string —
  nothing is actually encrypted.
- **Registry**: [`simulate/hive_writer.py`](ransomtrace/simulate/hive_writer.py)
  creates a private, throwaway registry hive using the real Windows Registry
  API (`RegLoadAppKeyW`) — not loaded into `HKLM`/`HKCU`, not visible in
  `regedit`, containing zero real system data, populated only with obviously
  fake values (`C:\Users\Public\svchost_update.exe`, etc.). This exists
  because `regipy` (our hive *parser*, chosen per the project spec) has no
  write support, and hand-rolling a binary REGF/HBIN writer would mean
  reinventing exactly the kind of low-level parser the spec says not to
  build — letting Windows itself write a real, valid hive sidesteps that
  without needing a hand-rolled writer or any real system data.
- **Event log**: since `python-evtx` is also read-only, the fixture writes a
  small JSON file of "mocked event records" (an explicitly-sanctioned
  fallback in the original project spec) shaped like a parsed EVTX record,
  containing one entry whose text resembles `vssadmin delete shadows /all`
  execution evidence.
- **Mode A disk image**: [`simulate/synthetic_disk_image.py`](ransomtrace/simulate/synthetic_disk_image.py)
  packages the same benign content into a real FAT32 raw disk image (via
  `pyfatfs`, pure Python, no administrator rights required) so
  `ingest/disk_image.py`'s real `pytsk3` code path gets exercised
  end-to-end with zero external downloads. See
  [Platform notes](#platform-notes) for why FAT32 rather than NTFS.

All three synthetic artifact types share one tight timestamp window by
construction (they're written within the same few seconds of one simulator
run), which is what lets `tests/test_correlation_rules.py` and
`tests/test_disk_image.py` assert — with a real, automated test — that the
correlation engine ties the full attack chain together end-to-end (the R4
"Ransomware Execution Sequence" finding).

## Scope & limitations

- **Single-host, single-image, single-analysis-session.** No multi-host or
  batch orchestration.
- **NTFS/Windows-only** in intent. (The self-generated Mode A test fixture
  is FAT32, not NTFS — see [Platform notes](#platform-notes) — but
  `ingest/disk_image.py` targets real Windows/NTFS artifact locations
  (`\Windows\System32\config\`, `\Windows\System32\winevt\Logs\`,
  `\Users\<profile>\NTUSER.DAT`) for real engagements.)
- **Rule-based, not exhaustive.** No ML/AI classifier. A missing finding is
  not proof an incident didn't happen; an unconfirmed finding is not proof
  it did — every finding needs analyst review.
- **Log clearing reduces visibility.** Rule 5 exists specifically to flag
  this rather than silently producing an artificially "clean" report when
  Event ID 1102 is present.
- **Deterministic.** Given the same input, the same findings are produced
  every time — no randomness, no external calls at analysis time.
- **PDF export was evaluated and dropped.** `weasyprint` installs via pip
  but needs native GTK libraries (Pango/GObject) that Windows doesn't ship;
  fighting that toolchain wasn't worth it per the project's own guidance.
  Reports are HTML-only (any browser can print-to-PDF if a PDF copy is
  needed).

## Platform notes

- **Analysis** (`ransomtrace analyze`) is cross-platform: `regipy` and
  `python-evtx` are pure Python, and `pytsk3` ships prebuilt wheels for
  Windows/Linux/macOS.
- **Test-fixture *generation*** (`ransomtrace simulate`, and the registry
  tests) requires **Windows**, for two independent reasons:
  1. `simulate/hive_writer.py` uses the Windows Registry API
     (`RegLoadAppKeyW`) to create a genuinely valid, zero-real-data
     synthetic hive — there is no cross-platform equivalent, and no
     maintained pure-Python registry *writer* exists.
  2. The self-generated Mode A disk image is FAT32 rather than real NTFS:
     building a true NTFS filesystem from scratch needs either OS-level
     volume mounting (requires administrator privileges, not available in
     this project's build environment / not something to request silently)
     or a pure-Python NTFS *writer* (does not exist). `pyfatfs` provides a
     no-admin-required, pure-Python FAT32 writer instead, and Sleuth
     Kit/`pytsk3` read FAT and NTFS through the same high-level
     directory-walk API for everything this project needs (path, extension,
     mtime, size) — so Mode A's real `pytsk3` code path is still fully
     exercised end-to-end. This is a test-fixture compromise, not a scope
     change: point `ransomtrace analyze --mode a` at a real NTFS image (a
     course-provided DFIR training image, or your own VM) to see the tool
     work against its actual real-world target.

Tests that need Windows-only fixture generation are marked
`@pytest.mark.skipif` and skip cleanly elsewhere; the rest of the suite
(filesystem extractor, event-log extractor with mocked JSON records, rule
logic, report generation) runs anywhere.

## MITRE ATT&CK coverage

T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1112
(Modify Registry), T1547.001 (Registry Run Keys), T1543.003 (Windows
Service), T1070.001 (Clear Windows Event Logs). See
[`correlation/mitre_map.py`](ransomtrace/correlation/mitre_map.py).

## Testing

```bash
pytest
```

52 tests across ingestion, all three extractors (including entropy
corroboration), all five correlation rules, both validation flows (CLI and
the Streamlit web UI, the latter via Streamlit's official `AppTest` harness
for real widget-interaction testing), and report generation — including
end-to-end tests (Mode A, Mode B, and the web UI) that generate the
synthetic fixture, run the whole pipeline, and assert the correlated R4
finding fires.

## Chain of custody

Every report embeds a SHA-256 hash of the analyzed input: a direct hash for
a disk image, or a manifest hash (sorted `path:sha256` lines, then hashed
again) for an artifact folder, so the hash is stable across machines and
changes if any file's content, name, or presence changes. The report's
dedicated "Chain of custody" block also shows the tool version and, when the
CLI or web UI supplies it, when processing started, when it completed, and
how long it took. See [`report/generate.py`](ransomtrace/report/generate.py).
