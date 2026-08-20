# RansomTrace — Build Prompt for Claude Code

Paste/upload this entire file to Claude Code as your first message (or save it as `CLAUDE.md` / `PROMPT.md` in an empty project folder and tell Claude Code to read it and start). It is written as a self-contained instruction set — Claude Code should be able to plan and build from this without needing you to explain the project verbally.

---

## 0. Read this first (context for the coding agent)

You are building **RansomTrace**, a BTech capstone project (2-member team, one semester) for a "Cyber Forensics Capstone — Disk Forensics" course. The official problem statement is:

> **Ransomware Artifact Analyzer** — Trace encryption activity, shadow copy deletion, and registry modifications from a disk image. Objective: identify artifacts associated with ransomware activity. Suggested approach: examine disk artifacts → trace encryption-related evidence → inspect shadow-copy deletion and registry changes → correlate findings. Tools: Sleuth Kit, Registry Explorer libraries, Python. Expected output: ransomware artifact timeline/analysis report with correlated evidence. Deliverable structure: Acquisition → Analysis → Validation → Report.

This build prompt is the result of a full research pass (real-world evidence, existing-tool landscape, gap analysis, and a scored comparison of alternative approaches). Do not deviate from the scope boundaries below — they exist for a reason (semester size, legal/ethical safety, and forensic credibility), not arbitrary preference.

**Ask me clarifying questions before starting if anything below is ambiguous for my specific environment (e.g., OS I'll run/demo on, whether I have a Windows VM available). Otherwise, proceed autonomously and build incrementally, committing working milestones as you go.**

---

## 1. Goal (one line)

A local, Python-only tool that ingests Windows forensic artifacts (a disk image, or a pre-extracted artifact set), automatically detects and correlates evidence of **(a) ransomware file-encryption activity, (b) shadow-copy/backup deletion, and (c) suspicious registry modifications**, tags each finding with a MITRE ATT&CK technique ID, requires a human analyst to confirm/reject each finding, and generates a timestamped, hash-verified HTML/PDF report.

## 2. Non-goals — explicitly DO NOT build these

Do not implement, and do not suggest implementing, any of the following. If you think one is needed, stop and ask me first — don't silently add it:

- **No ML/AI classifier** for ransomware family attribution. Use documented, inspectable rules only, not a trained model.
- **No cloud upload / SaaS / multi-tenant web service.** Everything must run 100% locally on the analyst's machine. Never transmit disk-image or artifact data over a network.
- **No live/real-time endpoint agent or monitoring daemon.** This is a post-incident, offline analysis tool only.
- **No memory forensics (Volatility, live RAM analysis).** Disk/artifact evidence only.
- **No multi-host / enterprise batch orchestration.** Single image, single host, single analysis session.
- **No actual malicious ransomware code, and no attempt to obtain, run, or distribute real ransomware binaries.** For test data, build a **benign synthetic simulator** (Section 6) that mimics ransomware *artifacts* (renamed files, fake registry keys, fake log entries) without any encryption, propagation, or destructive capability whatsoever. This is a hard safety boundary — do not cross it even if it seems like it would make testing more "realistic."
- **Do not reinvent low-level parsers that already exist** (don't hand-roll an NTFS parser, a registry hive binary parser, or an EVTX binary parser from scratch). Use the established libraries in Section 3. The project's value is the *correlation and interpretation layer*, not re-solving already-solved parsing problems.

## 3. Tech stack (use exactly this unless a library is genuinely broken/unmaintained — check and tell me before substituting)

- **Language:** Python 3.11+
- **Filesystem/disk image parsing:** `pytsk3` (Sleuth Kit Python bindings) — for walking NTFS, reading $MFT, and (where feasible) $UsnJrnl.
- **Registry hive parsing:** `regipy` (preferred) — pure Python, no Windows dependency, good documentation. Fall back to `python-registry` if `regipy` can't cover a needed hive/key type.
- **Event log (EVTX) parsing:** `python-evtx` (or `evtx` if you find it more actively maintained — check PyPI before deciding).
- **CLI:** `click` or `argparse`.
- **Optional web dashboard (SHOULD-HAVE, see Section 8):** `streamlit` (fast to build, good for a validation-step UI) — do not reach for a full Flask/React stack, it's not worth the time for this project.
- **Report generation:** Jinja2 → HTML report; optionally render to PDF via `weasyprint` if it installs cleanly in the environment, otherwise HTML-only is fine (say so in the README rather than fighting a PDF toolchain for hours).
- **Hashing:** Python's built-in `hashlib` (SHA-256) for chain-of-custody metadata.
- **Testing:** `pytest`.

## 4. Two ingestion modes (build both — Mode B first, it de-risks the whole project)

**Mode A — Full disk image.** Accepts a raw (`.dd`, `.raw`) or E01 disk image path, mounts/reads it via `pytsk3`, extracts the registry hives and `.evtx` files it needs from within the image, then feeds them into the same analysis pipeline as Mode B.

**Mode B — Pre-extracted artifact folder** (build this first — it's what makes the project testable without needing a full real disk image). Accepts a folder containing:
- `registry/` — exported hive files (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, etc.)
- `eventlogs/` — `.evtx` files
- `filelist.csv` or a `files/` directory tree — representing the filesystem state (filenames, extensions, mtimes; can be a real directory tree for testing)

Mode B lets you validate the correlation engine end-to-end using the synthetic simulator (Section 6) without ever needing a real disk image or a Windows VM. Mode A is the "real" forensic path for the final demo, but get Mode B working and fully tested first.

## 5. Architecture — build in this order

```
ransomtrace/
  ingest/
    disk_image.py        # Mode A: pytsk3-based extraction
    artifact_folder.py    # Mode B: read pre-extracted folder
  extractors/
    filesystem.py         # mass-rename/extension-change burst detector, entropy sampler, ransom-note filename matcher
    registry.py            # Run/RunOnce keys, service creation, MountedDevices, UserAssist/BAM execution evidence
    eventlog_vss.py         # VSS-related event log entries + vssadmin/wmic/wbadmin/bcdedit execution evidence (Prefetch/Amcache if available, else EVTX only)
  correlation/
    rules.py               # documented, versioned ransomware-pattern rules (see Section 7)
    engine.py              # time-buckets events from all 3 extractors, applies rules.py, outputs findings
    mitre_map.py            # technique-ID lookup table (T1486, T1490, T1112, T1070.001, etc.)
  validation/
    cli_review.py           # terminal-based confirm/reject-per-finding flow (MUST-HAVE)
    web_review.py            # optional Streamlit review UI (SHOULD-HAVE)
  report/
    templates/report.html.j2
    generate.py              # renders validated findings + evidence + hashes into HTML (and PDF if feasible)
  simulate/
    synthetic_incident.py    # BENIGN test-data generator, see Section 6 — never real malware
  cli.py                     # top-level `ransomtrace analyze <path> --mode a|b` entrypoint
  tests/
    test_filesystem.py
    test_registry.py
    test_eventlog_vss.py
    test_correlation_rules.py
    test_report.py
README.md
requirements.txt
```

## 6. Synthetic test-data simulator (build this early, it unblocks everything else)

Build `simulate/synthetic_incident.py`: a small, clearly-labeled, **entirely benign** script that generates a Mode-B artifact folder mimicking a ransomware incident, so the pipeline can be tested without any real malware or real infected VM:

- Creates a temp directory tree of dummy files, then renames a batch of them within a tight time window to a fake extension (e.g. `.locked_demo`) and writes a `README_RESTORE_FILES.txt`-style dummy note — this exercises the filesystem/encryption extractor.
- Writes a synthetic `SYSTEM`/`SOFTWARE` hive fixture (or a minimal valid hive generated with `regipy`'s write support, or a small pre-built fixture hive checked into `tests/fixtures/`) containing an added Run key and a new service entry within the same time window — exercises the registry extractor.
- Writes a synthetic `.evtx` (or a mocked event-record structure the eventlog extractor can parse) containing a log entry resembling `vssadmin delete shadows /all` execution evidence, timestamped in the same window — exercises the shadow-copy extractor.
- All three synthetic artifacts share a tight, overlapping timestamp window so the correlation engine has something real to correlate and you can prove — with a real automated test — that the pipeline detects the full attack chain end-to-end.

This is your primary test fixture. Also try to get **one publicly available DFIR training image** (e.g., from a source like CyberDefenders' disk-forensics track, if licensing permits redistribution/local use) as a secondary, more realistic validation case — but the synthetic simulator must work standalone with zero external downloads, since that's what makes the test suite reproducible.

## 7. Correlation ruleset (v1 — implement these exact rules, keep the list documented and easy to extend)

Each rule takes normalized events (with `timestamp`, `source_extractor`, `description`, `raw_evidence`) from all three extractors and outputs a `Finding` with a MITRE technique ID and a confidence label. Implement as a plain, readable list of rule functions in `rules.py` — not a black box, and not ML. Example v1 rules:

1. **Mass rename/extension-change burst** — N or more files renamed/extension-changed within a T-minute window → Finding tagged `T1486 (Data Encrypted for Impact)`, confidence scales with burst size.
2. **Shadow-copy deletion command evidence** (`vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit /set {default} recoveryenabled no`) found in event log / Prefetch / Amcache → Finding tagged `T1490 (Inhibit System Recovery)`.
3. **New persistence registry key** (new Run/RunOnce value, or new service `ImagePath` pointing outside standard system paths) → Finding tagged `T1112 (Modify Registry)` / `T1547 (Boot or Logon Autostart Execution)` as applicable.
4. **Correlated ransomware execution sequence (the core "novelty" rule)** — if a Rule-2 finding and a Rule-3 finding both occur within T minutes of a Rule-1 finding on the same artifact set, merge them into a single **high-confidence "Ransomware Execution Sequence"** finding referencing all underlying evidence — this is the cross-artifact correlation the whole project exists to demonstrate.
5. **Anti-forensics / log tampering signal** — presence of Event ID 1102 ("The audit log was cleared") or gaps in expected log continuity → separate Finding tagged `T1070.001 (Clear Windows Event Logs)`, surfaced clearly as "evidence may be incomplete due to log clearing" rather than silently producing a clean report.

Keep `T` (time window) and `N` (burst threshold) as named, documented constants at the top of `rules.py`, not magic numbers — and explain in a comment *why* those defaults were chosen (e.g., "ransomware encryption of thousands of files typically completes within minutes; see MITRE ATT&CK T1486/T1490 references in project README").

## 8. Build order / milestones (MUST → SHOULD → NICE, matches capstone scope discipline)

Build and get each milestone fully working + tested before moving to the next. Don't parallelize into unfinished half-features.

**MUST HAVE (this is the deliverable core — do not proceed to SHOULD until all of this works end-to-end on the synthetic fixture):**
1. Mode B ingestion working.
2. Filesystem extractor (mass-rename burst detector) with tests.
3. Registry extractor (Run keys, services, execution-evidence keys) with tests.
4. Event-log/VSS extractor with tests.
5. Correlation engine implementing all 5 rules in Section 7, with tests proving the synthetic fixture produces the expected "Ransomware Execution Sequence" finding.
6. CLI-based validation flow (`Confirmed` / `False Positive` / `Uncertain` per finding).
7. HTML report generator including: validated findings, MITRE tags, raw evidence per finding, SHA-256 hash of the input, generation timestamp.
8. Mode A (real disk image via pytsk3) wired up to the same pipeline — at minimum working against one real or realistic test image.
9. README documenting scope, limitations, and how the synthetic test data was generated (be explicit that no real malware was used).

**SHOULD HAVE (after MUST is fully solid):**
10. Streamlit web review UI as an alternative to the CLI validation flow.
11. Entropy-based encrypted-file corroboration in the filesystem extractor.
12. Chain-of-custody metadata block in the report (hash, processing timestamps, tool version).

**NICE TO HAVE (only if time remains — do not start these before SHOULD is done):**
13. "Teaching mode" — optional annotations in the report explaining *why* each artifact type matters (for the educator/student persona).
14. A second synthetic incident scenario with a different registry/rename pattern, to demonstrate the ruleset isn't hardcoded to one fixture.
15. Export the rule definitions in a simple external config format (YAML/JSON) so someone else could add a new pattern without touching Python code.

**Explicitly do not attempt** anything from Section 2 even if it seems easy to bolt on — flag it to me instead if you think it would meaningfully help.

## 9. Non-functional requirements

- **Local-only.** No network calls anywhere in the core pipeline (fine for `pip install` during setup, not fine at runtime).
- **Deterministic and explainable.** Given the same input, the tool must produce the same findings. Every finding must be traceable to specific raw evidence — no unexplained scores.
- **Honest about limitations.** The README and the generated report footer should state plainly: single-host/single-image scope, NTFS/Windows-only, rule-based (not exhaustive), and log-clearing can reduce visibility (which Rule 5 is specifically designed to at least flag).
- **Reasonable performance.** Should process a synthetic fixture in seconds and a realistic disk image in well under a few minutes — if pytsk3 iteration is slow, say so and propose an optimization rather than silently leaving it slow.

## 10. Deliverables checklist (what "done" looks like)

- [ ] Working CLI: `ransomtrace analyze <path> --mode b` runs the synthetic fixture end-to-end and produces a report.
- [ ] Working CLI: `ransomtrace analyze <image.dd> --mode a` runs against a real/realistic disk image.
- [ ] `pytest` suite passing, including an end-to-end test on the synthetic fixture that asserts the "Ransomware Execution Sequence" finding is produced.
- [ ] Sample generated HTML report checked into `examples/` for demo purposes.
- [ ] README covering: setup instructions, architecture diagram (ASCII is fine), the ruleset with justification, explicit scope/limitations section, and a note on how test data was generated safely (no real malware).
- [ ] A short `DEMO.md` walking through exactly what to run and say during a live capstone demo.

## 11. How to work

- Work in small, testable increments. After each milestone in Section 8, run the tests and show me a summary before moving on.
- If a library (pytsk3, regipy, python-evtx) fails to install or behaves unexpectedly in this environment, tell me immediately with the exact error rather than silently swapping in a different approach.
- If you're ever unsure whether something falls under Section 2's "do not build" list, stop and ask rather than guessing.
- Keep commit messages and code comments clear enough that a non-expert reviewer (e.g., a course evaluator) can follow the logic.

---

**Start with:** setting up the repo structure (Section 5), then Section 6 (synthetic simulator), then Milestone 1–2 of Section 8. Confirm the plan with me before writing code if anything above needs a judgment call specific to my machine/environment.
