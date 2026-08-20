# RansomTrace — Live Demo Script

A ~5 minute walkthrough for the capstone demo. Run everything from the repo
root with the virtualenv active (`.venv\Scripts\activate`).

## 1. Say what this is (30s)

> "RansomTrace ingests Windows forensic artifacts — a disk image, or a
> pre-extracted artifact set — and correlates evidence of ransomware
> encryption, shadow-copy deletion, and registry persistence into one
> MITRE-tagged, human-validated report. It's rule-based, not machine
> learning, runs entirely offline, and never touches real ransomware —
> we built a benign synthetic incident simulator instead."

## 2. Generate the benign synthetic incident (30s)

```bash
ransomtrace simulate demo_run --disk-image
```

Point out live: this creates `demo_run/files/` (renamed files + a fake
ransom note), `demo_run/registry/` (a synthetic hive — explain it's built
via the real Windows Registry API so it's a genuinely valid hive with zero
real system data, see README), `demo_run/eventlogs/` (a mocked VSS-deletion
event record), and `demo_run/synthetic_incident.raw` (a real FAT32 disk
image containing the same content, for the Mode A path).

## 3. Run the analysis — Mode B (90s)

```bash
ransomtrace analyze demo_run --mode b -o demo_report.html
```

Walk through the CLI validation prompts live for 2-3 findings — confirm the
mass-rename burst, confirm the shadow-copy deletion, mark the registry
persistence finding Confirmed too. This is the "human in the loop" story:
nothing in the report is asserted without an analyst decision.

Then either finish the remaining prompts or hit Ctrl+C and re-run with
`--no-review` for speed if time is tight:

```bash
ransomtrace analyze demo_run --mode b --no-review -o demo_report.html
```

## 4. Run the analysis — Mode A (60s)

```bash
ransomtrace analyze demo_run/synthetic_incident.raw --mode a --no-review -o demo_report_a.html
```

> "Same pipeline, same rules, same output shape — the only difference is
> where the bytes came from. This time pytsk3 is walking a real disk image
> filesystem via Sleuth Kit instead of reading files off a folder."

## 5. Open the report (60s)

Open `demo_report.html` in a browser. Walk through:

- The chain-of-custody header: SHA-256 hash, generation timestamp, tool
  version, ingestion mode.
- The **Ransomware Execution Sequence** finding (Rule R4) — explain this is
  the correlation engine's core output: it only fires when a mass-encryption
  burst, a shadow-copy-deletion command, and a registry persistence entry
  all land within the same 30-minute window. Click to expand its evidence.
- Expand a burst-detection (R1) event and point out the entropy line
  (`high-entropy content, 7.9x bits/byte`) — the "encrypted" files are
  `os.urandom()` output, so this is honest corroboration, not a canned string.
- A couple of individual findings (R1/R2/R3) to show the granular evidence
  is still visible, not swallowed by the correlated finding.
- The scope/limitations footer — be upfront that this is rule-based and not
  exhaustive.

## 5.5. (Optional) Show the web review UI (60s)

```bash
streamlit run ransomtrace/validation/web_review.py
```

Same review guarantee as the CLI, in a browser: point it at `demo_run`,
click Analyze, expand a finding, set it Confirmed, generate the report.
Useful if the audience is more comfortable with a GUI than a terminal.

## 6. Show the tests (30s)

```bash
pytest -v
```

Point out `test_synthetic_incident_produces_ransomware_execution_sequence`
(Mode B) and `test_synthetic_disk_image_mode_a_produces_ransomware_execution_sequence`
(Mode A) — both are automated proof that the full attack chain gets detected
end-to-end, on a fixture with zero external downloads and zero real malware.

## Anticipated questions

- **"How do you know this generalizes beyond your synthetic fixture?"** —
  Point to the rule thresholds (`BURST_MIN_FILES`, `BURST_WINDOW_MINUTES`,
  `CORRELATION_WINDOW_MINUTES` in `rules.py`) being independently documented
  against real incident-response literature (MITRE ATT&CK T1486/T1490), not
  tuned to the fixture's specific numbers. If you tested against a real
  DFIR training image, mention what you saw there.
- **"Why not NTFS for the Mode A test image?"** — Explain the FAT32
  test-fixture compromise from the README: no admin rights available to
  mount/format a real NTFS volume, no pure-Python NTFS writer exists, and
  `pytsk3` reads FAT/NTFS through the same API for what this tool needs —
  `ingest/disk_image.py` targets real NTFS artifact paths and works against
  a real Windows image.
- **"What happens if the attacker clears the event log?"** — Rule 5: Event
  ID 1102 gets its own finding, and the report explicitly says evidence may
  be incomplete rather than silently looking clean.
