"""HTML report generator (Milestone 7).

PDF export was evaluated (weasyprint) and dropped: it installs via pip but
requires native GTK libraries (Pango/GObject) not present on Windows without
a separate GTK runtime install. Per the project spec (Section 3), we do not
fight that toolchain - reports are HTML-only, viewable in any browser and
easy to print-to-PDF from there if a PDF copy is needed.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import jinja2

from ransomtrace.correlation.mitre_map import technique_name
from ransomtrace.models import Finding

TOOL_VERSION = "0.1.0"
TEMPLATE_DIR = Path(__file__).parent / "templates"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_input(path: str | Path) -> str:
    """SHA-256 chain-of-custody hash of the analyzed input.

    - A single file (e.g. a disk image, Mode A) is hashed directly, streamed
      in chunks so multi-GB images don't need to fit in memory.
    - A directory (Mode B artifact folder) is hashed as a manifest: every
      file's own SHA-256 is computed, then the sorted "relative_path:hash"
      lines are hashed together. This changes if any file's *content*
      changes, or a file is added/removed/renamed, while staying independent
      of filesystem iteration order (so it's reproducible across machines).
    """
    path = Path(path)
    if path.is_file():
        return _hash_file(path)
    if path.is_dir():
        manifest_lines = []
        for file_path in sorted(path.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(path).as_posix()
                manifest_lines.append(f"{rel}:{_hash_file(file_path)}")
        manifest = "\n".join(manifest_lines).encode("utf-8")
        return hashlib.sha256(manifest).hexdigest()
    raise FileNotFoundError(f"Input path not found: {path}")


def generate_report(
    findings: list[Finding],
    input_path: str | Path,
    output_path: str | Path,
    mode: str,
) -> Path:
    """Render the validated findings to a self-contained HTML report."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=jinja2.select_autoescape(["html"]),
    )
    env.filters["technique_name"] = technique_name
    template = env.get_template("report.html.j2")

    html = template.render(
        findings=findings,
        input_path=str(input_path),
        input_hash=hash_input(input_path),
        generated_at=datetime.now(timezone.utc).isoformat(),
        tool_version=TOOL_VERSION,
        mode=mode,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
