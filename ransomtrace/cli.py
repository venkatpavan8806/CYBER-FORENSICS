"""RansomTrace CLI entrypoint.

    ransomtrace analyze <path> --mode b     # pre-extracted artifact folder
    ransomtrace analyze <image.dd> --mode a # raw disk image
    ransomtrace simulate <output_dir>       # generate the benign synthetic fixture
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from ransomtrace.correlation.engine import run_correlation
from ransomtrace.ingest.artifact_folder import ingest_artifact_folder
from ransomtrace.ingest.disk_image import ingest_disk_image
from ransomtrace.models import Finding
from ransomtrace.report.generate import generate_report
from ransomtrace.validation.cli_review import review_findings_cli


@click.group()
def main() -> None:
    """RansomTrace - offline ransomware artifact analyzer."""


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--mode", "-m", type=click.Choice(["a", "b"]), required=True,
    help="a = raw disk image (pytsk3), b = pre-extracted artifact folder",
)
@click.option(
    "--output", "-o", type=click.Path(), default="report.html",
    help="Where to write the HTML report (default: ./report.html)",
)
@click.option(
    "--no-review", is_flag=True,
    help="Skip the interactive validation step (all findings stay Unreviewed). "
         "Useful for CI / non-interactive runs.",
)
def analyze(path: str, mode: str, output: str, no_review: bool) -> None:
    """Analyze PATH (a disk image or an artifact folder) and produce a report."""
    click.echo(f"RansomTrace: analyzing {path!r} (mode {mode})")

    if mode == "a":
        events = ingest_disk_image(path)
    else:
        events = ingest_artifact_folder(path)

    click.echo(f"Extracted {len(events)} normalized event(s) from 3 extractors.")

    findings: list[Finding] = run_correlation(events)
    click.echo(f"Correlation engine produced {len(findings)} finding(s).")

    if not findings:
        click.echo("No findings - nothing to review.")
    elif no_review:
        click.echo("--no-review set: skipping interactive validation.")
    else:
        review_findings_cli(findings)

    report_path = generate_report(findings, input_path=path, output_path=output, mode=mode)
    click.echo(f"Report written to {report_path}")


@main.command()
@click.argument("output_dir", type=click.Path())
@click.option("--disk-image", is_flag=True, help="Also generate a Mode A raw disk image fixture.")
def simulate(output_dir: str, disk_image: bool) -> None:
    """Generate the benign synthetic ransomware-incident test fixture."""
    from ransomtrace.simulate.synthetic_incident import generate_synthetic_incident

    folder = generate_synthetic_incident(output_dir)
    click.echo(f"Synthetic Mode B artifact folder written to {folder}")

    if disk_image:
        from ransomtrace.simulate.synthetic_disk_image import generate_synthetic_disk_image

        image_path = generate_synthetic_disk_image(Path(output_dir) / "synthetic_incident.raw")
        click.echo(f"Synthetic Mode A disk image written to {image_path}")


if __name__ == "__main__":
    sys.exit(main())
