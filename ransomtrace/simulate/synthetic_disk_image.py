"""Generates a real, mountable raw disk image containing the synthetic
incident (Milestone 8's Mode A test fixture) - benign, zero real malware,
same hard safety boundary as synthetic_incident.py.

Why FAT32 and not NTFS: creating a genuine NTFS filesystem from scratch
requires either OS-level volume mounting (needs administrator privileges,
not available in this project's dev/build environment) or a pure-Python NTFS
*writer* (does not exist - regipy and pytsk3 are both read-only for
filesystem/registry structures, matching Section 2's "don't reinvent
low-level parsers/writers" guidance). `pyfatfs` provides a pure-Python,
no-admin-required FAT32 writer, and Sleuth Kit/pytsk3 read FAT and NTFS
through the same high-level directory-walk API for everything this project
needs (path, extension, mtime, size) - so this fixture fully exercises the
real Mode A pytsk3 code path end-to-end. This is a test-fixture compromise,
not a scope change: RansomTrace's real-world target remains NTFS Windows
images, and the README says so explicitly.
"""
from __future__ import annotations

import datetime as dt
import shutil
import tempfile
from pathlib import Path

from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS

from ransomtrace.simulate.synthetic_incident import generate_synthetic_incident

# 128 MiB comfortably clears pyfatfs's minimum FAT32 cluster-size requirements
# while staying small and fast to build/read for a test fixture.
IMAGE_SIZE_BYTES = 128 * 1024 * 1024


def _copy_tree_into_image(fs: PyFatFS, local_root: Path, image_root: str) -> None:
    for local_path in sorted(local_root.rglob("*")):
        rel = local_path.relative_to(local_root).as_posix()
        image_path = f"{image_root.rstrip('/')}/{rel}"
        if local_path.is_dir():
            fs.makedirs(image_path, recreate=True)
        else:
            fs.makedirs(str(Path(image_path).parent.as_posix()), recreate=True)
            fs.writebytes(image_path, local_path.read_bytes())
            mtime = local_path.stat().st_mtime
            fs.setinfo(image_path, {"details": {"modified": mtime}})


def generate_synthetic_disk_image(
    output_path: str | Path,
    num_encrypted_files: int = 40,
    num_benign_files: int = 15,
    ransom_extension: str = "locked_demo",
) -> Path:
    """Build a FAT32 raw disk image at `output_path` containing the same
    synthetic incident content as generate_synthetic_incident(), laid out at
    plausible Windows paths so ingest/disk_image.py can find it."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ransomtrace_synth_") as tmp:
        artifact_folder = generate_synthetic_incident(
            Path(tmp) / "incident",
            num_encrypted_files=num_encrypted_files,
            num_benign_files=num_benign_files,
            ransom_extension=ransom_extension,
            include_registry=True,
        )

        with output_path.open("wb") as f:
            f.truncate(IMAGE_SIZE_BYTES)

        fat = PyFat()
        fat.mkfs(str(output_path), fat_type=PyFat.FAT_TYPE_FAT32, size=IMAGE_SIZE_BYTES)
        fat.close()

        fs = PyFatFS(str(output_path))
        try:
            fs.makedirs("Windows/System32/config", recreate=True)
            fs.makedirs("Windows/System32/winevt/Logs", recreate=True)
            fs.makedirs("Users/victim/Documents", recreate=True)

            _copy_tree_into_image(
                fs, artifact_folder / "files", "Users/victim/Documents"
            )

            registry_files = list((artifact_folder / "registry").glob("*"))
            if registry_files:
                # The synthetic hive bundles Run-key, service, and BAM
                # evidence together (see hive_writer.py) - one copy at the
                # SYSTEM path is enough, since extractors/registry.py checks
                # all known key paths regardless of which "hive type" the
                # file nominally is.
                hive_bytes = registry_files[0].read_bytes()
                fs.writebytes("Windows/System32/config/SYSTEM", hive_bytes)
                mtime = registry_files[0].stat().st_mtime
                fs.setinfo("Windows/System32/config/SYSTEM", {"details": {"modified": mtime}})

            eventlog_files = list((artifact_folder / "eventlogs").glob("*"))
            for log_file in eventlog_files:
                image_path = f"Windows/System32/winevt/Logs/{log_file.name}"
                fs.writebytes(image_path, log_file.read_bytes())
                fs.setinfo(image_path, {"details": {"modified": log_file.stat().st_mtime}})
        finally:
            fs.close()

    return output_path
