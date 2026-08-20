"""Mode A ingestion: read artifacts directly from a raw disk image via pytsk3
(Sleuth Kit's Python bindings - Section 3 of the project spec).

Walks the image's filesystem to build the same normalized FileRecord list
Mode B builds from a files/ directory, and pulls registry hives + event log
files out of their standard Windows locations to a temp directory, so the
same regipy/python-evtx based extractors used in Mode B can read them - Mode
A and Mode B converge onto one shared analysis pipeline once ingestion is
done (see ingest/artifact_folder.py for the Mode B side of that contract).

Handles both a partitioned image (MBR/GPT containing an NTFS/FAT volume) and
an unpartitioned raw filesystem image (the whole file *is* one filesystem):
tries Volume_Info first and falls back to opening FS_Info directly. The
partitioned-image path is exercised only against a real partitioned image
(not the zero-download synthetic fixture, which is a single unpartitioned
FAT32 volume - see simulate/synthetic_disk_image.py) - note this in the
README limitations section rather than claiming untested coverage.

Performance note: this does a full recursive directory walk of the image,
which is the straightforward approach and is fine for the small synthetic
fixture and modest real images. For a very large multi-hundred-GB image this
would be the place to optimize - e.g. skip well-known noise directories
(WinSxS, page files) or parallelize the walk - but that's out of scope until
it's actually shown to be a bottleneck on a real image.
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytsk3

from ransomtrace.extractors.eventlog_vss import extract_eventlog_events
from ransomtrace.extractors.filesystem import FileRecord, extract_filesystem_events
from ransomtrace.extractors.registry import extract_registry_events
from ransomtrace.models import Event

REGISTRY_HIVE_PATHS = [
    "/Windows/System32/config/SYSTEM",
    "/Windows/System32/config/SOFTWARE",
]
USERS_ROOT = "/Users"
EVENTLOG_DIR = "/Windows/System32/winevt/Logs"


def _open_filesystem(image_path: str) -> pytsk3.FS_Info:
    img = pytsk3.Img_Info(image_path)
    try:
        volume = pytsk3.Volume_Info(img)
    except Exception:
        volume = None

    if volume is not None:
        last_error: Exception | None = None
        for partition in volume:
            try:
                return pytsk3.FS_Info(img, offset=partition.start * volume.info.block_size)
            except Exception as exc:  # not every partition has a mountable filesystem
                last_error = exc
                continue
        raise RuntimeError(
            f"No mountable filesystem found in any partition of {image_path}: {last_error}"
        )

    return pytsk3.FS_Info(img)


def _walk_files(
    fs_info: pytsk3.FS_Info, dir_path: str = "/", _visited: set[str] | None = None
) -> list[FileRecord]:
    if _visited is None:
        _visited = set()
    records: list[FileRecord] = []
    try:
        directory = fs_info.open_dir(dir_path)
    except Exception:
        return records

    for entry in directory:
        raw_name = entry.info.name.name
        if raw_name in (b".", b".."):
            continue
        name = raw_name.decode("utf-8", errors="replace")
        entry_path = f"{dir_path.rstrip('/')}/{name}"

        meta = entry.info.meta
        if meta is None:
            continue

        if int(entry.info.name.type) == pytsk3.TSK_FS_NAME_TYPE_DIR:
            if entry_path in _visited:
                continue  # guards against filesystem corruption / cycles
            _visited.add(entry_path)
            records.extend(_walk_files(fs_info, entry_path, _visited))
        else:
            mtime = meta.mtime or 0
            records.append(
                FileRecord(
                    path=entry_path,
                    extension=Path(name).suffix.lstrip(".").lower(),
                    mtime=datetime.fromtimestamp(mtime, tz=timezone.utc),
                    size=meta.size or 0,
                )
            )
    return records


def _read_file_bytes(fs_info: pytsk3.FS_Info, path: str) -> bytes | None:
    try:
        f = fs_info.open(path)
        size = f.info.meta.size
        return f.read_random(0, size)
    except Exception:
        return None


def _extract_registry_events_from_image(fs_info: pytsk3.FS_Info, tmp_dir: Path) -> list[Event]:
    events: list[Event] = []
    hive_image_paths = list(REGISTRY_HIVE_PATHS)

    try:
        for entry in fs_info.open_dir(USERS_ROOT):
            name = entry.info.name.name
            if name in (b".", b".."):
                continue
            if int(entry.info.name.type) == pytsk3.TSK_FS_NAME_TYPE_DIR:
                profile = name.decode("utf-8", errors="replace")
                hive_image_paths.append(f"{USERS_ROOT}/{profile}/NTUSER.DAT")
    except Exception:
        pass

    for image_path in hive_image_paths:
        data = _read_file_bytes(fs_info, image_path)
        if data is None:
            continue
        local_path = tmp_dir / image_path.strip("/").replace("/", "_")
        local_path.write_bytes(data)
        events.extend(extract_registry_events(local_path))

    return events


def _extract_eventlog_events_from_image(fs_info: pytsk3.FS_Info, tmp_dir: Path) -> list[Event]:
    events: list[Event] = []
    try:
        logs_dir = fs_info.open_dir(EVENTLOG_DIR)
    except Exception:
        return events

    for entry in logs_dir:
        name = entry.info.name.name
        if name in (b".", b".."):
            continue
        decoded = name.decode("utf-8", errors="replace")
        if not decoded.lower().endswith((".evtx", ".json")):
            continue
        data = _read_file_bytes(fs_info, f"{EVENTLOG_DIR}/{decoded}")
        if data is None:
            continue
        local_path = tmp_dir / decoded
        local_path.write_bytes(data)
        events.extend(extract_eventlog_events(local_path))

    return events


def ingest_disk_image(image_path: str | Path) -> list[Event]:
    """Mode A: read a raw disk image and return normalized Events from all
    three extractors, same shape as Mode B's ingest_artifact_folder()."""
    fs_info = _open_filesystem(str(image_path))

    with tempfile.TemporaryDirectory(prefix="ransomtrace_modea_") as tmp:
        tmp_dir = Path(tmp)
        events: list[Event] = []
        events.extend(extract_filesystem_events(_walk_files(fs_info)))
        events.extend(_extract_registry_events_from_image(fs_info, tmp_dir))
        events.extend(_extract_eventlog_events_from_image(fs_info, tmp_dir))
        return events
