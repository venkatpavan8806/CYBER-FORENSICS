"""Filesystem extractor.

Turns a normalized list of file records (current on-disk state: path, extension,
mtime, size - the same shape whether it came from Mode A's pytsk3 $MFT walk or
Mode B's artifact folder) into `Event` objects.

Design note on scope: real ransomware rewrites file content and appends/changes
the extension, which updates the file's modification time. Detecting the actual
*rename* operation would require parsing the NTFS $UsnJrnl change journal, which
is a genuinely complex binary format outside what pytsk3 gives you for free -
and Section 2 of the project spec says not to hand-roll low-level parsers that
already exist (and there isn't a maintained one for $UsnJrnl). Instead we use a
lighter, well-established DFIR heuristic: a burst of files sharing an unusual
extension, all modified within a tight time window, is itself strong evidence of
mass encryption - no journal parsing required. This extractor stays deliberately
"dumb" (it just emits per-file observations); the burst threshold/window logic
lives in correlation/rules.py per the project spec.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ransomtrace.models import Event, SourceExtractor

# Common, everyday extensions we do NOT want to treat as "suspicious" on their
# own - keeps normal bulk file operations (e.g. extracting a zip full of .txt
# files) from flooding the event stream. This is a known heuristic limitation:
# an extension not on this list is *unusual*, not *malicious* - see README.
COMMON_EXTENSIONS = {
    "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "csv", "json",
    "xml", "html", "htm", "css", "js", "py", "java", "c", "cpp", "h", "cs",
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp",
    "mp3", "mp4", "avi", "mov", "wav", "flac",
    "zip", "rar", "7z", "tar", "gz",
    "exe", "dll", "sys", "ini", "cfg", "log", "bak", "tmp",
    "md", "yml", "yaml", "toml", "cfg", "conf", "db", "sqlite",
}

# Ransom notes overwhelmingly follow a small set of naming conventions across
# real-world families (README/DECRYPT/RESTORE/RECOVER/HOW_TO + txt/html/hta).
RANSOM_NOTE_PATTERN = re.compile(
    r"(?i)^(read.?me|decrypt|restore|recovery|how.?to.?(decrypt|recover|restore)"
    r"|your.?files|help.?decrypt)[\w\-. ]*\.(txt|html|htm|hta)$"
)


@dataclass
class FileRecord:
    """Normalized current-state record for one file, from any ingestion mode."""

    path: str
    extension: str  # lowercase, no leading dot; "" if none
    mtime: datetime
    size: int


def _is_ransom_note(filename: str) -> bool:
    return bool(RANSOM_NOTE_PATTERN.match(filename))


def extract_filesystem_events(file_records: list[FileRecord]) -> list[Event]:
    """Convert file records into normalized Events.

    Emits one `file_extension_change` Event per file whose extension is not in
    the common whitelist (candidate encrypted/renamed file), and one
    `ransom_note_file` Event per filename matching a known ransom-note pattern.
    Files with common extensions and non-matching names are not emitted - they
    carry no signal for this extractor and would only add noise.
    """
    events: list[Event] = []
    for record in file_records:
        filename = Path(record.path).name

        if _is_ransom_note(filename):
            events.append(
                Event(
                    timestamp=record.mtime,
                    source_extractor=SourceExtractor.FILESYSTEM,
                    event_type="ransom_note_file",
                    description=f"Filename matches known ransom-note pattern: {record.path}",
                    raw_evidence={
                        "path": record.path,
                        "extension": record.extension,
                        "size": record.size,
                    },
                )
            )

        if record.extension and record.extension.lower() not in COMMON_EXTENSIONS:
            events.append(
                Event(
                    timestamp=record.mtime,
                    source_extractor=SourceExtractor.FILESYSTEM,
                    event_type="file_extension_change",
                    description=(
                        f"File with unrecognized extension '.{record.extension}': {record.path}"
                    ),
                    raw_evidence={
                        "path": record.path,
                        "extension": record.extension,
                        "size": record.size,
                    },
                )
            )

    return events
