"""Registry extractor.

Reads one or more hive files with `regipy` and normalizes three kinds of
ransomware-relevant artifacts into Events:

  1. Run/RunOnce persistence values (SOFTWARE or NTUSER.DAT hives)
  2. New service entries whose ImagePath points outside standard system
     directories (SYSTEM hive)
  3. Execution evidence for known shadow-copy/recovery-tampering binaries,
     via BAM (Background Activity Moderator) and UserAssist

All lookups are best-effort: a hive may legitimately lack a given key (wrong
hive type passed in, key never populated, artifact not present on this
system), so a missing key is treated as "no finding here", not an error. Only
truly malformed hive files raise.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

from ransomtrace.models import Event, SourceExtractor

# Run/RunOnce live at the same relative path under both HKLM\SOFTWARE and
# HKCU (i.e. an NTUSER.DAT hive) - only the hive root differs.
RUN_KEY_PATHS = [
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
]

# Real SYSTEM hives store services under \ControlSet00N\Services, with
# \Select telling you which ControlSet is "Current". Our synthetic hive
# (built by simulate/hive_writer.py) skips that indirection and writes
# straight to \Services, so we try both.
SERVICES_KEY_PATHS = [
    r"\ControlSet001\Services",
    r"\CurrentControlSet\Services",
    r"\Services",
]

BAM_STATE_PATHS = [
    r"\ControlSet001\Services\bam\State\UserSettings",
    r"\Services\bam\State\UserSettings",
]

# Standard install locations - a service ImagePath outside these is unusual.
STANDARD_PATH_PREFIXES = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\program files",
    r"c:\program files (x86)",
    r"\systemroot\system32",
    r"system32",
)

# Binaries whose *execution* is itself a strong signal (shadow-copy/recovery
# tampering), independent of any registry persistence mechanism.
SUSPICIOUS_EXECUTION_BINARIES = {"vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe"}


def _is_standard_path(image_path: str) -> bool:
    normalized = image_path.strip('"').strip().lower()
    return any(normalized.startswith(prefix) for prefix in STANDARD_PATH_PREFIXES)


def _key_timestamp(key) -> datetime:
    return convert_wintime(key.header.last_modified)


def _extract_run_keys(hive: RegistryHive, hive_path: str) -> list[Event]:
    events: list[Event] = []
    for run_path in RUN_KEY_PATHS:
        try:
            key = hive.get_key(run_path)
        except RegistryKeyNotFoundException:
            continue

        timestamp = _key_timestamp(key)
        for value in key.get_values():
            events.append(
                Event(
                    timestamp=timestamp,
                    source_extractor=SourceExtractor.REGISTRY,
                    event_type="run_key_persistence",
                    description=(
                        f"Autostart value '{value.name}' added under {run_path}: "
                        f"{value.value}"
                    ),
                    raw_evidence={
                        "hive_file": hive_path,
                        "key_path": run_path,
                        "value_name": value.name,
                        "value_data": str(value.value),
                    },
                )
            )
    return events


def _extract_services(hive: RegistryHive, hive_path: str) -> list[Event]:
    events: list[Event] = []
    for services_path in SERVICES_KEY_PATHS:
        try:
            services_key = hive.get_key(services_path)
        except RegistryKeyNotFoundException:
            continue

        for service_key in services_key.iter_subkeys():
            image_path = None
            for value in service_key.get_values():
                if value.name == "ImagePath":
                    image_path = str(value.value)
                    break

            if image_path and not _is_standard_path(image_path):
                events.append(
                    Event(
                        timestamp=_key_timestamp(service_key),
                        source_extractor=SourceExtractor.REGISTRY,
                        event_type="suspicious_service_created",
                        description=(
                            f"Service '{service_key.name}' created with ImagePath "
                            f"outside standard system directories: {image_path}"
                        ),
                        raw_evidence={
                            "hive_file": hive_path,
                            "key_path": f"{services_path}\\{service_key.name}",
                            "service_name": service_key.name,
                            "image_path": image_path,
                        },
                    )
                )
        # Only the first services path that actually resolves is used, to
        # avoid double-counting the same services under two aliases.
        break
    return events


def _extract_bam_execution_evidence(hive: RegistryHive, hive_path: str) -> list[Event]:
    events: list[Event] = []
    for bam_path in BAM_STATE_PATHS:
        try:
            user_settings_key = hive.get_key(bam_path)
        except RegistryKeyNotFoundException:
            continue

        for sid_key in user_settings_key.iter_subkeys():
            for value in sid_key.get_values():
                exe_name = Path(value.name.strip('\\')).name.lower()
                if exe_name not in SUSPICIOUS_EXECUTION_BINARIES:
                    continue

                raw = value.value if isinstance(value.value, (bytes, bytearray)) else b""
                timestamp = _key_timestamp(sid_key)
                if len(raw) >= 8:
                    filetime_int = int.from_bytes(raw[:8], byteorder="little")
                    if filetime_int:
                        timestamp = convert_wintime(filetime_int)

                events.append(
                    Event(
                        timestamp=timestamp,
                        source_extractor=SourceExtractor.REGISTRY,
                        event_type="suspicious_binary_execution",
                        description=(
                            f"BAM execution evidence for {value.name} "
                            f"(user {sid_key.name})"
                        ),
                        raw_evidence={
                            "hive_file": hive_path,
                            "key_path": f"{bam_path}\\{sid_key.name}",
                            "executable": value.name,
                            "user_sid": sid_key.name,
                        },
                    )
                )
        break
    return events


def extract_registry_events(hive_path: str | Path) -> list[Event]:
    """Parse one hive file and return all normalized Events found in it."""
    hive_path = str(hive_path)
    hive = RegistryHive(hive_path)

    events: list[Event] = []
    events.extend(_extract_run_keys(hive, hive_path))
    events.extend(_extract_services(hive, hive_path))
    events.extend(_extract_bam_execution_evidence(hive, hive_path))
    return events
