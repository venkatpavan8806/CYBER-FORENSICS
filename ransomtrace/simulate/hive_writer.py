"""Windows-only helper that creates small, fully synthetic registry hive files.

`regipy` (our chosen hive parser, see Section 3 of the project spec) is read-only
- it has no write support - and hand-rolling a binary REGF/HBIN writer would mean
reinventing the exact kind of low-level parser Section 2 tells us not to build.

Instead, we use the real Windows Registry API (`RegLoadAppKeyW`) to create a
private, unattached hive file that Windows itself formats correctly. It is not
loaded into HKLM/HKCU and is not visible in regedit or the live system registry
- it's just a standalone .hiv file on disk that we then populate with entirely
made-up keys/values. This gives us a genuinely valid hive (so the extractor
exercises the real regipy parsing path) built from zero real system data.

This module only runs on Windows. It is used by simulate/synthetic_incident.py
to build test fixtures; it is not part of the analysis pipeline itself.
"""
from __future__ import annotations

import ctypes
import os
import platform
from ctypes import wintypes
from pathlib import Path

REG_SZ = 1
REG_BINARY = 3
KEY_ALL_ACCESS = 0xF003F


class HiveWriterUnavailable(RuntimeError):
    """Raised when the synthetic hive writer cannot run on this platform."""


def _load_advapi32():
    if platform.system() != "Windows":
        raise HiveWriterUnavailable(
            "Synthetic registry hive generation uses the Windows Registry API "
            "(RegLoadAppKeyW) and only runs on Windows. regipy-based *parsing* "
            "of hives remains cross-platform; only fixture *generation* needs "
            "Windows. See README limitations section."
        )
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    advapi32.RegLoadAppKeyW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(wintypes.HKEY),
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    ]
    advapi32.RegLoadAppKeyW.restype = wintypes.LONG

    advapi32.RegCreateKeyExW.argtypes = [
        wintypes.HKEY, wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPCWSTR,
        wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ctypes.POINTER(wintypes.HKEY), ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.RegCreateKeyExW.restype = wintypes.LONG

    advapi32.RegSetValueExW.argtypes = [
        wintypes.HKEY, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_char_p, wintypes.DWORD,
    ]
    advapi32.RegSetValueExW.restype = wintypes.LONG

    advapi32.RegCloseKey.argtypes = [wintypes.HKEY]
    advapi32.RegCloseKey.restype = wintypes.LONG

    return advapi32


class SyntheticHiveBuilder:
    """Builds one synthetic hive file, populated with caller-supplied keys/values.

    Usage:
        with SyntheticHiveBuilder(path) as hive:
            hive.set_value(r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "SecurityUpdate", REG_SZ, "C:\\Users\\Public\\evil.exe")
    """

    def __init__(self, path: str | Path):
        self._advapi32 = _load_advapi32()
        self.path = str(Path(path).resolve())
        if os.path.exists(self.path):
            os.remove(self.path)
        self._root = wintypes.HKEY()

    def __enter__(self) -> "SyntheticHiveBuilder":
        res = self._advapi32.RegLoadAppKeyW(
            self.path, ctypes.byref(self._root), KEY_ALL_ACCESS, 0, 0
        )
        if res != 0:
            raise OSError(f"RegLoadAppKeyW failed for {self.path!r} (Win32 error {res})")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._advapi32.RegCloseKey(self._root)
        for suffix in (".LOG1", ".LOG2", ".blf", ".regtrans-ms"):
            leftover = self.path + suffix
            if os.path.exists(leftover):
                os.remove(leftover)

    def set_value(
        self, key_path: str, value_name: str, value_type: int, value
    ) -> None:
        """Create `key_path` (relative to hive root) if needed, and set a value."""
        subkey = wintypes.HKEY()
        disposition = wintypes.DWORD()
        res = self._advapi32.RegCreateKeyExW(
            self._root, key_path, 0, None, 0, KEY_ALL_ACCESS, None,
            ctypes.byref(subkey), ctypes.byref(disposition),
        )
        if res != 0:
            raise OSError(f"RegCreateKeyExW failed for {key_path!r} (Win32 error {res})")

        try:
            if value_type == REG_SZ:
                data = str(value).encode("utf-16le") + b"\x00\x00"
            elif value_type == REG_BINARY:
                data = bytes(value)
            else:
                raise ValueError(f"Unsupported value_type: {value_type}")

            res = self._advapi32.RegSetValueExW(
                subkey, value_name, 0, value_type, data, len(data)
            )
            if res != 0:
                raise OSError(
                    f"RegSetValueExW failed for {value_name!r} in {key_path!r} "
                    f"(Win32 error {res})"
                )
        finally:
            self._advapi32.RegCloseKey(subkey)


def filetime_bytes(timestamp) -> bytes:
    """Encode a datetime as a little-endian 8-byte Windows FILETIME, the layout
    BAM (Background Activity Moderator) uses at the start of its value data."""
    import datetime as _dt

    epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=_dt.timezone.utc)
    delta = timestamp - epoch
    filetime_int = int(delta.total_seconds() * 10_000_000)
    return filetime_int.to_bytes(8, byteorder="little") + b"\x00" * 8
