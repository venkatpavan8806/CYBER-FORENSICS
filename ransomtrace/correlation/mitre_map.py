"""MITRE ATT&CK technique ID lookup table used to tag Findings.

Only the techniques this project's rules actually reference are listed - this
is not meant to be a general-purpose ATT&CK library, just enough to give every
Finding a traceable, well-known reference ID and name.
"""
from __future__ import annotations

MITRE_TECHNIQUES: dict[str, str] = {
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1112": "Modify Registry",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1543.003": "Create or Modify System Process: Windows Service",
}


def technique_name(technique_id: str) -> str:
    return MITRE_TECHNIQUES.get(technique_id, "Unknown technique")
