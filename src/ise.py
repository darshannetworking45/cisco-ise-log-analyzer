"""Cisco ISE 802.1X and MAB RADIUS Log Analyzer."""

from dataclasses import dataclass
import re
from typing import Dict, List, Optional


@dataclass(frozen=True)
class IseAuthEvent:
    """Normalized RADIUS authentication session record."""
    timestamp: str
    username: str
    mac_address: str
    nas_ip: str
    auth_status: str
    failure_reason: str


class IseLogAnalyzer:
    """Parser for Cisco ISE Live Logs & Syslog feeds."""

    LOG_RE = re.compile(
        r"^(\S+\s+\S+),\s+USER:([^,]+),\s+MAC:([^,]+),\s+NAS:([^,]+),\s+STATUS:([^,]+),\s+REASON:(.*)"
    )

    @classmethod
    def parse_line(cls, line: str) -> Optional[IseAuthEvent]:
        """Parses a structured syslog authentication entry."""
        m = cls.LOG_RE.match(line.strip())
        if not m:
            return None
        return IseAuthEvent(
            timestamp=m.group(1),
            username=m.group(2).strip(),
            mac_address=m.group(3).strip(),
            nas_ip=m.group(4).strip(),
            auth_status=m.group(5).strip().upper(),
            failure_reason=m.group(6).strip()
        )

    @classmethod
    def aggregate_failures(cls, events: List[IseAuthEvent]) -> Dict[str, int]:
        """Aggregates failed authentications by Cisco ISE failure reason code."""
        failures: Dict[str, int] = {}
        for ev in events:
            if ev.auth_status == "FAIL":
                failures[ev.failure_reason] = failures.get(ev.failure_reason, 0) + 1
        return failures
