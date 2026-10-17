"""
src/scanners/base.py
====================
Extensible scanner interface for VulnWatch.

Defines the BaseScanner abstract contract and Finding data model so additional
scanners (e.g. Authenticated SSH Scanner, Container Image Scanner, Local Host Collector)
can be added without altering the database schema or dashboard components.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class Finding:
    """Standardized finding produced by any scanner implementation."""

    asset: str
    vulnerability: str
    cve: str = ""
    cvss: float = 0.0
    severity: str = "Medium"
    risk_score: float = 0.0
    service: str = ""
    port: int | None = None
    asset_type: str = "Host"
    asset_criticality: str = "Medium"
    owner: str = "me"
    status: str = "Open"
    date_found: str = ""
    target_date: str = ""
    overdue: int = 0
    notes: str = ""
    nist_csf: str = "Identify,Detect"
    iso_control: str = "A.8.8"
    source: str = "nmap-live"

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary compatible with database insertion."""
        return asdict(self)


class BaseScanner(ABC):
    """
    Abstract Base Class for all vulnerability and port scanner implementations.

    Any new scanner (e.g., SshScanner, ContainerScanner) should inherit from
    BaseScanner and implement `name`, `is_available`, and `scan`.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the scanner."""
        pass

    @abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """
        Check if the required binary, tools, or dependencies are available.

        Returns
        -------
        tuple of (is_available: bool, status_or_instruction_message: str)
        """
        pass

    @abstractmethod
    def scan(
        self,
        target: str,
        asset_criticality: str = "Medium",
        owner: str = "me",
        asset_type: str = "Host",
        timeout_seconds: int = 300,
    ) -> list[Finding]:
        """
        Execute a scan against the target and return standardized findings.

        Parameters
        ----------
        target:
            Validated IP address string.
        asset_criticality:
            Criticality rating ('High', 'Medium', 'Low').
        owner:
            Assigned owner or team.
        asset_type:
            Asset type classification.
        timeout_seconds:
            Subprocess execution timeout.

        Returns
        -------
        list[Finding]
            Standardized list of discovered findings.
        """
        pass
