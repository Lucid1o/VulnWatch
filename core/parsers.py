"""
core/parsers.py
===============
Data ingestion parsers for Nmap XML and generic CSV formats.
"""

from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET
from datetime import date
from typing import Any

from core.scoring import compute_risk_score, cvss_to_severity, sla_target_date, is_overdue

# Default mapping used when a CVE's NIST/ISO fields are unknown
_DEFAULT_NIST = "Identify,Detect"
_DEFAULT_ISO = "A.8.8"


def _build_finding(
    asset: str,
    asset_type: str,
    asset_criticality: str,
    vulnerability: str,
    cve: str,
    cvss: float,
    service: str,
    port: int | None,
    owner: str = "Unassigned",
    status: str = "Open",
    notes: str = "",
    nist_csf: str = _DEFAULT_NIST,
    iso_control: str = _DEFAULT_ISO,
) -> dict[str, Any]:
    severity = cvss_to_severity(cvss)
    risk_score = compute_risk_score(cvss, asset_criticality)
    date_found = date.today()
    target = sla_target_date(severity, date_found)
    overdue = int(is_overdue(severity, date_found, status))
    return {
        "asset": asset,
        "asset_type": asset_type,
        "asset_criticality": asset_criticality,
        "vulnerability": vulnerability,
        "cve": cve,
        "cvss": cvss,
        "severity": severity,
        "risk_score": risk_score,
        "service": service,
        "port": port,
        "owner": owner,
        "status": status,
        "date_found": date_found.isoformat(),
        "target_date": target.isoformat(),
        "overdue": overdue,
        "notes": notes,
        "nist_csf": nist_csf,
        "iso_control": iso_control,
    }


# ---------------------------------------------------------------------------
# Nmap XML parser
# ---------------------------------------------------------------------------

def parse_nmap_xml(xml_bytes: bytes) -> list[dict[str, Any]]:
    """
    Parse an Nmap -sV XML scan output into findings.

    Each open port with a detected service becomes a potential finding.
    CVSS is estimated from service/version heuristics (conservative 5.0
    default) since Nmap doesn't output CVSS scores.

    Parameters
    ----------
    xml_bytes:
        Raw bytes of the Nmap XML file.

    Returns
    -------
    list[dict]
        List of finding dicts ready for database insertion.
    """
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML: {exc}") from exc

    for host_el in root.findall("host"):
        # Determine address
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "unknown")

        # Hostname
        hostname_el = host_el.find(".//hostname[@type='user']")
        if hostname_el is None:
            hostname_el = host_el.find(".//hostname")
        hostname = hostname_el.get("name", ip) if hostname_el is not None else ip

        # OS guess for asset_type
        os_el = host_el.find(".//osmatch")
        os_name = os_el.get("name", "") if os_el is not None else ""
        if "Windows" in os_name:
            asset_type = "Server-Windows"
        elif "Linux" in os_name:
            asset_type = "Server-Linux"
        else:
            asset_type = "Network"

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_num = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")

            service_el = port_el.find("service")
            svc_name = ""
            svc_product = ""
            svc_version = ""
            if service_el is not None:
                svc_name = service_el.get("name", "unknown")
                svc_product = service_el.get("product", "")
                svc_version = service_el.get("version", "")

            service_str = f"{svc_product}/{svc_version}".strip("/") or svc_name

            # Conservative CVSS heuristic based on port/service
            cvss = _estimate_cvss(port_num, svc_name, svc_version)

            vuln_desc = (
                f"Exposed {svc_name} service on {protocol}/{port_num}"
                + (f" ({svc_product} {svc_version})" if svc_product else "")
            )

            findings.append(
                _build_finding(
                    asset=hostname,
                    asset_type=asset_type,
                    asset_criticality="Medium",
                    vulnerability=vuln_desc,
                    cve="",
                    cvss=cvss,
                    service=service_str,
                    port=port_num,
                )
            )

    return findings


def _estimate_cvss(port: int, service: str, version: str) -> float:
    """Heuristic CVSS estimate from Nmap service data."""
    # High-risk ports
    high_risk = {21, 23, 69, 135, 137, 138, 139, 445, 512, 513, 514, 1433, 3306, 3389, 5985, 5986}
    med_risk = {22, 25, 53, 80, 110, 143, 389, 443, 636, 1521, 5432, 8080, 8443}
    if port in high_risk:
        return 7.5
    if port in med_risk:
        return 5.0
    # Check for outdated version hints
    svc_lower = f"{service} {version}".lower()
    if any(kw in svc_lower for kw in ["1.", "2.", "3.", "4.", "5.0", "5.1"]):
        return 6.0  # Likely outdated
    return 4.0


# ---------------------------------------------------------------------------
# CSV parser
# ---------------------------------------------------------------------------

_CSV_FIELD_ALIASES = {
    "host": "asset",
    "hostname": "asset",
    "ip": "asset",
    "ip_address": "asset",
    "vuln": "vulnerability",
    "description": "vulnerability",
    "finding": "vulnerability",
    "cve_id": "cve",
    "cvss_score": "cvss",
    "cvss_base": "cvss",
    "score": "cvss",
    "severity_label": "severity",
    "risk": "severity",
}


def parse_csv(csv_bytes: bytes) -> list[dict[str, Any]]:
    """
    Parse a generic vulnerability scan CSV into findings.

    Minimum required columns: asset (or alias), vulnerability (or alias).
    Optional columns: cve, cvss, severity, service, port, owner, status,
                      asset_criticality, asset_type, notes.

    Parameters
    ----------
    csv_bytes:
        Raw bytes of the CSV file.

    Returns
    -------
    list[dict]
        List of finding dicts ready for database insertion.
    """
    text = csv_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        raise ValueError("CSV file appears to be empty or has no header row.")

    # Normalise field names
    norm_fields = {f.strip().lower().replace(" ", "_"): f for f in reader.fieldnames}
    alias_map: dict[str, str] = {}
    for norm, original in norm_fields.items():
        canonical = _CSV_FIELD_ALIASES.get(norm, norm)
        alias_map[original] = canonical

    findings: list[dict[str, Any]] = []
    for row in reader:
        mapped: dict[str, str] = {alias_map.get(k, k): (v or "").strip() for k, v in row.items()}

        asset = mapped.get("asset", "").strip()
        vulnerability = mapped.get("vulnerability", "").strip()
        if not asset or not vulnerability:
            continue  # Skip rows missing mandatory fields

        cve = mapped.get("cve", "")
        asset_type = mapped.get("asset_type", "Server-Linux")
        asset_criticality = mapped.get("asset_criticality", "Medium")
        service = mapped.get("service", "")
        notes = mapped.get("notes", "")
        owner = mapped.get("owner", "Unassigned")
        status = mapped.get("status", "Open")

        # CVSS resolution: prefer explicit column, fall back to severity bucket
        cvss_raw = mapped.get("cvss", "")
        severity_raw = mapped.get("severity", "")
        try:
            cvss = float(cvss_raw)
        except (ValueError, TypeError):
            # Infer from severity label
            _sev_to_cvss = {
                "critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.0, "info": 0.0
            }
            cvss = _sev_to_cvss.get(severity_raw.lower(), 5.0)

        port_raw = mapped.get("port", "")
        try:
            port = int(port_raw)
        except (ValueError, TypeError):
            port = None

        findings.append(
            _build_finding(
                asset=asset,
                asset_type=asset_type,
                asset_criticality=asset_criticality,
                vulnerability=vulnerability,
                cve=cve,
                cvss=cvss,
                service=service,
                port=port,
                owner=owner,
                status=status,
                notes=notes,
            )
        )

    return findings
