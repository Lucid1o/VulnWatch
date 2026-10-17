"""
core/demo_data.py
=================
Generates realistic sample vulnerability findings for VulnWatch.

Models a personal home lab environment (~5 devices: Laptop, Raspberry Pi,
Home Server, Router, and VM).
CVE IDs, CVSS scores, and services reflect real-world CVEs.
Dates are distributed over the past 6 months.
"""

from __future__ import annotations

import random
from datetime import date, timedelta
from typing import Any

from core.scoring import compute_risk_score, cvss_to_severity, sla_target_date, is_overdue

# ---------------------------------------------------------------------------
# Source data pools: personal devices and home lab
# ---------------------------------------------------------------------------

HOSTS = [
    {"asset": "thinkpad-laptop", "asset_type": "Laptop",          "asset_criticality": "Medium"},
    {"asset": "raspberrypi-4b",  "asset_type": "Raspberry Pi",    "asset_criticality": "Low"},
    {"asset": "homelab-server",  "asset_type": "Home Server",     "asset_criticality": "High"},
    {"asset": "openwrt-router",  "asset_type": "Router",          "asset_criticality": "High"},
    {"asset": "dev-ubuntu-vm",   "asset_type": "Virtual Machine", "asset_criticality": "Medium"},
]

# Real CVE data pool: (cve_id, cvss, description, service, port, nist_csf, iso_control)
CVE_POOL: list[tuple[str, float, str, str, int, str, str]] = [
    # Critical
    ("CVE-2021-44228", 10.0, "Apache Log4Shell RCE via JNDI injection",           "apache-log4j/2.14.1",  443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2021-26855", 9.8,  "Exchange Server SSRF vulnerability",                 "exchange/15.1.2375",   443,  "Identify,Protect,Respond", "A.8.8"),
    ("CVE-2022-26134", 9.8,  "Confluence OGNL injection RCE",                      "confluence/7.13.0",    8090, "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2023-23397", 9.8,  "NTLM credential hash leak vulnerability",           "outlook/16.0.15726",   443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2021-34527", 9.8,  "Windows Print Spooler RCE (PrintNightmare)",         "spoolsv/10.0.19041",   445,  "Identify,Protect,Respond", "A.8.8"),
    ("CVE-2022-30190", 9.8,  "MSDT remote code execution flaw",                    "msdt/10.0.19041",      0,    "Identify,Respond",         "A.8.8"),
    ("CVE-2023-4966",  9.4,  "NetScaler session token leak",                       "netscaler/13.1-49.15", 443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2021-44832", 9.0,  "Apache Log4j2 RCE via JDBC Appender",               "apache-log4j/2.17.0",  8080, "Identify,Detect",          "A.8.8"),
    ("CVE-2023-20198", 10.0, "Web UI privilege escalation flaw",                  "router-webui/17.9.1a", 443,  "Identify,Protect,Respond", "A.8.8"),
    ("CVE-2023-44487", 7.5,  "HTTP/2 Rapid Reset DoS vulnerability",               "nginx/1.24.0",         443,  "Protect,Detect",           "A.12.6"),
    # High
    ("CVE-2021-21985", 9.8,  "Management server RCE via health check",             "vcenter/7.0.0.10600",  443,  "Identify,Detect",          "A.8.8"),
    ("CVE-2021-40444", 8.8,  "MSHTML remote code execution vulnerability",         "mshtml/11.0.19041",    0,    "Protect,Respond",          "A.8.8"),
    ("CVE-2022-1388",  9.8,  "REST auth bypass remote code execution",             "mgmt-api/16.1.2.2",    443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2022-22965", 9.8,  "Spring Framework RCE (Spring4Shell)",                "spring-core/5.3.17",   8080, "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2022-0847",  7.8,  "Linux kernel Dirty Pipe local privilege escalation", "kernel/5.8.0",         0,    "Protect",                  "A.8.8"),
    ("CVE-2023-0386",  7.8,  "Linux kernel OverlayFS privilege escalation",        "kernel/6.1.0",         0,    "Protect",                  "A.8.8"),
    ("CVE-2021-3156",  7.8,  "sudo heap overflow privilege escalation",            "sudo/1.9.5p1",         0,    "Protect",                  "A.9.4"),
    ("CVE-2022-21907", 9.8,  "HTTP Protocol Stack RCE (worm potential)",           "http.sys/10.0.19041",  80,   "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2023-21716", 9.8,  "RTF font table heap corruption flaw",                "office/16.0.16501",    0,    "Protect,Respond",          "A.8.8"),
    ("CVE-2021-42278", 8.8,  "Active Directory machine account spoofing",          "kerberos/10.0.17763",  88,   "Identify,Protect",         "A.9.2"),
    # Medium
    ("CVE-2023-32784", 7.5,  "KeePass master password plaintext memory dump",      "keepass/2.53",         0,    "Protect",                  "A.10.1"),
    ("CVE-2022-3602",  7.5,  "OpenSSL X.509 buffer overflow (punycode)",           "openssl/3.0.6",        443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2023-27350", 9.8,  "PaperCut auth bypass remote code execution",         "papercut/22.0.5",      9191, "Identify,Detect",          "A.8.8"),
    ("CVE-2021-22986", 9.8,  "Management interface auth bypass vulnerability",     "mgmt/15.1.2",          443,  "Identify,Protect",         "A.9.4"),
    ("CVE-2022-27925", 7.2,  "Mail server arbitrary file upload vulnerability",    "zimbra/8.8.15",        443,  "Protect,Detect",           "A.8.8"),
    ("CVE-2022-40684", 9.8,  "Gateway administration auth bypass flaw",            "router-os/7.2.1",      443,  "Identify,Protect",         "A.9.4"),
    ("CVE-2023-20273", 7.2,  "Network OS command injection vulnerability",         "router-os/17.9.2",     443,  "Identify,Protect",         "A.8.8"),
    ("CVE-2023-2868",  9.8,  "Mail filter appliance command injection",            "mailfilter/9.2.1",     25,   "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2022-47966", 9.8,  "SAML SSO authentication bypass RCE",                 "saml-sso/14.0",        8443, "Identify,Detect",          "A.8.8"),
    ("CVE-2023-29357", 9.8,  "Document server privilege escalation",               "doc-server/16.0",      443,  "Identify,Protect",         "A.9.2"),
    # Low / Medium
    ("CVE-2022-1096",  8.8,  "Google Chrome V8 type confusion flaw",               "chrome/99.0.4844.84",  0,    "Protect",                  "A.8.8"),
    ("CVE-2023-36884", 8.8,  "Document parsing remote code execution",             "office/16.0.16501",    0,    "Protect,Respond",          "A.8.8"),
    ("CVE-2022-24521", 7.8,  "Common Log File System driver elevation flaw",       "clfs/10.0.19041",      0,    "Protect",                  "A.8.8"),
    ("CVE-2021-36942", 7.5,  "Authentication service spoofing (PetitPotam)",       "lsass/10.0.19041",     445,  "Identify,Protect",         "A.9.4"),
    ("CVE-2022-26923", 8.8,  "Certificate authority privilege escalation",         "cert-srv/10.0.17763",  0,    "Identify,Protect",         "A.9.2"),
    ("CVE-2023-21554", 9.8,  "Message Queuing service remote code execution",      "msmq/10.0.19041",      1801, "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2023-28252", 7.8,  "Kernel driver local privilege escalation flaw",      "clfs/10.0.19044",      0,    "Protect",                  "A.8.8"),
    ("CVE-2022-34718", 9.8,  "TCP/IP stack remote code execution flaw",            "tcpip.sys/10.0.19041", 0,    "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2023-36745", 8.8,  "Mail server remote code execution flaw",             "exchange/15.2.1118",   443,  "Identify,Detect,Respond",  "A.8.8"),
    ("CVE-2021-27085", 8.8,  "Scripting engine remote code execution flaw",        "jscript9/11.0.19041",  0,    "Protect",                  "A.8.8"),
]

OWNERS = [
    "me",
    "homelab",
]


def _random_date_within(days: int) -> date:
    """Return a random date within the past `days` days."""
    delta = random.randint(0, days)
    return date.today() - timedelta(days=delta)


def generate_demo_findings(
    target_count: int = 25,
    seed: int = 42,
    team_mode: bool = False,
) -> list[dict[str, Any]]:
    """
    Generate realistic vulnerability findings for a personal home lab environment.

    Parameters
    ----------
    target_count:
        Approximate number of findings to generate.
    seed:
        Random seed for reproducibility.
    team_mode:
        If True, includes enterprise status sets and owners.
        If False (default), uses personal statuses (Open, Fixed, Ignored with note).
    """
    random.seed(seed)
    findings: list[dict[str, Any]] = []

    while len(findings) < target_count:
        host = random.choice(HOSTS)
        cve_data = random.choice(CVE_POOL)
        cve_id, cvss, description, service, port, nist_csf, iso_control = cve_data

        # Slightly vary CVSS ±0.2 to avoid identical scores
        cvss_jitter = round(max(0.0, min(10.0, cvss + random.uniform(-0.2, 0.2))), 1)
        severity = cvss_to_severity(cvss_jitter)
        risk_score = compute_risk_score(cvss_jitter, host["asset_criticality"], team_mode=team_mode)

        date_found = _random_date_within(180)
        age_days = (date.today() - date_found).days

        if not team_mode:
            # Personal mode statuses: Open, Fixed, Ignored
            if age_days > 90:
                status_pool = ["Open", "Fixed", "Ignored"]
                weights = [0.35, 0.45, 0.20]
            elif age_days > 30:
                status_pool = ["Open", "Fixed", "Ignored"]
                weights = [0.55, 0.35, 0.10]
            else:
                status_pool = ["Open", "Fixed", "Ignored"]
                weights = [0.75, 0.20, 0.05]
            status = random.choices(status_pool, weights=weights, k=1)[0]
            notes = "Test service isolated in lab environment" if status == "Ignored" else ""
        else:
            # Team mode statuses: Open, In Progress, Mitigated, Accepted
            if age_days > 120:
                status_pool = ["Open", "In Progress", "Mitigated", "Accepted"]
                weights = [0.25, 0.25, 0.35, 0.15]
            elif age_days > 60:
                status_pool = ["Open", "In Progress", "Mitigated", "Accepted"]
                weights = [0.40, 0.35, 0.20, 0.05]
            else:
                status_pool = ["Open", "In Progress", "Mitigated", "Accepted"]
                weights = [0.60, 0.30, 0.08, 0.02]
            status = random.choices(status_pool, weights=weights, k=1)[0]
            notes = ""

        target = sla_target_date(severity, date_found)
        overdue = int(is_overdue(severity, date_found, status))
        owner = random.choice(OWNERS)

        findings.append(
            {
                "asset": host["asset"],
                "asset_type": host["asset_type"],
                "asset_criticality": host["asset_criticality"],
                "vulnerability": description,
                "cve": cve_id,
                "cvss": cvss_jitter,
                "severity": severity,
                "risk_score": risk_score,
                "service": service,
                "port": port if port else None,
                "owner": owner,
                "status": status,
                "date_found": date_found.isoformat(),
                "target_date": target.isoformat(),
                "overdue": overdue,
                "notes": notes,
                "nist_csf": nist_csf,
                "iso_control": iso_control,
                "source": "demo",
            }
        )

    return findings
