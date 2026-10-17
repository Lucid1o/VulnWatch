"""
src/scanners/validator.py
=========================
Target validation for live network scanning.

CRITICAL SECURITY & LEGAL COMPLIANCE NOTE:
------------------------------------------
Network scanning without authorization is illegal under the Computer Fraud and Abuse
Act (CFAA, 18 U.S.C. 1030) in the United States and equivalent computer misuse legislation
globally (e.g., UK Computer Misuse Act 1990).

To prevent accidental or malicious scanning of external/public infrastructure, this validator
STRICTLY enforces that only RFC 1918 private subnets and localhost loopback (127.0.0.1)
can be targeted by the scanner engine. All public IPs, hostnames that could resolve externally,
command injection characters, and Nmap command-line flags are unconditionally rejected.
"""

from __future__ import annotations

import ipaddress
import re

# Allowed RFC 1918 private subnets + localhost
ALLOWED_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Characters strictly forbidden: spaces, flags (-), shell meta-characters
FORBIDDEN_CHARS_PATTERN = re.compile(r"[\s;`$&|><!\"'\\{}()\[\]]")


def validate_scan_target(target: str) -> tuple[bool, str, ipaddress.IPv4Address | None]:
    """
    Validate that a user-supplied target is safe and legally permissible to scan.

    Enforces:
    1. Input cannot be empty.
    2. Input must not contain spaces, flags (e.g. -sS, -oN), or shell metacharacters.
    3. Input must parse strictly as an IPv4 address.
    4. Input must fall strictly inside private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12,
       192.168.0.0/16) or loopback (127.0.0.1 / 127.0.0.0/8).
    5. All public Internet IPs and broadcast/multicast IPs are rejected.

    Parameters
    ----------
    target:
        The target address string entered by the user.

    Returns
    -------
    tuple of (is_valid: bool, error_message: str, ip_obj: IPv4Address | None)
    """
    if not target or not target.strip():
        return False, "Target address cannot be empty.", None

    clean_target = target.strip()

    # Reject any flag-like input (starts with '-') or containing shell injection tokens
    if clean_target.startswith("-"):
        return (
            False,
            "Target rejection: Command-line flags and parameters are not permitted.",
            None,
        )

    if FORBIDDEN_CHARS_PATTERN.search(clean_target):
        return (
            False,
            "Target rejection: Whitespace, flags, and shell metacharacters are strictly forbidden.",
            None,
        )

    # Normalize 'localhost' alias to 127.0.0.1 loopback
    if clean_target.lower() == "localhost":
        clean_target = "127.0.0.1"

    # Parse as IPv4 address
    try:
        ip = ipaddress.IPv4Address(clean_target)
    except ValueError:
        return (
            False,
            f"Invalid target '{clean_target}'. Must be a valid IPv4 address (e.g. 192.168.1.50 or 127.0.0.1).",
            None,
        )

    # Security check: Must reside within RFC 1918 or Loopback subnets
    is_allowed = any(ip in network for network in ALLOWED_PRIVATE_NETWORKS)

    if not is_allowed:
        return (
            False,
            f"Authorization & Safety Restriction: Target '{clean_target}' is not a private IP. "
            "Scanning is strictly limited to RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, "
            "192.168.0.0/16) and 127.0.0.1 to prevent unauthorized external network probing.",
            None,
        )

    # Disallow network/broadcast boundaries if applicable
    if ip == ipaddress.IPv4Address("0.0.0.0"):
        return False, "Target rejection: 0.0.0.0 is not a scannable host address.", None

    return True, "", ip
