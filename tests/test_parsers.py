"""
tests/test_parsers.py
=====================
Unit tests for the Nmap XML and CSV parsers.
"""

import textwrap

import pytest

from core.parsers import parse_nmap_xml, parse_csv


# ---------------------------------------------------------------------------
# Nmap XML Parser Tests
# ---------------------------------------------------------------------------

MINIMAL_NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web-server-01" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.51"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

MULTI_HOST_NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="3.0.3"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNmapXmlParser:
    def test_basic_parse_returns_open_ports_only(self):
        findings = parse_nmap_xml(MINIMAL_NMAP_XML)
        # Port 443 is closed → should not appear
        assert len(findings) == 2

    def test_hostname_extracted(self):
        findings = parse_nmap_xml(MINIMAL_NMAP_XML)
        assets = [f["asset"] for f in findings]
        assert "web-server-01" in assets

    def test_port_numbers_correct(self):
        findings = parse_nmap_xml(MINIMAL_NMAP_XML)
        ports = {f["port"] for f in findings}
        assert 80 in ports
        assert 22 in ports

    def test_all_required_fields_present(self):
        findings = parse_nmap_xml(MINIMAL_NMAP_XML)
        required = {"asset", "cvss", "severity", "risk_score", "status", "date_found", "target_date"}
        for f in findings:
            missing = required - f.keys()
            assert not missing, f"Missing fields: {missing}"

    def test_cvss_assigned(self):
        findings = parse_nmap_xml(MINIMAL_NMAP_XML)
        for f in findings:
            assert 0.0 <= f["cvss"] <= 10.0

    def test_high_risk_port_rdp_gets_high_cvss(self):
        findings = parse_nmap_xml(MULTI_HOST_NMAP_XML)
        rdp = next(f for f in findings if f["port"] == 3389)
        assert rdp["cvss"] >= 7.0  # 3389 is in high_risk set

    def test_ftp_high_risk_port(self):
        findings = parse_nmap_xml(MULTI_HOST_NMAP_XML)
        ftp = next(f for f in findings if f["port"] == 21)
        assert ftp["cvss"] >= 7.0  # FTP on 21 is high risk

    def test_multi_host_count(self):
        findings = parse_nmap_xml(MULTI_HOST_NMAP_XML)
        assert len(findings) == 2

    def test_invalid_xml_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid Nmap XML"):
            parse_nmap_xml(b"this is not xml <broken>")

    def test_no_address_host_skipped(self):
        xml = b"""<?xml version="1.0"?>
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""
        findings = parse_nmap_xml(xml)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CSV Parser Tests
# ---------------------------------------------------------------------------

STANDARD_CSV = b"""asset,vulnerability,cve,cvss,service,port,owner,status,asset_criticality
192.168.1.50,Apache Log4Shell RCE,CVE-2021-44228,10.0,apache/2.14.1,443,alice@corp,Open,High
192.168.1.51,SSH weak cipher,CVE-2023-38408,5.5,openssh/8.2,22,bob@corp,In Progress,Medium
"""

ALIAS_CSV = b"""host,description,score,port
win-server-01,Unpatched Windows SMB,7.8,445
"""

SEVERITY_FALLBACK_CSV = b"""asset,vulnerability,severity
db-server,MySQL outdated version,High
"""

EMPTY_CSV = b"""asset,vulnerability,cve
"""

MISSING_MANDATORY_CSV = b"""cve,cvss
CVE-2021-1234,7.5
"""


class TestCsvParser:
    def test_standard_csv_parses_two_rows(self):
        findings = parse_csv(STANDARD_CSV)
        assert len(findings) == 2

    def test_cvss_parsed_correctly(self):
        findings = parse_csv(STANDARD_CSV)
        log4shell = next(f for f in findings if f["cve"] == "CVE-2021-44228")
        assert log4shell["cvss"] == 10.0

    def test_severity_computed_from_cvss(self):
        findings = parse_csv(STANDARD_CSV)
        log4shell = next(f for f in findings if f["cve"] == "CVE-2021-44228")
        assert log4shell["severity"] == "Critical"

    def test_risk_score_computed(self):
        findings = parse_csv(STANDARD_CSV)
        for f in findings:
            assert 0.0 <= f["risk_score"] <= 100.0

    def test_field_aliases_resolved(self):
        """'host' and 'score' aliases should be resolved to 'asset' and 'cvss'."""
        findings = parse_csv(ALIAS_CSV)
        assert len(findings) == 1
        assert findings[0]["asset"] == "win-server-01"
        assert findings[0]["cvss"] == 7.8

    def test_severity_fallback_when_no_cvss(self):
        """If no CVSS column, severity label should map to a CVSS estimate."""
        findings = parse_csv(SEVERITY_FALLBACK_CSV)
        assert len(findings) == 1
        assert findings[0]["cvss"] == 7.5  # High → 7.5

    def test_empty_csv_returns_empty_list(self):
        findings = parse_csv(EMPTY_CSV)
        assert findings == []

    def test_row_missing_mandatory_fields_skipped(self):
        findings = parse_csv(MISSING_MANDATORY_CSV)
        assert findings == []

    def test_all_required_fields_present(self):
        findings = parse_csv(STANDARD_CSV)
        required = {"asset", "cvss", "severity", "risk_score", "status", "date_found", "target_date"}
        for f in findings:
            assert required <= f.keys()

    def test_port_parsed_as_int(self):
        findings = parse_csv(STANDARD_CSV)
        apache = next(f for f in findings if f.get("cve") == "CVE-2021-44228")
        assert apache["port"] == 443

    def test_utf8_bom_handled(self):
        bom_csv = b"\xef\xbb\xbfasset,vulnerability\ntest-host,Test vuln\n"
        findings = parse_csv(bom_csv)
        assert len(findings) == 1
        assert findings[0]["asset"] == "test-host"
