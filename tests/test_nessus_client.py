from pathlib import Path

from pentest_pipeline.vulnscan.nessus_client import NessusClient

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nessus_report.xml"


def test_only_cve_bearing_findings_are_kept():
    vulns = NessusClient(base_url="unused").from_xml_file(FIXTURE)
    # the "SSL Certificate Cannot Be Trusted" finding has no <cve> and must be dropped
    assert all(v.cve for v in vulns)
    assert len(vulns) == 5


def test_severity_mapping():
    vulns = NessusClient(base_url="unused").from_xml_file(FIXTURE)
    eternalblue = next(v for v in vulns if v.cve == "CVE-2017-0144")
    assert eternalblue.severity == "critical"
    assert eternalblue.host_ip == "10.10.10.11"
    assert eternalblue.port == 445


def test_severity_rank_ordering():
    vulns = NessusClient(base_url="unused").from_xml_file(FIXTURE)
    heartbleed = next(v for v in vulns if v.cve == "CVE-2014-0160")
    eternalblue = next(v for v in vulns if v.cve == "CVE-2017-0144")
    assert eternalblue.severity_rank > heartbleed.severity_rank
