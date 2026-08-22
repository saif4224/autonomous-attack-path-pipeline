from pathlib import Path

from pentest_pipeline.discovery.nmap_scanner import NmapScanner

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap_scan.xml"


def test_parses_only_up_hosts():
    hosts = NmapScanner().from_xml_file(FIXTURE)
    ips = {h.ip for h in hosts}
    assert ips == {"10.10.10.11", "10.10.10.22"}
    assert "10.10.10.33" not in ips  # host was 'down'


def test_parses_open_ports_and_service_metadata():
    hosts = NmapScanner().from_xml_file(FIXTURE)
    fs01 = next(h for h in hosts if h.ip == "10.10.10.11")
    assert {p.number for p in fs01.ports} == {445, 3389}

    smb_port = next(p for p in fs01.ports if p.number == 445)
    assert smb_port.service == "microsoft-ds"
    assert smb_port.protocol == "tcp"


def test_hostname_extracted():
    hosts = NmapScanner().from_xml_file(FIXTURE)
    app01 = next(h for h in hosts if h.ip == "10.10.10.22")
    assert app01.hostname == "app01.lab.local"
