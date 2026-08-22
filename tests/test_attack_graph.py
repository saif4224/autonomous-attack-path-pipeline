import tempfile
from pathlib import Path

from pentest_pipeline.exploit.msf_client import MetasploitClient
from pentest_pipeline.models import Host, Port
from pentest_pipeline.pipeline import map_vulnerabilities_to_exploits
from pentest_pipeline.report.attack_graph import build_attack_graph, render_attack_graph
from pentest_pipeline.vulnscan.nessus_client import NessusClient

FIXTURES = Path(__file__).parent / "fixtures"


def _sample_data():
    hosts = [
        Host(
            ip="10.10.10.11",
            hostname="fs01",
            ports=[Port(number=445, protocol="tcp", service="microsoft-ds")],
        )
    ]
    vulns = NessusClient(base_url="unused").from_xml_file(FIXTURES / "sample_nessus_report.xml")
    return hosts, vulns


def test_graph_contains_host_cve_and_module_nodes():
    hosts, vulns = _sample_data()
    matches = map_vulnerabilities_to_exploits(vulns, MetasploitClient())
    graph = build_attack_graph(hosts, matches)

    assert "10.10.10.11" in graph.nodes
    assert "CVE-2017-0144" in graph.nodes
    assert "exploit/windows/smb/ms17_010_eternalblue" in graph.nodes
    assert graph.has_edge("CVE-2017-0144", "exploit/windows/smb/ms17_010_eternalblue")


def test_render_writes_png():
    hosts, vulns = _sample_data()
    matches = map_vulnerabilities_to_exploits(vulns, MetasploitClient())
    graph = build_attack_graph(hosts, matches)

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "graph.png"
        render_attack_graph(graph, out_path)
        assert out_path.exists()
        assert out_path.stat().st_size > 0
