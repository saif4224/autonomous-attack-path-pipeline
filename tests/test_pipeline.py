import json
import tempfile
from pathlib import Path

from pentest_pipeline.discovery.nmap_scanner import NmapScanner
from pentest_pipeline.pipeline import run_pipeline
from pentest_pipeline.vulnscan.nessus_client import NessusClient

FIXTURES = Path(__file__).parent / "fixtures"


def test_full_pipeline_end_to_end_offline():
    hosts = NmapScanner().from_xml_file(FIXTURES / "sample_nmap_scan.xml")
    vulns = NessusClient(base_url="unused").from_xml_file(FIXTURES / "sample_nessus_report.xml")

    with tempfile.TemporaryDirectory() as tmp:
        report = run_pipeline(hosts, vulns, target_label="unit-test", output_dir=tmp)

        assert report["summary"]["hosts_discovered"] == 2
        assert report["summary"]["cve_findings"] == 5
        # EternalBlue, Struts2, BlueKeep, Zerologon all have weaponized exploit modules
        assert report["summary"]["findings_with_weaponized_exploit"] >= 3

        report_file = Path(tmp) / "report.json"
        graph_file = Path(tmp) / "attack_graph.png"
        assert report_file.exists()
        assert graph_file.exists()

        on_disk = json.loads(report_file.read_text())
        assert on_disk["target"] == "unit-test"


def test_findings_sorted_by_severity_descending():
    hosts = NmapScanner().from_xml_file(FIXTURES / "sample_nmap_scan.xml")
    vulns = NessusClient(base_url="unused").from_xml_file(FIXTURES / "sample_nessus_report.xml")

    with tempfile.TemporaryDirectory() as tmp:
        report = run_pipeline(hosts, vulns, target_label="unit-test", output_dir=tmp)
        ranks = [f["vulnerability"]["severity"] for f in report["findings"]]
        rank_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        values = [rank_order[r] for r in ranks]
        assert values == sorted(values, reverse=True)
