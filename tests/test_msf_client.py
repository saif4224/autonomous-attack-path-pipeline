from pentest_pipeline.exploit.msf_client import MetasploitClient


def test_falls_back_to_offline_index_when_not_connected():
    client = MetasploitClient()
    assert not client.is_connected

    modules = client.search_by_cve("CVE-2017-0144")
    assert any(m.name == "exploit/windows/smb/ms17_010_eternalblue" for m in modules)


def test_context_manager_without_connect_is_safe_to_skip():
    # disconnect() on a never-connected client must be a no-op, not raise
    client = MetasploitClient()
    client.disconnect()
    assert not client.is_connected
