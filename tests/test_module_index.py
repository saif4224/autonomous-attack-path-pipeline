from pentest_pipeline.exploit.module_index import OfflineModuleIndex


def test_finds_known_cve():
    modules = OfflineModuleIndex().search_by_cve("CVE-2017-0144")
    assert any(m.name == "exploit/windows/smb/ms17_010_eternalblue" for m in modules)


def test_case_insensitive_lookup():
    modules = OfflineModuleIndex().search_by_cve("cve-2017-0144")
    assert len(modules) == 1


def test_unknown_cve_returns_empty():
    assert OfflineModuleIndex().search_by_cve("CVE-1999-9999") == []


def test_cve_with_only_auxiliary_module_is_not_weaponized():
    modules = OfflineModuleIndex().search_by_cve("CVE-2015-1635")
    assert modules and all(m.module_type != "exploit" for m in modules)
