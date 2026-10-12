"""OSV 证据转换不得自行猜测严重度。"""
from tools.osv_tool import _detail, _extract_fixed


def test_osv_detail_preserves_vector_without_inferred_label():
    raw = {
        "id": "GHSA-test",
        "aliases": ["CVE-2023-50447"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"ranges": [{"events": [{"fixed": "10.2.0"}, {"fixed": "12.0.0"}]}]}],
    }
    detail = _detail(raw)

    assert detail["severity"] == raw["severity"]
    assert "severity_label" not in detail
    assert detail["fixed_versions"] == ["10.2.0", "12.0.0"]
    assert _extract_fixed(raw) == ["10.2.0", "12.0.0"]
