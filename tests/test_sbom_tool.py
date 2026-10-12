"""M11 —— SBOM 生成单元测试。"""
import json
import tempfile
from pathlib import Path

from api.context import reset_session_context, set_session_context
from tools.sbom_tool import build_sbom, write_sbom


def test_write_sbom():
    with tempfile.TemporaryDirectory() as d:
        token = set_session_context(d)
        try:
            result = write_sbom.func([{"name": "requests", "version": "2.31.0"}])
        finally:
            reset_session_context(token)

        assert "sbom.json" in result
        data = json.loads(Path(d, "sbom.json").read_text(encoding="utf-8"))
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.6"
        assert data["serialNumber"].startswith("urn:uuid:")
        assert data["metadata"]["tools"]["components"][0]["name"] == "DepGuard Agent"
        assert data["components"][0]["name"] == "requests"
        assert data["components"][0]["version"] == "2.31.0"
        assert data["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"


def test_build_sbom_skips_empty_names_and_supports_npm():
    data = build_sbom([
        {"name": "", "version": "1.0"},
        {"name": "@scope/pkg", "version": "2.0.0", "ecosystem": "npm"},
    ])
    assert len(data["components"]) == 1
    assert data["components"][0]["purl"] == "pkg:npm/@scope/pkg@2.0.0"
