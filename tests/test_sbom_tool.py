"""M11 —— SBOM 生成单元测试。"""
import json
import tempfile
from pathlib import Path

from api.context import reset_session_context, set_session_context
from tools.sbom_tool import write_sbom


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
        assert data["specVersion"] == "1.4"
        assert data["components"][0]["name"] == "requests"
        assert data["components"][0]["version"] == "2.31.0"
