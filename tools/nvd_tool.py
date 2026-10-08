"""NVD 数据源工具（对齐 M11）：查询 CVE 的 CVSS 评分。"""
import httpx
from langchain_core.tools import tool

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@tool
def query_cvss(cve_id: str) -> str:
    """查询 NVD 上指定 CVE 的 CVSS 评分/严重度。"""
    try:
        resp = httpx.get(NVD_URL, params={"cveId": cve_id}, timeout=10)
        resp.raise_for_status()
        d = resp.json()
        vulns = d.get("vulnerabilities", [])
        if not vulns:
            return f"未找到 {cve_id}"
        metrics = vulns[0]["cve"].get("metrics", {})
        scores = []
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in metrics.get(key, []):
                cvss = m.get("cvssData", {})
                scores.append(f"{cvss.get('baseScore')}({cvss.get('baseSeverity')})")
        return f"{cve_id} CVSS: " + "; ".join(scores[:3]) if scores else f"{cve_id} 无 CVSS 数据"
    except Exception as e:
        return f"NVD 查询失败：{e}"
