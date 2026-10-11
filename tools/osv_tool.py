"""OSV.dev 漏洞查询工具（对齐 M11）。

两段式查询（OSV API 本身的设计）：
  1. POST /v1/querybatch —— 按包名+版本批量查出「哪些包有哪些漏洞 ID」（精简，每条只回 id + modified）
  2. GET  /v1/vulns/{id}  —— 逐条补全详情（severity / summary / aliases(CVE) / fixed 版本）

只用 querybatch 会丢 severity / summary / CVE / 修复版本，导致报告只能靠模型猜。
"""
import json

import httpx
from langchain_core.tools import tool

from db.cache import cache_get, cache_set
from utils.retry import retry_with_backoff

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns"


@retry_with_backoff(max_retries=3, base_delay=1.0, max_delay=10.0)
def _query_osv(payload: dict) -> dict:
    """POST /v1/querybatch（带 24h 缓存 + 退避重试）。"""
    cache_key = "osv:" + json.dumps(payload, sort_keys=True)
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    resp = httpx.post(OSV_QUERYBATCH, json=payload, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    cache_set(cache_key, data, 24 * 3600)
    return data


def _get_vuln_detail(vuln_id: str) -> dict:
    """GET /v1/vulns/{id} 拿单条漏洞完整详情（带 24h 缓存）。"""
    cache_key = "osv-vuln:" + vuln_id
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    resp = httpx.get(f"{OSV_VULN}/{vuln_id}", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    cache_set(cache_key, data, 24 * 3600)
    return data


def _extract_fixed(vuln: dict) -> str:
    """从 affected[].ranges[].events[] 提取第一个 fixed（修复版本）。"""
    for a in vuln.get("affected", []):
        for rng in a.get("ranges", []):
            for e in rng.get("events", []):
                if "fixed" in e:
                    return e["fixed"]
    return ""


def _cvss_level(vector: str) -> str:
    """从 CVSS 3.x 向量粗略推断严重等级（近似；精确分数可交给 NVD 源）。"""
    if not vector:
        return ""
    metrics = {}
    for part in vector.split("/"):
        if len(part) >= 2 and part[1] == ":":
            metrics[part[0]] = part[2]
    c, i, a = metrics.get("C", "N"), metrics.get("I", "N"), metrics.get("A", "N")
    highs = sum(1 for x in (c, i, a) if x == "H")
    if highs == 3:
        return "Critical"
    if highs >= 1:
        return "High"
    if "L" in (c, i, a):
        return "Medium"
    return "Low"


@tool
def query_osv_vulns(
    package_names: list[str],
    ecosystem: str = "PyPI",
    versions: list[str] | None = None,
    max_details: int = 30,
) -> str:
    """批量查询多个包的已知漏洞（OSV.dev），返回「ID + 等级 + 摘要 + CVE 别名 + 修复版本」。

    ecosystem: 包生态（PyPI/npm/Maven/Go 等），默认 PyPI。
    versions: 可选，与 package_names 对齐，传入后按版本精确匹配。
    max_details: 最多为多少条漏洞补全详情（每包前 3 条优先，其余只返回 ID，控制请求量）。
    """
    # 注意：querybatch 要求 package 里必须带 ecosystem，只传 name 会返回 400
    queries = []
    for i, n in enumerate(package_names):
        q = {"package": {"name": n, "ecosystem": ecosystem}}
        if versions and i < len(versions) and versions[i]:
            q["version"] = versions[i]
        queries.append(q)

    data = _query_osv({"queries": queries})

    lines: list[str] = []
    detail_count = 0
    per_package = 3  # 每包最多补全几条详情，避免单个包占满请求配额
    for i, name in enumerate(package_names):
        res = data.get("results", [])[i] if i < len(data.get("results", [])) else {}
        vulns = res.get("vulns", [])
        ver = versions[i] if versions and i < len(versions) and versions[i] else ""
        label = f"{name} {ver}".strip()
        if not vulns:
            lines.append(f"{label}: 未发现已知漏洞")
            continue
        lines.append(f"{label}: {len(vulns)} 条漏洞")
        for j, v in enumerate(vulns):
            vid = v.get("id", "")
            if j < per_package and detail_count < max_details:
                try:
                    d = _get_vuln_detail(vid)
                    sev = _cvss_level((d.get("severity") or [{}])[0].get("score", ""))
                    aliases = ", ".join(d.get("aliases", []))
                    summary = (d.get("summary") or "").strip()
                    fixed = _extract_fixed(d)
                    parts = [vid]
                    if sev:
                        parts.append(f"等级:{sev}")
                    if summary:
                        parts.append(summary[:80])
                    if aliases:
                        parts.append(f"CVE:{aliases}")
                    if fixed:
                        parts.append(f"修复:{fixed}")
                    lines.append("  - " + " | ".join(parts))
                    detail_count += 1
                except Exception:
                    lines.append(f"  - {vid}")
            else:
                lines.append(f"  - {vid}")
    return "\n".join(lines) or "未发现已知漏洞"


def query_osv_vuln_ids(
    package_names: list[str],
    ecosystem: str = "PyPI",
    versions: list[str] | None = None,
) -> dict[str, set[str]]:
    """按包返回其所有漏洞的完整 ID 集合（主 ID + 别名），供评测/多源去重使用。

    与 query_osv_vulns 的区别：不做截断、不做摘要，只返回可用于归一化对比的 ID 集合。
    别名归一化是漏洞聚合的关键：GHSA / CVE / PYSEC / GO 可能指向同一个漏洞。
    """
    queries = []
    for i, n in enumerate(package_names):
        q = {"package": {"name": n, "ecosystem": ecosystem}}
        if versions and i < len(versions) and versions[i]:
            q["version"] = versions[i]
        queries.append(q)

    data = _query_osv({"queries": queries})
    result: dict[str, set[str]] = {}
    for i, name in enumerate(package_names):
        res = data.get("results", [])[i] if i < len(data.get("results", [])) else {}
        ids: set[str] = set()
        for v in res.get("vulns", []):
            vid = v.get("id", "")
            if not vid:
                continue
            ids.add(vid)
            try:
                ids.update(_get_vuln_detail(vid).get("aliases", []))
            except Exception:
                pass
        result[name] = ids
    return result
