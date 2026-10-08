"""OSV.dev 漏洞查询工具（对齐 M11）。"""
import json

import httpx
from langchain_core.tools import tool

from db.cache import cache_get, cache_set
from utils.retry import retry_with_backoff

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"


@retry_with_backoff(max_retries=3, base_delay=1.0, max_delay=10.0)
def _query_osv(payload: dict) -> dict:
    """调用 OSV querybatch 接口，429/超时会被 retry_with_backoff 自动重试。带 24h 缓存。"""
    cache_key = "osv:" + json.dumps(payload, sort_keys=True)
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    resp = httpx.post(OSV_QUERYBATCH, json=payload, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    cache_set(cache_key, data, 24 * 3600)
    return data


@tool
def query_osv_vulns(package_names: list[str], ecosystem: str = "PyPI", versions: list[str] | None = None) -> str:
    """批量查询多个包的已知漏洞（OSV.dev，无需 API key）。

    ecosystem: 包生态（PyPI/npm/Maven/Go 等），默认 PyPI。
    versions: 可选，与 package_names 对齐，传入后 OSV 按版本精确匹配（只返回影响该版本的漏洞）。
    """
    # 注意：OSV querybatch 要求 package 里必须带 ecosystem，只传 name 会返回 400
    queries = []
    for i, n in enumerate(package_names):
        q = {"package": {"name": n, "ecosystem": ecosystem}}
        if versions and i < len(versions) and versions[i]:
            q["version"] = versions[i]
        queries.append(q)
    payload = {"queries": queries}
    data = _query_osv(payload)
    # 只返回精简摘要，避免大 JSON 打爆上下文
    results = []
    for q in data.get("results", []):
        for v in q.get("vulns", []):
            results.append(
                f"{v.get('id')} | {', '.join(v.get('aliases', []))} | {v.get('summary', '')[:100]}"
            )
    return "\n".join(results[:50]) or "未发现已知漏洞"
