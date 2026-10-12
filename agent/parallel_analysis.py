"""S2/S3/S4 并行分析组。

S1 的标准化组件证据由主 Agent 传入；本模块用三个独立 Agent 图并发执行，
汇合为一个结构化结果后交回主 Agent，再进入 S5/S6。
"""
import asyncio
import json
import time
import uuid
from typing import Any

from langchain.agents import create_agent
from langchain_core.tools import tool

from agent.llm import model
from agent.subagents.impact_analysis_agent import impact_analysis_agent
from agent.subagents.license_maintenance_agent import license_maintenance_agent
from agent.subagents.vulnerability_intelligence_agent import vulnerability_intelligence_agent
from api.monitor import monitor

_BRANCHES = {
    "S2": vulnerability_intelligence_agent,
    "S3": license_maintenance_agent,
    "S4": impact_analysis_agent,
}
_agents: dict[str, Any] | None = None
_agents_lock = asyncio.Lock()


async def _get_agents() -> dict[str, Any]:
    global _agents
    if _agents is not None:
        return _agents
    async with _agents_lock:
        if _agents is None:
            _agents = {
                stage_id: create_agent(
                    model=model,
                    tools=spec["tools"],
                    system_prompt=spec["system_prompt"],
                    name=f"depguard-{stage_id.lower()}",
                )
                for stage_id, spec in _BRANCHES.items()
            }
    return _agents


def _message_text(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(block.get("text") if isinstance(block, dict) else block)
            for block in content
        )
    return str(content)


async def _invoke_branch(
    stage_id: str,
    agent: Any,
    component_evidence: str,
    analysis_context: str,
    group_id: str,
) -> dict:
    spec = _BRANCHES[stage_id]
    name = spec["name"]
    started = time.perf_counter()
    monitor.report_agent_status(stage_id, name, "started", group_id)
    instruction = f"""你正在执行 DepGuard 并行分析组的 {stage_id} 分支。
以下是 S1 依赖解析助手产出的标准化组件证据，必须以此为输入，不得改写版本：
<component_evidence>
{component_evidence}
</component_evidence>

补充上下文：
{analysis_context or "无"}

返回本分支的 Evidence Bundle JSON。你与另外两个分支并行运行，不要等待或假设它们的结果。"""
    try:
        result = await agent.ainvoke({"messages": [{"role": "user", "content": instruction}]})
        messages = result.get("messages", [])
        content = _message_text(messages[-1]) if messages else ""
        duration_ms = round((time.perf_counter() - started) * 1000)
        monitor.report_agent_status(stage_id, name, "completed", group_id, duration_ms)
        return {
            "stage_id": stage_id,
            "assistant_name": name,
            "status": "completed",
            "duration_ms": duration_ms,
            "evidence": content,
        }
    except Exception as exc:
        duration_ms = round((time.perf_counter() - started) * 1000)
        monitor.report_agent_status(stage_id, name, "failed", group_id, duration_ms, str(exc))
        return {
            "stage_id": stage_id,
            "assistant_name": name,
            "status": "failed",
            "duration_ms": duration_ms,
            "error": str(exc),
        }


async def run_parallel_analysis(
    component_evidence: str,
    analysis_context: str = "",
    stage_ids: list[str] | None = None,
) -> dict:
    """并发执行指定分支；默认严格同时启动 S2/S3/S4。"""
    selected = stage_ids or ["S2", "S3", "S4"]
    invalid = [stage for stage in selected if stage not in _BRANCHES]
    if invalid:
        raise ValueError("不支持的并行阶段: " + ", ".join(invalid))
    agents = await _get_agents()
    group_id = str(uuid.uuid4())
    monitor.report_parallel_group(group_id, selected, "started")
    group_started = time.perf_counter()
    results = await asyncio.gather(*[
        _invoke_branch(stage, agents[stage], component_evidence, analysis_context, group_id)
        for stage in selected
    ])
    duration_ms = round((time.perf_counter() - group_started) * 1000)
    status = "completed" if all(item["status"] == "completed" for item in results) else "partial_failure"
    monitor.report_parallel_group(group_id, selected, status, duration_ms)
    return {
        "parallel_group_id": group_id,
        "status": status,
        "duration_ms": duration_ms,
        "stages": {item["stage_id"]: item for item in results},
    }


@tool
async def parallel_dependency_analysis(
    component_evidence: str,
    analysis_context: str = "",
    stage_ids: list[str] | None = None,
) -> str:
    """在一个并行组中执行 S2 漏洞、S3 许可证维护性、S4 影响分析。

    首次调用不要传 stage_ids，将同时启动 S2/S3/S4；仅在某分支失败重试时传对应阶段。
    """
    result = await run_parallel_analysis(component_evidence, analysis_context, stage_ids)
    return json.dumps(result, ensure_ascii=False)
