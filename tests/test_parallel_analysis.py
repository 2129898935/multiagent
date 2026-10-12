import asyncio
import time

import pytest

import agent.parallel_analysis as parallel


class FakeAgent:
    def __init__(self, stage_id, timeline):
        self.stage_id = stage_id
        self.timeline = timeline

    async def ainvoke(self, state):
        self.timeline.append((self.stage_id, "start", time.perf_counter()))
        await asyncio.sleep(0.12)
        self.timeline.append((self.stage_id, "end", time.perf_counter()))
        return {"messages": [type("Message", (), {"content": '{"ok": true}'})()]}


@pytest.mark.asyncio
async def test_s2_s3_s4_really_run_concurrently(monkeypatch):
    timeline = []
    agents = {stage: FakeAgent(stage, timeline) for stage in ("S2", "S3", "S4")}

    async def fake_get_agents():
        return agents

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(parallel.monitor, "report_agent_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)

    started = time.perf_counter()
    result = await parallel.run_parallel_analysis("[]")
    elapsed = time.perf_counter() - started

    assert result["status"] == "completed"
    assert set(result["stages"]) == {"S2", "S3", "S4"}
    assert elapsed < 0.28  # 串行至少约 0.36 秒
    starts = [item[2] for item in timeline if item[1] == "start"]
    first_end = min(item[2] for item in timeline if item[1] == "end")
    assert max(starts) < first_end  # 三个分支都在任一分支结束前启动


@pytest.mark.asyncio
async def test_can_retry_only_failed_branch(monkeypatch):
    timeline = []
    agents = {stage: FakeAgent(stage, timeline) for stage in ("S2", "S3", "S4")}

    async def fake_get_agents():
        return agents

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(parallel.monitor, "report_agent_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)

    result = await parallel.run_parallel_analysis("[]", stage_ids=["S3"])

    assert set(result["stages"]) == {"S3"}
    assert {item[0] for item in timeline} == {"S3"}


def test_main_agent_registers_parallel_tool():
    from pathlib import Path

    source = (Path(__file__).parents[1] / "agent" / "main_agent.py").read_text(encoding="utf-8")
    assert "tools=[read_file_content, parallel_dependency_analysis]" in source
    assert "S1 → [S2、S3、S4 并行] → S5 → S6" in source


def test_frontend_handles_parallel_events():
    from pathlib import Path

    source = (Path(__file__).parents[1] / "api" / "static" / "index.html").read_text(encoding="utf-8")
    assert "case 'parallel_group'" in source
    assert "case 'agent_status'" in source
    assert "并行运行中" in source


@pytest.mark.asyncio
async def test_parallel_monitor_exposes_three_running_branches(monkeypatch):
    timeline = []
    events = []
    agents = {stage: FakeAgent(stage, timeline) for stage in ("S2", "S3", "S4")}

    async def fake_get_agents():
        return agents

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(
        parallel.monitor,
        "report_agent_status",
        lambda stage, name, status, group, *rest: events.append((stage, status)),
    )
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)

    await parallel.run_parallel_analysis("[]")

    started_indexes = [events.index((stage, "started")) for stage in ("S2", "S3", "S4")]
    completed_indexes = [events.index((stage, "completed")) for stage in ("S2", "S3", "S4")]
    assert max(started_indexes) < min(completed_indexes)


def test_main_agent_limits_repeated_stage_calls():
    from pathlib import Path

    source = (Path(__file__).parents[1] / "agent" / "main_agent.py").read_text(encoding="utf-8")
    assert "subagent_call_counts[subagent_type] > 2" in source
    assert "阶段子 Agent 重复调用超过上限" in source
