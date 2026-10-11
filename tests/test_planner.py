"""M4 —— 结构化 Plan/Replan 单元测试。"""
from agent.planner import PlanTracker, default_scan_plan, tool_to_step_id


def test_default_scan_plan_has_five_steps():
    plan = default_scan_plan()
    assert len(plan.steps) == 5
    assert plan.steps[0].id == "S1"


def test_mark_and_progress():
    t = PlanTracker(default_scan_plan())
    assert t.done_count() == 0
    t.mark("S1", "done")
    t.mark("S2", "done")
    assert t.done_count() == 2
    assert t.is_complete() is False


def test_is_complete():
    t = PlanTracker(default_scan_plan())
    for s in t.plan.steps:
        t.mark(s.id, "done")
    assert t.is_complete() is True


def test_replan_after_consecutive_failures():
    t = PlanTracker(default_scan_plan(), replan_after_failures=3)
    t.mark("S1", "failed")
    t.mark("S2", "failed")
    assert t.should_replan() is False  # 只有 2 次失败
    t.mark("S3", "failed")
    assert t.should_replan() is True   # 连续 3 次失败 → Replan


def test_success_resets_failure_count():
    t = PlanTracker(default_scan_plan(), replan_after_failures=3)
    t.mark("S1", "failed")
    t.mark("S2", "done")   # 成功重置失败计数
    t.mark("S3", "failed")
    assert t.should_replan() is False


def test_summary_contains_steps():
    summary = PlanTracker(default_scan_plan()).summary()
    assert "S1" in summary and "S5" in summary


def test_tool_to_step_id():
    assert tool_to_step_id("query_osv_vulns") == "S2"
    assert tool_to_step_id("parse_requirements_tool") == "S1"
    assert tool_to_step_id("query_package_info") == "S3"
    assert tool_to_step_id("generate_markdown") == "S5"
    assert tool_to_step_id("query_advisory") == "S2"   # GHSA 详情也属查漏洞
    assert tool_to_step_id("internet_search") is None  # 非依赖扫描工具不映射
