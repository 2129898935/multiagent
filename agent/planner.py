"""结构化 Plan / Replan（M4）：扫描计划 + 升级计划双阶段，含进度追踪与 Replan 判定。

背景：光靠 prompt 让模型「先列 todo」不可校验、无反馈闭环、不可观测。
用结构化 Plan（机器可读、可追踪）+ 事件驱动 Replan（连续失败触发）。
"""
from pydantic import BaseModel


class PlanStep(BaseModel):
    id: str
    description: str
    status: str = "pending"  # pending / running / done / failed


class Plan(BaseModel):
    name: str
    steps: list[PlanStep]


def default_scan_plan() -> Plan:
    """DepGuard 默认扫描计划（解析 → 查漏洞 → 查许可证 → 可达性 → 报告）。"""
    return Plan(
        name="scan",
        steps=[
            PlanStep(id="S1", description="解析依赖文件"),
            PlanStep(id="S2", description="查询 OSV 漏洞"),
            PlanStep(id="S3", description="查询许可证与维护性"),
            PlanStep(id="S4", description="可达性分析"),
            PlanStep(id="S5", description="生成风险报告"),
        ],
    )


class PlanTracker:
    """追踪计划进度，判定是否完成 / 是否该 Replan。"""

    def __init__(self, plan: Plan, replan_after_failures: int = 3):
        self.plan = plan
        self.replan_after_failures = replan_after_failures
        self._by_id = {s.id: s for s in plan.steps}
        self._consecutive_failures = 0

    def mark(self, step_id: str, status: str) -> None:
        """更新某个 step 的状态。failed 连续计数，非 failed 清零。"""
        if step_id in self._by_id:
            self._by_id[step_id].status = status
        if status == "failed":
            self._consecutive_failures += 1
        else:
            self._consecutive_failures = 0

    def done_count(self) -> int:
        return sum(1 for s in self.plan.steps if s.status == "done")

    def is_complete(self) -> bool:
        return all(s.status == "done" for s in self.plan.steps)

    def should_replan(self) -> bool:
        """连续 N 次失败触发 Replan（事件驱动，而非每轮重规划）。"""
        return self._consecutive_failures >= self.replan_after_failures

    def summary(self) -> str:
        return "\n".join(f"- {s.id} [{s.status}] {s.description}" for s in self.plan.steps)
