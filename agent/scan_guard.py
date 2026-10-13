"""Full-scan detection and completion checks for DepGuard sessions."""

import json
import re
from pathlib import Path

from agent.planner import PlanTracker
from tools.parse_requirements import parse_requirements
from tools.sbom_tool import validate_deliverables, build_sbom
from api.context import get_session_context
from agent.report_builder import deduplicate_vulnerabilities, render_report

_MANIFEST_NAMES = {
    "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
}
_SCAN_TERMS = re.compile(
    r"扫描|审计|漏洞清单|风险报告|依赖风险|生成报告|生成\s*sbom|完整分析|全面分析|full scan|security audit",
    re.I,
)


def is_requirements_file(name: str) -> bool:
    value = name.lower()
    return value.startswith("requirements") and value.endswith(".txt")


def requires_full_scan(query: str, uploaded_files: list[str]) -> bool:
    """A dependency manifest submitted for analysis requires the six-stage workflow."""
    return any(is_requirements_file(name) or name.lower() in _MANIFEST_NAMES
               for name in uploaded_files) or bool(_SCAN_TERMS.search(query or ""))


def scan_completion_errors(tracker: PlanTracker, session_dir: Path,
                           uploaded_files: list[str]) -> list[str]:
    """Check stage results, deliverables, and direct requirements coverage."""
    errors = []
    if not tracker.is_complete():
        errors.append("未完成阶段：" + ", ".join(
            step.id for step in tracker.plan.steps if step.status != "done"
        ))
    result = json.loads(validate_deliverables.func(
        report_filename="dependency_risk_report.md",
        sbom_filename="sbom.cdx.json",
    ))
    errors.extend(result.get("errors", []))
    sbom_path = session_dir / "sbom.cdx.json"
    if not sbom_path.is_file():
        return errors
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        actual = {
            (re.sub(r"[-_.]+", "-", str(c.get("name", "")).lower()),
             str(c.get("version", "")))
            for c in sbom.get("components", [])
        }
        for filename in uploaded_files:
            if not is_requirements_file(filename):
                continue
            path = session_dir / Path(filename).name
            if not path.is_file():
                continue
            expected = parse_requirements(path.read_text(encoding="utf-8"))
            missing = [
                package["name"] for package in expected
                if not any(
                    name == re.sub(r"[-_.]+", "-", package["name"].lower())
                    and (not package["version"] or version == package["version"])
                    for name, version in actual
                )
            ]
            if missing:
                errors.append(
                    f"SBOM 未覆盖 {filename} 中 {len(missing)} 个直接依赖："
                    + ", ".join(missing[:10])
                )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        errors.append(f"依赖覆盖校验失败：{exc}")
    return errors


def prepare_requirements_evidence(session_dir: Path, uploaded_files: list[str]) -> dict | None:
    """Parse complete uploaded requirements locally and persist lossless S1 evidence."""
    components = []
    sources = []
    for filename in uploaded_files:
        if not is_requirements_file(filename):
            continue
        path = session_dir / Path(filename).name
        if not path.is_file():
            continue
        packages = parse_requirements(path.read_text(encoding="utf-8"))
        components.extend({**package, "ecosystem": "PyPI", "source_file": filename}
                          for package in packages)
        sources.append(filename)
    if not sources:
        return None
    if not components:
        raise ValueError("上传的 requirements 文件没有可解析的依赖声明")
    result = {"stage": "S1", "source_files": sources,
              "total_components": len(components), "components": components}
    (session_dir / "s1_components.json").write_text(
        json.dumps(result, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    return result


class ScanExecution:
    """Only successful tool responses may complete stages."""

    def __init__(self, tracker: PlanTracker):
        self.tracker = tracker
        self.prevalidated_steps: set[str] = set()
        self.pending: dict[str, tuple[str, str | None]] = {}
        self.order_errors: list[str] = []

    def record_call(self, call: dict) -> None:
        name = call.get("name", "")
        args = call.get("args") or {}
        if name == "task":
            from agent.planner import subagent_to_step_id
            step_id = subagent_to_step_id(args.get("subagent_type", ""))
            if step_id and step_id not in self.prevalidated_steps:
                self._check_order(step_id)
                self.tracker.mark(step_id, "running")
                if call.get("id"):
                    self.pending[call["id"]] = ("task", step_id)
        elif name == "parallel_dependency_analysis":
            for step_id in (args.get("stage_ids") or ["S2", "S3", "S4"]):
                self._check_order(step_id)
                self.tracker.mark(step_id, "running")
            if call.get("id"):
                self.pending[call["id"]] = ("parallel", None)

    def _check_order(self, step_id: str) -> None:
        step = next((s for s in self.tracker.plan.steps if s.id == step_id), None)
        if step:
            missing = [dep for dep in step.depends_on
                       if next(s for s in self.tracker.plan.steps if s.id == dep).status != "done"]
            if missing:
                self.order_errors.append(f"{step_id} 启动时前置阶段未完成：{', '.join(missing)}")

    def record_result(self, message) -> None:
        call_id = getattr(message, "tool_call_id", None)
        pending = self.pending.pop(call_id, None)
        if not pending:
            return
        kind, step_id = pending
        content = getattr(message, "content", "")
        if isinstance(content, list):
            content = "\n".join(str(item) for item in content)
        content = str(content).strip()
        is_error = (getattr(message, "status", "success") == "error" or not content
                    or content.lower().startswith(("error:", "tool execution error", "工具执行失败")))
        if kind == "task" and step_id:
            if step_id == "S5" and not is_error:
                try:
                    plan = json.loads(content)
                    if not isinstance(plan, dict):
                        is_error = True
                except (ValueError, TypeError):
                    is_error = True
                if not is_error and get_session_context():
                    (Path(get_session_context()) / "s5_plan.txt").write_text(content, encoding="utf-8")
            self.tracker.mark(step_id, "failed" if is_error else "done")
        elif kind == "parallel":
            try:
                payload = json.loads(content) if not is_error else {}
                stages = payload.get("stages", {})
            except (ValueError, TypeError, AttributeError):
                stages = {}
            for stage in ("S2", "S3", "S4"):
                if self.tracker._by_id[stage].status == "running":
                    result = stages.get(stage)
                    self.tracker.mark(stage, "done" if result and result.get("status") == "completed" else "failed")


def build_deliverables_from_evidence(session_dir: Path) -> bool:
    """Build a factual report and CycloneDX SBOM from persisted stage evidence.

    Returns False until S1-S5 evidence is available. S6 reviews these files.
    """
    needed = ["s1_components.json", "s2_evidence.json", "s3_evidence.json",
              "s4_evidence.json", "s5_plan.txt"]
    if not all((session_dir / name).is_file() for name in needed):
        return False
    s1, s2, s3, s4 = [json.loads((session_dir / name).read_text(encoding="utf-8"))
                      for name in needed[:4]]
    upgrade_plan = (session_dir / "s5_plan.txt").read_text(encoding="utf-8")
    packages = s1.get("components", [])
    if not isinstance(packages, list) or not packages:
        raise ValueError("S1 缺少组件清单")
    raw_vulnerabilities = s2.get("vulnerabilities", [])
    if not isinstance(raw_vulnerabilities, list):
        raise ValueError("S2 vulnerabilities 不是数组")
    unique = {item["canonical_id"]: item for item in
              deduplicate_vulnerabilities(raw_vulnerabilities)}
    vulnerabilities = []
    for canonical_id, item in unique.items():
        ratings = item.get("ratings") or []
        rating = next((r for r in ratings if isinstance(r, dict) and r.get("score") is not None),
                      ratings[0] if ratings and isinstance(ratings[0], dict) else {})
        affected = item.get("affected_component") or item.get("package")
        if isinstance(affected, dict):
            affected = affected.get("name")
        if not affected:
            raise ValueError(f"漏洞 {canonical_id} 缺少受影响组件")
        references = item.get("references") or []
        advisory_urls = [r.get("url") if isinstance(r, dict) else str(r)
                         for r in references]
        entry = {
            "id": canonical_id,
            "source": rating.get("source") or "OSV",
            "severity": str(rating.get("severity") or "unknown").lower(),
            "description": item.get("summary") or "",
            "affects": [affected],
            "advisories": [u for u in advisory_urls if u],
        }
        if rating.get("score") is not None:
            entry["score"] = rating["score"]
        if rating.get("cvss_version"):
            entry["method"] = rating["cvss_version"]
        vulnerabilities.append(entry)
    sbom = build_sbom(packages, vulnerabilities, application_name="scanned-application")
    (session_dir / "sbom.cdx.json").write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (session_dir / "dependency_risk_report.md").write_text(
        render_report(s1, s2, s3, s4, upgrade_plan, sbom), encoding="utf-8"
    )
    return True
