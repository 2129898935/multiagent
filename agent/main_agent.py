from agent.subagents.dependency_parser_agent import dependency_parser_agent
from agent.subagents.vulnerability_intelligence_agent import vulnerability_intelligence_agent
from agent.subagents.license_maintenance_agent import license_maintenance_agent
from agent.subagents.impact_analysis_agent import impact_analysis_agent
from agent.subagents.upgrade_planning_agent import upgrade_planning_agent
from agent.subagents.report_review_agent import report_review_agent
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from tools.upload_file_read_tool import read_file_content

from deepagents import create_deep_agent

from agent.llm import model
from agent.prompts import main_agent_content

from api.monitor import monitor
import asyncio
import uuid
import shutil
from pathlib import Path
import re

from api.context import set_session_context, reset_session_context, set_thread_context

from agent.loop_guard import ProgressDetector
from agent.planner import PlanTracker, default_scan_plan, subagent_to_step_id, tool_to_step_id
from utils.context_budget import truncate_text
from db.session_store import update_session_status
from memory.retrieve import retrieve_memories
from memory.extract import extract_memories
from memory.store import add_memory

from langchain_core.messages import AIMessage

# 持久化 checkpoint：使用 SQLite 替代内存存储
# 服务重启后对话历史不丢失，支持多轮对话上下文
checkpoint_db_path = Path(__file__).parents[1] / "data" / "checkpoints.db"
checkpoint_db_path.parent.mkdir(parents=True, exist_ok=True)


# ---- M0: Agent 单例化 ----
# 整个进程只构建一次 LangGraph 图、只开一次 checkpointer 连接。
# 图本身是无状态的，会话状态在 checkpointer 里，靠 config["configurable"]["thread_id"]
# 隔离不同会话，所以「重的图共享一份、轻的状态按会话隔离」，不需要每次请求重建 Agent。
_agent = None
_checkpointer = None
_checkpointer_cm = None  # 保留异步上下文管理器引用，便于进程结束时优雅关闭连接（对齐 M10）
_agent_lock = asyncio.Lock()


async def get_agent():
    """懒加载单例：整个进程只构建一次 Agent 图 + checkpointer 连接。"""
    global _agent, _checkpointer, _checkpointer_cm
    if _agent is not None:
        return _agent

    async with _agent_lock:
        # 双重检查：拿到锁后可能已被并发的首个请求构建过
        if _agent is not None:
            return _agent

        # AsyncSqliteSaver.from_conn_string 是 @asynccontextmanager，调用返回的是「异步
        # 上下文管理器」，而不是 saver 本身。手动 __aenter__ 一次让底层 SQLite 连接常驻到
        # 进程结束，拿到真正的 AsyncSqliteSaver 实例复用。
        _checkpointer_cm = AsyncSqliteSaver.from_conn_string(str(checkpoint_db_path))
        _checkpointer = await _checkpointer_cm.__aenter__()

        _agent = create_deep_agent(
            model=model,
            system_prompt=main_agent_content["system_prompt"],
            tools=[read_file_content],
            checkpointer=_checkpointer,
            subagents=[
                dependency_parser_agent,
                vulnerability_intelligence_agent,
                license_maintenance_agent,
                impact_analysis_agent,
                upgrade_planning_agent,
                report_review_agent,
            ],
        )
        print("[Agent] create_deep_agent 已构建（单例，只应出现一次）")
        return _agent


async def close_agent():
    """优雅停机：关闭单例 checkpointer 连接（M10）。"""
    global _agent, _checkpointer, _checkpointer_cm
    if _checkpointer_cm is not None:
        await _checkpointer_cm.__aexit__(None, None, None)
        _checkpointer_cm = None
        _checkpointer = None
        _agent = None


# 执行
"""
  1. 执行主智能体 一定选异步，原因：对应多个客户端
  2. 什么时候触发我们智能体的调用或者执行？？？
  3. 客户端 -》 api/task -> fastapi 接口 -》 异步执行 -》 main_agent的运行 （异步方法）
  4. main_agent执行stream流式处理 -》 调用工具 -》 已经埋好了点  
                                   调用子智能体 -》 结果解析 -》 name = task -> monitor -> 发送子智能体
                                   调用最终结果 -》 结果 -》 monitor -> 发送结果的方法
                                   开启调用以后 -》 当前会话 -》 文件夹地址 -》 推送到前端
"""

project_root_path = Path(__file__).parents[1].resolve()  # 绝对 解析路径标识以及软连接
# project_root_path = Path(__file__).parents[1].absolute() # 绝对
# main_agent.invoke()
# main_agent.stream()
# main_agent.astream() [选他]

async def run_deep_agent(task_query, session_id, user_id=None):
    """
    定义流式+异步执行主智能体！！
    执行过程中，返回  会话文件化返回  调用子智能体  调用最终结果 （monitor）
    task_query: 前端提问的问题
    session_id: 每个前端会话对应的标识 （1.存储session_id ContextVars 2.session_id 给他创建对应的output输出地址）
    """
    print(f"当前会话的main_agent开始执行了！ 会话id:{session_id}")
    # 准备工作 【1. session_dir（前端） 2. relative_session_dir (大模型) 3. 上传的文件拼接上传文件专属提示词】
    # project_root_path / output / session_session_id(uuid)
    # 当前会话存储生成文件的专属文件夹
    session_dir = project_root_path / "output" / f"session_{session_id}"
    # 文件夹可能没有，第一次请求要创建
    session_dir.mkdir(parents=True, exist_ok=True)
    # \  \n \t -> /
    session_dir_str = str(session_dir).replace("\\", "/")
    # 获取相对文件夹
    # session_dir : project_root_path / output / session_session_id(uuid)
    # project_root_path : project_root_path
    # relative_session_dir_str: / output / session_session_id(uuid)
    relative_session_dir_str = str(session_dir.relative_to(project_root_path)).replace("\\", "/")

    # 处理上传文件 （updated / session_session_id）
    updated_dir_path = project_root_path / "updated" / f"session_{session_id}"
    updated_info_prompt = ""  # 有上传文件，拼接上传文件专属解析位置的提示词
    if updated_dir_path.exists():
        # 有
        files = [f.name for f in updated_dir_path.iterdir() if f.is_file()]
        # 将上传文件统一赋值到 output_dir 方便前端统一读取 session_dir
        if files:
            for filename in files:
                # 将原文件 -》 复制 -》 目标文件中  （copy2 保留原文件修改时间和权限等元数据）
                shutil.copy2(updated_dir_path / filename, session_dir / filename)
            # 构建提示词！告诉大模型，有上传文件，你要读取上传文件！！
            updated_info_prompt = (f"\n    [已上传文件] 已加载到工作目录:\n" +
                                   "\n".join([f"    - {f}" for f in files]) +
                                   "\n    请优先使用工具（read_file_content）读取并参考这些文件。")

    # 继续准备 1. 当前会话的对应的session_id session_dir 存储到contextVars [后续工具获取，socket -> 推送消息] 2.调用monitor给前端推送session_dir信息
    session_dir_token = set_session_context(session_dir_str)  # 存储的当前会话对应的文件夹地址
    session_id_token = set_thread_context(session_id)  # 获取当前会话的session_id对应socket

    monitor.report_session_dir(session_dir_str)  # 当前会话对应的文件夹地址推送给起前端！

    # 执行main_agent
    config = {
        "configurable": {
            "thread_id": session_id
        }
    }

    # 构建提示词
    path_instruction = f"""
    【工作环境指令】
    工作目录: {relative_session_dir_str}
    {updated_info_prompt}

    规则：
    1. 自定义文件工具已通过 ContextVar 锚定工作目录；调用 generate_markdown/write_sbom/read_file_content 时只传文件名，path 留空。
    2. 禁止把 '{relative_session_dir_str}' 再作为自定义工具的 path 参数，否则会重复嵌套目录。
    3. 若存在上传文件，必须使用 read_file_content 读取，或委派“依赖解析助手”读取；传递文件名，不要带绝对目录前缀。
    4. 禁止使用 deepagents 内置的 ls/read_file 读取上传文件：它们是虚拟文件系统，看不到宿主机会话目录。
    5. 使用相对路径，禁止使用绝对路径
    6. 依赖解析完成后再进入漏洞、许可证、影响、升级和报告阶段
    """
    # M3: 召回用户长期记忆，注入用户消息（跨会话记忆）
    memory_prompt = await asyncio.to_thread(retrieve_memories, user_id, task_query) if user_id else ""

    # M2: Context 预算——输入过长时截断，防止超大输入打爆上下文
    user_content = truncate_text(
        task_query + ("\n\n" + memory_prompt if memory_prompt else "") + path_instruction,
        max_tokens=8000,
    )

    # M7: 死循环防护——进度检测器，识别「同工具同参数重复」的假推进
    detector = ProgressDetector()

    # M4: 结构化计划——追踪扫描进度（解析→查漏洞→查许可证→可达性→报告）
    plan_tracker = PlanTracker(default_scan_plan())
    running_subagent_steps: set[str] = set()
    seen_usage_messages: set[str] = set()
    token_usage = 0

    # 反馈结果
    try:
        # 复用单例 Agent（整个进程只构建一次，会话隔离靠 thread_id）
        main_agent = await get_agent()
        update_session_status(session_id, "running")  # M1: 会话状态 → running

        final_result = ""  # 最终回答内容，供 M3 记忆提炼使用

        # 执行
        async for chunk in main_agent.astream({
            "messages": [
                {
                    "role": "user", "content": user_content
                }
            ]
        }, config=config):
            # {"model [大模型决定调用工具 子智能体  最终结果] / tools" : {messages:[xxx...]}}
            for node_name, state in chunk.items():
                if not state or "messages" not in state:
                    continue
                messages = state["messages"]
                if messages and isinstance(messages, list):
                    last_msg = messages[-1]
                    if node_name == 'model':
                        # 主模型重新获得控制权，说明上一批子 Agent 已经返回。
                        for completed_step in running_subagent_steps:
                            plan_tracker.mark(completed_step, "done")
                        running_subagent_steps.clear()

                        usage = getattr(last_msg, "usage_metadata", None) or {}
                        message_key = str(getattr(last_msg, "id", "") or id(last_msg))
                        if message_key not in seen_usage_messages:
                            token_usage += int(usage.get("total_tokens", 0) or 0)
                            seen_usage_messages.add(message_key)

                        if last_msg.tool_calls:
                            # 工具和子智能体
                            for tool_call in last_msg.tool_calls:
                                """
                                  tool_call = {
                                      name: task
                                      args:{
                                          subagent_type:子智能体的名字
                                          description:子智能体的描述
                                      }
                                  }
                                """
                                if tool_call['name'] == 'task':
                                    # 调用某个子智能体
                                    subagent_type = tool_call['args']['subagent_type']
                                    monitor.report_assistant(
                                        subagent_type,
                                        {'description': tool_call['args']['description']}
                                    )
                                    step_id = subagent_to_step_id(subagent_type)
                                    if step_id:
                                        plan_tracker.mark(step_id, "running")
                                        running_subagent_steps.add(step_id)
                                else:
                                    # M4: 根据工具调用更新计划步骤进度
                                    step_id = tool_to_step_id(tool_call['name'])
                                    if step_id:
                                        plan_tracker.mark(step_id, "done")
                                    # M7: 观察工具调用，检测假推进/死循环（只按「同工具同参数」判定）
                                    detector.observe(tool_call['name'], tool_call.get('args', {}))
                                    if detector.is_stuck():
                                        monitor._emit("error", "检测到任务可能陷入无进展循环（重复调用同一工具）")
                        elif last_msg.content:
                            # 最终结果
                            print(f"主智能体执行结果，最终结果：{last_msg.content[:100]}")
                            monitor.report_task_result(last_msg.content)
                            final_result = last_msg.content

        # M3: 任务结束后提炼长期记忆（跨会话有价值的信息）
        if user_id and final_result:
            for m in await extract_memories(task_query + "\n" + final_result, model):
                await asyncio.to_thread(add_memory, user_id, m["type"], m["content"])

        # 流结束时，最后一批子 Agent 已返回但可能没有下一轮 model chunk。
        for completed_step in running_subagent_steps:
            plan_tracker.mark(completed_step, "done")
        running_subagent_steps.clear()

        finding_count = len(set(re.findall(
            r"\b(?:CVE-\d{4}-\d+|GHSA-[0-9a-z-]+)\b",
            final_result,
            re.IGNORECASE,
        )))
        from db.session_store import update_session_metrics
        update_session_metrics(session_id, token_usage=token_usage, finding_count=finding_count)

        # M4: 报告计划执行进度
        print(f"[Plan] 六阶段计划进度 ({plan_tracker.done_count()}/{len(plan_tracker.plan.steps)}):\n{plan_tracker.summary()}")

        update_session_status(session_id, "done")  # M1: 会话状态 → done

    except Exception as e:
        # 报错推送错误信息给前端
        monitor._emit("error", f"执行主智能发生异常信息：{str(e)}")
        update_session_status(session_id, "failed", str(e))  # M1: 会话状态 → failed
    finally:
        # 释放存储的地址和session_id
        reset_session_context(session_dir_token, session_id_token)