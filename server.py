"""全国排污许可证管理信息平台公开端 MCP Server 启动入口。

运行：
    python server.py
或（使用 uv）：
    uv run server.py

客户端可通过 MCP 标准协议连接，暴露工具（统一 permit_pub_ 前缀）：
    permit_pub_search_licenses / permit_pub_license_detail / permit_pub_license_pages
    permit_pub_download_page / permit_pub_qrcode_info / permit_pub_post_permit_status
    permit_pub_rectification_list / permit_pub_announcements / permit_pub_policy_docs
    permit_pub_policy_detail / permit_pub_discharge_points / permit_pub_monitoring_entry

⚠️ 部署位置约束（2026-09-01 实测）：
    permit.mee.gov.cn 对云主机 IP 段实施风控，本 MCP 部署在云服务器上时
    所有查询会被 302 到 errorinfo.jsp（反爬页面），仅返回空结果。
    必须运行在本机（家庭/办公宽带出口）才能正常取数。
"""

from fastmcp import FastMCP

from permit_mcp import config
from permit_mcp.tools import register_tools

# ===== P0.A1 统一错误返回（跨服务横切改造；错误返回函数由本改造独占）=====
import json as _p0a1_json
import asyncio as _p0a1_asyncio

try:
    from mcp.types import CallToolResult as _p0a1_CTR, TextContent as _p0a1_TC
except Exception:  # pragma: no cover
    _p0a1_CTR = None
    _p0a1_TC = None

_P0A1_BLOCKED_HINTS = ("webshield", "验证", "风控", "反爬", "captcha", "人机验证", "403", "blocked", "访问验证")


def _p0a1_classify(err):
    """异常分类为统一错误码；detail 仅保留安全上下文（参数名），绝不暴露堆栈。"""
    tname = type(err).__name__
    msg = str(err)
    low = msg.lower()
    if isinstance(err, _p0a1_asyncio.TimeoutError) or "timeout" in low or "timed out" in low or "超时" in msg:
        return "UPSTREAM_TIMEOUT", "上游请求超时，请稍后重试", None
    if any(h in msg for h in _P0A1_BLOCKED_HINTS):
        return "UPSTREAM_BLOCKED", "上游返回反爬/风控验证页，请求被拦截", None
    _not_found = ("unknown tool", "not found", "找不到", "does not exist", "未知工具")
    if any(k in low for k in _not_found):
        return "INVALID_PARAM", "参数校验失败：缺少或非法参数（或未知工具）", None
    _val_hints = ("validation error", "input should", "input was invalid", "field required",
                  "required", "missing", "must be", "expected", "should be a valid",
                  "invalid", "参数", "类型", "provide")
    if any(k in low for k in _val_hints):
        return "INVALID_PARAM", "参数校验失败：缺少或非法参数", None
    if tname in ("ValidationError", "ValueError", "TypeError", "MissingArgumentsError",
                 "NotFoundError", "InvalidParams", "FastMCPError", "ToolError"):
        detail = None
        errs = getattr(err, "errors", None)
        if callable(errs):
            try:
                detail = [".".join(str(p) for p in e.get("loc", [])) for e in errs() if e.get("loc")]
            except Exception:
                detail = None
        if tname in ("FastMCPError", "ToolError") and not detail:
            if any(k in low for k in _not_found):
                return "INVALID_PARAM", "参数校验失败：缺少或非法参数（或未知工具）", None
            return "INTERNAL", "服务内部错误，请联系管理员", None
        return "INVALID_PARAM", "参数校验失败：缺少或非法参数", detail
    return "INTERNAL", "服务内部错误，请联系管理员", None


def _p0a1_err_json(code, message, detail=None):
    payload = {"code": code, "message": message}
    if detail is not None:
        payload["detail"] = detail
    return _p0a1_json.dumps(payload, ensure_ascii=False)


def _p0a1_install_error_guard(mcp):
    """包裹 mcp._tool_manager.call_tool，统一错误返回 {code,message,detail}。"""
    tm = getattr(mcp, "_tool_manager", None)
    if tm is None or not hasattr(tm, "call_tool"):
        return False
    _orig = tm.call_tool

    async def _guarded(*args, **kwargs):
        # 只做分类日志，不再包装返回值：fastmcp 2.14 server 层对返回值
        # 调用 .to_mcp_result()，包装成 CallToolResult/dict 都会二次报错；
        # 异常直接 re-raise，由 fastmcp 统一转 isError 结果。
        try:
            return await _orig(*args, **kwargs)
        except Exception as _e:
            code, message, detail = _p0a1_classify(_e)
            print(f"[permit-mcp] tool error {code}: {message}", flush=True)
            raise

    try:
        tm.call_tool = _guarded
    except Exception:
        return False
    return True


def create_server() -> FastMCP:
    mcp = FastMCP(
        "排污许可公开端",
        version="0.1.0",
        instructions=(
            "【排污许可·公开端】数据源：permit.mee.gov.cn 全国排污许可管理信息平台 公开端。"
            "无需登录，覆盖全国，权威公开数据。\n"
            "【优先选我的场景】查企业是否持证、许可证编号、有效期、行业类别、"
            "重点管理/简化管理类别、排放口经纬度坐标、执行报告与自行监测情况、"
            "限期整改与注销撤销公告。\n"
            "【不要选我的场景】① 需要企业申报/变更/台账等内网业务数据 —— 那是"
            "『排污许可管理端』(permit-management，依赖政务内网 10.100.248.253) 或"
            "『排污许可企业端』(eco-permit-enterprise) 的职责；"
            "② 建设项目环评报告与审批 —— 那是『环评知识库』(epxz-mcp) 的职责；"
            "③ 执法检查与案件办理 —— 那是『执法一体化』(eco-zfyth) 的职责。\n"
            "【重要】本工具名一律 permit_pub_ 前缀。若调用返回『平台拦截/风控』报错，"
            "说明出口 IP 被封，不是查无此企业，须换本机出口重试，切勿据此断言企业未持证。"
            "【找周边企业/附近排污单位/某区域有哪些排污企业】→ **优先用 permit_pub_nearby_enterprises**（按行政区划或关键字拉持证清单，可加中心点+半径过滤）。地图 POI（高德/天地图）只给工商点位，没有持证状态、许可证编号、行业类别与重点/简化管理类别，执法与溯源场景不得以 POI 代替本工具的持证清单。"
        ),
    )
    register_tools(mcp)
    _p0a1_install_error_guard(mcp)
    return mcp


def main() -> None:
    mcp = create_server()
    mcp.run()


if __name__ == "__main__":
    main()
