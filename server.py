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
        ),
    )
    register_tools(mcp)
    return mcp


def main() -> None:
    mcp = create_server()
    mcp.run()


if __name__ == "__main__":
    main()
