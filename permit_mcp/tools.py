"""MCP 工具定义：全国排污许可证公开端全量数据读取。"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from fastmcp import FastMCP

from . import config
from .client import PermitClient, resolve_region
from .local_store import get_record as _local_get_record
from .local_store import search as _local_search
from .local_store import stats as _local_stats
from .parser import (decrypt_point_data, parse_announce_list, parse_license_detail,
                     parse_license_list, parse_laws_list, parse_news_detail,
                     parse_news_list, parse_post_permit_status)


# ------------------------------------------------------------------
# OCR 结果来源标注（2026-09-28 第二轮深度测试补充）
#
# 实测背景：permit_pub_license_profile 早期版本把平台 summary 里的
# 「大气主要污染物种类」（全厂 12 种汇总清单）按 OCR 行序拆散分配到
# DA001-DA004，产出「DA001 排砷及其化合物、镉及其」这类平台从未声明的
# 对应关系，DA004 的 name 甚至是「常温」（温度列错位到名称列），
# 而返回体是清爽的结构化 JSON、不带任何来源或质量提示
# ——客户端无从分辨「平台字段」与「OCR 猜测」。
#
# 铁律：凡由 OCR 派生的数据输出，必须携带 _provenance 标注，
#      且 _is_official 恒为 False，不得让调用方误当作平台真值。
# ------------------------------------------------------------------
_OCR_PROVENANCE = {
    "_source": "OCR(rapidocr_onnxruntime) 对排污许可证副本页面图片的自动识别与结构化抽取",
    "_trust_level": "derived",
    "_is_official": False,
    "_notice": (
        "本结果来源于对副本扫描图片的自动识别，不是平台结构化字段；"
        "可能存在字符识别错误、表格列错位或跨列串接。"
        "凡用于执法、排污许可审查、限值比对、总量核算等场景，"
        "必须回到 permit_pub_license_detail / permit_pub_discharge_points "
        "等平台接口核实，或直接核对副本原件。"
    ),
}


def _ocr_provenance(extra=None):
    d = dict(_OCR_PROVENANCE)
    if extra:
        d.update(extra)
    return d


# ===== 写入安全护栏（2026-09-28 深度测试修复）=====
# permit_pub_download_page 会用 open(output_path,"wb") 写盘，而本服务以 root 运行。
# 实测外部可通过该工具写入任意路径（/root/*、源码目录、路径穿越），构成任意文件写。
# 收口为：必须落在白名单根目录 + 扩展名白名单。
_DOWNLOAD_ROOT = os.environ.get(
    "ECO_PERMIT_DOWNLOAD_DIR", "/opt/pollution-permit-mcp/downloads")
_ALLOW_EXT = (".png", ".jpg", ".jpeg", ".pdf")


def _safe_output_path(path: str) -> str:
    """把 output_path 限制在下载根目录内；返回规范化后的绝对路径。"""
    p = os.path.abspath(os.path.expanduser((path or "").strip()))
    root = os.path.abspath(_DOWNLOAD_ROOT)
    if os.path.commonpath([p, root]) != root:
        raise ValueError(
            "output_path 必须位于下载目录 %s 内（禁止目录穿越 / 写系统路径）" % root)
    ext = os.path.splitext(p)[1].lower()
    if ext not in _ALLOW_EXT:
        raise ValueError("output_path 扩展名必须是 %s（当前：%s）"
                         % ("/".join(_ALLOW_EXT), ext or "无扩展名"))
    os.makedirs(os.path.dirname(p) or root, exist_ok=True)
    return p


def _check_page(page: int) -> int:
    """分页边界收口（2026-09-28）：page<1 与超大页码都不该交给上游慢慢扛。"""
    try:
        p = int(page)
    except (TypeError, ValueError):
        raise ValueError("page 必须是整数，当前：%r" % (page,))
    if p < 1:
        raise ValueError("page 必须 >= 1，当前：%d" % p)
    if p > 10000:
        raise ValueError(
            "page=%d 超出公开端分页上限 10000；请改用 registerentername / xkznum 缩小范围" % p)
    return p


_client: PermitClient | None = None


def get_client() -> PermitClient:
    global _client
    if _client is None:
        _client = PermitClient()
    return _client


def _out(data: Any) -> str:
    """统一输出为紧凑 JSON 字符串（兼容 MCP 文本返回）。"""
    return json.dumps(data, ensure_ascii=False, indent=1)


import re  # 2026-10-03（留言板 #37）：错误信息净化用

# ---- 2026-10-03 修复（留言板 #37）：上游错误信息净化 ----
# 上游异常报文里常带完整内部 URL（xkgkAction!xkgk.action?...）与 500 状态码，
# 直接抛给调用方既难读又泄露内部地址。统一转成友好文案。
_URL_RE = re.compile(r"https?://\S+|[A-Za-z0-9_!\-]+\.action\S*|\b\d{3}\s*Server Error\b")


def _sanitize_err(s: str) -> str:
    t = _URL_RE.sub("[上游地址已省略]", str(s))
    t = re.sub(r"\s+", " ", t).strip()
    return t[:160]


def _valid_dataid(dataid: str) -> bool:
    """平台 dataid 为 32 位十六进制。"""
    d = (dataid or "").strip()
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", d))


def _local_note(rec: dict) -> dict:
    """本地命中时的来源标注（本地库 = 平台公开端抓取的结构化快照，非实时回源）。"""
    return {
        "source": "local_permit_full",
        "_local_db": rec.get("_local_db"),
        "_snapshot_note": ("本条来自本地全本库（permit_full.db），"
                           "系公开端结构化字段的历史快照，非实时回源；"
                           "如需确认平台最新变更，请用 force 回源或核对平台原件。"),
    }


def _merge_local_meta(payload: dict, rec: dict) -> dict:
    """把本地库命中信息并入工具返回体，保持既有字段结构不变（仅新增标注字段）。"""
    out = dict(payload or {})
    out.update(_local_note(rec))
    return out


def _build_post_permit(dataid: str, main_html: str | None = None) -> dict:
    """证后管理聚合（执行报告+监督执法+自行监测入口），供 post_permit_status 与
    one_paper 共用，避免嵌套调用工具函数导致的脆弱性。

    - 执行报告：近 3 年报告清单（年报/季报）+ 文档链接；
    - 监督执法：zxbg 页真实监督执法表（含 detail_pkid），无记录返回 []；
    - 自行监测：wryjc 平台 iframe 在主页 getxxgkContent，main_html 已取到则复用，
      否则现抓一次。
    """
    import datetime
    import re as _re
    _c = get_client()
    # 1) 执行报告清单（近 3 年，带文档链接）
    reports = []
    now_year = datetime.date.today().year
    for year in range(now_year, now_year - 3, -1):
        try:
            resp = _c.post(config.URL_ZXBG_YEAR,
                           data={"reportYear": str(year), "dataid": dataid})
            rows = json.loads(resp)
        except Exception:  # noqa: BLE001
            rows = []
        for r in rows:
            reports.append({"year": str(year), "type": r.get("type"),
                            "report_time": r.get("reportTime"),
                            "doc_url": r.get("docUrl")})
    # 2) 监督执法 + 自行监测（zxbg 三合一页）
    supervision: list = []
    monitoring_url = None
    monitoring_note = ("自行监测信息由全国污染源监测信息管理共享平台提供"
                       "（wryjc.mee.gov.cn）")
    try:
        zxbg = _c.get(config.URL_LICENSE_DETAIL,
                      params={"xkgk": "getxxgkContentzxbg", "dataid": dataid})
        from .parser import parse_post_permit_status
        _post = parse_post_permit_status(zxbg)
        supervision = _post.get("supervision") or []
        monitoring_note = _post.get("monitoring_note") or monitoring_note
        # 自行监测 iframe 在主页，复用已抓的 main_html
        if main_html is None:
            main_html = _c.get(config.URL_LICENSE_DETAIL,
                               params={"xkgk": "getxxgkContent", "dataid": dataid})
        _m = _re.search(r'<iframe[^>]+src="(https://wryjc\.mee\.gov\.cn[^"]+)"',
                        main_html)
        if _m:
            monitoring_url = _m.group(1)
    except Exception as _e:  # noqa: BLE001
        monitoring_note = "监督执法/自行监测页解析失败：%s" % str(_e)[:160]
    return {
        "execution_reports": reports,
        "execution_report_count": len(reports),
        "supervision": supervision,
        "supervision_count": len(supervision),
        "supervision_note": ("该企业平台无监督执法公示记录（属正常：公开端仅公示"
                             "被抽查/核查企业）" if not supervision else ""),
        "monitoring_url": monitoring_url,
        "monitoring_note": monitoring_note,
        "source": ("全国排污许可证管理信息平台公开端 · 证后管理"
                   "（执行报告+监督执法+自行监测）"),
    }


def register_tools(mcp: FastMCP) -> None:
    c = get_client()

    @mcp.tool()
    def permit_pub_search_licenses(
        registerentername: str = "",
        xkznum: str = "",
        management: str = "",
        province: str = "",
        city: str = "",
        page: int = 1,
    ) -> str:
        """按企业名/许可证编号/管理类别/省份/城市分页查询全国排污许可证（公开端，无需登录）。

        2026-09-28 补充：page 已做 [1, 10000] 边界收口。此前越界页码会让平台
        慢速吐出超大响应，单次调用实测阻塞 549~584 秒且最终返回无意义的
        「content already consumed」，等于把 MCP 工作线程占死。

        实测平台参数能力边界（2026-08-30 验证）：
        - registerentername：企业名称关键字（子串匹配）✅ 生效，如 "湖南" 命中 484 页
        - xkznum：排污许可证编号（精确匹配）✅ 生效
        - management：管理类别，仅接受代码 "1"=重点管理 / "0"=简化管理（传中文无效）✅ 生效
        - page：页码，从 1 开始 ✅ 生效

        ⚠️ treadname（行业）参数平台已失效，勿用；省/市过滤请用 province/city 参数
        （接受中文省市名，内部自动映射为平台 regioncode，2026-09-28 实测生效：
        province=广西 返回广西企业、province=湖南 返回湖南企业）。
        若同时用 registerentername 则平台按 AND 组合过滤（子串+省市）。
        """
        page = _check_page(page)
        # 管理类别：兼容中文映射到平台代码（1=重点 / 0=简化）
        _mgmt_map = {"重点管理": "1", "简化管理": "0", "重点": "1", "简化": "0"}
        mgmt = _mgmt_map.get(management, management)
        p_code, c_code = resolve_region(province, city)
        # 2026-10-01 修复（AI 调用方建议 1.2）：省/市过滤传了但未匹配到对应行政代码时，
        # 此前静默忽略（如 city="冷水江" 县级市 → c_code 空 → 退化为全国 38237 页），
        # AI 误以为拿到的是本地企业。现显式报错 + 提示改用企业名关键字或地级市。
        if (province or "").strip() and not p_code:
            return _out({"error": "未匹配到省份「%s」" % province, "count": 0,
                         "page_count": 0,
                         "hint": "请使用省级行政区名（如「湖南」「广西」「广东」）；"
                                 "区县级请改用 registerentername 关键字或地级市 city 过滤"})
        if (city or "").strip() and not c_code:
            return _out({"error": "未匹配到地级市「%s」" % city, "count": 0,
                         "page_count": 0,
                         "hint": "平台仅支持地级市过滤（如「娄底市」「长沙市」）；"
                                 "县级市/区县请改用 registerentername 关键字（如「冷水江」）"
                                 "或传 province 过滤"})
        filters = {
            "registerentername": registerentername, "xkznum": xkznum,
            "management": mgmt,
        }
        if p_code:
            filters["province"] = p_code
        if c_code:
            filters["city"] = c_code
        # 翻页优先级：本地索引 > 翻页缓存 > 回源上游（深翻页根治；来源见 result.source）
        try:
            payload, _, source = c.search_licenses_paged(filters, page)
        except Exception as _e:
            # 2026-10-27：上游被风控/超时时降级到本地全本库（permit_full.db），
            # 但必须如实标注覆盖范围——本地快照只含娄底市 862 家，不是全国/全省全量，
            # 不能让调用方把「本地没有」误读成「全省没有」。
            _lp = None
            try:
                _lp = _local_search(kw=(registerentername or "").strip(),
                                    city=(city or "").strip(),
                                    province=(province or "").strip(),
                                    page=page)
            except Exception:  # noqa: BLE001
                _lp = None
            if _lp and _lp.get("count"):
                _lp["cache"] = True
                _lp["source"] = "local_permit_full"
                _lp["_degraded_from"] = "upstream_failed"
                _lp["_upstream_error"] = str(_e)[:120]
                _lp["_scope_note"] = (
                    "上游平台本次查询失败（风控/超时），已降级为本地全本库快照。"
                    "本地快照覆盖范围＝娄底市 %d 家持证企业，非全国/全省全量；"
                    "「未命中」只代表本地快照没有，不代表平台没有。"
                    % (_local_stats().get("total") or 0))
                return _out(_lp)
            # 2026-09-28：上游（permit.mee.gov.cn）接口异常时返回明确错误，
            # 避免异常穿透到 FastMCP 层被包装成「content already consumed」误导排查。
            return _out({"error": "上游全国排污许可平台查询失败：%s" % str(_e)[:120],
                         "_transient": True, "source": "upstream_failed",
                         "cache": False, "hint": "可稍后重试或改用已缓存的企业名查询"})
        if source == "local_db":
            result = payload
        else:
            result = parse_license_list(payload)
        result["cache"] = (source != "upstream")
        result["source"] = source

        # ---- 2026-10-03 修复（留言板 #32）：空参不再静默返回全国 ----
        # 此前不传任何过滤条件即返回全国 38240 页，调用方毫无察觉，
        # 会误以为拿到的是「本地/本省」清单。现显著标注为全库浏览。
        _no_filter = not any(
            (str(filters.get(k) or "")).strip()
            for k in ("registerentername", "xkznum", "management", "province", "city"))
        if _no_filter:
            result["mode"] = "全库浏览"
            result["warning"] = ("当前未传任何过滤条件，返回的是【全国】排污许可证清单，"
                                 "并非某省/某市数据；请补充 registerentername / xkznum / "
                                 "province / city 中至少一个条件以缩小范围。")
            result["_notice"] = {"no_filter": True, "scope": "全国",
                                 "hint": "建议至少传 province（如「湖南」）或 registerentername 关键字"}

        # ---- 2026-10-03 修复（留言板 #31）：企业简称搜不到 ----
        # 平台 registerentername 仅支持【子串匹配】，无别名字段，
        # 「华菱湘钢」这类简称命中不了全称「湖南华菱湘潭钢铁有限公司」。
        # 零命中时：① 明确说明原因与改用全称/核心字号的做法；
        #          ② 用「核心字号」（前 2~4 字）自动降级重试一次，命中则回带候选。
        try:
            _nm = (registerentername or "").strip()
            if _nm and int(result.get("count") or 0) == 0:
                result["hint"] = ("平台按【子串匹配】检索营业执照全称，不支持简称/别名。"
                                  "请用全称，或改用更短的核心字号（如「%s」）重试。"
                                  % (_nm[:2] if len(_nm) > 2 else _nm))
                _core = _nm[:2] if len(_nm) >= 3 else ""
                if _core and _core != _nm:
                    try:
                        _p2, _, _s2 = c.search_licenses_paged(
                            dict(filters, registerentername=_core), 1)
                        # cache 源命中的是「已解析 dict」，再喂 parse_license_list 会丢 items
                        _r2 = _p2 if isinstance(_p2, dict) else parse_license_list(_p2)
                        if not isinstance(_r2, dict):
                            _r2 = {}
                        _n2 = int(_r2.get("count") or 0)
                        if _n2:
                            _pool2 = (_r2.get("items") or _r2.get("results")
                                      or _r2.get("list") or [])
                            _sample = []
                            for _x in _pool2[:8]:
                                if not isinstance(_x, dict):
                                    continue
                                _s = (str(_x.get("company_name") or _x.get("name")
                                          or _x.get("registerentername") or "")).strip()
                                if _s:
                                    _sample.append(_s)
                            _sample = _sample[:5]
                            _sg = {"retry_keyword": _core, "count": _n2}
                            if _sample:
                                _sg["matched_names"] = _sample
                                _sg["hint"] = ("已用核心字号「%s」重试命中 %d 条，"
                                               "请从中选择营业执照全称再查详情。" % (_core, _n2))
                            else:
                                _sg["hint"] = ("核心字号「%s」可命中 %d 条（本次未回带名单），"
                                               "请改用该关键词再查一次以获取全称。" % (_core, _n2))
                            result["suggestion"] = _sg
                    except Exception:
                        pass
        except Exception:
            pass
        return _out(result)

    # ---------- 1b. 区域/周边持证排污单位清单（2026-10-03 新增） ----------
    @mcp.tool()
    def permit_pub_nearby_enterprises(
        province: str = "",
        city: str = "",
        keyword: str = "",
        management: str = "",
        max_pages: int = 3,
        center_lat: float = 0.0,
        center_lon: float = 0.0,
        radius_km: float = 0.0,
        max_coord_lookups: int = 20,
    ) -> str:
        """检索某区域/某点周边的**持证排污单位**清单（官方公开端口径）。

        🔴 这是「找周边企业 / 附近排污单位 / 某区域内有哪些排污企业」的**首选工具**。
        地图 POI（高德等）只能给出工商点位，**没有持证状态、许可证编号、行业类别、
        重点/简化管理类别、有效期** —— 执法与溯源场景必须用本工具，不要用 POI 代替。

        两种用法：
        ① 行政区划口径（推荐，快）：传 province / city，如 city="娄底市"；
           县市区/乡镇级平台无区划过滤 → 改用 keyword（如 keyword="冷水江"）。
        ② 空间半径口径（慢，要逐家取排放口坐标）：额外传 center_lat/center_lon/radius_km，
           仅对前 max_coord_lookups 家企业解密排放口坐标后按距离过滤。

        Args:
            province: 省名（如「湖南」）
            city: 地级市名（如「娄底市」），平台仅支持地级市
            keyword: 企业名关键字（子串匹配，平台无别名字段）；县市区请用此参数
            management: 管理类别，「重点管理」/「简化管理」或平台代码 "1"/"0"
            max_pages: 最多翻页数（每页 10 条），默认 3，上限 10
            center_lat / center_lon: 中心点经纬度（十进制），用于半径过滤，不给则不做
            radius_km: 半径（公里），>0 且给了中心点才启用
            max_coord_lookups: 半径过滤时最多取多少家的排放口坐标（默认 20，上限 60）

        Returns:
            items[]：province/city/company_name/license_no/industry/manage_type/
            valid_period/dataid；启用半径过滤时额外带 distance_km / 最近排放口坐标。
            未取坐标的企业一律标注 coord_status="未定位"，**不静默排除**。
        """
        import math
        from .structured import build_outlet_coords

        max_pages = max(1, min(int(max_pages or 1), 10))
        max_coord_lookups = max(1, min(int(max_coord_lookups or 20), 60))
        _mgmt_map = {"重点管理": "1", "简化管理": "0", "重点": "1", "简化": "0"}
        mgmt = _mgmt_map.get(management, management)
        p_code, c_code = resolve_region(province, city)
        if (province or "").strip() and not p_code:
            return _out({"error": "未匹配到省份「%s」" % province, "count": 0,
                         "hint": "请用省级行政区名（如「湖南」）"})
        if (city or "").strip() and not c_code:
            return _out({"error": "未匹配到地级市「%s」" % city, "count": 0,
                         "hint": "平台仅支持地级市过滤；县市区请改用 keyword 参数"})
        filters = {"registerentername": keyword, "xkznum": "", "management": mgmt}
        if p_code:
            filters["province"] = p_code
        if c_code:
            filters["city"] = c_code

        items, pages_done, total_pages, err = [], 0, 0, ""
        for pg in range(1, max_pages + 1):
            try:
                payload, _, source = c.search_licenses_paged(dict(filters), pg)
            except Exception as _e:  # noqa: BLE001
                err = "上游查询失败：%s" % str(_e)[:120]
                break
            res = payload if source == "local_db" else parse_license_list(payload)
            if not isinstance(res, dict):
                res = {}
            total_pages = int(res.get("total_pages") or res.get("page_count") or 0) or total_pages
            _pool = (res.get("items") or res.get("results") or res.get("list") or [])
            if not _pool:
                break
            for it in _pool:
                if isinstance(it, dict) and it.get("company_name"):
                    items.append(it)
            pages_done = pg
            if len(_pool) < 10:
                break

        # 去重（多页可能重复）
        seen, uniq = set(), []
        for it in items:
            k = (it.get("license_no") or "") + "|" + (it.get("company_name") or "")
            if k in seen:
                continue
            seen.add(k)
            uniq.append(it)
        items = uniq

        out = {
            "检索口径": "官方公开端持证清单（permit.mee.gov.cn），非地图 POI",
            "过滤条件": {"province": province, "city": city, "keyword": keyword,
                         "management": management},
            "已翻页": pages_done, "总页数": total_pages,
            "count": len(items),
        }

        # ---- 半径过滤（可选，逐家取排放口坐标，慢）----
        do_radius = (radius_km and radius_km > 0
                     and center_lat and center_lon
                     and abs(center_lat) <= 90 and abs(center_lon) <= 180)
        if do_radius:
            def _hav(lat1, lon1, lat2, lon2):
                R = 6371.0
                p1, p2 = math.radians(lat1), math.radians(lat2)
                dp = p2 - p1
                dl = math.radians(lon2 - lon1)
                a = (math.sin(dp / 2) ** 2
                     + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
                return 2 * R * math.asin(min(1.0, math.sqrt(a)))

            looked, kept, failed = 0, [], 0
            for it in items:
                if looked >= max_coord_lookups:
                    it = dict(it)
                    it.setdefault("coord_status", "未定位")
                    kept.append(it)
                    continue
                looked += 1
                try:
                    oc = build_outlet_coords(c, it.get("dataid") or "")
                    pts = (oc or {}).get("points") or []
                except Exception:  # noqa: BLE001
                    pts = []
                    failed += 1
                best = None
                for p in pts:
                    try:
                        la, lo = float(p.get("latitude")), float(p.get("longitude"))
                    except (TypeError, ValueError):
                        continue
                    if not (-90 <= la <= 90 and -180 <= lo <= 180):
                        continue
                    d = _hav(center_lat, center_lon, la, lo)
                    if best is None or d < best[0]:
                        best = (d, la, lo)
                it = dict(it)
                if best:
                    it["distance_km"] = round(best[0], 2)
                    it["nearest_outlet"] = {"latitude": best[1], "longitude": best[2]}
                    it["coord_status"] = "已定位"
                    if best[0] <= radius_km:
                        it["within_radius"] = True
                        kept.append(it)
                    else:
                        it["within_radius"] = False
                else:
                    it["coord_status"] = "未定位（无排放口坐标）"
                    it["within_radius"] = None
                # 未定位的也要保留在结果里，但标注清楚（不静默排除）
                if it.get("coord_status", "").startswith("未定位"):
                    if it not in kept:
                        kept.append(it)
            inside = [x for x in kept if x.get("within_radius") is True]
            inside.sort(key=lambda x: x.get("distance_km", 9e9))
            for x in kept:
                if x.get("within_radius") is not True:
                    inside.append(x)
            items = inside
            out["半径过滤"] = {
                "center": {"lat": center_lat, "lon": center_lon},
                "radius_km": radius_km,
                "已取坐标家数": looked,
                "坐标解密失败": failed,
                "半径内家数": sum(1 for x in items if x.get("within_radius") is True),
                "未定位家数": sum(1 for x in items
                                  if str(x.get("coord_status") or "").startswith("未定位")),
                "提示": ("未定位 = 本次未取到排放口坐标，未参与半径判定，"
                         "不能据此认定在半径外；需要精确判定请单独调 "
                         "permit_pub_outlet_coords(dataid)"),
            }
        else:
            for it in items:
                it.setdefault("coord_status", "未定位")
            if radius_km or center_lat or center_lon:
                out["半径过滤"] = {"状态": "未启用",
                                   "原因": "需同时给出 center_lat / center_lon / radius_km>0"}
        if err:
            out["error"] = err
        out["items"] = items
        if not items:
            out["hint"] = ("零命中：平台按【子串匹配】检索营业执照全称，不支持简称；"
                           "县市区请改用 keyword（如「冷水江」），或改用所属地级市 city。")
        return _out(out)

    # ---------- 2. 许可证详情 ----------
    @mcp.tool()
    def permit_pub_license_detail(dataid: str) -> str:
        """获取企业排污许可证详情：基本信息、许可证正本版本、副本摘要、经纬度、排放口点位。

        Args:
            dataid: 数据 ID（由 search_licenses 返回，32 位十六进制）
        """
        # 2026-10-03 修复（留言板 #37）：dataid 非法/失效时不再抛上游 500 与内部 URL
        if not _valid_dataid(dataid):
            return _out({"error": "dataid 无效：应为 32 位十六进制字符串（由 "
                                  "permit_pub_search_licenses 返回）",
                         "dataid": dataid, "count": 0,
                         "hint": "请先用 permit_pub_search_licenses 查到企业的 dataid 再查详情"})
        # 2026-10-27 离线优先：本地全本库命中则直接返回（上游对云端出口风控时仍可用）
        # 本地命中但 basic 为空（采集期真实缺失）时如实标注，不回落回源
        # ——回源在风控期挂死 90~160s，且「本地为空」不等于「平台为空」。
        _rec = _local_get_record(dataid)
        if _rec:
            _b = _rec.get("basic")
            if not _b or not _b.get("company_name"):
                _b = {"error": "本地快照无基本信息（采集期该企业详情页未取到）",
                      "dataid": dataid,
                      "company": _rec.get("company"),
                      "license_no": _rec.get("license_no")}
            return _out(_merge_local_meta(_b, _rec))
        try:
            html = c.get(config.URL_LICENSE_DETAIL,
                         params={"xkgk": "getxxgkContent", "dataid": dataid})
        except Exception as _e:
            return _out({"error": "上游全国排污许可平台查询失败（已省略内部地址）：%s"
                                  % _sanitize_err(_e),
                         "dataid": dataid, "count": 0, "_transient": True,
                         "hint": "该 dataid 可能已失效或平台暂时不可用，请核实后重试"})
        if not html or (isinstance(html, str) and len(html.strip()) < 200):
            return _out({"error": "该 dataid 未查询到有效许可证内容（可能已失效/已注销）",
                         "dataid": dataid, "count": 0,
                         "hint": "请先用 permit_pub_search_licenses 重新获取最新 dataid"})
        try:
            return _out(parse_license_detail(html))
        except Exception as _e:
            return _out({"error": "许可证详情解析失败：%s" % _sanitize_err(_e),
                         "dataid": dataid, "count": 0,
                         "hint": "该 dataid 返回内容非标准许可证页面，可能已失效"})

    # ---------- 3. 副本图片页列表 ----------
    @mcp.tool()
    def permit_pub_license_pages(dataid: str) -> str:
        """获取排污许可证副本图片清单（页数与每页 datafileid），供 OCR 还原全文。

        Args:
            dataid: 数据 ID
        """
        # 2026-10-03（留言板 #37）：dataid 校验 + 异常净化，不外泄上游地址
        if not _valid_dataid(dataid):
            return _out({"error": "dataid 无效：应为 32 位十六进制字符串",
                         "total_pages": 0, "pages": []})
        try:
            html = c.get(config.URL_LICENSE_IMAGE_LIST, params={"dataid": dataid})
        except Exception as _e:
            return _out({"error": "上游查询失败（已省略内部地址）：%s" % _sanitize_err(_e),
                         "total_pages": 0, "pages": [], "_transient": True})
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        img_count = soup.find("input", {"id": "imgCount"})
        pkid = soup.find("input", {"id": "pkid"})
        if img_count is None or pkid is None:
            return _out({"total_pages": 0, "pages": [], "error": "页面未找到 imgCount/pkid"})
        n = int(img_count.get("value") or 0)
        pid = pkid.get("value") or ""
        pages = [{"page": i + 1, "datafileid": f"{pid}_{i + 1}"} for i in range(n)]
        return _out({"total_pages": n, "pkid": pid, "pages": pages})

    # ---------- 2b. 企业画像（版本指纹+缓存+只留结构化） ----------
    @mcp.tool()
    def permit_pub_license_profile(dataid: str, force: bool = False) -> str:
        """查询企业排污许可证完整画像（按需惰性：仅在首次查询或平台数据更新时下载+OCR）。

        机制：
        1) 版本指纹比对（详情接口版本链最新 version+finish_date）；
        2) 缓存命中且指纹一致 → 直接返回结构化缓存（秒回，零下载零OCR）；
        3) 首次查询 / 指纹变化（企业有变更/延续）→ 下载关键表页(3基本信息/5表1/6排放口/7+限值)
           → OCR → 结构化抽取（法人/电话/排放口/限值行）→ 写缓存 → 临时图片立即删除；
        4) 缓存只存结构化 JSON，OCR 原文与图片不保留。

        Args:
            dataid: 数据 ID（permit_pub_search_licenses 返回）
            force: True=忽略缓存强制重新下载+OCR（平台刚更新但版本链未刷新时用）
        """
        from .profile_engine import build_profile
        import concurrent.futures as _cf

        # C. 时间预算：首次构建要走「下载关键表页 -> pdftoppm -> RapidOCR 推理」，
        #    实测在负载偏高的机器上超 180s 仍不返回，期间占死 MCP 工作线程。
        #    这里套硬预算，超时降级返回（后台线程继续并把缓存写好）。
        budget = float(getattr(config, "PROFILE_BUILD_TIMEOUT", 240))
        _pool = _cf.ThreadPoolExecutor(max_workers=1)
        _fut = _pool.submit(build_profile, dataid, c, config,
                            permit_pub_license_detail, force=force)
        _pool.shutdown(wait=False)
        try:
            res = _fut.result(timeout=budget)
        except Exception as _e:
            return _out({
                "_incomplete": True,
                "_budget_sec": budget,
                "_error": "画像构建在 %gs 预算内未完成（%r）" % (budget, _e),
                "_hint": "后台仍在继续构建，完成后写入缓存；请稍后重试，命中缓存后秒回。",
                "_provenance": _ocr_provenance(),
            })

        if isinstance(res, dict):
            res = dict(res)
            # 2026-10-02：结构化直读（明文模块 + AES 坐标）与 OCR 是两条
            # 完全不同的数据链，来源标注必须跟着变，否则下游会把平台真值
            # 当成「OCR 猜测」弃用，或反过来把 OCR 串列当真值。
            _bm = ((res.get("profile") or {}).get("meta") or {}).get("build_mode")
            if _bm == "platform_structured":
                res["_provenance"] = {
                    "_source": ("全国排污许可证管理平台公开端明文 HTML 模块"
                                "（approveWater_xkzgk / approveAtmosphere_xkzgk）"
                                " + getxxgkContent 页 AES 坐标解密"),
                    "_trust_level": "official",
                    "_is_official": True,
                    "_fields_official": ["meta", "basic.company_name", "summary",
                                         "versions", "coordinates",
                                         "air.organized_limits", "water.limits"],
                    "_fields_unavailable": ["basic（法定代表人/电话等仅印在副本原件上，"
                                            "平台无对应结构化字段）",
                                            "ledger / reports / disclosure / "
                                            "solid_waste / noise / changes"],
                    "_field_guide": ("限值与坐标取自平台明文字段，无 OCR 识别误差；"
                                     "上述字段平台侧未提供，为空属正常，"
                                     "需原件可用 permit_pub_ocr_license。"),
                }
            else:
                res["_provenance"] = _ocr_provenance({
                    "_fields_official": ["coordinates", "summary", "versions",
                                         "basic.license_no", "basic.company_name"],
                    "_fields_ocr_derived": ["air", "water", "monitoring", "ledger",
                                            "reports", "disclosure", "solid_waste",
                                            "noise", "changes"],
                    "_field_guide": ("coordinates/summary/versions 取自平台详情接口；"
                                     "其余全部由 OCR 行序抽取，表格复杂处可能串列。"),
                })
        return _out(res)

    # ---------- 2c. 结构化限值（免 OCR，替代逐页 OCR 读取）----------
    @mcp.tool()
    def permit_pub_structured_limits(
            dataid: str, media: str = "all", with_numeric: bool = False) -> str:
        """读取排污许可证许可限值表（结构化，秒级，无需 OCR）—— 执法/限值比对首选。

        数据来源：全国排污许可证管理平台公开端的**明文 HTML 模块**
        （approveWater_xkzgk / approveAtmosphere_xkzgk），由服务端渲染，
        与副本扫描件 OCR 完全同源且零识别误差。

        Args:
            dataid: 数据 ID（由 permit_pub_search_licenses 返回）
            media: all=水+大气（默认）；water=仅水污染物；air=仅大气污染物
            with_numeric: True=额外输出 *_value / *_unit 数值视图（默认关，
                          开启后返回体约 3 倍，用于批量程序化比对）

        Returns:
            outlets[]：每条 = 一个排放口的一种污染物限值，字段
            outlet_no（排放口编号）/ outlet_name（排放口名称）/ pollutant（污染物种类）/
            conc_hour（小时浓度限值）/ conc_daily（日均浓度限值）/
            rate_kg_h（速率 kg/h）/ annual_t_a（年排放量 t/a）/ media / table
            浓度值保留平台原文含单位（如 "10mg/Nm3"）；平台留空（只剩单位串
            如 "mg/Nm3"）一律返回 null，不会冒充限值。
        """
        from .structured import build_structured_limits
        # 2026-10-27 离线优先：本地全本库命中则直接返回（不回源）。
        # 本地命中但限值为空（采集期真实缺失，如大体量多排放口企业）时，
        # 如实返回「本地快照无此模块」，不再回落回源——回源在云端出口风控期
        # 会挂死 90~160s，把一次查询拖到超时；且本地为空≠平台为空。
        _rec = _local_get_record(dataid)
        if _rec:
            _lp = dict(_rec.get("limits") or {})
            if not _lp.get("outlets"):
                _lp = {"dataid": dataid, "outlets": [], "outlet_count": 0,
                       "error": "本地快照无结构化限值（采集期该企业限值模块未取到）",
                       "_fallback_hint": ("可用 permit_pub_ocr_license 对副本原件 OCR 兜底；"
                                         "或改用 permit_pub_license_one_paper 看全本聚合。")}
                return _out(_merge_local_meta(_lp, _rec))
            if media and media != "all":
                _outs = _lp.get("outlets") or []
                _f = [o for o in _outs if (o or {}).get("media") == media]
                _lp["outlets"] = _f
                _lp["outlet_count"] = len(_f)
                _lp["_media_filter_applied"] = media
            if with_numeric and not _lp.get("_numeric_requested"):
                _lp["_numeric_hint"] = ("本地快照未带数值视图；如需 *_value/*_unit "
                                         "数值视图，请回源调用或用 permit_pub_license_one_paper"
                                         "(with_numeric=True)。")
            return _out(_merge_local_meta(_lp, _rec))
        try:
            payload = build_structured_limits(c, dataid, media, with_numeric)
        except Exception as _e:  # noqa: BLE001
            return _out({"dataid": dataid, "error": "结构化限值读取失败：%s"
                         % str(_e)[:200], "outlets": [], "outlet_count": 0})
        if payload.get("error"):
            # 结构化缺失 → 交给调用方决定是否回退 OCR，不在本工具内静默降级
            payload["_fallback_hint"] = (
                "结构化模块为空；可用 permit_pub_ocr_license 对副本原件 OCR 兜底")
        return _out(payload)

    # ---------- 2d. 排放口坐标（AES 解密，免 OCR）----------
    @mcp.tool()
    def permit_pub_outlet_coords(dataid: str) -> str:
        """读取排污许可证全部排放口经纬度坐标（AES 解密，秒级，无需 OCR）。

        数据来源：平台详情页内联的 `var pwd` + `var word` 密文，
        AES-128-ECB / Pkcs7 解密后即排放口点位表，含废水/大气分类。

        Args:
            dataid: 数据 ID

        Returns:
            points[]：icon（平台原始图标键）/ icon_class（wastewater|air|
            project_site|noise|other）/ icon_label（中文档别类）/
            longitude / latitude（十进制）/ lng_dms / lat_dms（度分秒整数部分）
            counts_by_class：按类别统计个数。
        """
        from .structured import build_outlet_coords
        # 2026-10-27 离线优先：本地全本库命中则直接返回
        _rec = _local_get_record(dataid)
        if _rec:
            _co = _rec.get("coords") or {}
            if not _co.get("points"):
                _co = {"dataid": dataid, "points": [], "point_count": 0,
                       "error": "本地快照无排放口坐标（采集期该企业坐标未取到）"}
            return _out(_merge_local_meta(_co, _rec))
        try:
            return _out(build_outlet_coords(c, dataid))
        except Exception as _e:  # noqa: BLE001
            return _out({"dataid": dataid, "error": "坐标解密失败：%s"
                         % str(_e)[:200], "points": [], "point_count": 0,
                         "_transient": True})

    # ---------- 3b. 副本 OCR 全文读取 ----------
    @mcp.tool()
    def permit_pub_ocr_license(dataid: str, start_page: int = 1, end_page: int = 1) -> str:
        """下载并 OCR 排污许可证副本指定页，返回全文文本（含法定代表人、联系电话、
        排放口参数、许可限值等表内数据；2026-09-28 新增，穿透到副本图片内容）。

        Args:
            dataid: 数据 ID（由 permit_pub_search_licenses 返回）
            start_page: 起始页（副本第1页=封面），默认 1
            end_page: 结束页（含），默认 1；单次最多 10 页，超过自动截断为 10 页
        """
        import os as _os
        from .ocr_engine import ocr_to_text

        # D. 边界收口：此前负值/非整数会一路打到 range()
        try:
            start_page = int(start_page)
            end_page = int(end_page)
        except (TypeError, ValueError):
            return _out({"error": "start_page/end_page 必须是整数"})
        if start_page < 1:
            return _out({"error": "start_page 必须 >= 1（副本第 1 页=封面），收到 %s"
                                  % start_page})
        if end_page < start_page:
            return _out({"error": "end_page(%s) 不能小于 start_page(%s)"
                                  % (end_page, start_page)})
        end_page = min(end_page, start_page + 9)
        # 拿副本页列表（pkid + 页数）
        # 2026-10-03（留言板 #37）：dataid 校验 + 异常净化，不外泄上游地址
        if not _valid_dataid(dataid):
            return _out({"error": "dataid 无效：应为 32 位十六进制字符串",
                         "total_pages": 0, "pages": []})
        try:
            html = c.get(config.URL_LICENSE_IMAGE_LIST, params={"dataid": dataid})
        except Exception as _e:
            return _out({"error": "上游查询失败（已省略内部地址）：%s" % _sanitize_err(_e),
                         "total_pages": 0, "pages": [], "_transient": True})
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        img_count = soup.find("input", {"id": "imgCount"})
        pkid = soup.find("input", {"id": "pkid"})
        n = int((img_count.get("value") or 0) if img_count else 0)
        pid = (pkid.get("value") or "") if pkid else ""
        if n <= 0:
            return _out({"error": "未找到副本图片", "total_pages": 0})
        pages_out = []
        results = []
        _os.makedirs(_DOWNLOAD_ROOT, exist_ok=True)
        for pg in range(start_page, min(end_page, n) + 1):
            datafileid = f"{pid}_{pg}"
            out_path = _os.path.join(_DOWNLOAD_ROOT, f"ocr_{dataid[:8]}_p{pg}.jpg")
            # 复用 permit_pub_download_page 的下载逻辑（含安全路径校验）
            try:
                _dst = _safe_output_path(out_path)
            except ValueError as _e:
                results.append(f"--- 第{pg}页 路径被拒: {_e} ---")
                continue
            try:
                content = c.download(config.URL_LICENSE_IMAGE_PAGE,
                                     params={"datafileid": datafileid, "fileType": "pdffile",
                                             "dataid": dataid})
                with open(_dst, "wb") as f:
                    f.write(content)
            except Exception as _e:
                results.append(f"--- 第{pg}页 下载失败: {_e} ---")
                continue
            if _os.path.getsize(_dst) < 1000:
                results.append(f"--- 第{pg}页 文件异常(可能为空页) ---")
                continue
            text = ocr_to_text(_dst)
            # B. 副本页含法定代表人、联系电话等企业信息，取到文本后立即删除，
            #    不在服务端留存（对齐 profile_engine 的 finally 删图策略）。
            try:
                _os.remove(_dst)
            except Exception:
                pass
            results.append(f"===== 第{pg}页 =====")
            results.append(text)
            pages_out.append(pg)
        return _out({
            "dataid": dataid,
            "pages_processed": pages_out,
            "total_pages": n,
            "text": "\n".join(results),
            "hint": "副本页码结构参考：1封面 2持证须知 3-4基本信息 5表1基本信息 6表2排放口 7+许可限值/许可量/自行监测",
            "_provenance": _ocr_provenance({
                "_detail": "text 为 OCR 按 (行,列) 排序拼接的原文行，不是结构化键值。",
            }),
        })

    # ---------- 4. 副本页图片下载 ----------
    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True,
                           "idempotentHint": False, "openWorldHint": True},
              title="下载许可证副本图片")
    def permit_pub_download_page(dataid: str, datafileid: str, output_path: str) -> str:
        """下载排污许可证副本指定页 PNG 到本地，供 OCR。

        Args:
            dataid: 数据 ID（get_license_pages 返回的 pkid 对应同一许可证）
            datafileid: 形如 <pkid>_<页码> 的文件 ID（get_license_pages 返回）
            output_path: 保存图片的绝对路径
        """
        try:
            _dst = _safe_output_path(output_path)
        except ValueError as _e:
            return _out({"error": "拒绝写入：%s" % _e,
                         "allowed_root": _DOWNLOAD_ROOT,
                         "datafileid": datafileid})
        content = c.download(config.URL_LICENSE_IMAGE_PAGE,
                             params={"datafileid": datafileid, "fileType": "pdffile",
                                     "dataid": dataid})
        with open(_dst, "wb") as f:
            f.write(content)
        return _out({"saved": _dst, "bytes": len(content)})

    # ---------- 5. 排放口二维码 ----------
    @mcp.tool()
    def permit_pub_qrcode_info(dataid: str) -> str:
        """生成排放口二维码（平台二维码接口，内容为许可证详情地址）。

        Args:
            dataid: 数据 ID
        """
        url = f"{config.URL_QRCODE}/{dataid}"
        return _out({"qrcode_url": url, "note": "扫码可查看该企业排污许可公开信息"})

    # ---------- 6. 证后管理状态 ----------
    @mcp.tool()
    def permit_pub_post_permit_status(dataid: str) -> str:
        """获取证后管理实时情况：执行报告（年度/季度报告文档链接）、监督执法信息、自行监测入口。

        数据源：全国排污许可公开端「执行报告+监督执法+自行监测」三合一页面
        (xkgk=getxxgkContentzxbg) + 主页 getxxgkContent（wryjc 自行监测 iframe），
        均为平台公开数据，无需登录。
        - 执行报告：近 3 年报告清单（年报/季报）+ 报告文档公开查看链接；
        - 监督执法信息：核查日期/是否超许可浓度限值/是否落实自行监测要求/处罚情况；
          有核查记录才有行（行内 detail_pkid 供 permit_pub_supervision_detail 取明细），
          无记录属正常（公开端仅公示被抽查/核查企业）；
        - 自行监测：对接全国污染源监测信息管理共享平台（wryjc.mee.gov.cn）。

        Args:
            dataid: 数据 ID（permit_pub_search_licenses 返回）
        """
        if not _valid_dataid(dataid):
            return _out({"error": "dataid 无效：应为 32 位十六进制字符串",
                         "dataid": dataid, "count": 0})
        # 2026-10-27 离线优先：本地全本库已含执行报告清单（2026-10-27 全量普查回填，
        # 829/861 家有执行报告），云端出口被风控时仍可秒回。
        _rec = _local_get_record(dataid)
        if _rec:
            _pp = dict(_rec.get("post_permit") or {})
            _pp.setdefault("execution_reports", [])
            _pp.setdefault("execution_report_count",
                           len(_pp.get("execution_reports") or []))
            return _out(_merge_local_meta(_pp, _rec))
        return _out(_build_post_permit(dataid))

    # ---------- 7. 限期整改 ----------
    @mcp.tool()
    def permit_pub_rectification_list(province: str = "", unit_name: str = "",
                                      page: int = 1) -> str:
        """查询限期整改公示列表。

        Args:
            province: 省份（中文名，如「湖南省」；留空=全国）
            unit_name: 单位名称（对应平台「单位名称」字段，模糊匹配）
            page: 页码
        """
        page = _check_page(page)
        # 2026-10-02 修复（企业视角缺陷清单 P2-1）：
        # 原实现传 {"province","unitName","pageIndex","pageSize"}，与平台真实表单字段
        # 完全对不上 —— 实测该页 <form id="mainForm"> 的真实字段为：
        #   page.pageNo / page.orderBy / page.order / province / city /
        #   registerentername / xkznum / treadname / treadcode / publishtime
        # 参数键错 → 平台按默认条件查询 → 恒返回「暂无数据！」（实测空省/湖南省/
        # regioncode 三种传法、全国各省一律 count:0），企业查「我是否被列入整改」
        # 永远为空，且分不清「确无记录」还是「参数没生效」。
        # 另：该列表是**表格**（省/直辖市、地市、整改通知书编号、单位名称、行业类别、
        # 有效期限、下达时间、查看），原用 parse_news_list（只抓 getNewsDetail 链接）
        # 解析，即便上游有数据也解析不出 —— 改用表格解析器 parse_announce_list。
        data = {
            "page.pageNo": page,
            "page.orderBy": "",
            "page.order": "",
            "province": province,
            "city": "",
            "registerentername": unit_name,
            "xkznum": "",
            "treadname": "",
            "treadcode": "",
            "publishtime": "",
        }
        html = c.post(config.URL_RECTIFY_LIST, data=data)
        out = parse_announce_list(html)
        # 空结果如实说明：区分「上游确无记录」与「参数未生效」，避免调用方误读成
        # 「本企业不在限期整改名单内」。本工具传参已按平台真实字段校正。
        if not out.get("items"):
            out["note"] = ("上游返回「暂无数据！」：该查询条件下无记录，或平台该栏目录当前为空。"
                           "注意：本条只说明平台未返回记录，**不能推论**该单位未被列入限期整改。")
            out["source"] = "全国排污许可证管理信息平台 · 限期整改公示"
            out["query"] = {"province": province, "unit_name": unit_name, "page": page}
        return _out(out)

    # ---------- 8. 公告（注销/撤销/遗失） ----------
    @mcp.tool()
    def permit_pub_announcements(announce_type: str = "注销", page: int = 1) -> str:
        """查询排污许可证公告：注销、撤销、遗失声明。

        Args:
            announce_type: 注销 / 撤销 / 遗失
            page: 页码
        """
        page = _check_page(page)
        url = {
            "注销": config.URL_ANNOUNCE_CANCEL,
            "撤销": config.URL_ANNOUNCE_REVOKE,
            "遗失": config.URL_ANNOUNCE_LOST,
        }.get(announce_type)
        if not url:
            return _out({"error": "announce_type 仅支持：注销/撤销/遗失"})
        data = {"province": "", "unitName": "", "pageIndex": page, "pageSize": 20}
        html = c.post(url, data=data)
        return _out(parse_announce_list(html))

    # ---------- 9. 政策法规列表 ----------
    @mcp.tool()
    def permit_pub_policy_docs(category: str = "Law", page: int = 1) -> str:
        """按分类列出环保政策法规/标准目录。

        Args:
            category: Law=法律法规, XKJSGF=许可技术规范, SSHYPFBZ=实施行业排放标准,
                      HYKXJSZN=行业可行技术指南, HYZXJCZN=行业自行监测指南, XKJGYQ=许可监管要求
            page: 页码
        """
        page = _check_page(page)
        data = {"columntype": category, "pageIndex": page, "pageSize": 20}
        html = c.post(config.URL_LAWS_LIST, data=data)
        return _out(parse_laws_list(html))

    # ---------- 10. 政策法规全文 ----------
    @mcp.tool()
    def permit_pub_policy_detail(pkid: str) -> str:
        """获取政策法规/新闻/公告全文（明文正文 + 附件下载链接）。

        Args:
            pkid: 文档 ID（list_policy_docs / get_announcements 返回）
        """
        html = c.get(config.URL_NEWS_DETAIL, params={"pkid": pkid})
        return _out(parse_news_detail(html))

    # ---------- 11. 排放口点位解密（辅助） ----------
    @mcp.tool()
    def permit_pub_discharge_points(dataid: str) -> str:
        """解密并返回企业排放口经纬度点位坐标数组（AES-128-ECB，密钥来自详情页内联脚本）。

        2026-10-19 优化：走坐标库（coords.db）优先——命中 0ms 不回源；
        未命中回源解密后自动落库（30 天 TTL）。返回体为分类增强版
        （points[].icon_class/icon_label + counts_by_class），兼容原 icon/longitude/latitude。

        Args:
            dataid: 数据 ID
        """
        from .structured import build_outlet_coords
        # 2026-10-27 离线优先：本地全本库命中则直接返回
        _rec = _local_get_record(dataid)
        if _rec:
            _co = _rec.get("coords") or {}
            if not _co.get("points"):
                _co = {"dataid": dataid, "points": [], "point_count": 0,
                       "error": "本地快照无排放口坐标（采集期该企业坐标未取到）"}
            return _out(_merge_local_meta(_co, _rec))
        try:
            return _out(build_outlet_coords(c, dataid))
        except Exception as _e:  # noqa: BLE001
            return _out({"dataid": dataid, "error": "坐标解密失败：%s"
                         % str(_e)[:200], "points": [], "point_count": 0,
                         "_transient": True})

    # ---------- 11b. 缓存与风控治理观测（2026-10-19）----------
    @mcp.tool()
    def permit_pub_cache_stats() -> str:
        """缓存与风控治理观测：各层缓存条数、坐标库规模、本地索引进度、风控熔断状态。"""
        import glob as _glob
        import sqlite3 as _sq
        from . import structured as _st
        from .client import LICENSE_DB as _LICDB, risk_cooldown_state
        out = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        try:
            conn = _sq.connect(config.CACHE_DB, timeout=3)
            out["html_cache_rows"] = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            conn.close()
        except Exception as e:  # noqa: BLE001
            out["html_cache_rows"] = "err:%s" % str(e)[:60]
        for key, path in (("page_cache_files", config.PAGE_CACHE_DIR),
                          ("struct_cache_files", str(_st.STRUCT_CACHE_DIR))):
            try:
                out[key] = len([f for f in _glob.glob(os.path.join(path, "*"))
                                if not f.endswith(".tmp")])
            except Exception:  # noqa: BLE001
                out[key] = None
        try:
            conn = _sq.connect(_st.COORD_DB, timeout=3)
            out["coord_db_rows"] = conn.execute("SELECT COUNT(*) FROM coords").fetchone()[0]
            conn.close()
        except Exception:  # noqa: BLE001
            out["coord_db_rows"] = 0
        try:
            conn = _sq.connect(_LICDB, timeout=3)
            out["licenses_db_rows"] = conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
            conn.close()
        except Exception:  # noqa: BLE001
            out["licenses_db_rows"] = 0
        out["risk_cooldown"] = risk_cooldown_state()
        # 2026-10-27：本地全本库（离线能力）规模观测
        try:
            out["local_permit_full"] = _local_stats()
        except Exception as _e:  # noqa: BLE001
            out["local_permit_full"] = {"available": False, "error": str(_e)[:120]}
        return _out(out)

    # ---------- 12. 证后管理监控接口（对接 wryjc 平台） ----------
    @mcp.tool()
    def permit_pub_monitoring_entry(dataid: str) -> str:
        """返回企业自行监测信息对接地址（全国污染源监测信息管理共享平台）。

        Args:
            dataid: 数据 ID
        """
        # 2026-10-27 离线优先：本地全本库已存自行监测平台入口（monitoring_url）
        # 本地命中时不再回源：回源在风控期挂死 90~160s；
        # 本地无 monitoring_url 如实返回「未配置」，并说明这是本地快照结论。
        _rec = _local_get_record(dataid)
        if _rec:
            _pp = _rec.get("post_permit") or {}
            _mu = _pp.get("monitoring_url")
            _note = (_pp.get("monitoring_note")
                     or "自行监测信息由全国污染源监测信息管理共享平台提供（wryjc.mee.gov.cn）")
            if _mu:
                return _out({"monitoring_url": _mu, "note": _note,
                             **_local_note(_rec)})
            return _out({"monitoring_url": None,
                         "note": ("该企业本地快照未配置自行监测信息；"
                                  "如需确认平台最新状态，请回源核对。"),
                         **_local_note(_rec)})
        html = c.get(config.URL_LICENSE_DETAIL, params={"xkgk": "getxxgkContent", "dataid": dataid})
        import re
        m = re.search(r'<iframe[^>]+src="(https://wryjc\.mee\.gov\.cn[^"]+)"', html)
        if m:
            return _out({"monitoring_url": m.group(1),
                         "note": "实时排放数据属自动监控专网，公开端不直接提供；请通过该平台查询"})
        return _out({"monitoring_url": None, "note": "该企业未配置自行监测信息"})

    # ---------- 13. 监督执法记录明细（证后管理闭环）----------
    @mcp.tool()
    def permit_pub_supervision_detail(pkid: str) -> str:
        """获取单条监督执法记录的完整明细（核查日期/是否超许可浓度限值/是否落实自行监测/处罚情况/整改要求等）。

        数据源：公开端 hpsp-company-sewage!showSupervision.action?pkid=<id>
        （permit_pub_post_permit_status 返回的 supervision[].detail_pkid 即此处入口）。

        Args:
            pkid: 监督执法记录 ID（来自 permit_pub_post_permit_status 的 supervision 明细）
        """
        if not (pkid or "").strip():
            return _out({"error": "pkid 不能为空（来自 permit_pub_post_permit_status 的 supervision 明细）"})
        try:
            html = c.get(config.URL_SUPERVISION_DETAIL, params={"pkid": pkid})
        except Exception as _e:  # noqa: BLE001
            return _out({"error": "上游查询失败（已省略内部地址）：%s"
                                 % _sanitize_err(_e), "_transient": True})
        if not html or (isinstance(html, str) and len(html.strip()) < 200):
            return _out({"error": "该 pkid 未查询到监督执法明细（可能已失效）", "pkid": pkid})
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        rows = []
        for tr in soup.find_all("tr"):
            th = tr.find("th")
            td = tr.find("td")
            if th and td:
                rows.append({th.get_text(strip=True).rstrip("：:"):
                             td.get_text(" ", strip=True)})
        if not rows:  # 退化：整页结构化表格缺失时回退纯文本
            import re as _re
            rows = [_re.sub(r"\s+", " ", soup.get_text(" ", strip=True))[:2000]]
        return _out({"pkid": pkid, "detail": rows,
                     "source": "全国排污许可证管理信息平台公开端 · 监督执法信息"})

    # ---------- 14. 排污许可证「一张纸」聚合视图（登记企业全量）----------
    @mcp.tool()
    def permit_pub_license_one_paper(
            dataid: str, include_contacts: bool = False,
            with_numeric: bool = False) -> str:
        """排污许可证「一张纸」聚合视图：点名企业→一次性返回公开端全量结构化信息（执法/监管/溯源首选）。

        聚合自平台公开端明文字段（零 OCR，秒级）：
        ① 基本信息（企业名/地址/行业/管理类别/登记机关/版本谱系/有效期）；
        ② 排放口坐标（AES 解密，企业 + 各排放口经纬度）；
        ③ 许可排放限值（大气+水，结构化，含浓度/速率/年排放量 t/a）；
        ④ 证后管理（执行报告清单+文档链接、监督执法公示、自行监测平台入口）。

        ⚠️ 法定代表人/联系电话、主要排口高度与内径 等仅印在副本原件（平台无结构化字段），
          include_contacts=True 时通过副本图片 OCR 兜底返回，标注 _is_official=False，
          用于执法/限值比对前必须回平台接口或核对原件。

        Args:
            dataid: 数据 ID（permit_pub_search_licenses 返回）
            include_contacts: True=额外 OCR 副本取联系人与排口高度内径（慢，约 3-6s/页，派生数据）
            with_numeric: True=限值额外输出 *_value/*_unit 数值视图

        Returns:
            one_page: {basic, outlet_coords, limits, post_permit, _provenance}
        """
        import re as _re
        import os as _os
        import tempfile
        if not _valid_dataid(dataid):
            return _out({"error": "dataid 无效：应为 32 位十六进制字符串",
                         "dataid": dataid, "hint": "请先用 permit_pub_search_licenses 查到企业的 dataid"})
        out: dict = {}
        # 2026-10-27 离线优先：本地全本库命中 → 直接组装，不触上游
        _rec = _local_get_record(dataid)
        if _rec:
            _b = _rec.get("basic")
            if not _b or not _b.get("company_name"):
                _b = {"error": "本地快照无基本信息（采集期该企业详情页未取到）",
                      "company": _rec.get("company"),
                      "license_no": _rec.get("license_no")}
            out["basic"] = _b
            out["outlet_coords"] = _rec.get("coords") or {"points": [], "point_count": 0}
            _lm = _rec.get("limits") or {}
            if not _lm.get("outlets"):
                _lm = {"outlets": [], "outlet_count": 0,
                       "error": "本地快照无结构化限值（采集期该企业限值模块未取到）"}
            out["limits"] = _lm
            _pp = dict(_rec.get("post_permit") or {})
            _pp.setdefault("execution_reports", [])
            _pp.setdefault("execution_report_count",
                           len(_pp.get("execution_reports") or []))
            out["post_permit"] = _pp
            out["_provenance"] = {
                "_is_official": True,
                "_source": ("本地全本库（permit_full.db）：公开端明文 HTML 模块"
                            "（getxxgkContent / approveAtmosphere_xkzgk / "
                            "approveWater_xkzgk）+ getxxgkContentzxbg + AES 坐标解密"),
                "_fields_official": ["basic", "outlet_coords", "limits", "post_permit"],
                "_note": ("basic/coordinates/limits/post_permit 均来自平台结构化字段，"
                          "无 OCR 误差；本次为本地历史快照，非实时回源。"),
                **_local_note(_rec),
            }
            return _out(out)
        # ① 基本信息 + 坐标 + 版本谱系
        detail_html = None
        try:
            detail_html = c.get(config.URL_LICENSE_DETAIL,
                                params={"xkgk": "getxxgkContent", "dataid": dataid})
            from .parser import parse_license_detail
            out["basic"] = parse_license_detail(detail_html)
        except Exception as _e:  # noqa: BLE001
            out["basic"] = {"error": "基本信息解析失败：%s" % str(_e)[:160]}
        # ② 排放口坐标
        try:
            from .structured import build_outlet_coords
            out["outlet_coords"] = build_outlet_coords(c, dataid)
        except Exception as _e:  # noqa: BLE001
            out["outlet_coords"] = {"error": "坐标解密失败：%s" % str(_e)[:160]}
        # ③ 许可限值（大气+水）
        try:
            from .structured import build_structured_limits
            out["limits"] = build_structured_limits(c, dataid, "all", with_numeric)
        except Exception as _e:  # noqa: BLE001
            out["limits"] = {"error": "限值读取失败：%s" % str(_e)[:160]}
        # ④ 证后管理（执行报告 + 监督执法 + 自行监测）；复用已抓的 detail_html 取 wryjc iframe
        try:
            out["post_permit"] = _build_post_permit(dataid, main_html=detail_html)
        except Exception as _e:  # noqa: BLE001
            out["post_permit"] = {"error": "证后管理读取失败：%s" % str(_e)[:160]}
        # ⑤ 可选 OCR 副本（联系人 / 排口高度内径）—— 派生数据，标 provenance
        out["_provenance"] = {
            "_is_official": True,
            "_source": ("全国排污许可证管理信息平台公开端明文 HTML 模块"
                        "（getxxgkContent / approveAtmosphere_xkzgk / approveWater_xkzgk）"
                        " + getxxgkContentzxbg + AES 坐标解密"),
            "_fields_official": ["basic", "outlet_coords", "limits", "post_permit"],
            "_note": ("basic/coordinates/limits/post_permit 均来自平台结构化字段，无 OCR 误差；"
                      "include_contacts=True 时 contacts/outlet_params 标注 _is_official=False。"),
        }
        if include_contacts:
            try:
                from bs4 import BeautifulSoup as _BS
                from .ocr_engine import ocr_to_text
                _im = c.get(config.URL_LICENSE_IMAGE_LIST, params={"dataid": dataid})
                _soup = _BS(_im, "html.parser")
                _ic = _soup.find("input", {"id": "imgCount"})
                _pk = _soup.find("input", {"id": "pkid"})
                _n = int((_ic.get("value") or 0) if _ic else 0)
                _pid = (_pk.get("value") or "") if _pk else ""
                _pages = [3, 6, 7] if _n >= 7 else ([3] if _n >= 3 else list(range(1, _n + 1)))
                _contacts_text, _params_text, _contact_kv = [], [], {}
                for _pg in _pages:
                    _dfid = f"{_pid}_{_pg}"
                    try:
                        _blob = c.download(config.URL_LICENSE_IMAGE_PAGE,
                                           params={"datafileid": _dfid, "fileType": "pdffile",
                                                   "dataid": dataid})
                        _fh, _pp = tempfile.mkstemp(suffix=".png")
                        _os.write(_fh, _blob)
                        _os.close(_fh)
                        _txt = ocr_to_text(_pp)
                        _os.remove(_pp)
                    except Exception:  # noqa: BLE001
                        continue
                    if _pg == 3:
                        _contacts_text.append(_txt)
                        for _k in ("法定代表人", "技术负责人", "联系电话", "固定电话", "移动电话"):
                            _m = _re.search(r"%s[:：]\s*([^\n]+)" % _k, _txt)
                            if _m:
                                _contact_kv[_k] = _m.group(1).strip()
                    else:
                        _params_text.append("===== 副本第%d页（大气排放口参数） =====\n%s" % (_pg, _txt))
                out["contacts"] = {
                    "contact_kv": _contact_kv,
                    "page3_text": "\n".join(_contacts_text),
                    "_is_official": False,
                    "_source": "OCR(RapidOCR) 对排污许可证副本图片的自动识别，非平台结构化字段",
                    "_notice": "派生数据，可能有识别误差；执法/限值比对前须核对副本原件或平台接口",
                }
                if _params_text:
                    out["outlet_params"] = {
                        "pages_text": "\n".join(_params_text),
                        "_is_official": False,
                        "_source": "OCR(RapidOCR) 对副本表2（大气排放口基本情况表）的识别",
                        "_notice": "排气筒高度(m)/出口内径(m)/排气温度(℃) 等；表格复杂处可能串列，须核对原件",
                    }
            except Exception as _e:  # noqa: BLE001
                out["contacts"] = {"error": "副本 OCR 失败：%s" % str(_e)[:160],
                                   "_is_official": False}
        return _out(out)
