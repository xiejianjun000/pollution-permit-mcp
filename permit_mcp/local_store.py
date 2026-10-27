"""本地全本库读取层（permit_full.db）——让 8018 在上游被风控时仍能离线服务。

背景（2026-10-27 实测）：
- 8018 部署在腾讯云主机，permit.mee.gov.cn 对该出口长期风控，回源单次 93~160s 超时。
- 本机家庭网（36.157.186.60）访问公开端全通，家宽单请求 0.5~0.6s。
- 娄底 861 家已用家宽把「全本」（基本信息 + 排放口坐标 + 许可限值 + 证后管理）
  抓全并入库到 /opt/eco-matrix/data/permit_full.db（862 行 licenses_full）。
  其中 basic_json / limits_json / coords_json / post_permit_json 的结构，
  与 permit_pub_license_detail / permit_pub_structured_limits /
  permit_pub_outlet_coords / permit_pub_post_permit_status 的返回体同构，
  因此可以零改造直接离线复用。

策略：工具面「本地优先 → 回源兜底」。
- 命中本地 → 直接返回本地结构化数据，带 source="local_permit_full" 标注；
- 未命中 → 走原回源路径（保持全国覆盖能力与工具语义不变）。

铁律：
1. 只读连接（mode=ro），永不写本地库；写库由采集器负责。
2. 每次调用新建连接：sqlite3 连接默认 check_same_thread=True，而 MCP 工具
   在不同工作线程执行，复用连接会抛 "SQLite objects created in a thread..."。
3. 命中/未命中必须显式区分，不得把「本地没有」当成「平台没有」。
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Optional

PERMIT_FULL_DB = os.environ.get(
    "ECO_PERMIT_FULL_DB", "/opt/eco-matrix/data/permit_full.db")

# 需要随记录一起返回的标量列
_SCALAR_COLS = ("dataid", "company", "license_no", "province", "city",
                 "industry", "manage_type", "valid_period", "issue_date",
                 "注册地址", "法定代表人", "技术负责人", "固定电话", "移动电话",
                 "排污权交易", "大气污染物种类", "废水污染物种类",
                 "大气执行标准", "废水执行标准",
                 "n_outlets", "n_points", "has_contacts", "has_params",
                 "has_sections", "exec_report_count", "supervision_count")


def _connect():
    """只读连接；库不存在或不可用时返回 None（调用方据此走回源）。"""
    if not os.path.exists(PERMIT_FULL_DB):
        return None
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % PERMIT_FULL_DB, uri=True, timeout=3)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error:
        return None


def _loads(raw: Any) -> Any:
    if not raw:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return None


def available() -> bool:
    """本地库是否可用（供健康检查工具观测）。"""
    return os.path.exists(PERMIT_FULL_DB)


def stats() -> dict:
    """本地库规模概览。"""
    conn = _connect()
    if conn is None:
        return {"available": False, "db": PERMIT_FULL_DB}
    try:
        total = conn.execute("SELECT COUNT(*) FROM licenses_full").fetchone()[0]
        with_reports = conn.execute(
            "SELECT COUNT(*) FROM licenses_full WHERE exec_report_count>0").fetchone()[0]
        cities = conn.execute(
            "SELECT city, COUNT(*) FROM licenses_full WHERE city IS NOT NULL "
            "GROUP BY city ORDER BY 2 DESC LIMIT 10").fetchall()
        return {"available": True, "db": PERMIT_FULL_DB, "total": total,
                "with_exec_reports": with_reports,
                "cities": [{"city": r[0], "count": r[1]} for r in cities]}
    except sqlite3.Error as e:
        return {"available": False, "db": PERMIT_FULL_DB, "error": str(e)[:120]}
    finally:
        conn.close()


def get_record(dataid: str) -> Optional[dict]:
    """按 dataid 取本地全本记录；未命中返回 None（= 本地没有，不是平台没有）。"""
    did = (dataid or "").strip().lower()
    if not did:
        return None
    conn = _connect()
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT * FROM licenses_full WHERE lower(dataid)=?", (did,)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    rec = {k: row[k] for k in _SCALAR_COLS if k in row.keys()}
    rec["basic"] = _loads(row["basic_json"])
    rec["limits"] = _loads(row["limits_json"])
    rec["coords"] = _loads(row["coords_json"])
    rec["post_permit"] = _loads(row["post_permit_json"])
    rec["sections"] = _loads(row["sections_json"])
    rec["source"] = "local_permit_full"
    rec["_local_db"] = PERMIT_FULL_DB
    return rec


def search(kw: str = "", city: str = "", province: str = "",
           page: int = 1, size: int = 15) -> Optional[dict]:
    """本地库检索（子串匹配 + 省市过滤 + 分页），返回 parse_license_list 同构结果。

    未命中返回 None（= 本地库没有匹配，不等于平台没有）。
    """
    kw = (kw or "").strip()
    city = (city or "").strip()
    province = (province or "").strip()
    if not any((kw, city, province)):
        return None
    clauses, args = [], []
    if kw:
        like = "%%%s%%" % kw
        clauses.append("(company LIKE ? OR license_no LIKE ? OR 注册地址 LIKE ?)")
        args += [like, like, like]
    if city:
        clauses.append("city LIKE ?")
        args.append("%%%s%%" % city)
    if province:
        clauses.append("province LIKE ?")
        args.append("%%%s%%" % province)
    where = " AND ".join(clauses)
    conn = _connect()
    if conn is None:
        return None
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM licenses_full WHERE " + where, args).fetchone()[0]
        if total == 0:
            return None
        off = max(0, (int(page) - 1)) * int(size)
        rows = conn.execute(
            "SELECT dataid, company, license_no, province, city, industry, "
            "manage_type, valid_period, issue_date FROM licenses_full WHERE "
            + where + " ORDER BY company LIMIT ? OFFSET ?",
            args + [int(size), off]).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    items = [{
        "province": r[3], "city": r[4], "license_no": r[2],
        "company_name": r[1], "industry": r[5], "valid_period": r[7],
        "issue_date": r[8], "manage_type": r[6], "dataid": r[0],
    } for r in rows]
    return {
        "total_pages": (total + int(size) - 1) // int(size),
        "count": len(items),
        "items": items,
        "source": "local_permit_full",
    }
