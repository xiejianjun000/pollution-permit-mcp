# -*- coding: utf-8 -*-
"""娄底 861 家执行报告 + 省市字段 回填（permit_full.db / full_licenses*.db）

背景：
- 2026-10-26 验收判定「执行报告清单 19/861 = 2.2%」，10-27 本机家宽全量普查实测
  829/861 = 96.3%（共 4850 条）。差额是采集侧假阴性（熔断丢数 + 云端风控把
  「请求失败」记成「无此数据」），不是公开端无数据。
- permit_full.db 的 licenses_full.exec_report_count 仅 19 家 >0；province/city 仅 90 家有值
  （都是「湖南省/娄底市」），其余 772 家为 NULL → 省市过滤与清单检索都不可用。

回填目标（全部幂等，值相等即跳过）：
  A. /opt/eco-matrix/data/permit_full.db  licenses_full
     - exec_report_count  ← 队列 n_reports
     - post_permit_json.execution_reports / .execution_report_count ← 队列明细（保留其余字段）
     - province / city   ← 缺失时补「湖南省 / 娄底市」（队列 city 字段已核实为地级市）
  B. /opt/pollution-permit-mcp/work/full_licenses.db、full_licenses_local.db
     - payload.execution_reports / payload.execution_report_count

用法：
  python3 backfill_exec_reports.py --dry-run     # 只读量化影响
  python3 backfill_exec_reports.py --apply       # 备份 + 写入 + 幂等断言
"""
import argparse
import json
import os
import shutil
import sqlite3
import time

QUEUE = "/opt/pollution-permit-mcp/work/queues/loudi_reports_full_20261027.json"
PERMIT_FULL = "/opt/eco-matrix/data/permit_full.db"
SRC_DBS = ["/opt/pollution-permit-mcp/work/full_licenses.db",
           "/opt/pollution-permit-mcp/work/full_licenses_local.db"]
PROV_FALLBACK = "湖南省"
STAMP = time.strftime("%Y%m%d_%H%M%S")


def load_queue(path=QUEUE):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    for r in data:
        reports = []
        for y, blk in (r.get("per_year") or {}).items():
            for it in (blk.get("items") or []):
                reports.append({"year": y, "type": it.get("type"),
                                "report_time": it.get("time"),
                                "doc_url": it.get("doc_url")})
        if not reports:
            for it in (r.get("reports") or []):
                reports.append({"year": it.get("year"), "type": it.get("type"),
                                "report_time": it.get("time"),
                                "doc_url": it.get("doc_url")})
        n = r.get("n_reports")
        if n is None:
            n = len(reports)
        out[r["dataid"]] = {"n": n, "reports": reports,
                            "city": (r.get("city") or "").strip(),
                            "license_no": r.get("license_no"),
                            "company": r.get("company")}
    return out


def payload_dict(pl):
    if not pl:
        return {}
    try:
        return json.loads(pl)
    except Exception:
        return {}


def _upsert_fields(cur, table, did, sets, params):
    # sets 中每项已自带 "字段=?"，直接拼；params 顺序与 sets 严格一致
    cur.execute("UPDATE %s SET %s WHERE dataid=?" % (table, ", ".join(sets)),
                tuple(params) + (did,))


def plan_permit_full(q):
    c = sqlite3.connect("file:%s?mode=ro" % PERMIT_FULL, uri=True)
    rows = c.execute("SELECT dataid, company, exec_report_count, province, city, "
                      "post_permit_json FROM licenses_full").fetchall()
    c.close()
    chg_rep = chg_geo = 0
    det = []
    for did, comp, old_n, prov, city, ppj in rows:
        src = q.get(did)
        if not src:
            continue
        if (old_n or 0) != src["n"]:
            chg_rep += 1
            det.append((comp, old_n or 0, src["n"]))
        if not prov or not city:
            chg_geo += 1
    return rows, chg_rep, chg_geo, det


def plan_src_db(db, q):
    if not os.path.exists(db):
        return None
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    rows = c.execute("SELECT dataid, company, payload FROM full_licenses").fetchall()
    c.close()
    chg = 0
    det = []
    for did, comp, pl in rows:
        src = q.get(did)
        if not src:
            continue
        d = payload_dict(pl)
        old_n = d.get("execution_report_count") or 0
        old_has = bool(d.get("execution_reports"))
        if old_n == src["n"] and old_has == (src["n"] > 0):
            continue
        chg += 1
        det.append((comp, old_n, src["n"]))
    return len(rows), chg, det


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--queue", default=QUEUE)
    a = ap.parse_args()
    q = load_queue(a.queue)
    print("普查源: %s  覆盖 %d 家" % (a.queue, len(q)))

    rows, chg_rep, chg_geo, det = plan_permit_full(q)
    print("\n===== DRY-RUN 影响量化 =====")
    print("  %s: licenses_full %d 行 → 执行报告需改 %d 行；省市缺失需补 %d 行"
          % (os.path.basename(PERMIT_FULL), len(rows), chg_rep, chg_geo))
    for name, o, n in det[:5]:
        print("      %-40s exec_report %s -> %d" % (name[:40], o, n))
    if len(det) > 5:
        print("      ...另 %d 家" % (len(det) - 5))

    src_plans = []
    for db in SRC_DBS:
        p = plan_src_db(db, q)
        if p:
            src_plans.append((db, p))
            print("  %s: full_licenses %d 行 → 需改 %d 行" % (os.path.basename(db), p[0], p[1]))

    if not a.apply:
        print("\n--dry-run 模式，未写入。确认后加 --apply 执行（自动备份 + 幂等断言）。")
        return

    print("\n===== APPLY =====")
    backups = {}

    # ---- A. permit_full.db ----
    bak = PERMIT_FULL + ".bak_execbackfill_" + STAMP
    shutil.copy2(PERMIT_FULL, bak)
    backups[PERMIT_FULL] = bak
    print("  备份: %s (%.1fMB)" % (os.path.basename(bak), os.path.getsize(bak) / 1e6))
    c = sqlite3.connect(PERMIT_FULL, timeout=180)
    c.execute("PRAGMA busy_timeout=180000")
    n_rep = n_geo = 0
    try:
        c.execute("BEGIN IMMEDIATE")
        for did, comp, old_n, prov, city, ppj in c.execute(
                "SELECT dataid, company, exec_report_count, province, city, post_permit_json "
                "FROM licenses_full").fetchall():
            src = q.get(did)
            if not src:
                continue
            d = payload_dict(ppj)
            sets, params = [], []
            if (old_n or 0) != src["n"]:
                sets.append("exec_report_count=?"), params.append(src["n"])
                n_rep += 1
            if src["reports"]:
                d["execution_reports"] = src["reports"]
                d["execution_report_count"] = src["n"]
            else:
                d["execution_reports"] = []
                d["execution_report_count"] = 0
            d["_exec_report_backfill"] = {
                "source": "本机家宽全量普查 2026-10-27",
                "endpoint": "hpsp-company-sewage!getZxbgByYear.action",
                "years": ["2026", "2025", "2024"], "ts": STAMP}
            sets.append("post_permit_json=?"), params.append(json.dumps(d, ensure_ascii=False))
            if not prov or not city:
                sets.append("province=?"), params.append(prov or PROV_FALLBACK)
                sets.append("city=?"), params.append(city or src["city"] or "娄底市")
                n_geo += 1
            _upsert_fields(c, "licenses_full", did, sets, params)
        c.commit()
    except Exception as e:
        c.rollback()
        print("  回滚:", e)
        raise
    finally:
        c.close()
    print("  licenses_full: 写入 %d 行（执行报告 %d + 省市 %d）" % (len(rows), n_rep, n_geo))

    # ---- B. 源库 payload ----
    for db, (nrows, _chg, _det) in src_plans:
        bak = db + ".bak_execbackfill_" + STAMP
        shutil.copy2(db, bak)
        backups[db] = bak
        print("  备份: %s (%.1fMB)" % (os.path.basename(bak), os.path.getsize(bak) / 1e6))
        c = sqlite3.connect(db, timeout=180)
        c.execute("PRAGMA busy_timeout=180000")
        applied = 0
        try:
            c.execute("BEGIN IMMEDIATE")
            for did, src in q.items():
                row = c.execute("SELECT payload FROM full_licenses WHERE dataid=?", (did,)).fetchone()
                if not row:
                    continue
                d = payload_dict(row[0])
                old_n = d.get("execution_report_count") or 0
                old_has = bool(d.get("execution_reports"))
                if old_n == src["n"] and old_has == (src["n"] > 0):
                    continue
                d["execution_reports"] = src["reports"]
                d["execution_report_count"] = src["n"]
                d["_exec_report_backfill"] = {
                    "source": "本机家宽全量普查 2026-10-27",
                    "endpoint": "hpsp-company-sewage!getZxbgByYear.action",
                    "years": ["2026", "2025", "2024"], "ts": STAMP}
                c.execute("UPDATE full_licenses SET payload=? WHERE dataid=?",
                          (json.dumps(d, ensure_ascii=False), did))
                applied += 1
            c.commit()
        except Exception as e:
            c.rollback()
            print("  回滚:", e)
            raise
        finally:
            c.close()
        print("  %s: 写入 %d 行" % (os.path.basename(db), applied))

    # ---- 幂等断言：再算一次差集，应为 0 ----
    print("\n===== 幂等断言 =====")
    rows2, chg_rep2, chg_geo2, _ = plan_permit_full(q)
    ok = (chg_rep2 == 0 and chg_geo2 == 0)
    print("  permit_full 差集: 执行报告 %d / 省市 %d %s"
          % (chg_rep2, chg_geo2, "✅" if ok else "❌"))
    for db in SRC_DBS:
        p = plan_src_db(db, q)
        if p:
            print("  %s 差集: %d %s" % (os.path.basename(db), p[1],
                                        "✅" if p[1] == 0 else "❌"))
            ok = ok and p[1] == 0

    # ---- 验收口径 ----
    c = sqlite3.connect("file:%s?mode=ro" % PERMIT_FULL, uri=True)
    tot = c.execute("SELECT COUNT(*) FROM licenses_full").fetchone()[0]
    have = c.execute("SELECT COUNT(*) FROM licenses_full WHERE exec_report_count>0").fetchone()[0]
    geo = c.execute("SELECT COUNT(*) FROM licenses_full WHERE province IS NOT NULL AND city IS NOT NULL").fetchone()[0]
    sum_n = c.execute("SELECT SUM(exec_report_count) FROM licenses_full").fetchone()[0] or 0
    c.close()
    print("\n===== 回填后验收 =====")
    print("  licenses_full 总行 %d；执行报告>0：%d 家（%.1f%%）；省市齐全：%d 家；执行报告总条数 %d"
          % (tot, have, have / max(tot, 1) * 100, geo, sum_n))

    with open("/opt/pollution-permit-mcp/work/backfill_exec_reports_%s.json" % STAMP, "w") as f:
        json.dump({"ts": STAMP, "queue": a.queue, "backups": backups,
                   "exec_report_changed": n_rep, "geo_changed": n_geo,
                   "idempotent": ok}, f, ensure_ascii=False, indent=1)
    print("\n回滚档: %s" % json.dumps(backups, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
