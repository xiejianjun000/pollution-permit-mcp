# -*- coding: utf-8 -*-
"""排污许可公开端全量遍历建库（SQLite），支持断点续传。

用法：
  python build_license_db.py --mgmt 1            # 只建重点管理库（10804 页，约 3 小时）
  python build_license_db.py --mgmt 0            # 只建简化管理库（27341 页）
  python build_license_db.py --mgmt all          # 全量（38145 页，约 10.6 小时）

建库后可精确统计任意省/市/行业/管理类别的企业数（解决"市州名关键词"漏检/误命中问题）。
"""
import sys, os, sqlite3, time, argparse, json, re
sys.path.insert(0, "/opt/pollution-permit-mcp")
os.chdir("/opt/pollution-permit-mcp")
from permit_mcp.client import PermitClient
from permit_mcp.parser import parse_license_list
from permit_mcp import config

DB_PATH = "/opt/pollution-permit-mcp/work/licenses.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            dataid TEXT PRIMARY KEY,
            company_name TEXT,
            license_no TEXT,
            province TEXT,
            city TEXT,
            industry TEXT,
            manage_type TEXT,
            valid_period TEXT,
            issue_date TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS crawl_meta (
            mgmt TEXT PRIMARY KEY,
            last_page INTEGER,
            total_pages INTEGER,
            updated_at TEXT
        )
    """)
    conn.commit()
    return conn

def crawl(mgmt, start_page=1, max_pages=None):
    conn = init_db()
    c = PermitClient(use_cache=False)
    mgmt_name = "重点管理" if mgmt == "1" else "简化管理"

    # 探首页拿总页数 + 初始 tempReportKey
    key = c.get_temp_report_key()
    data = {"management": mgmt, "page.pageNo": 1, "tempReportKey": key}
    html = c.post(config.URL_LICENSE_LIST, data=data)
    r = parse_license_list(html)
    total_pages = r["total_pages"] or 0
    print(f"[{mgmt_name}] 总页数 {total_pages}，tempReportKey 初始 {key[:12]}...")
    if max_pages:
        total_pages = min(total_pages, max_pages)

    def extract_key(h):
        m = re.search(r'name="tempReportKey"\s+value="([^"]+)"', h)
        return m.group(1) if m else ""

    # 链式翻页：每次 POST 返回新 tempReportKey，下一页必须用新 key
    inserted = 0
    t0 = time.time()
    # 若从 start_page > 1 续传，先链式翻到 start_page-1
    for p in range(1, start_page):
        data = {"management": mgmt, "page.pageNo": p, "tempReportKey": key}
        h = c.post(config.URL_LICENSE_LIST, data=data)
        key = extract_key(h)

    for p in range(start_page, total_pages + 1):
        data = {"management": mgmt, "page.pageNo": p, "tempReportKey": key}
        try:
            h = c.post(config.URL_LICENSE_LIST, data=data)
        except Exception as e:
            print(f"  第{p}页异常: {e}，等待重试")
            time.sleep(3)
            try:
                h = c.post(config.URL_LICENSE_LIST, data=data)
            except Exception as e2:
                print(f"  第{p}页重试仍失败: {e2}，跳过")
                continue
        key = extract_key(h)
        r = parse_license_list(h)

        if r["count"] == 0:
            print(f"  第{p}页返回 0 条，停在第 {p} 页")
            break

        for it in r["items"]:
            conn.execute(
                "INSERT OR REPLACE INTO licenses VALUES (?,?,?,?,?,?,?,?,?)",
                (it["dataid"], it["company_name"], it["license_no"],
                 it["province"], it["city"], it["industry"], it["manage_type"],
                 it["valid_period"], it["issue_date"]),
            )
            inserted += 1

        if p % 100 == 0:
            conn.execute("INSERT OR REPLACE INTO crawl_meta VALUES (?,?,?,datetime('now','localtime'))",
                         (mgmt, p, total_pages))
            conn.commit()
            el = time.time() - t0
            print(f"  第{p}/{total_pages}页，已入库 {inserted} 条，耗时 {el/60:.1f}min，速度 {p/(el+1e-6):.2f}页/s")

    conn.execute("INSERT OR REPLACE INTO crawl_meta VALUES (?,?,?,datetime('now','localtime'))",
                 (mgmt, total_pages, total_pages))
    conn.commit()
    print(f"[{mgmt_name}] 完成：共 {inserted} 条，总耗时 {(time.time()-t0)/60:.1f}min")
    conn.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mgmt", default="1", help="1=重点 0=简化 all=全量")
    ap.add_argument("--resume", action="store_true", help="断点续传（从上次记录页继续）")
    ap.add_argument("--max-pages", type=int, default=None, help="最多遍历页数（测试用）")
    args = ap.parse_args()

    mgmts = ["1", "0"] if args.mgmt == "all" else [args.mgmt]
    for m in mgmts:
        start = 1
        if args.resume:
            conn = init_db()
            row = conn.execute("SELECT last_page FROM crawl_meta WHERE mgmt=?", (m,)).fetchone()
            conn.close()
            if row and row[0]:
                start = row[0] + 1
                print(f"断点续传：{m} 从第 {start} 页继续")
        crawl(m, start_page=start, max_pages=args.max_pages)
