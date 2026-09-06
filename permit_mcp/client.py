"""HTTP 会话封装：WebShield 会话 token 维护、限速、重试、缓存。"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

import requests

from . import config
from .parser import parse_license_list

# 本地全量索引库（build_license_db.py 后台持续灌入；深翻页优先读此库）
LICENSE_DB = "/opt/pollution-permit-mcp/work/licenses.db"



class RiskControlError(RuntimeError):
    """上游 permit.mee.gov.cn 风控/反爬拦截：命中引导页/errorinfo 或连续超时。

    与一般网络错误区分，供上层明确识别为『上游风控』而非静默空结果。
    """


class Cache:
    """SQLite 轻量缓存，按 (method, url, body) 摘要为 key。"""

    def __init__(self, db_path: str | Path | None = None):
        self._lock = threading.RLock()
        self._path = str(db_path or Path(config.CACHE_DB).resolve())
        with self._lock:
            self._conn = sqlite3.connect(self._path, check_same_thread=False)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS cache ("
                " key TEXT PRIMARY KEY,"
                " value TEXT NOT NULL,"
                " expire_at REAL NOT NULL)"
            )
            self._conn.commit()

    @staticmethod
    def _key(method: str, url: str, body: Any) -> str:
        raw = f"{method}|{url}|{json.dumps(body, ensure_ascii=False, sort_keys=True)}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def get(self, method: str, url: str, body: Any | None = None) -> Optional[str]:
        k = self._key(method, url, body)
        with self._lock:
            row = self._conn.execute(
                "SELECT value, expire_at FROM cache WHERE key=?", (k,)
            ).fetchone()
        if not row:
            return None
        value, expire_at = row
        if expire_at < time.time():
            with self._lock:
                self._conn.execute("DELETE FROM cache WHERE key=?", (k,))
                self._conn.commit()
            return None
        return value

    def set(self, method: str, url: str, body: Any | None, value: str, ttl: float = config.CACHE_TTL) -> None:
        k = self._key(method, url, body)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, expire_at) VALUES (?,?,?)",
                (k, value, time.time() + ttl),
            )
            self._conn.commit()

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM cache")
            self._conn.commit()


class JsonFileCache:
    """翻页结果磁盘缓存：按 (url, params) 摘要为 key，写 JSON 文件，TTL 过期。"""

    def __init__(self, cache_dir: str | Path | None = None):
        self._dir = Path(cache_dir or config.PAGE_CACHE_DIR)
        self._dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _key(url: str, params: dict) -> str:
        raw = f"{url}|{json.dumps(params, ensure_ascii=False, sort_keys=True)}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def get(self, url: str, params: dict) -> Optional[str]:
        path = self._dir / f"{self._key(url, params)}.json"
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None
        if payload.get("expire_at", 0) < time.time():
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            return None
        return payload.get("value")

    def set(self, url: str, params: dict, value: str, ttl: float = config.CACHE_TTL) -> None:
        path = self._dir / f"{self._key(url, params)}.json"
        payload = {
            "url": url,
            "params": params,
            "expire_at": time.time() + ttl,
            "value": value,
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)


class PermitClient:
    """平台 HTTP 客户端：自动预热会话（WebShield）、限速、重试、可选缓存。"""

    def __init__(self, use_cache: bool = True, cache_db: str | None = None,
                 interval: float = config.REQUEST_INTERVAL,
                 page_cache_dir: str | None = None):
        self.session = requests.Session()
        self.session.headers.update(config.DEFAULT_HEADERS)
        self._last_ts = 0.0
        self._lock = threading.RLock()
        self.interval = interval
        self.cache: Cache | None = Cache(cache_db) if use_cache else None
        self.page_cache: JsonFileCache | None = JsonFileCache(page_cache_dir) if use_cache else None
        self._ready = False
        self._chain = None  # 增量链式翻页状态：{filters, page, key}

    # ---- 会话预热 ----
    def _ensure_ready(self) -> None:
        """访问首页获取并维护 WebShieldDRSessionVerify 会话 token。"""
        if self._ready:
            return
        with self._lock:
            if self._ready:
                return
            try:
                self._throttle()
                self.session.get(config.URL_HOME, timeout=config.TIMEOUT)
                self._ready = True
            except requests.RequestException:
                # 预热失败不阻塞：部分接口无 token 也可访问
                self._ready = True

    def _throttle(self) -> None:
        with self._lock:
            wait = self.interval - (time.time() - self._last_ts)
            if wait > 0:
                time.sleep(wait)
            self._last_ts = time.time()

    # ---- 核心请求 ----
    def request(self, method: str, url: str, params: dict | None = None,
                data: dict | None = None, use_cache: bool = True) -> str:
        self._ensure_ready()
        body = {"params": params, "data": data}

        if use_cache and self.cache:
            hit = self.cache.get(method, url, body)
            if hit is not None:
                return hit

        last_err: Optional[Exception] = None
        risk_blocked = False
        for attempt in range(config.RETRY_TIMES):
            try:
                self._throttle()
                resp = self.session.request(
                    method, url, params=params, data=data, timeout=config.TIMEOUT
                )
                resp.raise_for_status()
                resp.encoding = resp.apparent_encoding or resp.encoding
                text = resp.text
                # 反爬错误页检测：平台对异常出口（云主机 IP / 缺 Referer）返回
                # errorinfo.jsp，HTTP 仍是 200。不拦截会被解析成 count=0 的空结果，
                # 让调用方误判为"查无数据"。此处显式抛错，且绝不写入缓存。
                self._guard_blocked(text, url)
                if use_cache and self.cache:
                    self.cache.set(method, url, body, text)
                return text
            except RiskControlError as e:  # noqa: PERF203
                last_err = e
                risk_blocked = True
            except requests.Timeout as e:  # 超时与风控同样按指数退避重试
                last_err = e
                risk_blocked = True
            except requests.RequestException as e:  # noqa: PERF203
                last_err = e
            if attempt < config.RETRY_TIMES - 1:
                time.sleep(config.RISK_RETRY_BACKOFF * (2 ** attempt))

        if risk_blocked:
            raise RiskControlError(
                f"【上游风控】permit.mee.gov.cn 连续 {config.RETRY_TIMES} 次返回反爬页或超时，"
                f"已按 2^n×{config.RISK_RETRY_BACKOFF}s 指数退避重试仍失败：{url}。"
                "当前出口 IP 处于风控期，请稍后重试或改用本地网络出口；"
                "这不是『查无此企业』，数据不可信。"
            )
        raise RuntimeError(f"请求失败 {method} {url}: {last_err}")

    @staticmethod
    def _guard_blocked(text: str, url: str) -> None:
        """识别平台反爬/风控错误页并抛错，避免静默空结果。"""
        if not text or len(text.strip()) < 200:
            raise RiskControlError(
                f"平台返回空/异常短响应（{len(text or '')} 字节），疑似出口 IP 被风控：{url}"
            )
        for marker in config.BLOCK_PAGE_MARKERS:
            if marker in text:
                raise RiskControlError(
                    "【排污许可公开端·平台拦截】permit.mee.gov.cn 返回反爬错误页 "
                    "(errorinfo.jsp)：当前出口 IP 已被风控，或缺少首页 Referer 会话链路。"
                    "本次未返回任何数据——这不是『查无此企业』，数据不可信。"
                    "处置建议：① 改用本地网络出口运行本 MCP（云主机 IP 易被封）；"
                    "② 降低请求频率（REQUEST_INTERVAL 调至 3s 以上）；③ 稍后重试。"
                )

    def get(self, url: str, params: dict | None = None, use_cache: bool = True) -> str:
        return self.request("GET", url, params=params, use_cache=use_cache)

    def post(self, url: str, data: dict | None = None, use_cache: bool = True) -> str:
        return self.request("POST", url, data=data, use_cache=use_cache)

    def get_temp_report_key(self) -> str:
        """访问搜索列表页，提取隐藏字段 tempReportKey（分页搜索会话 token）。

        平台搜索页会生成一个 32 位 hex 的 tempReportKey，POST 搜索需带上，
        否则部分场景（尤其分页）可能被拒。提取失败返回空串（接口对缺省有容错）。
        """
        try:
            self._ensure_ready()
            html = self.get(config.URL_LICENSE_LIST, use_cache=False)
            m = re.search(r'name="tempReportKey"\s+value="([^"]+)"', html)
            return m.group(1) if m else ""
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _extract_key(html: str) -> str:
        m = re.search(r'name="tempReportKey"\s+value="([^"]+)"', html)
        return m.group(1) if m else ""

    def _search_local(self, filters: dict, page: int):
        """本地索引优先：关键字 / 许可证号 / 管理类别查询若本地库已覆盖该页，直接返回（≤5s，不触上游）。

        支持 registerentername（子串）、xkznum（精确）、management（1=重点 / 0=简化）
        任意组合。深翻页根治路径——命中本地库即 ≤5s 返回，绝不回源逐页重走。
        全量无过滤（三者皆空）仍回源上游维护更准（数据过大，本地不全）。
        若本地库尚未覆盖到所请求的页（建库进行中 / 该管理类别尚未爬全），返回 None 让调用方回源上游。
        """
        kw = (filters.get("registerentername") or "").strip()
        xkz = (filters.get("xkznum") or "").strip()
        mgmt = (filters.get("management") or "").strip()
        if not kw and not xkz and mgmt not in ("1", "0"):
            return None
        size = 15
        off = (page - 1) * size
        clauses = []
        args = []
        if kw:
            like = f"%{kw}%"
            clauses.append("(company_name LIKE ? OR license_no LIKE ? OR city LIKE ? OR province LIKE ?)")
            args += [like, like, like, like]
        if xkz:
            clauses.append("license_no = ?")
            args.append(xkz)
        if mgmt in ("1", "0"):
            clauses.append("manage_type = ?")
            args.append("重点管理" if mgmt == "1" else "简化管理")
        where = " AND ".join(clauses)
        base = (
            "SELECT dataid,company_name,license_no,province,city,industry,"
            "manage_type,valid_period,issue_date FROM licenses WHERE " + where
        )
        try:
            conn = sqlite3.connect(LICENSE_DB, timeout=3)
            conn.execute("PRAGMA busy_timeout=3000")
            total = conn.execute(
                "SELECT COUNT(*) FROM (" + base + ")", args
            ).fetchone()[0]
            if total == 0:
                conn.close()
                return None
            # 请求的页超出本地已建覆盖范围 → 回源上游（结果更全，避免截断假分页）
            if off >= total:
                conn.close()
                return None
            rows = conn.execute(
                base + " ORDER BY company_name LIMIT ? OFFSET ?",
                args + [size, off],
            ).fetchall()
            conn.close()
        except sqlite3.OperationalError:
            # 建库进程持写锁等：安全回源
            return None
        items = [
            {
                "province": r[3], "city": r[4], "license_no": r[2],
                "company_name": r[1], "industry": r[5], "valid_period": r[7],
                "issue_date": r[8], "manage_type": r[6], "dataid": r[0],
            }
            for r in rows
        ]
        return {
            "total_pages": (total + size - 1) // size,
            "count": len(items),
            "items": items,
            "source": "local_db",
        }

    def _write_through(self, html: str, filters: dict) -> None:
        """上游回源拿到的页写透到本地库：深页回源一次后，后续直接走本地索引。

        建库进程（build_license_db.py）也在并发写同一库，此处用 INSERT OR REPLACE +
        busy_timeout 容错，写锁冲突时静默放弃（非致命）。
        """
        try:
            rows = parse_license_list(html).get("items") or []
            if not rows:
                return
            conn = sqlite3.connect(LICENSE_DB, timeout=3)
            conn.execute("PRAGMA busy_timeout=3000")
            data = [
                (r["dataid"], r["company_name"], r["license_no"], r["province"],
                 r["city"], r["industry"], r["manage_type"], r["valid_period"],
                 r["issue_date"])
                for r in rows
            ]
            conn.executemany(
                "INSERT OR REPLACE INTO licenses "
                "(dataid,company_name,license_no,province,city,industry,"
                "manage_type,valid_period,issue_date) VALUES (?,?,?,?,?,?,?,?,?)",
                data,
            )
            conn.commit()
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    def _chain_fetch(self, filters: dict, page: int):
        """上游链式翻页：同关键词顺次翻页时复用上一页 tempReportKey，仅发 1 个 POST。

        深页（如第 13 页）不再从首页重走 13 次——这是此前 50s 超时的根因。
        跳页或换关键词时回退到从首页链式重走的保底逻辑。
        """
        url = config.URL_LICENSE_LIST
        if (self._chain and self._chain.get("filters") == filters
                and page == self._chain.get("page", 0) + 1):
            data = dict(filters)
            data["page.pageNo"] = page
            data["tempReportKey"] = self._chain["key"]
            html = self.post(url, data=data, use_cache=False)
            key = self._extract_key(html)
            self._chain = {"filters": dict(filters), "page": page, "key": key}
            return html, key
        # 冷启动 / 跳页 / 本地索引断档：从「已缓存最深页」续链而非从首页重走，
        # 避免深页（如第 13 页）重走 1..N 次触发 ~50s 超时。缓存页 HTML 内已含下一页 tempReportKey，可直接续翻。
        start = 1
        key = None
        cached_html = None
        if self.page_cache:
            for p in range(page, 0, -1):
                cp = dict(filters)
                cp["page.pageNo"] = p
                cached = self.page_cache.get(url, cp)
                if cached is not None:
                    start = p + 1
                    key = self._extract_key(cached)
                    cached_html = cached
                    break
        if key is None:
            key = self.get_temp_report_key()
        html = cached_html  # 若下面循环为空（精确页已缓存），直接返回缓存页，避免 UnboundLocalError
        for p in range(start, page + 1):
            data = dict(filters)
            data["page.pageNo"] = p
            data["tempReportKey"] = key
            html = self.post(url, data=data, use_cache=False)
            key = self._extract_key(html)
            # 边翻边写透翻页缓存，缩短后续回源链
            if self.page_cache:
                self.page_cache.set(url, {"page.pageNo": p, **filters}, html, ttl=config.PAGE_CACHE_TTL)
        self._chain = {"filters": dict(filters), "page": page, "key": key}
        return html, key

    def search_licenses_paged(self, filters: dict, page: int):
        """分页查询许可证列表，返回 (payload, 下一页 tempReportKey, 来源)。

        来源优先级：local_db（命中本地索引）> cache（翻页磁盘缓存）> upstream（回源上游）。
        payload 在 local_db 时为已解析 dict，其余为上游 HTML 字符串。
        """
        url = config.URL_LICENSE_LIST
        cache_params = dict(filters)
        cache_params["page.pageNo"] = page

        # 1) 本地索引优先（深翻页根治路径）
        local = self._search_local(filters, page)
        if local is not None:
            return local, "", "local_db"

        # 2) 翻页磁盘缓存
        if self.page_cache:
            cached = self.page_cache.get(url, cache_params)
            if cached is not None:
                return cached, "", "cache"

        # 3) 回源上游（增量链式，避免深页重走）
        html, key = self._chain_fetch(filters, page)
        self._write_through(html, filters)
        if self.page_cache:
            self.page_cache.set(url, cache_params, html, ttl=config.PAGE_CACHE_TTL)
        return html, key, "upstream"

    def download(self, url: str, params: dict | None = None) -> bytes:
        """下载二进制文件（不缓存）。"""
        self._ensure_ready()
        last_err: Optional[Exception] = None
        for attempt in range(config.RETRY_TIMES):
            try:
                self._throttle()
                resp = self.session.get(url, params=params, timeout=config.TIMEOUT * 2)
                resp.raise_for_status()
                return resp.content
            except requests.RequestException as e:  # noqa: PERF203
                last_err = e
                if attempt < config.RETRY_TIMES - 1:
                    time.sleep(config.RETRY_BACKOFF * (attempt + 1))
        raise RuntimeError(f"下载失败 {url}: {last_err}")
