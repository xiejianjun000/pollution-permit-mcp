"""平台常量与接口地址配置（基于真实站点穿透分析）。"""

BASE_URL = "https://permit.mee.gov.cn"

# 公开端核心接口
URL_HOME = BASE_URL + "/permitExt/defaults/default-index!getInformation.action"
URL_LICENSE_LIST = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!licenseInformation.action"
URL_LICENSE_DETAIL = BASE_URL + "/perxxgkinfo/xkgkAction!xkgk.action"
URL_LICENSE_DETAIL_ZXBG = BASE_URL + "/perxxgkinfo/xkgkAction!xkgk.action?xkgk=getxxgkContentzxbg"
URL_ZXBG_YEAR = BASE_URL + "/perxxgkinfo/syssb/wysb/hpsp/hpsp-company-sewage!getZxbgByYear.action"
URL_LICENSE_IMAGE_LIST = BASE_URL + "/perxxgkinfo/syssb/wysb/hpsp/hpsp-company-sewage!showImage.action"
URL_LICENSE_IMAGE_PAGE = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!downFilePng.action"
URL_LICENSE_FILE_DOWNLOAD = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!downloadFile.action"
URL_PRE_PUBLICITY = BASE_URL + "/perxxgkinfo/syssb/xxgk/xxgk!sqqlist.action"
URL_REGISTER_INFO = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!getRegisterInfo.action"

# 公告栏目
URL_ANNOUNCE_CANCEL = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!xkgg_zxggList.action"   # 注销
URL_ANNOUNCE_REVOKE = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!xkgg_cxggList.action"   # 撤销
URL_ANNOUNCE_LOST = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!xkgg_yssmList.action"     # 遗失
URL_NEWS_LIST = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!xkgg_zytzList.action"         # 重要通知
URL_RECTIFY_LIST = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!xxgkXqzgList.action"       # 限期整改

# 法规标准
URL_LAWS_STANDARD = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!lawsStandard.action"
URL_LAWS_LIST = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!lawsStandardList.action"
URL_NEWS_DETAIL = BASE_URL + "/perxxgkinfo/syssb/xkgg/xkgg!getNewsDetail.action"

# 排放口二维码
URL_QRCODE = BASE_URL + "/2dcode"

# 自行监测平台（详情页 iframe 对接）
URL_MONITOR_PLATFORM = "https://wryjc.mee.gov.cn/gkpt"

# AES 解密参数（详情页内联 JS 硬编码）
AES_PWD_RE = r"var pwd = '([0-9a-fA-F]+)'"
AES_WORD_RE = r"var word = '([^']+)'"

# 法规分类
LAWS_COLUMNS = {
    "Law": "法律法规",
    "XKJSGF": "许可技术规范",
    "SSHYPFBZ": "实施行业排放标准",
    "HYKXJSZN": "行业可行技术指南",
    "HYZXJCZN": "行业自行监测指南",
    "XKJGYQ": "许可监管要求",
}

# 请求行为
DEFAULT_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9",
    # /perxxgkinfo/ 应用校验来源页：必须声明从公开端首页点入。
    # 缺失 Referer 时列表页会 302 到 errorinfo.jsp（平台反爬拦截）。
    "Referer": BASE_URL + "/permitExt/defaults/default-index!getInformation.action",
}
# 平台反爬错误页特征：HTTP 仍返回 200，但正文是 errorinfo.jsp 提示。
# 未识别会导致解析层静默返回 count=0，调用方无法区分"确无匹配"与"被拦截"。
BLOCK_PAGE_MARKERS = ("errorinfo.jsp", "请您访问", "点击许可信息公开查询")
REQUEST_INTERVAL = 3.0      # 秒，相邻请求最小间隔（合规限速，2026-09-04 上调以缓解出口 IP 风控）
RETRY_TIMES = 3             # 失败重试次数
RETRY_BACKOFF = 2.0         # 重试退避基数（秒）
# 单请求超时。原值 20s 偏紧：2026-09-02 实测平台高峰期首页即需 10–12s，
# 列表页偶发超过 20s，导致正常请求被误判为失败。放宽到 45s。
# 注意：超时与"平台拦截"是两回事，超时时应重试或稍后再试，不要当作 IP 被封。
TIMEOUT = 45                # 单请求超时
CACHE_TTL = 3600            # 缓存默认有效期（秒），1 小时
CACHE_DB = "permit_cache.db"
# 翻页结果磁盘缓存目录：按 (url+params) hash 存 JSON 文件，TTL 复用 CACHE_TTL
PAGE_CACHE_DIR = "/opt/pollution-permit-mcp/work/cache"
# 命中反爬页/超时后的指数退避基数：第 n 次重试等待 2^n * RISK_RETRY_BACKOFF 秒
RISK_RETRY_BACKOFF = 3.0
