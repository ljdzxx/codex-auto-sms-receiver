# -*- coding: utf-8 -*-
"""
通用 API 取码邮箱客户端。

邮箱池导入格式：
    email----code_url

取码时 GET code_url，并从纯文本、HTML、JSON 或受支持的网页收件箱中提取
6 位验证码。网页收件箱会先读取邮件列表，再请求同源的邮件详情接口。
"""
import base64
import binascii
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, parse_qs, unquote_to_bytes, urljoin, urlparse

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

_CODE_REGEX = re.compile(r"\b(\d{6})\b")
_CONTEXT_WORDS = ("code", "verify", "verification", "验证码", "代码", "确认码", "認証", "コード")
_MESSAGE_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_FRESHNESS_TOLERANCE_SECONDS = 3.0
_CONTEXT_CACHE: dict[str, "GenericApiEmailAccount"] = {}
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ACCOUNTS_FILE = _PROJECT_ROOT / "用于注册的API邮箱.txt"


class GenericApiMailError(RuntimeError):
    """通用 API 取码邮箱错误。"""


@dataclass
class GenericApiEmailAccount:
    email: str
    code_url: str


@dataclass(frozen=True)
class _InboxMessage:
    message_id: str
    text: str


class _InboxListParser(HTMLParser):
    """提取以 ``a.item[data-id]`` 表示的邮件列表，保持页面原始顺序。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.messages: list[_InboxMessage] = []
        self._message_id: str | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if self._message_id is not None or tag.casefold() != "a":
            return
        values = {str(key).casefold(): str(value or "") for key, value in attrs}
        classes = {part.casefold() for part in values.get("class", "").split()}
        message_id = values.get("data-id", "").strip()
        if "item" in classes and _MESSAGE_ID_REGEX.fullmatch(message_id):
            self._message_id = message_id
            self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._message_id is not None and data.strip():
            self._text_parts.append(data.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() != "a" or self._message_id is None:
            return
        self.messages.append(
            _InboxMessage(
                message_id=self._message_id,
                text=" ".join(self._text_parts),
            )
        )
        self._message_id = None
        self._text_parts = []


class _CardInboxParser(HTMLParser):
    """解析 icloud-api.top 这类"直接展示邮件"页面。

    页面结构为若干 ``<div class="card">``，每张卡片含子块
    ``.fr``(发件人) / ``.su``(主题) / ``.dt``(时间) / ``.bd``(邮件正文)。
    正文里嵌套完整邮件 HTML，故用 div 深度跟踪出卡片边界，并把卡片内所有
    文本聚合起来供验证码抽取。
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.cards: list[dict[str, str]] = []
        self._div_depth = 0
        self._card_depth: int | None = None
        self._cur: dict[str, list[str]] | None = None
        self._field: str | None = None
        self._field_depth: int | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.casefold() != "div":
            return
        classes = {
            part.casefold()
            for part in dict((str(k).casefold(), str(v or "")) for k, v in attrs)
            .get("class", "")
            .split()
        }
        self._div_depth += 1
        if self._cur is None:
            if "card" in classes:
                self._cur = {"fr": [], "su": [], "dt": [], "all": []}
                self._card_depth = self._div_depth
            return
        if self._field is None:
            for field in ("fr", "su", "dt"):
                if field in classes:
                    self._field = field
                    self._field_depth = self._div_depth
                    break

    def handle_data(self, data: str) -> None:
        if self._cur is None:
            return
        text = data.strip()
        if not text:
            return
        self._cur["all"].append(text)
        if self._field is not None:
            self._cur[self._field].append(text)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() != "div" or self._cur is None:
            return
        if self._field is not None and self._div_depth == self._field_depth:
            self._field = None
            self._field_depth = None
        if self._div_depth == self._card_depth:
            self.cards.append(
                {key: " ".join(parts).strip() for key, parts in self._cur.items()}
            )
            self._cur = None
            self._card_depth = None
        self._div_depth -= 1


def _parse_card_date(text: str) -> float | None:
    raw = str(text or "").strip()
    if not raw:
        return None
    # 去掉尾部时区注释，如 "+0000 (UTC)"。
    raw = re.sub(r"\s*\([^)]*\)\s*$", "", raw).strip()
    try:
        return parsedate_to_datetime(raw).timestamp()
    except (TypeError, ValueError, OverflowError):
        pass
    return _parse_message_timestamp({"date": raw})


def _extract_from_card_inbox(
    html_text: str,
    after_ts: float | None = None,
    exclude_codes: "frozenset[str] | set[str] | None" = None,
) -> tuple[bool, str | None]:
    """解析卡片式收件箱页面。

    返回 ``(recognized, code)``；recognized=True 时禁止再退回裸正则抽取
    （那条路径没有新鲜度校验，会误取旧码/占位码，比如 000000）。
    """
    if 'class="card"' not in html_text and "class='card'" not in html_text:
        return False, None
    parser = _CardInboxParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        return False, None
    if not parser.cards:
        return False, None

    newest: tuple[float, str] | None = None
    for card in parser.cards:
        context = f"{card.get('su', '')} {card.get('fr', '')} {card.get('all', '')}"
        # 只认验证码邮件，避免把普通邮件里的数字当验证码。
        if not _has_otp_context(context):
            continue
        code = _extract_code(card.get("all", ""))
        if not code:
            continue
        if exclude_codes and code in exclude_codes:
            logger.debug("[GenericAPI] 已跳过上一轮已使用过的验证码邮件")
            continue
        received_ts = _parse_card_date(card.get("dt", ""))
        if after_ts is not None:
            if received_ts is None:
                logger.debug("[GenericAPI] 卡片邮件缺少可解析时间，已跳过以避免使用旧验证码")
                continue
            if received_ts < after_ts - _FRESHNESS_TOLERANCE_SECONDS:
                logger.debug("[GenericAPI] 已跳过本次发码前的旧验证码邮件")
                continue
        if newest is None or (received_ts or 0.0) >= (newest[0] or 0.0):
            newest = (received_ts or 0.0, code)
    return True, (newest[1] if newest else None)


def _flatten_json(obj) -> str:
    parts: list[str] = []

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif x is not None:
            parts.append(str(x))
    walk(obj)
    return "\n".join(parts)


def _extract_code(text: str) -> str | None:
    """从纯文本/HTML/JSON 文本中提取 6 位 OTP。"""
    if not text:
        return None

    # 兼容 JSON：优先把所有 value 拉平再抽取。
    candidates_text = [text]
    try:
        parsed = json.loads(text)
        candidates_text.insert(0, _flatten_json(parsed))
    except Exception:
        pass

    for body in candidates_text:
        # 复用邮件 OTP 抽取逻辑。
        code = extract_otp({"text": body, "content": body, "subject": body[:200]})
        if code:
            return code

        codes = _CODE_REGEX.findall(body)
        if not codes:
            continue
        lower = body.lower()
        for code in codes:
            idx = lower.find(code)
            window = lower[max(0, idx - 80): idx + 86]
            if any(w.lower() in window for w in _CONTEXT_WORDS):
                return code
        return codes[-1]
    return None


def _script_string(html_text: str, name: str) -> str | None:
    """读取页面脚本中的简单字符串常量，不执行 JavaScript。"""
    match = re.search(
        rf"\b{re.escape(name)}\s*=\s*(['\"])(.*?)\1",
        html_text,
        flags=re.DOTALL,
    )
    if not match:
        return None
    value = match.group(2)
    return (
        value.replace(r"\/", "/")
        .replace(r"\'", "'")
        .replace(r"\"", '"')
        .replace(r"\\", "\\")
    )


def _origin(url: str) -> tuple[str, str, int | None] | None:
    try:
        parsed = urlparse(url)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return None
        return parsed.scheme.casefold(), parsed.hostname.casefold(), parsed.port
    except ValueError:
        return None


def _weimail_api_url(code_url: str) -> str | None:
    """把 weimail 取码页 ``/latest?email=X&auth_code=Y`` 换算成后端 JSON 接口。

    该邮箱服务发给用户的是一个 JS 单页（``/latest``），真实邮件数据由前端
    再去请求 ``/mail-api/{auth_code}/{email}?folder=inbox`` 拿。直接 GET
    ``/latest`` 只会得到 HTML 外壳、抽不到验证码，因此这里把它重写成后端
    JSON 接口（与页面 JS 的 apiUrl 逻辑保持一致）。无法识别时返回 None。
    """
    try:
        parsed = urlparse(code_url)
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return None
    path = parsed.path.rstrip("/").casefold()
    # 已经是 /mail-api 直连接口就不再重写。
    if "/mail-api/" in path:
        return None
    if not (path.endswith("/latest") or path == "" or path.endswith("/mail")):
        return None
    params = parse_qs(parsed.query)

    def _first(*keys: str) -> str:
        for key in keys:
            values = params.get(key)
            if values and str(values[0]).strip():
                return str(values[0]).strip()
        return ""

    email = _first("email", "mail")
    key = _first("auth_code", "code", "key")
    if not email or not key:
        return None
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return (
        f"{origin}/mail-api/{quote(key, safe='')}/{quote(email, safe='')}"
        "?folder=inbox"
    )


def _decode_data_uri(value: str) -> str:
    """解码 data URI 邮件正文；普通字符串原样返回。"""
    if not value.lstrip().casefold().startswith("data:") or "," not in value:
        return value
    header, encoded = value.split(",", 1)
    charset = "utf-8"
    charset_match = re.search(r"(?:^|;)charset=([^;]+)", header, flags=re.IGNORECASE)
    if charset_match:
        charset = charset_match.group(1).strip("\"' ") or "utf-8"
    try:
        if re.search(r"(?:^|;)base64(?:;|$)", header, flags=re.IGNORECASE):
            raw = base64.b64decode(encoded, validate=False)
        else:
            raw = unquote_to_bytes(encoded)
        try:
            return raw.decode(charset, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return ""


def _message_payload_text(payload) -> tuple[str, str]:
    """返回可抽取正文与用于判定验证码语义的文本。"""
    if not isinstance(payload, dict):
        text = _decode_data_uri(str(payload or ""))
        return text, text

    normalized = dict(payload)
    decoded_parts: list[str] = []
    for key in ("body", "html", "content", "text", "bodyText", "bodyHtml"):
        value = payload.get(key)
        if not isinstance(value, str):
            continue
        decoded = _decode_data_uri(value)
        normalized[key] = decoded
        decoded_parts.append(decoded)

    subject = str(payload.get("subject") or "")
    sender = str(
        payload.get("fromAddress")
        or payload.get("from")
        or payload.get("fromEmail")
        or ""
    )
    flattened = _flatten_json(normalized)
    context = "\n".join((subject, sender, *decoded_parts, flattened))
    return json.dumps(normalized, ensure_ascii=False), context


def _has_otp_context(text: str) -> bool:
    lower = unescape(text or "").casefold()
    return any(word.casefold() in lower for word in _CONTEXT_WORDS)


def _parse_message_timestamp(payload) -> float | None:
    """从常见邮件详情字段读取时间，统一为 Unix 秒。"""
    if not isinstance(payload, dict):
        return None
    value = None
    for key in (
        "receivedAt",
        "received_at",
        "receivedDateTime",
        "createdAt",
        "created_at",
        "timestamp",
        "date",
    ):
        candidate = payload.get(key)
        if candidate not in (None, ""):
            value = candidate
            break
    if value in (None, "") or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 100_000_000_000:
            timestamp /= 1000.0
        return timestamp if timestamp > 0 else None

    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        timestamp = float(text)
        if timestamp > 100_000_000_000:
            timestamp /= 1000.0
        return timestamp if timestamp > 0 else None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.timestamp()
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(text).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _extract_structured_code_payload(
    text: str,
    after_ts: float | None = None,
    exclude_codes: "frozenset[str] | set[str] | None" = None,
) -> tuple[bool, str | None]:
    """
    解析 ``{ok, code, mail, email, fetched_at}`` 风格的取码响应。

    ``fetched_at`` 只是查询时间，不能证明验证码属于本轮登录；启用
    ``after_ts`` 时必须以 mail 或顶层邮件时间字段判断新鲜度。
    ``exclude_codes`` 内的验证码属于此前已提交过的旧码，OTP 均为一次性，
    复用必然失败，直接跳过。
    """
    try:
        payload = json.loads(text or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return False, None
    if not isinstance(payload, dict):
        return False, None
    if "code" not in payload or not (
        "ok" in payload or "mail" in payload or "fetched_at" in payload
    ):
        return False, None
    if payload.get("ok") is False:
        raise GenericApiMailError("取码接口返回失败状态，请检查邮箱或 API Key")

    raw_code = payload.get("code")
    code = str(raw_code or "").strip()
    if not code:
        return True, None
    if not _CODE_REGEX.fullmatch(code):
        return True, None
    if exclude_codes and code in exclude_codes:
        logger.debug("[GenericAPI] 已跳过上一轮已使用过的验证码")
        return True, None
    if after_ts is None:
        return True, code

    mail_payload = payload.get("mail")
    received_ts = _parse_message_timestamp(mail_payload)
    if received_ts is None:
        received_ts = _parse_message_timestamp(payload)
    if received_ts is None:
        logger.debug("[GenericAPI] 结构化取码响应缺少邮件时间，已跳过以避免使用旧验证码")
        return True, None
    if received_ts < after_ts - _FRESHNESS_TOLERANCE_SECONDS:
        logger.debug("[GenericAPI] 已跳过结构化接口返回的旧验证码")
        return True, None
    return True, code


def _inbox_messages(html_text: str) -> list[_InboxMessage]:
    parser = _InboxListParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        return []
    return parser.messages


def _inbox_detail_url(page_url: str, html_text: str, message_id: str) -> str | None:
    detail_base = _script_string(html_text, "detailBase")
    detail_suffix = _script_string(html_text, "detailSuffix")
    if detail_base is None or detail_suffix is None:
        return None
    detail_url = urljoin(
        page_url,
        f"{detail_base}{quote(message_id, safe='')}{detail_suffix}",
    )
    page_origin = _origin(page_url)
    if page_origin is None or _origin(detail_url) != page_origin:
        raise GenericApiMailError("收件箱邮件详情地址不是同源 HTTP(S) 地址")
    return detail_url


def _extract_from_web_inbox(
    session: requests.Session,
    response,
    page_url: str,
    headers: dict[str, str],
    after_ts: float | None = None,
    exclude_codes: "frozenset[str] | set[str] | None" = None,
) -> tuple[bool, str | None]:
    """
    尝试解析网页收件箱。

    返回 ``(recognized, code)``；recognized=True 时禁止再从列表 HTML 直接
    抽取数字，因为 ``data-id`` 很可能恰好也是 6 位数。
    """
    html_text = response.text or ""
    messages = _inbox_messages(html_text)
    if not messages:
        return False, None
    if _script_string(html_text, "detailBase") is None:
        return False, None
    if _script_string(html_text, "detailSuffix") is None:
        return False, None

    # 页面通常按最新邮件在前排列。只读取主题明确属于验证码的邮件；
    # 不打开普通邮件，也不会把列表中的数字型 data-id 当成验证码。
    relevant = [item for item in messages if _has_otp_context(item.text)]
    newest_fresh: tuple[float, str] | None = None
    for item in relevant[:10]:
        detail_url = _inbox_detail_url(page_url, html_text, item.message_id)
        if not detail_url:
            continue
        detail_headers = dict(headers)
        detail_headers["Accept"] = "application/json,*/*"
        detail_response = session.get(detail_url, headers=detail_headers, timeout=20)
        final_detail_url = str(getattr(detail_response, "url", "") or detail_url)
        if _origin(final_detail_url) != _origin(page_url):
            raise GenericApiMailError("收件箱邮件详情发生了跨域跳转")
        if detail_response.status_code != 200:
            continue
        try:
            payload = detail_response.json()
        except (TypeError, ValueError, json.JSONDecodeError):
            try:
                payload = json.loads(detail_response.text or "")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue

        extractable, context = _message_payload_text(payload)
        if not (_has_otp_context(item.text) or _has_otp_context(context)):
            continue
        code = _extract_code(extractable)
        if not code:
            continue
        if exclude_codes and code in exclude_codes:
            logger.debug("[GenericAPI] 已跳过上一轮已使用过的验证码邮件")
            continue
        if after_ts is None:
            return True, code

        received_ts = _parse_message_timestamp(payload)
        if received_ts is None:
            logger.debug("[GenericAPI] 邮件详情缺少可解析时间，已跳过以避免使用旧验证码")
            continue
        if received_ts < after_ts - _FRESHNESS_TOLERANCE_SECONDS:
            logger.debug("[GenericAPI] 已跳过本次发码前的旧验证码邮件")
            continue
        if newest_fresh is None or received_ts > newest_fresh[0]:
            newest_fresh = (received_ts, code)
    return True, newest_fresh[1] if newest_fresh else None


def _fetch_current_code(
    session: requests.Session,
    code_url: str,
    headers: dict[str, str],
    after_ts: float | None = None,
    exclude_codes: "frozenset[str] | set[str] | None" = None,
) -> str | None:
    """执行一轮安全取码；支持直接响应和网页收件箱。"""
    # 有些取码服务发的是 JS 单页地址（如 weimail 的 /latest?email=&auth_code=），
    # 真正的邮件 JSON 在后端接口。先尝试换算成后端接口，抽不到时再回退原地址。
    fetch_url = _weimail_api_url(code_url) or code_url
    if _origin(fetch_url) is None:
        raise GenericApiMailError("取码地址必须是有效的 HTTP(S) URL")
    response = session.get(fetch_url, headers=headers, timeout=20)
    if response.status_code != 200:
        raise GenericApiMailError(f"取码接口返回 HTTP {response.status_code}")

    page_url = str(getattr(response, "url", "") or fetch_url)
    if _origin(page_url) is None:
        raise GenericApiMailError("取码页面跳转到了无效地址")
    structured, code = _extract_structured_code_payload(
        response.text or "",
        after_ts=after_ts,
        exclude_codes=exclude_codes,
    )
    if structured:
        return code
    recognized, code = _extract_from_web_inbox(
        session,
        response,
        page_url,
        headers,
        after_ts=after_ts,
        exclude_codes=exclude_codes,
    )
    if recognized:
        return code
    # icloud-api.top 等"直接展示邮件"的卡片式页面：带发件人/主题/时间/正文，
    # 用专用解析器做 OTP 上下文 + 新鲜度校验，避免退回裸正则误取旧码/占位码。
    recognized, code = _extract_from_card_inbox(
        response.text or "",
        after_ts=after_ts,
        exclude_codes=exclude_codes,
    )
    if recognized:
        return code
    code = _extract_code(response.text or "")
    if code and exclude_codes and code in exclude_codes:
        logger.debug("[GenericAPI] 已跳过上一轮已使用过的验证码")
        return None
    return code


def pick_account() -> GenericApiEmailAccount:
    """领取一个可用通用 API 邮箱。"""
    from core.db import claim_next_generic_api_email, generic_api_email_pool_summary

    inserted, skipped = import_from_file()
    if inserted:
        logger.info(f"[GenericAPI] 已自动从 {_ACCOUNTS_FILE.name} 导入 {inserted} 个邮箱（跳过 {skipped} 个）")

    row = claim_next_generic_api_email()
    if row is None:
        summary = generic_api_email_pool_summary()
        raise GenericApiMailError(
            f"通用 API 邮箱池没有可用账号: {summary}. 请在 WebUI 邮箱池导入：邮箱----取码地址"
        )
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[account.email] = account
    logger.info(f"[GenericAPI] 已选择一个通用 API 邮箱（DB id={row.get('id')}）")
    return account


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """从文本文件导入通用 API 邮箱，每行：email----code_url 或 email====code_url。"""
    from core.db import import_generic_api_emails
    p = Path(path) if path else _ACCOUNTS_FILE
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    if not p.exists():
        return 0, 0
    records = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----") if "----" in line else line.split("====")
        parts = [x.strip() for x in parts]
        if len(parts) < 2:
            continue
        records.append({"email": parts[0], "code_url": parts[1]})
    return import_generic_api_emails(records)


def get_account_context(email: str) -> GenericApiEmailAccount | None:
    if email in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[email]
    from core.db import get_generic_api_email_by_email
    row = get_generic_api_email_by_email(email)
    if row is None:
        return None
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[email] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_generic_api_email
    release_generic_api_email(email, status=status, note=note)
    _CONTEXT_CACHE.pop(email, None)


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
    exclude_codes: "list[str] | tuple[str, ...] | set[str] | None" = None,
) -> str:
    """
    轮询该邮箱配置的 code_url，直到提取到 6 位验证码或超时。

    settle 机制：首次拿到验证码后不立刻返回，而是继续等 OTP_SETTLE_SECONDS 秒。
    如果期间取码地址返回了不同验证码，则替换候选并重置 settle 倒计时；
    连续 settle 秒没有变化后才返回，避免取到接口缓存中的旧码。
    ``exclude_codes`` 内为此前已提交过的一次性验证码，直接跳过以免复用旧码。
    """
    account = get_account_context(email)
    if account is None:
        raise GenericApiMailError("通用 API 邮箱不存在或未导入")

    excluded = frozenset(
        str(c).strip() for c in (exclude_codes or ()) if str(c or "").strip()
    )

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    headers = {
        "Accept": "application/json,text/plain,text/html,*/*",
        "User-Agent": "Mozilla/5.0 (compatible; gpt-register/1.0)",
    }
    last_error = ""
    best_otp: str | None = None
    best_seen_at: float = 0.0
    settle_until: float | None = None
    logger.info(
        f"[GenericAPI] 开始轮询取码地址，"
        f"最长 {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s"
    )

    with requests.Session() as session:
        while time.time() < deadline:
            try:
                code = _fetch_current_code(
                    session,
                    account.code_url,
                    headers,
                    after_ts=after_ts,
                    exclude_codes=excluded,
                )
                if code:
                    now_seen = time.time()
                    if not best_otp:
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                        logger.info(
                            f"[GenericAPI] 首次锁定 OTP 候选，"
                            f"等 {settle}s 看取码接口是否出现更新验证码..."
                        )
                    elif code != best_otp:
                        logger.info(
                            f"[GenericAPI] 发现更新 OTP 候选，"
                            f"已替换旧候选并重置 settle 计时"
                        )
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                    else:
                        logger.debug("[GenericAPI] 取码接口仍返回同一 OTP 候选")
                else:
                    last_error = "HTTP 200 但未提取到验证码"
            except GenericApiMailError as exc:
                last_error = str(exc)
            except requests.RequestException as exc:
                last_error = f"网络请求失败（{type(exc).__name__}）"
            except Exception as exc:
                last_error = f"取码解析失败（{type(exc).__name__}）"

            now = time.time()
            if best_otp and settle_until is not None and now >= settle_until:
                logger.info(
                    f"[GenericAPI] settle 完成，返回已锁定的 OTP 候选，"
                    f"候选锁定时间={time.strftime('%H:%M:%S', time.localtime(best_seen_at))}"
                )
                return best_otp

            remaining = int(deadline - now)
            if best_otp and settle_until is not None:
                logger.info(
                    f"[GenericAPI] 已锁定候选 OTP，等 settle 中"
                    f"（剩余 settle ~{max(0, int(settle_until - now))}s, 总剩余 {remaining}s）..."
                )
            else:
                logger.info(
                    f"[GenericAPI] 暂未从取码接口拿到验证码，"
                    f"{interval}s 后重试（剩余 {remaining}s）..."
                )
            time.sleep(interval)

    if best_otp:
        logger.warning("[GenericAPI] 总超时但已有候选，返回已锁定的 OTP")
        return best_otp

    raise GenericApiMailError(f"等待通用 API 验证码超时；{last_error}")
