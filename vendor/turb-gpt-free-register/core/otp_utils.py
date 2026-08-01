# -*- coding: utf-8 -*-
"""
OTP 检测与抽取通用工具，被 outlook_client（Outlook 邮箱）使用。

要求：
    - 多语言关键字识别（英 / 中 / 日 / 韩）
    - 字段名容错（不同邮件 API 用不同的字段命名约定）
    - 上下文优先：在多个 6 位数中，选择离"验证码"等关键字最近的那个
"""
import re

_OPENAI_SENDER_HINT = "openai"

# 多语言关键字（用于判断是否是 OpenAI 邮件）
_OPENAI_KEYWORDS = (
    "chatgpt", "openai",
    # 英文
    "verification code", "code is", "your code", "verify your email",
    # 中文
    "代码", "验证码", "确认码",
    # 日文
    "認証コード", "検証コード", "確認コード", "一時検証", "認証",
    # 韩文
    "인증 코드", "확인 코드",
)

# OTP 上下文关键字（用于在多个 6 位数中挑出真正的验证码）
_OTP_CONTEXT_KEYWORDS = (
    "code", "verify", "verification",
    "代码", "验证", "确认",
    "コード", "認証", "検証", "確認",
    "코드", "인증",
)

_OTP_REGEX = re.compile(r"\b(\d{6})\b")


def _pick_contextual_code(body: str, matches: list[re.Match]) -> str | None:
    """Pick the code nearest an OTP keyword, preferring keywords before it."""

    body_lower = body.lower()
    keyword_spans = [
        match.span()
        for keyword in _OTP_CONTEXT_KEYWORDS
        for match in re.finditer(re.escape(keyword.lower()), body_lower)
    ]
    best: tuple[int, int, str] | None = None
    for order, match in enumerate(matches):
        start, end = match.span(1)
        score: int | None = None
        for keyword_start, keyword_end in keyword_spans:
            if keyword_end <= start:
                gap = start - keyword_end
                candidate_score = gap
            elif keyword_start >= end:
                gap = keyword_start - end
                candidate_score = gap + 20
            else:
                gap = 0
                candidate_score = 0
            if gap <= 60 and (score is None or candidate_score < score):
                score = candidate_score
        if score is not None:
            candidate = (score, order, match.group(1))
            if best is None or candidate < best:
                best = candidate
    return best[2] if best else None


def _get_field(item: dict, *names: str) -> str:
    """
    从邮件 dict 中按顺序尝试多个可能的字段名，返回第一个非空字符串。
    用于兼容不同邮件 API 的字段命名约定（例如 sendEmail / from / fromEmail / from.address）。
    """
    for name in names:
        if "." in name:
            # 支持 "from.emailAddress.address" 这种点路径
            value = item
            for part in name.split("."):
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if isinstance(value, str) and value:
                return value
        else:
            value = item.get(name)
            if isinstance(value, str) and value:
                return value
    return ""


def looks_like_openai_email(item: dict) -> bool:
    """
    判断邮件是否来自 OpenAI / ChatGPT。多语言、多字段名兼容。

    字段名容错（不同 API 返回风格不一）：
        发件人:  sendEmail / from / fromEmail / from.emailAddress.address
        发件人名:sendName / fromName / from.emailAddress.name
        纯文本:  text / bodyPreview / bodyText
        HTML:    content / body / html / body.content / bodyHtml
    """
    sender = _get_field(item, "sendEmail", "from", "fromEmail", "from.emailAddress.address").lower()
    sender_name = _get_field(item, "sendName", "fromName", "from.emailAddress.name").lower()
    subject = _get_field(item, "subject").lower()
    text = _get_field(item, "text", "bodyPreview", "bodyText").lower()
    content = _get_field(item, "content", "body", "html", "body.content", "bodyHtml").lower()

    if _OPENAI_SENDER_HINT in sender or _OPENAI_SENDER_HINT in sender_name:
        return True

    return any(k in s for s in (subject, text, content) for k in _OPENAI_KEYWORDS)


def extract_otp(item: dict) -> str | None:
    """
    从邮件中抽出 6 位 OTP。

    抽取顺序：
        1. subject（OpenAI 部分邮件直接把 6 位数放在主题里，例 "Your OpenAI code is 525210"）
        2. 纯文本字段（text / bodyPreview / bodyText）
        3. HTML 字段（content / html / body / body.content / bodyHtml，去标签后）

    若 body 中含多个 6 位数，优先选择离 "验证码 / code / 認証" 等关键字最近的那个。
    """
    # 1. 主题里如果直接有 6 位数，最可信
    subject = _get_field(item, "subject")
    if subject:
        codes_in_subject = _OTP_REGEX.findall(subject)
        if len(codes_in_subject) == 1:
            # 主题里恰好只有一个 6 位数，几乎肯定就是 OTP
            return codes_in_subject[0]

    # 2. body 字段
    candidates = [
        ("text", _get_field(item, "text", "bodyPreview", "bodyText")),
        ("html", _get_field(item, "content", "html", "body", "body.content", "bodyHtml")),
    ]

    for kind, body in candidates:
        if not body:
            continue
        # 无论 text 还是 html，都先去 HTML 标签和 style 属性
        # （QQ 邮箱转发的 OpenAI 邮件，text 字段也可能含 HTML）
        body = re.sub(r"<style[^>]*>.*?</style>", " ", body, flags=re.DOTALL | re.IGNORECASE)
        body = re.sub(r"<[^>]+>", " ", body)
        code_matches = list(_OTP_REGEX.finditer(body))
        if not code_matches:
            continue
        # 优先选离上下文关键字最近的 6 位数，关键字在数字之前时可信度更高。
        contextual = _pick_contextual_code(body, code_matches)
        if contextual:
            return contextual
        return code_matches[0].group(1)
    return None
