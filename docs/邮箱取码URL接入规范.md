# 邮箱 + 验证码 URL 接入规范

本文档面向邮箱服务提供方和接码系统开发者，说明如何为每个邮箱提供一个可由程序访问的取码 URL，并将其导入自动验证工具。

## 1. 最终交付格式

每个邮箱对应一个独立取码 URL，每行一个账号：

```text
email----code_url
```

示例：

```text
alice@example.com----https://mail-api.example.com/code/3bd9d8f5d14a4ce5a7c2
bob@example.com----https://mail-api.example.com/code/48b21b61fd6c4ba89d17
```

请勿在真实数据中使用上述示例令牌。取码 URL 等同于邮箱的读取凭证，必须作为敏感信息保管。

## 2. URL 的基本要求

取码 URL 应满足以下条件：

- 使用 `https://`，并配置有效的 TLS 证书。
- 支持无请求体的 HTTP `GET` 请求。
- 在 20 秒内返回响应，建议在 3 秒内完成。
- 验证码必须出现在服务器直接返回的 JSON、纯文本或 HTML 中。
- 不能要求浏览器执行 JavaScript 后才加载验证码。
- 不能要求人机验证、二次登录或临时 Cookie。
- 同一个 URL 可以被每隔数秒重复请求，不应因正常轮询而立即失效。

客户端的典型请求如下：

```http
GET /code/3bd9d8f5d14a4ce5a7c2 HTTP/1.1
Host: mail-api.example.com
Accept: application/json,text/plain,text/html,*/*
User-Agent: Mozilla/5.0 (compatible; gpt-register/1.0)
```

## 3. 推荐的 JSON 响应

JSON 是最稳定的接入方式。建议固定返回 HTTP `200` 和 `application/json; charset=utf-8`。

### 尚未收到验证码

```json
{
  "ok": true,
  "code": "",
  "mail": null,
  "fetched_at": "2026-08-01T14:30:10+08:00"
}
```

`code` 为空表示当前没有可用的新验证码，客户端会继续轮询。

### 已收到验证码

```json
{
  "ok": true,
  "code": "654321",
  "mail": {
    "subject": "Your ChatGPT verification code is 654321",
    "from": "noreply@openai.com",
    "received_at": "2026-08-01T14:30:12+08:00"
  },
  "fetched_at": "2026-08-01T14:30:13+08:00"
}
```

字段说明：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `ok` | 是 | 请求是否成功。`false` 表示配置或服务错误。 |
| `code` | 是 | 独立的 6 位数字字符串；暂无新码时返回空字符串。 |
| `mail` | 建议 | 当前验证码所属邮件的信息。 |
| `mail.received_at` | 强烈建议 | 邮件真实接收时间，用于过滤上一轮登录的旧码。 |
| `fetched_at` | 可选 | 本次查询时间，不能代替邮件接收时间。 |

可识别的邮件时间字段包括：

```text
receivedAt
received_at
receivedDateTime
createdAt
created_at
timestamp
date
```

时间值可以是 ISO 8601、RFC 2822、Unix 秒或 Unix 毫秒。推荐使用带时区的 ISO 8601，例如 `2026-08-01T14:30:12+08:00`。

### 接口错误

```json
{
  "ok": false,
  "code": "",
  "mail": null,
  "error": "mailbox_not_found"
}
```

仅在 URL 无效、权限错误或服务异常时返回 `ok: false`。“邮件还没到”不是错误，应返回 `ok: true` 和空 `code`。

## 4. 纯文本响应

最简单的响应可以只包含验证码：

```text
654321
```

也可以包含说明文字：

```text
Your ChatGPT verification code is 654321
```

纯文本方式无法稳定提供邮件时间，不利于排除旧码，因此仅建议用于简单场景。

## 5. HTML 响应

HTML 本质上也是文本，因此可以直接解析：

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="Cache-Control" content="no-store">
    <title>Mailbox verification code</title>
  </head>
  <body>
    <p>Your verification code is <strong>654321</strong></p>
  </body>
</html>
```

客户端会下载这段 HTML，去掉标签后寻找 6 位数字。当页面有多个 6 位数字时，会优先选择离下列关键词最近的数字：

```text
code, verify, verification, 验证码, 确认码, 認証, コード
```

建议让验证码与关键词相邻，不要在同一页面输出无关的 6 位订单号、用户 ID 或邮件 ID。

以下页面不兼容：

```html
<div id="code"></div>
<script>
  // 验证码只在浏览器执行脚本后才显示
  fetch('/api/latest-code').then(/* ... */)
</script>
```

后台取码器不是浏览器，不会执行上述 JavaScript。遇到这种情况，请直接把 `/api/latest-code` 作为取码 URL。

## 6. 服务端处理逻辑

取码接口的推荐逻辑如下：

```text
1. 根据 URL 中的不可猜测令牌找到对应邮箱
2. 查询该邮箱最新的 OpenAI / ChatGPT 验证邮件
3. 从主题或正文中提取独立的 6 位数字
4. 返回验证码以及邮件的真实接收时间
5. 没有邮件时返回空 code，不要长时间阻塞请求
```

伪代码：

```python
def get_code(token):
    mailbox = find_mailbox_by_token(token)
    if mailbox is None:
        return {"ok": False, "code": "", "mail": None}, 404

    mail = find_latest_verification_mail(mailbox)
    if mail is None:
        return {
            "ok": True,
            "code": "",
            "mail": None,
            "fetched_at": now_iso8601(),
        }, 200

    return {
        "ok": True,
        "code": extract_six_digit_code(mail.subject, mail.body),
        "mail": {
            "subject": mail.subject,
            "from": mail.sender,
            "received_at": mail.received_at_iso8601,
        },
        "fetched_at": now_iso8601(),
    }, 200
```

建议同时设置以下 HTTP 响应头：

```http
Content-Type: application/json; charset=utf-8
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

## 7. 客户端轮询行为

当 OpenAI 发送验证码后，客户端会重复访问取码 URL。当前项目的通用 URL 取码任务最长等待 30 秒，通常每隔数秒请求一次。

第一次发现验证码后，客户端会短暂继续观察：

- 如果验证码不变，返回当前候选码。
- 如果期间出现不同验证码，改用新码并重新计时。
- 如果 JSON 中的邮件时间早于本轮登录开始时间，视为旧码并忽略。

因此，接口不需要自己长轮询，每次快速返回当前结果即可。

## 8. 在项目中导入

打开 WebUI 的“导入已有账号”：

1. 在“登录素材类型”中选择“验证码 URL（HTML / JSON / 文本）”。
2. 粘贴 `email----code_url`，每行一个账号。
3. 点击“导入账号”。
4. 账号列表显示“登录素材就绪”后，即可加入处理任务。

导入格式示例：

```text
alice@example.com----https://mail-api.example.com/code/3bd9d8f5d14a4ce5a7c2
```

## 9. 提供方联调方法

首先用 `curl` 确认取码 URL 不依赖浏览器：

```bash
curl --max-time 20 \
  -H "Accept: application/json,text/plain,text/html,*/*" \
  "https://mail-api.example.com/code/REPLACE_WITH_TEST_TOKEN"
```

收到验证邮件前，应返回空 `code`；收到邮件后，应返回 6 位验证码和真实邮件时间。

联调时按顺序检查：

1. URL 在无登录浏览器中是否可访问。
2. `curl` 是否可以直接看到 JSON、文本或完整 HTML。
3. 未收到邮件时是否快速返回空结果。
4. 收到邮件后 `code` 是否恰好为 6 位数字。
5. `received_at` 是否是邮件接收时间，而不是接口查询时间。
6. 连续请求数次是否不会触发人机验证或封禁。

## 10. 常见问题

| 现象 | 原因 | 处理方法 |
| --- | --- | --- |
| HTTP 200 但一直取不到码 | 验证码由 JavaScript 二次加载 | 改为直接导入后端 JSON 接口。 |
| 总是读到上一个验证码 | 缓存了旧响应，或没有邮件时间 | 设置 `Cache-Control: no-store`，并返回 `mail.received_at`。 |
| 读到订单号而非验证码 | 页面有多个 6 位数字 | 使用结构化 JSON，或让验证码紧邻 `verification code` 等关键词。 |
| 返回 401/403 | URL 还需要登录、Cookie 或防火墙放行 | 使用不可猜测的 URL 令牌完成授权，并允许后台 GET。 |
| TLS 连接失败 | HTTPS 证书无效或证书链不完整 | 使用受信任 CA 签发的有效证书。 |
| 超过 30 秒后失败 | 邮件到达太慢或接口响应太慢 | 减少邮件同步延迟，保证每次查询快速返回。 |

## 11. 安全要求

- 每个邮箱使用独立、高强度、不可猜测的随机令牌。
- 不要使用连续数字 ID，不要只用邮箱地址作为授权参数。
- 不要在公开日志、截图、Git 仓库或聊天记录中暴露完整 URL。
- 接口日志中应对 URL 令牌、邮箱和验证码脱敏。
- 支持令牌撤销和轮换；泄露后应能立即使旧 URL 失效。
- 如非必要，不要返回完整邮件正文或其他邮件内容。
- 可以按令牌做合理限速，但必须允许客户端每隔数秒轮询。

## 12. 提供方交付检查清单

正式交付前，请确认：

- [ ] 每个邮箱都有独立的 HTTPS 取码 URL。
- [ ] 已按 `email----code_url` 格式生成导入文本。
- [ ] URL 不依赖 JavaScript、Cookie 或人机验证。
- [ ] 未收到邮件时返回空 `code`。
- [ ] 收到邮件时返回独立的 6 位数字字符串。
- [ ] JSON 响应包含准确的 `mail.received_at`。
- [ ] 响应禁止缓存。
- [ ] 完整 URL、验证码和邮箱不会出现在公开日志中。
- [ ] 已用 `curl` 完成无浏览器联调。
