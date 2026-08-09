# CLAUDE.md

本文件为 Claude Code 在本仓库工作的指引。用中文回复；默认自主推进、少问 Yes/No；回答要直接说清"到底做没做"，别只做分析。

## 项目概述

`codex-auto-sms-receiver` = Chrome MV3 扩展 + Python/Flask 后端，自动化完成 Codex/ChatGPT 的 OAuth 账号创建/登录，全程自动接收邮箱 OTP 与短信 OTP。

- **`chrome_plus_ver/`** — MV3 扩展。`sidepanel.js`(侧边栏 UI + 桥接轮询) ↔ `background.js`(service worker，真正操作页面) ↔ Python 后端(HTTP 轮询桥接)。
- **`src/`** — Flask 后端与流水线。
  - `webapp.py` / `app.py` — Web 服务入口。
  - `codex_worker.py` — 单账号流水线子进程入口(`worker_main`)。**每次 job/重试通常是独立进程**。
  - `upstream_bridge.py` — 核心编排：驱动 OAuth 各阶段、等邮箱/短信 OTP、收尾拿 callback。
  - `browser_bridge.py` — 与扩展之间的请求/响应队列。桥接 kind：`navigate` / `page_action` / `cleanup`(清浏览器) / `page_fetch`(活动页带 cookie 请求，用于读 session)。
  - `mailbox_store.py` / `hero_sms.py` / `sms_config.py` — 邮箱池、短信 provider(Hero SMS / smsbower)。
- **产物落盘（均带日期子目录）**：OAuth 凭证 → `data/codex_accounts/{YYYY-MM-DD}/codex-{email}.json`（`codex_oauth.save_codex_credential`）；导出的 Session → `data/codex_sessions/{YYYY-MM-DD}/session-{email}.json`（`upstream_bridge._capture_and_save_session`）。`artifact_store` 的凭证读取三处都是 `recursive=True`，能扫到日期子目录；`_artifact_id` 基于相对路径哈希，加子目录不影响顶层旧文件的 id。
- **导出 Session 模式（仅登录，不接码/不 OAuth）**：插件"批量处理账号"处的「导出 Session」按钮 → `POST /api/codex-pipeline` 带 `mode:'session'` → `start_batch(mode='session')` 给每个 mailbox 打 `export_session=True` → worker `run_codex_only` 读该 flag 后走**独立的 `_run_session_export`**（不是完整 OAuth 流程）：只做 `submit_email` + `submit_email_otp`（或密码+TOTP）把账号登录进 chatgpt.com，然后 `page_fetch` `/api/auth/session` 直接拿到 token 落盘。**不走 Codex OAuth authorize、不做手机验证、不点 consent、不消耗短信。** 筛选条件和批量处理一致。踩坑：最初错误地在完整 OAuth 流程末尾加 `capture_session`，导致导 session 也要接码——session 导出只需登录态即可读 session 接口，已改为独立最小路径。
- **账号导入格式**：`password_totp`（密码 + TOTP 2FA）同时接受 `email----密码----密钥` 和 `email|密码|密钥`，密钥后可再跟任意扩展字段（自动忽略，不算无效行）。解析在 `mailbox_store._split_password_totp`：先按 `----` 再按 `|` 拆，优先取固定三列，第三列不是合法 Base32 密钥时才回退"密码里含分隔符、密钥在最后一列"的老写法。导入提示 UI 只有插件侧边栏一套（`sidepanel.js`）。
- **调试页的「标签页绑定 + 快照」（在插件侧边栏）**：调试工作区列出所有窗口的标签页（`[id] title — url`），用户选一个绑定，再点「快照」把该页信息落盘。
  - 扩展消息：`list-tabs`（`chrome.tabs.query({})` + 注入可行性判断）、`capture-tab-snapshot`（带 `tabId`）。都在 `background.js` 的 `onMessage` 里，**不经过 Python 桥接**，也没改 `getActiveTab()` / `performBridgeRequest`，OAuth 流水线路径零影响。
  - 快照走 `executeInIsolatedWorld(tabId, collectPageSnapshot)`：**`executeScript` 不要求目标 tab 是 active**，所以绑定的后台 tab 也能取，不抢焦点。`collectPageSnapshot` 必须自包含（会被序列化，闭包变量取不到）。
  - 快照内容面向"后续怎么操作这个页面"：page(url/title/readyState/viewport…) + 可操作元素清单（每个带 **`selector`（querySelector 可直接用）** 和 `xpath`、rect、visible、label、value）+ forms（含 submit 控件清单）+ iframes + **open shadow DOM 递归**（现代页面控件常在 shadow root 里，不递归会看着像空页）+ errors + storage keys + cookie names + 完整 HTML。password 类型的 value 一律脱敏成 `***(N 位)` 再落盘。
  - 落盘：`POST /api/extension/debug/snapshot` → `logs/debug/{tabId}-{YYYYmmdd-HHMMSS}-screenshot.log`（UTC，JSON 文本；同秒第二次自动加序号不覆盖）。`artifact_store.list_logs` 递归扫 `*.log`，所以快照会出现在「日志」页且可下载。
  - 绑定的 tabId 存 `chrome.storage.session`（不是全局变量：侧边栏一关一开脚本就重跑；tabId 也只在本次浏览器运行内有效，生命周期正好对上）。绑定的 tab 被关掉时列表刷新会清空绑定并提示，不会静默改打别的 tab。
  - `chrome://` / 应用商店 / `file://` 等页面无法注入，列表里标灰禁选；无痕窗口的标签页要用户在 `chrome://extensions` 给扩展开「允许在无痕模式下运行」才会出现在列表里。
  - **坑：后台 tab 的 timer 被 Chrome 节流**。快照是一次性注入，不受影响；但如果以后要在绑定 tab 上做"等元素出现"的轮询，页面里的 `setTimeout` 轮询在非可见 tab 会被降到分钟级——要么让两个 tab 各自在可见窗口，要么把轮询放到 service worker 侧、每次注入只做一次性判断。
- **gcash 提炼（`mode:'gcash'`，两个绑定标签页）**：插件「批量处理账号」的「gcash提炼」按钮（在「仅登录」后面）→ `start_batch(mode='gcash')` 从 `data/gcash-tabs.json`（`GcashTabStore`，调试页绑定后保存）取两个 tabId 塞进 mailbox → worker `run_codex_only` 读 `gcash_extract` flag 走 `_run_gcash_extraction`。**不接码、不走 OAuth**，但流程带人工：每个账号拿到付款链接后要人扫码。
  - **流程**：`_bridge_tab(login_tab)` 上下文里复用 `_login_account_in_browser`（线程局部 `_bridge_context.tab_id`，`_bridge_request` 自动补 `tab_id`，全部旧 helper 零改动）→ `_read_gcash_access_token`（登录确认时已拿到 session payload，取 `accessToken`，没有就再 `page_fetch`/打开 session 接口兜底）→ 切 `_bridge_tab(extract_tab)`：`gcash_probe` 探测（`page_ready`）→ `gcash_submit`（填 `#token` + 点 `#submitButton`）→ `_wait_for_gcash_outcome` 轮询判定 → 成功则 `_bridge_navigate(链接)` 回登录 tab，`_wait_for_gcash_scan` 监控 `tab_url` 直到离开 `m.gcash.com`/adyen 跳回 `chatgpt.com`。
  - **成败判定（快照实证）**：进度条 `#progressBar` 100% 为前提；`#resultPanel` **可见** 且有链接 = 成功，不可见 = 失败。**失败页的 `#resultValue` 里残留着上一轮的旧链接**（panel `hidden=""` 藏起来了），所以绝不能直接读 value 判成败。页面轮询 `setTimeout` 在后台 tab 会被节流，判定放 service worker 侧驱动。
  - **登录前清理只清登录 tab**：`_login_account_in_browser` 的 `_bridge_cleanup` 因 tab 上下文自动钉在登录 tab；前端 `startPipelineRun('gcash')` 启动前**跳过** `runBrowserCleanup`（它只认活动页，会把绑定的 153 提炼页打成 about:blank），`trackCompletedJobs` 对 `mode==='login'|'gcash'` 同样跳过收尾清理。
  - **失败语义**：提炼失败 / 扫码超时 / 链接为空 → 消息带 `gcash_extract_failed` 令牌 → `_failure_info` 分类 `gcash_extract_failed`（**不可重试**，必须排在 `超时` 规则之前）；标签页失效错误也补打该令牌。提炼失败会 `store.update_gcash(status='failed')` 落邮箱记录。
  - **导出**：账号清单「导出 gcash 提炼结果」按钮（`+导入账号` 后面）→ `POST /api/accounts/gcash-export`（`confirmed` + `account_ids`，**取当前筛选+搜索可见的账号**，有结果才导出）→ 按 `----提炼成功----` / `----提炼失败----` 分组，每行 = 原导入素材 + `----` + accessToken（`mailbox_store.export_gcash`）。账号列表 API 只暴露 `gcash_status`/`has_gcash_token`/`gcash_message`，token 不出口。
- **`vendor/turb-gpt-free-register/core/generic_api_mail_client.py`** — "通用 API 取码邮箱"客户端(轮询取码地址提取 6 位 OTP)。
- **仅登录模式（`mode:'login'`）**：插件「仅登录」按钮（在「导出 Session」之后）→ `start_batch(mode='login')` 给 mailbox 打 `login_only=True` → `run_codex_only` 走 `_run_login_only`：与 Session 导出共用 `_login_account_in_browser`（清浏览器 → `chatgpt.com/auth/login_with` → submit_email + 邮箱 OTP，或密码 + TOTP），登录完成后**不再做任何导航**直接返回，**不读 session、不走 OAuth、不接码**。后端强制一次只允许 1 个账号（`start_batch` 校验），UI 也只在恰好 1 个可运行账号时启用按钮。
  - **踩坑：仅登录必须跳过"任务完成后清理"**。`sidepanel.js` 的 `trackCompletedJobs` 见到 job 变终态就调 `runBrowserCleanup`，而 `background.js` 的 `cleanupBrowserState` 会清 cookies 并把标签页 `chrome.tabs.update(url:'about:blank')` —— 对仅登录来说等于刚登录就被登出、页面变 about:blank。修复：`start_batch` 把 `mode` 写进 pipeline（`_pipeline_public_locked` 直接透传），前端 `pipelineState.mode==='login'` 时跳过收尾清理；**启动前**的清理照常执行。
  - 登录成功后也不要再 `_bridge_navigate("https://chatgpt.com/")`：页面本来就在登录后的跳转链上，多这一次导航只会撞"标签页加载超时"，并和标签页被停到 about:blank 抢时序。
  - **帧销毁 = 登录成功（本轮实测：密码+TOTP 提交后必现 `Frame with ID 0 was removed`）**：登录（非 OAuth）路径里 OTP/密码提交成功后页面直接跳 chatgpt.com，注入帧被销毁，`executeScript` 抛 `Frame with ID 0 was removed`。绝不能当失败。`_login_account_in_browser` 用 `_submit_login_step`（`_is_frame_teardown_error` 识别帧销毁类错误：`Frame with ID X was removed` / `No frame with id` / `No tab with id` / `Target closed` / `context was destroyed` / `页面动作返回空结果`，返回 `frame_teardown` 标记继续）之后一律用 `_confirm_logged_in` 做**唯一判定**：轮询 `chatgpt.com/api/auth/session`（先原页读，读不到/未登录再导航到 chatgpt.com 后同源读，90s 预算），返回有 `user`/`accessToken` 的 JSON 才算登录成功；超时且发生过帧销毁则报"提交后页面跳转但未确认登录态"。`submit_email` 的 5 次重试仅针对它自己（导航链未稳时帧销毁），其它步骤不再盲目重试（会重复消费一次性 TOTP）。Session 导出复用同一判定：`_confirm_logged_in` 拿到的 payload 直接 `_save_session_payload` 落盘，不再二次读取。
- **`tests/`** — pytest；改动后跑 `python -m pytest -q`（当前基线 **189 passed**）。

## OAuth 流程阶段（OpenAI 新注册流）

`email → create-account/password(此时还没发 OTP) → activate_passwordless_signup(或设密码) → 邮箱 OTP → phone-verification → /about-you(填姓名+年龄) → /sign-in-with-chatgpt/codex/consent(点"继续") → localhost:1455/auth/callback?code=...`

- **手机验证两个 URL 要分清（重要）**：`https://auth.openai.com/add-phone` = 手机**号码输入**页；`https://auth.openai.com/phone-verification` = 收到号码后的**验证码输入**页。一个号码超时后，OpenAI 会把它**锁定在 /phone-verification 的验证码步骤**，重新打开 /phone-verification 只会显示同一个锁定号码——要换号必须导航到 **/add-phone** 拿到新的号码输入框。接码重试循环里 attempt>1 会先 `_bridge_navigate("https://auth.openai.com/add-phone")` 再取号，否则新号会落在旧号的验证码页上被白白浪费。
- **清 cookie 后 `auth.openai.com/log-in` 是"会话已结束"过渡页**（`is_missing_session:true`），只有一个"登录"链接（`href=chatgpt.com/auth/login_with?callback_path=/`），**没有邮箱输入框**。要进真正的邮箱登录页必须点这个链接 / 直接导航 `chatgpt.com/auth/login_with`。所以 Session 导出的登录入口用 `chatgpt.com/auth/login_with`（不是 `/log-in`）；`submit_email` 也加了兜底：没有邮箱框但有"登录"链接时先点它再等邮箱框（OAuth 流程走 authorize URL 会自建 session，不撞这个过渡页）。
  - `/auth/login_with` 是**重定向端点**，会连跳好几跳才落到邮箱表单；`submit_email` 可能注入到正在被销毁的帧里报 `Frame with ID X was removed`。`_run_session_export` 对 submit_email 做了 Python 侧重试（帧销毁/超时 → 等 2s 重试，最多 5 次），等重定向链稳定后邮箱表单就在了。
  - **登录页的邮箱框和"继续使用 Google/Microsoft/Apple"社交按钮在同一个 form 里**。`submitNearestForm()` 会点该 form 里**第一个** submit 控件，很可能就是 Google 按钮 → 页面跳去 Google 登录、OTP 邮件根本没发出，最后表现为"等待通用 API 验证码超时；HTTP 200 但未提取到验证码"（看着像取码邮箱坏了，其实是点错按钮）。`submit_email` 现在显式挑选邮箱的"继续/Continue"控件并**排除**社交 provider（google/microsoft/apple/facebook/github/sso/passkey/手机…），挑不到才回退按 Enter；并且若提交后落到第三方登录域名，直接报错而不是谎报"OTP 已发送"。

- **老账号重新走 OAuth 不需要接码**：只有官方真的跳到手机验证页时才接码。用 `probe_stage`(无副作用探测)判断 `needs_phone`，避免浪费短信号码。
- `background.js` 的 `executePageStep` 处理 `page_action`（submit_email / submit_email_otp / submit_phone / submit_phone_otp / activate_passwordless_signup / finalize_and_get_callback / probe_stage / snapshot_dom）。`navigateActiveTab` 单独处理 `navigate`。

## 接码（SMS）架构

- **多渠道 provider**：`src/hero_sms.py` 的 `_RuntimeSmsCoordinator` 在上游 SMS 生命周期模块上加一层，支持 `hero` + `smsbower` 两个渠道。渠道顺序由 `SMS_CHANNEL_PRIORITY` 决定（默认 hero）。`acquire_number` 按渠道优先级依次尝试；单渠道内按国家队列取号。
- **国家 cursor（hero 与 smsbower 对称）**：每个渠道各有一个 `_country_cursors[channel]`，取号成功后 `_advance_cursor` 前进一位，下次从下个国家开始（跨任务轮转，避免总卡同一国家）。指定了具体 country 时钉住该国不轮转。
- **无“最多换号次数”**：接码失败后按优先级把**所有渠道×国家组合**逐个试完才报失败。浏览器路径 `upstream_bridge._sms_slot_count()` 算出组合总数作为循环上限；`SMS_MAX_RETRIES` env 仅为 vendor 协议路径保留，保存时按组合数自动写入（不再是用户可填字段）。真无号（`SmsNoNumbersError`）时提前 break。
- **每次失败必取消**：每条失败路径都调用 `sms_provider.cancel()`（按渠道路由发 `setStatus=8`，过 2 分钟 EARLY_CANCEL 窗口后生效），避免号码后续再收短信被扣费。改重试循环时保证新增的失败分支也 cancel。
- **限价按国家生效（每国必填）**：不再有渠道级全局限价。Hero 每国 `{max, fixed}`（fixedPrice 默认 false）；smsbower 每国 `{min?, max}`。存储在 env `HERO_SMS_COUNTRY_PRICES` / `SMSBOWER_COUNTRY_PRICES`（JSON, 按国家 id）。`sms_config.normalize_country_prices` 校验每个选中国家必须有 max；`hero_sms._country_price_map` 在 acquire 时按国家覆盖价格参数。保存时缺任一国家的 maxPrice 会报错。
- **UI（只有一套）**：**Chrome 扩展侧边栏** `chrome_plus_ver/sidepanel.html` + `sidepanel.js`（含 hero + smsbower 两个渠道配置），打 `/api/sms-config`。Flask 网页版 UI（原 `templates/index.html`）已删除，后端只保留 JSON API（`/` 返回提示 JSON）。国家选择用共享的 `createCountryPicker` 工厂（`priceMode:'hero'|'smsbower'`），每个国家行内嵌限价输入：hero=价格上限+精准价(fixedPrice)，smsbower=最低价+价格上限；状态在 picker 的 `S.prices`，`getPrices()/setPrices()` 存取。已移除全局 `#heroMaxPrice`/`#smsMaxRetries`/`#smsbowerMinPrice`/`#smsbowerMaxPrice`。
- 两份接码平台 API 文档在 `C:\vs_project\my_register\web-workflow-reconsitution\doc\`（hero-sms-api.md、smsbower-api.md）。smsbower 取消用 `setStatus&status=8`；hero 用 `setStatus&status=8`。hero 取号 `getNumberV2` 支持 `maxPrice` + `fixedPrice`。

## 关键技术约定

- **改扩展 JS(`background.js`/`sidepanel.js`)→ 必须去 `chrome://extensions` 重载扩展**（sidepanel.js 改动还要关掉侧边栏重开一次，让它重新抓 windowId）。
- **改 Python → 必须重启 worker/服务进程**（接码智能门控、取码逻辑都在 Python 侧；只重载扩展无效）。
- 页面注入代码（`executeInMainWorld` 里那个大 `async (input)=>{...}` 箭头函数）在页面 MAIN world 运行，用 `fillValue`(原生 setter + input/change，兼容 React)、`trustedClick`(合成 pointer/mouse 事件)、`waitFor(predicate, timeoutMs)`。
- **活动页锁定到侧边栏所在窗口**：不要用 `chrome.tabs.query({active:true, currentWindow:true})`（在 SW 里跟随焦点窗口）。侧边栏用 `chrome.windows.getCurrent()` 拿 windowId，随每条桥接消息带上；后台 `getActiveTab()` 优先按 `boundWindowId` 查，窗口没了才回退 currentWindow。隐私窗口跑任务、切到普通窗口不会被劫持。
- **每个账号开始前必须清浏览器（隐私模式）**：串行流水线切下一个账号时，上一个账号的 Cookies/会话/consent 不能残留，否则 OpenAI 会显示 `/choose-an-account` 或 `consent verifier already used`。侧边栏的"任务完成后清理"是**轮询驱动的、有时序竞态**（下一个 worker 可能已经开始 OAuth）。可靠做法：worker 在 `_run_codex_in_browser` 首个 `_bridge_navigate` **之前**同步调用 `_bridge_cleanup()`（桥接 `kind:'cleanup'` → `background.js` 的 `cleanupBrowserState`，清 openai/chatgpt 的 cookies/cache/localStorage/indexedDB/serviceWorkers）。

## 踩坑经验（重要，避免重复犯）

1. **finalize 帧销毁 = OAuth 其实成功**。收尾时页面从 auth.openai.com 连跳到 localhost callback，注入帧被销毁有两种表现：抛 `Frame with ID X was removed`，**或 `executeScript` 静默返回 null → "页面动作返回空结果"**。两种都要恢复：轮询标签页自身 URL 拿 callback；没到就等下一页重新注入 finalize 继续驱动，直到拿到 callback 或超时。别只处理抛异常那一种。
2. **finalize 超时预算要 < Python 请求超时**，否则两个 180s 撞车 → 孤儿卡死（看起来像"崩溃"）。现在浏览器侧 120s 返回、Python 侧 180s 收，留 60s 余量；超时返回带 `snapshot: buildDebugSnapshot()`，Python 会打 `[BridgeDOM]` 卡在哪个页面。
3. **consent 页的"继续"只能点一次**（consent verifier 是一次性的）。finalize 收尾循环原来每 500ms 点一次主按钮，consent 页第一次点击已消费 verifier 并跳到 callback（带 code），但导航还没完成时循环又点了一次 → 第二次提交复用已花掉的 verifier → callback 变成 `access_denied: The consent verifier has already been used`。修复：finalize 循环对每个页面 URL **最多提交一次**（`submittedPages` 去重），点击后 `waitFor` 等 URL 变化/跳到 callback，不再狂点。
3. **OTP 误判成功（邮箱 & 手机同类坑）**：email-verification / phone-verification 页永远有"继续"按钮，且错/过期码只会在网络往返后才渲染错误（甚至只是静默清空输入框）。若在"仍停留在该验证页"时就当作通过，会白白浪费短信号码、并让 finalize 卡在空验证码框上狂点"继续"报"需要填写验证码"直到超时。
   - 邮箱：`onEmailOtpStep`(有 code 输入框 + 在 /email-verification) 守卫，还在该步只看 `visibleError()`，绝不当 post-otp。
   - 手机：`submit_phone_otp` 必须确认页面**真的离开了 /phone-verification**(跳到 about-you / consent / callback / 无 code 输入框)才算通过；否则回传 `error_text`(可为合成"手机验证码未通过：页面仍停留在 phone-verification")，让 Python 接码循环 cancel 当前号码、换新号重试，**绝不 log "手机号验证通过"**。SMS 码被 OpenAI 拒(号码被标记/码过期)时错误文案可能是"需要填写验证码"(必填)而非"代码不正确"。
4. **一次性 OTP 严禁复用旧码**。快速/背靠背重试时取码接口常把上一轮旧邮件的验证码当成本轮返回 → "代码不正确"。防御：
   - 时间戳新鲜度（`after_ts` + `_FRESHNESS_TOLERANCE_SECONDS`）+ settle 机制；`fetched_at` 只是查询时间不算数，必须用邮件真实时间。
   - **持久化"已用验证码"**：`data_dir/otp_consumed.json`（按邮箱 casefold 归档、去重、6h TTL、每邮箱最多 20 条）。`_wait_for_email_otp` 成功后 `_record_consumed_otp` 落盘；下轮（即便另一个进程）取码前 `_consumed_otps_for` 读出来作 `exclude_codes` 传给 `fetch_latest_otp`，贯穿结构化/网页收件箱/纯文本三条抽码路径。取码器只对标注 `supports_exclude_codes` 的 provider 传排除项。
5. **新取码邮箱可能是 JS SPA 壳**（如 weimail `sms.linlinflow.ccwu.cc` 的 `/latest`）。真正 JSON 在 `/mail-api/{auth_code}/{email}?folder=inbox`；`_weimail_api_url` 负责把 `/latest` 换算成后端接口，抽不到再回退原地址。
   - **卡片式收件箱**（如 `icloud-api.top/show/...`）：HTML 直接展示邮件，结构是 `<div class="card">` 内含 `.fr/.su/.dt/.bd`。不专门解析就会掉到裸正则 `_extract_code` 兜底——**没有新鲜度校验，最坏还会 `return codes[-1]` 瞎猜**，于是取到旧码/占位码（曾出现 `000000`）。用 `_CardInboxParser` + `_extract_from_card_inbox` 做 OTP 上下文 + `.dt` 新鲜度 + `exclude_codes` 校验，且 `recognized=True` 后**绝不回退裸正则**。新增取码邮箱格式时，优先写专用解析器而不是靠兜底。
6. **MV3 service worker 会休眠**导致漏收桥接请求 → 整轮超时且无响应（区别于 `waitForTabComplete` 自己的 45s 超时）。`_bridge_navigate` 对 navigate 超时做一次性重试。
7. **OpenAI 整页错误屏别塞进"未识别页面"**。提交邮箱 OTP 后 OpenAI 可能跳到整页错误屏（错误写在 `<h1>`+副标题里，`visibleError()`（只扫 `[role=alert]/.error`）看不到），常见两类：`身份验证错误 / account_deactivated`（账号已被删除停用——**死号，别重试别浪费短信**）、`糟糕，出错了！/ Operation timed out`（OpenAI 服务抖动——**可重试**）。若不识别就统一报成 `未识别页面阶段: unknown`，被 `_failure_info` 当 `task_failed` 不重试，且日志看不出真因。
   - `background.js` 的 `pageLevelError()` 专门识别这些整页错误，回传带 ASCII 令牌的消息（`account_deactivated` / `openai_transient`）；已接入 email-OTP 阶段判定。
   - `codex_service._failure_info` 按令牌分类：`account_deactivated → 不可重试`（且 `_handle_result_locked` 落成终态 `deactivated`、邮箱标记死号）；`openai_transient` / `浏览器桥接超时` / `超时` → `transient_network` 可重试。
8. **某一步"特别慢"先查 `background.js` 对应 `waitFor` 的判据，不是网络慢**。判据没覆盖到本流程真实出现的页面时，`waitFor` 会一路空转到 30s 超时才返回 falsy（不抛错，所以只表现为卡顿）。实例：`submit_email` 的判据只认 code inputs / `/email-verification` / create-account-password / 第三方域 / "验证码"文案，**漏了老账号登录流的密码输入页** → 每次填密码前白等 30s（填 2FA 那步判据能立刻命中，所以对比明显）。已补 `input[type=password]` → `'password'` 阶段，且必须排在 `isCreateAccountPasswordPage()` **之后**（注册流的设置密码页同样有 password input）。
9. **改完 Python 一定要重启后端进程再复现**。worker 是同进程内的线程，模块在服务启动时就加载完了，改文件不生效。判据：traceback 里的**行号与当前源码内容对不上**（例如报错行显示的是注释）就是在跑旧字节码；对一下后端进程 StartTime 和文件 mtime 即可确认，别去追不存在的代码 bug。

## 编辑注意

- 用 `Edit` 插入新函数时，`old_string` 要用**已存在的锚点**（如 `def _decode_data_uri`），别把要新增的内容当 old_string。
- 给大段代码重新缩进后用 `ast.parse` 验证 Python；JS 用 `node --check chrome_plus_ver/background.js`。
