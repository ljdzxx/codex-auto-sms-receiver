const DEFAULT_CLEANUP_ORIGINS = [
  'https://chatgpt.com',
  'https://auth.openai.com',
  'https://openai.com',
  'https://platform.openai.com',
  // 注册流程的邮箱验证页会出现 "Continue with Google" 等社交登录入口，
  // 不清掉 Google 的登录态/账号选择器缓存，下一个账号会看到上一个账号的邮箱、用户名残留。
  'https://accounts.google.com',
  'https://google.com',
];

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
});

chrome.runtime.onStartup?.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
});

// The window that owns the side panel driving the current run. The side panel
// sends its own windowId with every bridge message so we can pin tab lookups to
// that window instead of whatever window happens to be focused.
let boundWindowId = null;

function setBoundWindowId(windowId) {
  if (typeof windowId === 'number' && windowId >= 0) {
    boundWindowId = windowId;
  }
}

// ---------------------------------------------------------------- proxy pool
// The Python side round-robins the pool and tells us, once per account, which
// proxy the browser must use ("proxy_apply" bridge request). Chrome applies
// proxy settings browser-wide, so this is the only place that touches them.
const PROXY_STATE_KEY = 'activeProxyConfig';
// Everything the extension itself talks to must never go through the proxy:
// the backend is on loopback, and routing it through a remote proxy would break
// the bridge (and leak local traffic).
const PROXY_BYPASS_LIST = ['<local>', 'localhost', '127.0.0.1', '[::1]'];
let activeProxy = null;

function proxySchemeIsSocks(scheme) {
  return String(scheme || '').startsWith('socks');
}

async function loadActiveProxy() {
  // A service-worker restart must not forget which proxy needs its credentials,
  // otherwise the auth handler below would go silent mid-run.
  if (activeProxy !== null) return activeProxy;
  try {
    const stored = await chrome.storage.session.get(PROXY_STATE_KEY);
    const value = stored?.[PROXY_STATE_KEY];
    activeProxy = value && typeof value === 'object' ? value : null;
  } catch (error) {
    activeProxy = null;
  }
  return activeProxy;
}

async function persistActiveProxy(proxy) {
  activeProxy = proxy || null;
  try {
    if (activeProxy) await chrome.storage.session.set({ [PROXY_STATE_KEY]: activeProxy });
    else await chrome.storage.session.remove(PROXY_STATE_KEY);
  } catch (error) {
    /* session storage is best-effort; the in-memory copy still works */
  }
}

// ------------------------------------------------------- proxy stealth
// A proxy is not hidden by routing alone: left at Chrome's default, WebRTC lets
// a page ask for ICE candidates and learn the REAL local/public address behind
// the proxy. That is the single most common way "you are on a proxy" is
// detected. It cannot change the exit IP's own reputation — a flagged
// datacenter range stays flagged — but it stops handing the signal over free.
//
// Timezone and language used to be derived from the proxy's country here. They
// are now user-specified and browser-wide; see the 浏览器指纹 section below.
async function setWebRtcLeakProtection(enabled) {
  const setting = chrome.privacy?.network?.webRTCIPHandlingPolicy;
  if (!setting?.set) return;
  try {
    if (enabled) {
      // Only send candidates that go through the proxy — never the real address.
      await setting.set({ value: 'disable_non_proxied_udp' });
    } else {
      await setting.clear({});
    }
  } catch (error) {
    /* another extension may own this setting; routing still works */
  }
}

async function applyProxyStealth(proxy) {
  await setWebRtcLeakProtection(!!proxy);
}

// --------------------------------------------------- 浏览器指纹（用户指定）
// Timezone and language used to follow whatever country the proxy exited from.
// They are now set explicitly by the operator in 调试 → 指纹 and apply to the
// WHOLE browser — address-bar navigations, in-page fetch/XHR, every tab — until
// the switch is turned off again.
//
// Timezone is never in an HTTP header; it leaks through JavaScript
// (Intl.DateTimeFormat().resolvedOptions().timeZone, Date#getTimezoneOffset,
// Date#toString). The overrides therefore go through CDP rather than patching
// the page's JS: a patched Intl/Date is itself detectable (Function#toString,
// prototype checks), while Emulation.setTimezoneOverride changes what the
// engine itself reports. CDP overrides live only as long as the debugger is
// attached (they do survive navigations), so a session is held on every tab —
// that is what puts Chrome's "正在调试此浏览器" bar on top of the window.
//
// Accept-Language is additionally set through declarativeNetRequest, so requests
// that never reach an attached tab (or fire before we attach) still carry it.
const FINGERPRINT_STORAGE_KEY = 'fingerprintConfig';
const FINGERPRINT_LANG_RULE_ID = 9102;
// Session rule the proxy-driven implementation used to install; removed on
// every update so an extension reload mid-session cannot leave it behind.
const LEGACY_PROXY_LANG_RULE_ID = 9101;
const FINGERPRINT_DNR_RESOURCE_TYPES = [
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font',
  'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'other',
];
let fingerprintConfig = { enabled: false, timezone: '', language: '' };
let fingerprintLoad = null;
// Tabs this module currently holds (or shares) a debugger session on.
const fingerprintTabs = new Set();
let fingerprintUaMetadata = null;

function normalizeFingerprint(raw) {
  const source = raw && typeof raw === 'object' ? raw : {};
  const timezone = String(source.timezone || '').trim();
  const language = String(source.language || '').trim();
  // "Enabled" without both values would mean overriding with nothing at all;
  // guessing a timezone is worse than not touching it.
  return { enabled: !!source.enabled && !!timezone && !!language, timezone, language };
}

function fingerprintAcceptLanguage(language) {
  const tag = String(language || '').trim();
  if (!tag) return '';
  const base = tag.split('-')[0];
  return base && base.toLowerCase() !== tag.toLowerCase() ? `${tag},${base};q=0.9` : tag;
}

async function loadFingerprintConfig() {
  if (!fingerprintLoad) {
    fingerprintLoad = (async () => {
      try {
        const stored = await chrome.storage.local.get(FINGERPRINT_STORAGE_KEY);
        fingerprintConfig = normalizeFingerprint(stored?.[FINGERPRINT_STORAGE_KEY]);
      } catch (error) {
        fingerprintConfig = { enabled: false, timezone: '', language: '' };
      }
      return fingerprintConfig;
    })();
  }
  return fingerprintLoad;
}

// Overriding the UA string without its client-hint counterpart is itself a
// mismatch (Sec-CH-UA vs navigator.userAgent), so hand Chrome back its own
// real metadata; we only want the acceptLanguage part of this command.
async function resolveUserAgentMetadata() {
  if (fingerprintUaMetadata !== null) return fingerprintUaMetadata || null;
  try {
    const data = navigator.userAgentData;
    const high = await data.getHighEntropyValues([
      'architecture', 'bitness', 'model', 'platformVersion', 'uaFullVersion', 'fullVersionList', 'wow64',
    ]);
    fingerprintUaMetadata = {
      brands: (data.brands || []).map((item) => ({ brand: item.brand, version: item.version })),
      fullVersionList: (high.fullVersionList || []).map((item) => ({ brand: item.brand, version: item.version })),
      platform: high.platform || data.platform || '',
      platformVersion: high.platformVersion || '',
      architecture: high.architecture || '',
      model: high.model || '',
      mobile: !!data.mobile,
      bitness: high.bitness || '',
      wow64: !!high.wow64,
    };
  } catch (error) {
    fingerprintUaMetadata = false;
  }
  return fingerprintUaMetadata || null;
}

async function setFingerprintLanguageHeader(acceptLanguage) {
  if (!chrome.declarativeNetRequest?.updateSessionRules) return;
  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [FINGERPRINT_LANG_RULE_ID, LEGACY_PROXY_LANG_RULE_ID],
      addRules: acceptLanguage
        ? [{
          id: FINGERPRINT_LANG_RULE_ID,
          priority: 1,
          action: {
            type: 'modifyHeaders',
            requestHeaders: [{ header: 'Accept-Language', operation: 'set', value: acceptLanguage }],
          },
          // Browser-wide on purpose: the operator asked for every request,
          // address bar included, to speak the configured language. No
          // urlFilter — an absent condition matches every URL.
          condition: { resourceTypes: [...FINGERPRINT_DNR_RESOURCE_TYPES] },
        }]
        : [],
    });
  } catch (error) {
    /* header alignment is best-effort; never block a run on it */
  }
}

// Chrome refuses a second override while one is "already in effect" (which can
// linger from a session that went away); clearing first makes re-applying — on
// every navigation, on every service-worker wake-up — idempotent.
async function sendOverrideCommand(target, method, params, clearedParams) {
  try {
    await chrome.debugger.sendCommand(target, method, params);
    return;
  } catch (error) {
    if (!/already in effect/i.test(getErrorMessage(error))) throw error;
  }
  await chrome.debugger.sendCommand(target, method, clearedParams).catch(() => {});
  await chrome.debugger.sendCommand(target, method, params);
}

async function applyFingerprintToTab(tabId) {
  if (!fingerprintConfig.enabled || typeof tabId !== 'number' || !chrome.debugger?.attach) return false;
  const target = { tabId };
  if (!fingerprintTabs.has(tabId)) {
    try {
      await chrome.debugger.attach(target, '1.3');
    } catch (error) {
      // Someone is already attached. If it is one of our own sessions (a page
      // step's click pump) sendCommand still works and that path re-applies the
      // fingerprint when it releases; if it is DevTools, the commands below
      // fail and we simply skip this tab.
      if (!/Another debugger is already attached/i.test(getErrorMessage(error))) return false;
    }
    fingerprintTabs.add(tabId);
  }
  try {
    await sendOverrideCommand(
      target,
      'Emulation.setTimezoneOverride',
      { timezoneId: fingerprintConfig.timezone },
      { timezoneId: '' },
    );
  } catch (error) {
    // Not even the timezone went in (usually DevTools owning this tab): report
    // the tab as not covered instead of pretending it is.
    fingerprintTabs.delete(tabId);
    return false;
  }
  try {
    await sendOverrideCommand(target, 'Emulation.setLocaleOverride', { locale: fingerprintConfig.language }, {});
  } catch (error) {
    /* Intl's locale stays as-is; Accept-Language is still covered by the DNR rule */
  }
  try {
    // Keeps the real user agent — only navigator.language(s) and the
    // Accept-Language header of this tab's requests change.
    const metadata = await resolveUserAgentMetadata();
    await chrome.debugger.sendCommand(target, 'Emulation.setUserAgentOverride', {
      userAgent: navigator.userAgent,
      acceptLanguage: fingerprintAcceptLanguage(fingerprintConfig.language),
      ...(metadata ? { userAgentMetadata: metadata } : {}),
    });
  } catch (error) {
    /* navigator.language(s) stays as-is; the header rule still applies */
  }
  return true;
}

// Called after a page step gives its debugger session back: if that session was
// the one carrying the overrides, detaching it dropped them.
function reapplyFingerprintAfterRelease(tabId) {
  if (!fingerprintConfig.enabled) return;
  fingerprintTabs.delete(tabId);
  applyFingerprintToTab(tabId).catch(() => {});
}

async function detachFingerprintTabs() {
  const ids = [...fingerprintTabs];
  fingerprintTabs.clear();
  for (const tabId of ids) {
    try {
      await chrome.debugger.detach({ tabId });
    } catch (error) {
      /* tab closed, or the session was already gone */
    }
  }
}

async function applyFingerprintEverywhere() {
  await setFingerprintLanguageHeader(fingerprintConfig.enabled ? fingerprintAcceptLanguage(fingerprintConfig.language) : '');
  if (!fingerprintConfig.enabled) {
    await detachFingerprintTabs();
    return { applied: 0, skipped: 0 };
  }
  const tabs = await chrome.tabs.query({}).catch(() => []);
  let applied = 0;
  let skipped = 0;
  for (const tab of tabs) {
    if (!tabIsDrivable(tab)) continue;
    if (await applyFingerprintToTab(tab.id)) applied += 1;
    else skipped += 1;
  }
  return { applied, skipped };
}

async function setFingerprintConfig(raw) {
  await loadFingerprintConfig();
  const next = normalizeFingerprint(raw);
  const previous = fingerprintConfig;
  const changed = previous.enabled !== next.enabled
    || previous.timezone !== next.timezone
    || previous.language !== next.language;
  fingerprintConfig = next;
  try {
    await chrome.storage.local.set({ [FINGERPRINT_STORAGE_KEY]: next });
  } catch (error) {
    /* in-memory copy still drives this browser session */
  }
  // Values changed under a live session: drop it so the new ones are installed
  // from scratch instead of layered on top of the old overrides. Re-pushing the
  // SAME values (which the side panel does every time the 调试 page opens) must
  // not flap every tab's debugger session.
  if (changed && previous.enabled) await detachFingerprintTabs();
  const result = await applyFingerprintEverywhere();
  return { ...next, ...result, accept_language: next.enabled ? fingerprintAcceptLanguage(next.language) : '' };
}

async function fingerprintStatus() {
  await loadFingerprintConfig();
  return {
    ...fingerprintConfig,
    accept_language: fingerprintConfig.enabled ? fingerprintAcceptLanguage(fingerprintConfig.language) : '',
    tabs: fingerprintTabs.size,
  };
}

chrome.tabs.onCreated.addListener((tab) => {
  if (!fingerprintConfig.enabled || !tabIsDrivable(tab)) return;
  applyFingerprintToTab(tab.id).catch(() => {});
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (!fingerprintConfig.enabled) return;
  // A tab that was on chrome:// (unattachable) becomes attachable the moment it
  // navigates somewhere real, so re-check on every navigation instead of only
  // once at startup. Re-sending the commands on an existing session is cheap.
  if (info.status !== 'loading' && info.url === undefined) return;
  if (!tabIsDrivable(tab)) return;
  applyFingerprintToTab(tabId).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  fingerprintTabs.delete(tabId);
});

// A closed tab takes its debugger session with it; forget the stale id. If the
// user opened DevTools ('canceled_by_user') do not fight them for the session —
// re-attach only when something else dropped it.
chrome.debugger?.onDetach?.addListener((source, reason) => {
  const tabId = source?.tabId;
  if (typeof tabId !== 'number' || !fingerprintTabs.has(tabId)) return;
  fingerprintTabs.delete(tabId);
  if (!fingerprintConfig.enabled) return;
  if (reason === 'target_closed' || reason === 'canceled_by_user') return;
  setTimeout(() => {
    applyFingerprintToTab(tabId).catch(() => {});
  }, 500);
});

// The service worker sleeps and restarts constantly, and a restart takes the
// debugger sessions with it — so re-install on every wake-up, not just at
// browser start. While the switch is off this only clears leftover rules.
(async () => {
  await loadFingerprintConfig();
  await applyFingerprintEverywhere();
})().catch(() => {});

async function proxyControlBlocker() {
  // Another proxy extension (or enterprise policy) can own this setting; the
  // set() call then succeeds silently while traffic keeps using their proxy.
  // Detect it up front so the run reports the real cause instead of "登录失败".
  try {
    const current = await new Promise((resolve) => chrome.proxy.settings.get({}, resolve));
    const control = String(current?.levelOfControl || '');
    if (control === 'controlled_by_other_extensions') {
      return '浏览器代理设置被其他扩展占用，请在 chrome://extensions 停用其它代理类扩展后重试';
    }
    if (control === 'not_controllable') {
      return '浏览器代理设置被系统策略锁定，本扩展无法修改';
    }
  } catch (error) {
    /* get() failing is not itself a reason to refuse; let set() report it */
  }
  return '';
}

async function applyProxyConfig(payload) {
  const proxy = payload && typeof payload === 'object' ? payload : null;
  if (!chrome.proxy?.settings) {
    return { ok: false, error: '当前浏览器不支持 chrome.proxy 接口' };
  }
  const blocked = await proxyControlBlocker();
  if (blocked) {
    return { ok: false, error: blocked };
  }
  if (!proxy || !proxy.host || !proxy.port) {
    // No proxy for this account: drop whatever the previous account installed
    // instead of silently reusing it, and put the leak protections back to the
    // browser's own defaults so normal browsing is untouched.
    await new Promise((resolve) => chrome.proxy.settings.clear({ scope: 'regular' }, resolve));
    await applyProxyStealth(null);
    await persistActiveProxy(null);
    return { ok: true, mode: 'direct' };
  }
  const scheme = String(proxy.scheme || 'http').toLowerCase();
  const port = Number(proxy.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: `代理端口无效：${proxy.port}` };
  }
  const config = {
    mode: 'fixed_servers',
    rules: {
      singleProxy: { scheme, host: String(proxy.host), port },
      bypassList: [...PROXY_BYPASS_LIST],
    },
  };
  try {
    await new Promise((resolve, reject) => {
      chrome.proxy.settings.set({ value: config, scope: 'regular' }, () => {
        const error = chrome.runtime.lastError;
        if (error) reject(new Error(error.message));
        else resolve();
      });
    });
  } catch (error) {
    return { ok: false, error: `设置代理失败：${getErrorMessage(error)}` };
  }
  await persistActiveProxy({
    id: String(proxy.id || ''),
    scheme,
    host: String(proxy.host),
    port,
    username: String(proxy.username || ''),
    password: String(proxy.password || ''),
    label: String(proxy.label || ''),
    country_code: String(proxy.country_code || ''),
    timezone: String(proxy.timezone || ''),
  });
  await applyProxyStealth(proxy);
  // SOCKS5 proxies cannot answer an HTTP 407 challenge, so username/password on
  // a socks endpoint is silently unusable in Chrome — say so rather than let the
  // run fail later with an opaque connection error.
  const authUnsupported = proxySchemeIsSocks(scheme) && !!proxy.username;
  const geo = await fingerprintStatus();
  return {
    ok: true,
    mode: 'fixed_servers',
    scheme,
    country_code: String(proxy.country_code || ''),
    // Informational only now: the fingerprint is whatever the operator pinned in
    // 调试 → 指纹, it no longer follows this proxy's country.
    fingerprint_enabled: !!geo.enabled,
    fingerprint_timezone: geo.timezone || '',
    fingerprint_language: geo.language || '',
    proxy_timezone: String(proxy.timezone || ''),
    auth_unsupported: authUnsupported,
    ...(authUnsupported ? { warning: 'SOCKS 代理的用户名/密码无法通过 Chrome 代理认证，请改用 http(s) 代理或 IP 白名单' } : {}),
  };
}

// Chrome asks the extension for proxy credentials via a blocking onAuthRequired
// (allowed in MV3 thanks to the webRequestAuthProvider permission). Only answer
// challenges that actually come from the proxy — never from a website.
if (chrome.webRequest?.onAuthRequired) {
  chrome.webRequest.onAuthRequired.addListener(
    (details, callback) => {
      const respond = typeof callback === 'function' ? callback : () => {};
      if (!details.isProxy) {
        respond({});
        return;
      }
      loadActiveProxy().then((proxy) => {
        if (proxy && proxy.username) {
          respond({ authCredentials: { username: proxy.username, password: proxy.password || '' } });
        } else {
          respond({});
        }
      }).catch(() => respond({}));
    },
    { urls: ['<all_urls>'] },
    ['asyncBlocking'],
  );
}

// Pages the pipeline can never drive: injecting into them throws Chrome's
// "Cannot access contents of url ... must request permission" error. about:blank
// and a still-empty tab ARE drivable — the flow navigates them before injecting.
const UNDRIVABLE_TAB_URL = /^(chrome|edge|brave|opera|vivaldi|devtools|view-source|chrome-extension|moz-extension|chrome-search|chrome-untrusted|file):/i;

function tabIsDrivable(tab) {
  if (!tab || typeof tab.id !== 'number') return false;
  const url = String(tab.url || tab.pendingUrl || '');
  if (!url || url === 'about:blank') return true;
  if (UNDRIVABLE_TAB_URL.test(url)) return false;
  return !/^https:\/\/(chromewebstore\.google\.com|chrome\.google\.com\/webstore)/i.test(url);
}

async function pickDrivableTab(query) {
  const tabs = await chrome.tabs.query(query).catch(() => []);
  const usable = tabs.filter(tabIsDrivable);
  if (!usable.length) return null;
  // Prefer the one the user is looking at; otherwise the most recent.
  return usable.find((tab) => tab.active) || usable[usable.length - 1];
}

async function getActiveTab() {
  // Prefer the active tab of the side panel's own window. Otherwise switching
  // focus to another window (e.g. a normal window while a run is driving an
  // incognito one) would hijack the active tab there. Fall back to the focused
  // window only when the bound window is gone or has no active tab.
  // Whatever we pick must be drivable: if the active tab happens to be the
  // extension's own page, chrome://settings, the web store… injecting into it
  // fails with an opaque Chrome error, so pick another tab in the same window
  // (or open a fresh one) instead of handing back a tab we cannot use.
  if (typeof boundWindowId === 'number') {
    const pinned = await pickDrivableTab({ active: true, windowId: boundWindowId });
    if (pinned) return pinned;
    const sibling = await pickDrivableTab({ windowId: boundWindowId });
    if (sibling) {
      await chrome.tabs.update(sibling.id, { active: true }).catch(() => {});
      return sibling;
    }
  }
  const current = await pickDrivableTab({ active: true, currentWindow: true });
  if (current) return current;
  const anyTab = await pickDrivableTab({ currentWindow: true });
  if (anyTab) {
    await chrome.tabs.update(anyTab.id, { active: true }).catch(() => {});
    return anyTab;
  }
  // Every tab in reach is an internal page — open one we can actually drive.
  const created = await chrome.tabs.create({
    url: 'about:blank',
    active: true,
    ...(typeof boundWindowId === 'number' ? { windowId: boundWindowId } : {}),
  }).catch(() => null);
  if (created && typeof created.id === 'number') {
    return created;
  }
  throw new Error('未找到可操作的标签页（当前窗口只有扩展页/chrome:// 等无法注入的页面）');
}

// Bridge payloads may pin the request to one specific tab (gcash 提炼 drives two
// fixed tabs at once). Without tab_id every caller keeps the historical
// "whatever is active" behaviour, so the OAuth pipeline is unaffected.
async function resolveTargetTab(payload) {
  const raw = payload && payload.tab_id;
  if (raw === undefined || raw === null || raw === '') {
    return getActiveTab();
  }
  const id = Number(raw);
  if (!Number.isInteger(id) || id < 0) {
    throw new Error(`无效的目标标签页 id：${raw}`);
  }
  const tab = await chrome.tabs.get(id).catch(() => null);
  if (!tab || typeof tab.id !== 'number') {
    throw new Error(`绑定的标签页 ${id} 已不存在，请在调试页重新绑定`);
  }
  if (!tabIsDrivable(tab)) {
    // Fail with the actual reason instead of Chrome's opaque "Cannot access
    // contents of url ..." once we try to inject.
    throw new Error(`绑定的标签页 ${id} 现在是无法操作的页面（${String(tab.url || tab.pendingUrl || '')}），请在调试页重新绑定`);
  }
  return tab;
}

// Defeat background-tab throttling for the gcash 提炼 bound tabs. Chrome throttles
// setTimeout in a hidden (non-active) tab to ~once/min, which stalls the injected
// waitFor polling used by page_action/navigate until the 120s bridge timeout —
// the page appears frozen (stuck on /log-in, TOTP never submitted). Making the
// pinned tab the ACTIVE tab in its own window clears document.hidden so its timers
// run at full speed. Deliberately does NOT focus the window (chrome.windows.update
// focused:true) — that would steal focus from the side panel's window and could
// throttle the bridge polling instead. Only requests pinned with tab_id (gcash)
// do this; the normal OAuth pipeline (active-tab driven, no tab_id) is untouched.
async function foregroundPinnedTab(tab, payload) {
  const raw = payload && payload.tab_id;
  const pinned = raw !== undefined && raw !== null && raw !== '';
  if (!pinned || !tab || typeof tab.id !== 'number' || tab.active) {
    return;
  }
  try {
    await chrome.tabs.update(tab.id, { active: true });
  } catch (_e) {
    // A tab mid-navigation may briefly reject activation; the step's own waitFor
    // still runs (possibly throttled this once) and later steps retry.
  }
}

function normalizeOrigins(input, activeTabUrl) {
  const origins = new Set();
  for (const raw of [...(Array.isArray(input) ? input : []), activeTabUrl]) {
    try {
      const url = new URL(String(raw || ''));
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        origins.add(url.origin);
      }
    } catch {}
  }
  return [...origins];
}

async function executeScriptInWorld(tabId, func, args = [], world = 'MAIN') {
  const [injection] = await chrome.scripting.executeScript({
    target: { tabId },
    world,
    func,
    args,
  });
  return injection?.result;
}

async function executeInMainWorld(tabId, func, args = []) {
  return executeScriptInWorld(tabId, func, args, 'MAIN');
}

async function executeInIsolatedWorld(tabId, func, args = []) {
  return executeScriptInWorld(tabId, func, args, 'ISOLATED');
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function getErrorMessage(error) {
  return String(error?.message || error || '扩展执行失败');
}

async function withDebuggerSession(tabId, callback) {
  const target = { tabId };
  let attached = false;
  // The fingerprint module may already hold a session on this tab. Reuse it and
  // never detach it here: detaching would silently drop the timezone/locale
  // overrides it installed.
  const borrowed = fingerprintTabs.has(tabId);
  if (!borrowed) {
    try {
      await chrome.debugger.attach(target, '1.3');
      attached = true;
    } catch (error) {
      const message = getErrorMessage(error);
      if (!/Another debugger is already attached/i.test(message)) {
        throw error;
      }
    }
  }
  try {
    return await callback({
      send: (method, params = {}) => chrome.debugger.sendCommand(target, method, params),
    });
  } finally {
    if (attached) {
      try {
        await chrome.debugger.detach(target);
      } catch {}
      // We may have been the session the fingerprint was riding on.
      reapplyFingerprintAfterRelease(tabId);
    }
  }
}

// 读不到 Base32 密钥时的兜底：把 MFA 弹窗里的二维码原样截下来交给 Python 解码。
// 用 CDP 的 Page.captureScreenshot + clip，而不是把元素画进 canvas —— 二维码可能是
// <canvas>、<svg>、也可能是跨域 <img>（画进 canvas 会污染，toDataURL 直接抛错），
// 截图对三者一视同仁。scale 放大 + 留白边，是给解码器留必要的 quiet zone。
async function captureMfaQr(payload) {
  const tab = await resolveTargetTab(payload);
  await foregroundPinnedTab(tab, payload);
  const rect = await executeInMainWorld(tab.id, () => {
    const scope = document.querySelector('[aria-labelledby="enroll-totp-modal-title"]')
      || document.querySelector('#totp_otp')?.closest('[role="dialog"]')
      || document.querySelector('[role="dialog"]')
      || document.body;
    const candidates = Array.from(scope.querySelectorAll('canvas, svg, img'));
    const node = candidates.find((item) => {
      const box = item.getBoundingClientRect();
      // 二维码是个正方形的大块；图标、头像、logo 都会被这条筛掉。
      return box.width >= 80 && box.height >= 80 && Math.abs(box.width - box.height) <= box.width * 0.25;
    });
    if (!node) return null;
    node.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
    const box = node.getBoundingClientRect();
    const pad = 12;
    return {
      // clip 用的是**页面坐标**（含滚动量），不是视口坐标。
      x: Math.max(0, box.left + window.scrollX - pad),
      y: Math.max(0, box.top + window.scrollY - pad),
      width: box.width + pad * 2,
      height: box.height + pad * 2,
      tag: node.tagName.toLowerCase(),
    };
  }, []);
  if (!rect || !(rect.width > 0)) {
    return { ok: false, error: 'MFA 弹窗里没有找到二维码元素' };
  }
  const image = await withDebuggerSession(tab.id, async (cdp) => {
    await cdp.send('Page.bringToFront').catch(() => {});
    const shot = await cdp.send('Page.captureScreenshot', {
      format: 'png',
      captureBeyondViewport: false,
      clip: { x: rect.x, y: rect.y, width: rect.width, height: rect.height, scale: 3 },
    });
    return shot?.data ? `data:image/png;base64,${shot.data}` : '';
  }).catch((error) => {
    throw new Error(`二维码截图失败：${getErrorMessage(error)}`);
  });
  if (!image) {
    return { ok: false, error: '二维码截图为空' };
  }
  return { ok: true, qr_image: image, qr_tag: String(rect.tag || ''), qr_size: Math.round(rect.width) };
}

async function clickTrustedPoint(tabId, x, y) {
  await withDebuggerSession(tabId, async (cdp) => {
    await cdp.send('Page.bringToFront').catch(() => {});
    await cdp.send('Input.dispatchMouseEvent', {
      type: 'mouseMoved',
      x,
      y,
      button: 'none',
      buttons: 0,
      pointerType: 'mouse',
    });
    await cdp.send('Input.dispatchMouseEvent', {
      type: 'mousePressed',
      x,
      y,
      button: 'left',
      buttons: 1,
      clickCount: 1,
      pointerType: 'mouse',
    });
    await delay(80);
    await cdp.send('Input.dispatchMouseEvent', {
      type: 'mouseReleased',
      x,
      y,
      button: 'left',
      buttons: 0,
      clickCount: 1,
      pointerType: 'mouse',
    });
  });
}

async function inspectCreateAccountPasswordPage(tabId) {
  const result = await executeInIsolatedWorld(
    tabId,
    () => {
      const isVisible = (node) => {
        if (!node || !node.isConnected) return false;
        const style = globalThis.getComputedStyle ? getComputedStyle(node) : null;
        if (style && (style.display === 'none' || style.visibility === 'hidden')) return false;
        const rect = node.getBoundingClientRect?.();
        return !!rect && rect.width >= 1 && rect.height >= 1;
      };
      const summarizePageState = (document, location) => {
        const bodyText = String(document.body?.innerText || '').replace(/\s+/g, ' ').trim();
        const active = document.activeElement;
        const collect = (selectors, mapper, limit = 8) => Array.from(document.querySelectorAll(selectors))
          .filter(isVisible)
          .slice(0, limit)
          .map(mapper);
        return {
          url: String(location.href || ''),
          title: String(document.title || ''),
          body_preview: bodyText.slice(0, 500),
          active_tag: active?.tagName || '',
          active_type: active?.getAttribute?.('type') || '',
          headings: collect('h1, h2, h3', (node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean),
          buttons: collect(
            'button, input[type="submit"], input[type="button"], [role="button"]',
            (node) => ({
              text: String(node.innerText || node.textContent || node.value || node.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim(),
              type: String(node.getAttribute?.('type') || ''),
              id: String(node.id || ''),
              name: String(node.getAttribute?.('name') || ''),
              value: String(node.getAttribute?.('value') || ''),
              form: String(node.getAttribute?.('form') || ''),
            }),
          ).filter((item) => item.text || item.id),
          inputs: collect(
            'input, textarea, select',
            (node) => ({
              tag: String(node.tagName || '').toLowerCase(),
              type: String(node.getAttribute?.('type') || ''),
              name: String(node.getAttribute?.('name') || ''),
              id: String(node.id || ''),
              autocomplete: String(node.getAttribute?.('autocomplete') || ''),
              placeholder: String(node.getAttribute?.('placeholder') || ''),
            }),
          ),
        };
      };
      const visibleNodes = (selectors) => Array.from(document.querySelectorAll(selectors)).filter(isVisible);
      const firstNode = (selectors) => visibleNodes(selectors)[0] || null;
      const phoneInput = firstNode('input[type="tel"], input[autocomplete="tel"], input[name*="phone" i], input[id*="phone" i]');
      const passwordInput = firstNode('input[type="password"], input[autocomplete="new-password"], input[autocomplete="current-password"], input[name*="password" i], input[id*="password" i]');
      const codeInputs = visibleNodes('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[name*="otp" i], input[id*="otp" i], input[maxlength="1"]');
      const bodyText = String(document.body?.innerText || '').replace(/\s+/g, ' ').trim();
      const bodyHtml = String(document.body?.innerHTML || '').replace(/\s+/g, ' ').trim().slice(0, 12000);
      const currentUrl = String(location.href || '');
      const title = String(document.title || '');
      const visibleError = visibleNodes('[role="alert"], [aria-live="assertive"], .error, .text-red-500, .text-danger, .warning, [data-error]')
        .map((node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim())
        .find(Boolean) || '';
      const target = visibleNodes('button[name="intent"][value*="otp" i], input[name="intent"][value*="otp" i], button[name="intent"][value*="passwordless" i], input[name="intent"][value*="passwordless" i], button[form][name="intent"], input[form][name="intent"]').find((node) => {
        const value = String(node.getAttribute?.('value') || '').toLowerCase();
        return value.includes('otp') || value.includes('passwordless');
      }) || null;
      const rect = target?.getBoundingClientRect?.();
      let stage = 'unknown';
      if (currentUrl.startsWith('http://localhost:1455/auth/callback')) stage = 'callback';
      else if (phoneInput) stage = 'phone';
      else if (codeInputs.length) stage = 'otp';
      else if (passwordInput || currentUrl.toLowerCase().includes('/create-account/password')) stage = 'create-account-password';
      if (/passwordless_signup_disabled/i.test(bodyHtml) || /无法在不设置密码/.test(bodyText)) {
        stage = 'passwordless-disabled-error';
      } else if (visibleError && stage === 'unknown') {
        stage = 'error';
      }
      return {
        ok: true,
        stage,
        state: summarizePageState(document, location),
        snapshot: {
          url: currentUrl,
          title,
          body_text: bodyText.slice(0, 4000),
          body_html: bodyHtml,
        },
        error_text: visibleError,
        target: target && rect ? {
          centerX: rect.left + rect.width / 2,
          centerY: rect.top + rect.height / 2,
          id: String(target.id || ''),
          name: String(target.getAttribute?.('name') || ''),
          value: String(target.getAttribute?.('value') || ''),
          form: String(target.getAttribute?.('form') || ''),
        } : null,
      };
    },
  );
  return result && typeof result === 'object' ? result : { ok: false, error: '密码页检查返回空结果' };
}

async function restoreCreateAccountPasswordPage(tabId, timeoutMs = 15000) {
  await executeInMainWorld(tabId, () => {
    history.back();
    return true;
  }).catch(() => {});
  const deadline = Date.now() + Math.max(1000, timeoutMs);
  while (Date.now() < deadline) {
    const inspection = await inspectCreateAccountPasswordPage(tabId).catch(() => null);
    if (inspection?.stage === 'create-account-password' && inspection.target) {
      return inspection;
    }
    await delay(250);
  }
  return null;
}

async function activatePasswordlessSignupWithCdp() {
  const tab = await getActiveTab();
  const inspection = await inspectCreateAccountPasswordPage(tab.id);
  if (!inspection?.ok || !inspection?.target) {
    return {
      ok: false,
      error: '未找到可用于 CDP 可信点击的一次性验证码注册控件',
      state: inspection?.state || null,
      snapshot: inspection?.snapshot || null,
      error_text: inspection?.error_text || '',
    };
  }
  await clickTrustedPoint(tab.id, Number(inspection.target.centerX) || 0, Number(inspection.target.centerY) || 0);
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const next = await inspectCreateAccountPasswordPage(tab.id);
    if (next?.stage === 'phone' || next?.stage === 'otp' || next?.stage === 'callback') {
      return { ...next, ok: true, used_cdp_trusted_click: true, next_stage: String(next.stage || '') };
    }
    if (next?.stage === 'passwordless-disabled-error') {
      const restored = await restoreCreateAccountPasswordPage(tab.id);
      return {
        ok: true,
        used_cdp_trusted_click: true,
        passwordless_disabled: true,
        next_stage: 'create-account-password',
        state: restored?.state || next.state,
        snapshot: restored?.snapshot || next.snapshot,
        error_text: next.error_text || '',
      };
    }
    if (next?.stage === 'error') {
      return {
        ...next,
        ok: false,
        used_cdp_trusted_click: true,
      };
    }
    await delay(250);
  }
  const finalInspection = await inspectCreateAccountPasswordPage(tab.id).catch(() => null);
  return {
    ok: false,
    error: 'CDP 可信点击后未观察到页面进入下一阶段',
    used_cdp_trusted_click: true,
    state: finalInspection?.state || null,
    snapshot: finalInspection?.snapshot || null,
    error_text: finalInspection?.error_text || '',
  };
}

// Every cookie store, not just the default one: incognito windows keep their
// cookies in a separate store that chrome.browsingData never touches, so a run
// driven from a 隐私窗口 would keep the previous account's session forever.
async function allCookieStoreIds() {
  try {
    const stores = await chrome.cookies.getAllCookieStores();
    const ids = (stores || []).map((store) => store.id).filter(Boolean);
    return ids.length ? [...new Set(ids)] : [undefined];
  } catch {
    return [undefined];
  }
}

function cleanupDomains(origins) {
  return [...new Set(origins.map((origin) => new URL(origin).hostname))];
}

async function collectCookiesForOrigins(origins) {
  const found = [];
  for (const storeId of await allCookieStoreIds()) {
    for (const domain of cleanupDomains(origins)) {
      try {
        const query = storeId === undefined ? { domain } : { domain, storeId };
        for (const cookie of (await chrome.cookies.getAll(query)) || []) {
          found.push({ cookie, storeId });
        }
      } catch {}
    }
  }
  return found;
}

async function removeCookiesForOrigins(origins) {
  for (const { cookie, storeId } of await collectCookiesForOrigins(origins)) {
    const scheme = cookie.secure ? 'https' : 'http';
    const host = cookie.domain.startsWith('.') ? cookie.domain.slice(1) : cookie.domain;
    const url = `${scheme}://${host}${cookie.path || '/'}`;
    try {
      await chrome.cookies.remove({
        url,
        name: cookie.name,
        storeId: cookie.storeId ?? storeId,
      });
    } catch {}
  }
}

// Park every tab still sitting on the origins we are about to wipe — not just
// the active one. A live chatgpt.com tab keeps its page JS and service worker
// running, and they rewrite the session cookie from the in-memory token right
// after the wipe. That is exactly how "auth.openai.com cleared but chatgpt.com
// still logged in as the previous account" happens.
async function parkTabsOnCleanupOrigins(origins) {
  const hosts = cleanupDomains(origins);
  let parked = 0;
  try {
    for (const tab of (await chrome.tabs.query({})) || []) {
      const url = String(tab.url || '');
      if (!/^https?:/i.test(url)) {
        continue;
      }
      let host = '';
      try {
        host = new URL(url).hostname;
      } catch {
        continue;
      }
      if (!hosts.some((item) => host === item || host.endsWith(`.${item}`))) {
        continue;
      }
      try {
        await chrome.tabs.update(tab.id, { url: 'about:blank' });
        await waitForTabComplete(tab.id, 8000).catch(() => {});
        parked += 1;
      } catch {}
    }
  } catch {}
  return parked;
}

async function cleanupBrowserState(origins, payload) {
  let tab = null;
  try {
    // With a bound tab (gcash 提炼) the wipe must hit THAT tab — parking the
    // active tab on about:blank would blank out the operator's 153 提炼 page.
    tab = await resolveTargetTab(payload);
  } catch {}
  const cleanupOrigins = normalizeOrigins(origins?.length ? origins : DEFAULT_CLEANUP_ORIGINS, tab?.url);
  if (!cleanupOrigins.length) {
    return { ok: true, cleared_origins: [] };
  }
  try {
    if (tab && typeof tab.id === 'number' && /^https?:/i.test(String(tab.url || ''))) {
      await executeInMainWorld(
        tab.id,
        async () => {
          try {
            localStorage.clear();
            sessionStorage.clear();
            if (globalThis.caches?.keys) {
              const keys = await caches.keys();
              await Promise.all(keys.map((key) => caches.delete(key)));
            }
            if (globalThis.indexedDB?.databases) {
              const databases = await indexedDB.databases();
              await Promise.all(
                (databases || []).map((item) => {
                  if (!item?.name) {
                    return Promise.resolve();
                  }
                  return new Promise((resolve) => {
                    const request = indexedDB.deleteDatabase(item.name);
                    request.onsuccess = request.onerror = request.onblocked = () => resolve();
                  });
                }),
              );
            }
          } catch {}
          return true;
        },
      );
      // Detach the tab from the live openai/chatgpt page BEFORE unregistering its
      // service workers / clearing cache below. Clearing those out from under a
      // still-loaded page can wedge the tab in 'loading', which then makes the
      // next navigate time out ("标签页加载超时"). Parking on about:blank leaves a
      // clean, ready tab for the worker's next navigation.
      try {
        await chrome.tabs.update(tab.id, { url: 'about:blank' });
        await waitForTabComplete(tab.id, 8000).catch(() => {});
      } catch {}
    }
  } catch {}
  // Any OTHER tab still on these origins would rewrite the session cookie from
  // its in-memory token the moment we wipe it, so silence them all first.
  const parkedTabs = await parkTabsOnCleanupOrigins(cleanupOrigins);
  await removeCookiesForOrigins(cleanupOrigins);
  await chrome.browsingData.remove(
    { origins: cleanupOrigins },
    {
      cache: true,
      cacheStorage: true,
      cookies: true,
      indexedDB: true,
      localStorage: true,
      serviceWorkers: true,
    },
  );
  // Chrome 自己的自动填充/密码管理器数据是独立存储，不受上面按 origin 的清理
  // 影响：邮箱框会继续弹出上一个账号的地址建议。这里只关掉"保存/提示"开关，
  // 不去删用户已有的密码库——browsingData 的 passwords/formData 是浏览器全局
  // 且不可逆的，为自动化清场而清空用户整个密码库不可接受。
  try {
    await chrome.privacy.services.passwordSavingEnabled.set({ value: false });
    await chrome.privacy.services.autofillAddressEnabled.set({ value: false });
    await chrome.privacy.services.autofillCreditCardEnabled.set({ value: false });
  } catch {}
  // Verify instead of assuming. A surviving cookie here is the difference
  // between a clean run and OpenAI showing /choose-an-account with the previous
  // account, so sweep once more and report what is actually left — the caller
  // logs it, which turns "did the wipe work?" into a fact in the log.
  let remaining = await collectCookiesForOrigins(cleanupOrigins);
  if (remaining.length) {
    await removeCookiesForOrigins(cleanupOrigins);
    remaining = await collectCookiesForOrigins(cleanupOrigins);
  }
  return {
    ok: true,
    cleared_origins: cleanupOrigins,
    parked_tabs: parkedTabs,
    remaining_cookies: remaining.length,
    remaining_cookie_names: [
      ...new Set(remaining.map(({ cookie }) => `${cookie.domain}${cookie.name}`)),
    ].slice(0, 20),
  };
}

async function runPageFetch(request) {
  const tab = await resolveTargetTab(request);
  const result = await executeInMainWorld(
    tab.id,
    async (input) => {
      try {
        const response = await fetch(input.url, {
          method: input.method || 'GET',
          headers: input.headers || {},
          body: input.body,
          credentials: input.credentials || 'include',
          redirect: input.redirect || 'follow',
        });
        const headers = {};
        response.headers.forEach((value, key) => {
          headers[key] = value;
        });
        const text = await response.text();
        return {
          ok: true,
          status: response.status,
          url: response.url,
          headers,
          body: text,
        };
      } catch (error) {
        return {
          ok: false,
          error: String(error?.message || error || '页面请求失败'),
        };
      }
    },
    [request],
  );
  return result;
}

function summarizePageState(document, location) {
  const bodyText = String(document.body?.innerText || '').replace(/\s+/g, ' ').trim();
  const active = document.activeElement;
  const isVisible = (node) => {
    if (!node || !node.isConnected) return false;
    const style = globalThis.getComputedStyle ? getComputedStyle(node) : null;
    if (style && (style.display === 'none' || style.visibility === 'hidden')) return false;
    const rect = node.getBoundingClientRect?.();
    return !!rect && rect.width >= 1 && rect.height >= 1;
  };
  const collect = (selectors, mapper, limit = 8) => Array.from(document.querySelectorAll(selectors))
    .filter(isVisible)
    .slice(0, limit)
    .map(mapper);
  return {
    url: String(location.href || ''),
    title: String(document.title || ''),
    body_preview: bodyText.slice(0, 500),
    active_tag: active?.tagName || '',
    active_type: active?.getAttribute?.('type') || '',
    headings: collect('h1, h2, h3', (node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean),
    buttons: collect(
      'button, input[type="submit"], input[type="button"], [role="button"]',
      (node) => ({
        text: String(
          node.innerText ||
          node.textContent ||
          node.value ||
          node.getAttribute?.('aria-label') ||
          '',
        ).replace(/\s+/g, ' ').trim(),
        type: String(node.getAttribute?.('type') || ''),
        id: String(node.id || ''),
      }),
    ).filter((item) => item.text || item.id),
    inputs: collect(
      'input, textarea, select',
      (node) => ({
        tag: String(node.tagName || '').toLowerCase(),
        type: String(node.getAttribute?.('type') || ''),
        name: String(node.getAttribute?.('name') || ''),
        id: String(node.id || ''),
        autocomplete: String(node.getAttribute?.('autocomplete') || ''),
        placeholder: String(node.getAttribute?.('placeholder') || ''),
      }),
    ),
  };
}

async function waitForTabComplete(tabId, timeoutMs = 45000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const timer = setInterval(async () => {
      try {
        const tab = await chrome.tabs.get(tabId);
        if (tab.status === 'complete') {
          clearInterval(timer);
          resolve(tab);
          return;
        }
      } catch {}
      if (Date.now() >= deadline) {
        clearInterval(timer);
        reject(new Error('标签页加载超时'));
      }
    }, 250);
  });
}

// Same as waitForTabComplete, but returns as soon as the element the next step
// needs actually exists. A page's `status === 'complete'` means every last
// subresource finished; the login form is usable long before that, and through
// a proxy the gap is several seconds of pure dead time on every account.
async function waitForTabReady(tabId, { timeoutMs = 45000, readySelector = '', ignoreUrl = '' } = {}) {
  if (!readySelector) {
    return waitForTabComplete(tabId, timeoutMs);
  }
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let tab = null;
    try {
      tab = await chrome.tabs.get(tabId);
    } catch {}
    if (tab?.status === 'complete') {
      return tab;
    }
    // While the tab still reports the PREVIOUS url the navigation has not
    // committed, and the old document may well contain the selector we are
    // waiting for (e.g. re-entering the login flow from a login page). Probing
    // then would "succeed" against a document about to be destroyed.
    const committed = !ignoreUrl || String(tab?.url || '') !== ignoreUrl;
    if (tab && committed && /^https?:/i.test(String(tab.url || ''))) {
      const ready = await executeInIsolatedWorld(
        tabId,
        (selector) => {
          try {
            return document.readyState !== 'loading' && !!document.querySelector(selector);
          } catch {
            return false;
          }
        },
        [readySelector],
      ).catch(() => null);
      if (ready) {
        return tab;
      }
    }
    await delay(200);
  }
  throw new Error('标签页加载超时');
}

async function navigateActiveTab(payload) {
  const tab = await resolveTargetTab(payload);
  await foregroundPinnedTab(tab, payload);
  const previousUrl = String(tab.url || '');
  await chrome.tabs.update(tab.id, { url: String(payload?.url || '') });
  // Budget comes from 插件「调试」页 → 通用配置 (sent by the Python side with
  // every navigate); ready_selector lets the caller continue the moment its
  // target element exists instead of waiting for a full page load.
  const updated = await waitForTabReady(tab.id, {
    timeoutMs: Number(payload?.page_load_timeout_ms) || 45000,
    readySelector: String(payload?.ready_selector || ''),
    ignoreUrl: previousUrl,
  });
  return {
    ok: true,
    url: updated.url || '',
    title: updated.title || '',
  };
}

// Reload the target tab and wait for it to settle. Used when a page loaded but
// did not do what it was supposed to (see the login_with shell case): the
// second request carries the cookies the first one minted.
async function reloadTargetTab(payload) {
  const tab = await resolveTargetTab(payload);
  // Plain reload, NOT bypassCache: a hard reload re-downloads every JS chunk,
  // which through a slow proxy is exactly the wrong move when the page needs
  // its scripts to run in order to redirect.
  await chrome.tabs.reload(tab.id);
  const updated = await waitForTabReady(tab.id, {
    timeoutMs: Number(payload?.page_load_timeout_ms) || 45000,
    readySelector: String(payload?.ready_selector || ''),
  });
  return {
    ok: true,
    url: updated.url || '',
    title: updated.title || '',
  };
}

// Read a tab's own URL without injecting anything. The gcash payment page is a
// third-party origin mid-redirect; polling chrome.tabs.get is the only reliable
// way to watch it (script injection would race the navigations).
async function readTabUrl(payload) {
  const tab = await resolveTargetTab(payload);
  return {
    ok: true,
    url: String(tab.url || tab.pendingUrl || ''),
    title: String(tab.title || ''),
    status: String(tab.status || ''),
  };
}

async function captureDomSnapshot(payload) {
  const tab = await resolveTargetTab(payload);
  const result = await executeInIsolatedWorld(
    tab.id,
    () => {
      const summarizePageState = (document, location) => {
        const bodyText = String(document.body?.innerText || '').replace(/\s+/g, ' ').trim();
        const active = document.activeElement;
        const isVisible = (node) => {
          if (!node || !node.isConnected) return false;
          const style = globalThis.getComputedStyle ? getComputedStyle(node) : null;
          if (style && (style.display === 'none' || style.visibility === 'hidden')) return false;
          const rect = node.getBoundingClientRect?.();
          return !!rect && rect.width >= 1 && rect.height >= 1;
        };
        const collect = (selectors, mapper, limit = 8) => Array.from(document.querySelectorAll(selectors))
          .filter(isVisible)
          .slice(0, limit)
          .map(mapper);
        return {
          url: String(location.href || ''),
          title: String(document.title || ''),
          body_preview: bodyText.slice(0, 500),
          active_tag: active?.tagName || '',
          active_type: active?.getAttribute?.('type') || '',
          headings: collect('h1, h2, h3', (node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean),
          buttons: collect(
            'button, input[type="submit"], input[type="button"], [role="button"]',
            (node) => ({
              text: String(node.innerText || node.textContent || node.value || node.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim(),
              type: String(node.getAttribute?.('type') || ''),
              id: String(node.id || ''),
            }),
          ).filter((item) => item.text || item.id),
          inputs: collect(
            'input, textarea, select',
            (node) => ({
              tag: String(node.tagName || '').toLowerCase(),
              type: String(node.getAttribute?.('type') || ''),
              name: String(node.getAttribute?.('name') || ''),
              id: String(node.id || ''),
              autocomplete: String(node.getAttribute?.('autocomplete') || ''),
              placeholder: String(node.getAttribute?.('placeholder') || ''),
            }),
          ),
        };
      };
      const isVisible = (node) => {
        if (!node || !node.isConnected) return false;
        const style = globalThis.getComputedStyle ? getComputedStyle(node) : null;
        if (style && (style.display === 'none' || style.visibility === 'hidden')) return false;
        const rect = node.getBoundingClientRect?.();
        return !!rect && rect.width >= 1 && rect.height >= 1;
      };
      const collect = (selectors, mapper, limit = 12) => Array.from(document.querySelectorAll(selectors))
        .filter(isVisible)
        .slice(0, limit)
        .map(mapper);
      return {
        ok: true,
        state: summarizePageState(document, location),
        snapshot: {
          url: String(location.href || ''),
          title: String(document.title || ''),
          body_text: String(document.body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 4000),
          body_html: String(document.body?.innerHTML || '').replace(/\s+/g, ' ').trim().slice(0, 12000),
          headings: collect('h1, h2, h3', (node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean),
          buttons: collect('button, input[type="submit"], input[type="button"], [role="button"]', (node) => ({
            text: String(node.innerText || node.textContent || node.value || node.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim(),
            type: String(node.getAttribute?.('type') || ''),
            id: String(node.id || ''),
          })),
          inputs: collect('input, textarea, select', (node) => ({
            tag: String(node.tagName || '').toLowerCase(),
            type: String(node.getAttribute?.('type') || ''),
            name: String(node.getAttribute?.('name') || ''),
            id: String(node.id || ''),
            autocomplete: String(node.getAttribute?.('autocomplete') || ''),
            placeholder: String(node.getAttribute?.('placeholder') || ''),
          })),
        },
      };
    },
  );
  return result && typeof result === 'object' ? result : { ok: false, error: '页面 DOM 快照返回空结果' };
}

async function inspectAuthFlowStage(tabId) {
  const result = await executeInIsolatedWorld(
    tabId,
    () => {
      const isVisible = (node) => {
        // NOT offsetParent-based: the CSSOM spec makes offsetParent null for any
        // position:fixed element, so a modal dialog (chatgpt.com's "Log in or
        // sign up" chooser) and everything inside it would read as invisible —
        // which is exactly why "Continue with email" could never be found.
        if (!node || !node.isConnected || node.disabled) return false;
        const rect = node.getBoundingClientRect?.();
        if (!rect || rect.width <= 0 || rect.height <= 0) return false;
        const style = node.ownerDocument?.defaultView?.getComputedStyle?.(node);
        if (!style) return true;
        return style.visibility !== 'hidden' && style.display !== 'none' && Number(style.opacity) !== 0;
      };
      const visibleNodes = (selectors) => Array.from(document.querySelectorAll(selectors)).filter(isVisible);
      const firstNode = (selectors) => visibleNodes(selectors)[0] || null;
      const collectCodeInputs = () => visibleNodes('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[name*="otp" i], input[id*="otp" i], input[name*="code" i], input[id*="code" i], input[maxlength="1"]');
      const previewText = () => String(document.body?.innerText || '').replace(/\s+/g, ' ').trim();
      const summarizePageState = () => {
        const bodyText = previewText();
        const active = document.activeElement;
        const collect = (selectors, mapper, limit = 8) => Array.from(document.querySelectorAll(selectors))
          .filter(isVisible)
          .slice(0, limit)
          .map(mapper);
        return {
          url: String(location.href || ''),
          title: String(document.title || ''),
          body_preview: bodyText.slice(0, 500),
          active_tag: active?.tagName || '',
          active_type: active?.getAttribute?.('type') || '',
          headings: collect('h1, h2, h3', (node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean),
          buttons: collect(
            'button, input[type="submit"], input[type="button"], [role="button"]',
            (node) => ({
              text: String(node.innerText || node.textContent || node.value || node.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim(),
              type: String(node.getAttribute?.('type') || ''),
              id: String(node.id || ''),
            }),
          ).filter((item) => item.text || item.id),
          inputs: collect(
            'input, textarea, select',
            (node) => ({
              tag: String(node.tagName || '').toLowerCase(),
              type: String(node.getAttribute?.('type') || ''),
              name: String(node.getAttribute?.('name') || ''),
              id: String(node.id || ''),
              autocomplete: String(node.getAttribute?.('autocomplete') || ''),
              placeholder: String(node.getAttribute?.('placeholder') || ''),
            }),
          ),
        };
      };
      const bodyText = previewText();
      const bodyHtml = String(document.body?.innerHTML || '').replace(/\s+/g, ' ').trim().slice(0, 12000);
      const currentHref = String(location.href || '');
      const lowerHref = currentHref.toLowerCase();
      const phoneInput = firstNode('input[type="tel"], input[autocomplete="tel"], input[name*="phone" i], input[id*="phone" i]');
      const passwordInput = firstNode('input[type="password"], input[autocomplete="new-password"], input[autocomplete="current-password"], input[name*="password" i], input[id*="password" i]');
      const visibleError = visibleNodes('[role="alert"], [aria-live="assertive"], .error, .text-red-500, .text-danger, .warning, [data-error]')
        .map((node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim())
        .find(Boolean) || '';
      let stage = 'unknown';
      if (currentHref.startsWith('http://localhost:1455/auth/callback')) stage = 'callback';
      else if (phoneInput) stage = 'phone';
      else if (
        collectCodeInputs().length ||
        lowerHref.includes('/email-verification')
      ) stage = 'otp';
      else if (passwordInput || lowerHref.includes('/create-account/password')) stage = 'create-account-password';
      else if (/verification|验证码|otp|one-time/.test(bodyText.toLowerCase())) stage = 'otp';
      else if (firstNode('button[name="intent"][value*="authorize" i], button[name="intent"][value*="allow" i], form button[type="submit"], a[href*="/auth/callback?code="]')) stage = 'post-otp';
      if (/passwordless_signup_disabled/i.test(bodyHtml) || /无法在不设置密码/.test(bodyText)) {
        stage = 'passwordless-disabled-error';
      } else if (visibleError && stage === 'unknown') {
        stage = 'error';
      }
      return {
        ok: true,
        stage,
        state: summarizePageState(),
        snapshot: {
          url: currentHref,
          title: String(document.title || ''),
          body_text: bodyText.slice(0, 4000),
          body_html: bodyHtml,
        },
        error_text: visibleError,
      };
    },
  );
  return result && typeof result === 'object' ? result : { ok: false, error: '页面阶段检查返回空结果' };
}

async function recoverFinalizeCallback(tabId) {
  // The finalize step drives the tail of onboarding, where every forward
  // navigation (phone -> /about-you -> consent -> localhost callback) tears
  // down the injected auth.openai.com frame. The tab itself survives, so poll
  // its own URL: if it already reached the OAuth callback we are done; if it
  // instead settled on another OpenAI onboarding page, return null so the
  // caller re-injects finalize to keep driving it.
  for (let i = 0; i < 12; i += 1) {
    const info = await chrome.tabs.get(tabId).catch(() => null);
    const url = String(info?.url || '');
    if (url.startsWith('http://localhost:1455/auth/callback')) {
      return { ok: true, callback_url: url, state: { url } };
    }
    if (i >= 3 && /^https?:\/\/([^/]*\.)?(openai\.com|chatgpt\.com)/i.test(url)) {
      return null;
    }
    await delay(500);
  }
  return null;
}

// --- Debug workspace: explicit tab binding ---------------------------------
// The debug tools drive a tab the user picked by id instead of "whatever is
// active", so a fixed tab can be inspected without stealing focus or racing
// the pipeline's own active-tab usage. executeScript does not require the tab
// to be active: a tabId plus host permission is enough.

const UNINJECTABLE_SCHEME = /^(chrome|edge|brave|opera|vivaldi|about|devtools|view-source|chrome-extension|moz-extension|chrome-search|chrome-untrusted|data|blob):/i;
const WEB_STORE_URL = /^https:\/\/(chromewebstore\.google\.com|chrome\.google\.com\/webstore)/i;

function tabInjectionBlocker(url) {
  const value = String(url || '');
  if (!value) return '标签页还没有地址（可能尚未加载）';
  if (WEB_STORE_URL.test(value)) return 'Chrome 应用商店页面禁止扩展注入';
  if (/^file:/i.test(value)) return 'file:// 页面需在扩展详情里开启「允许访问文件网址」';
  if (UNINJECTABLE_SCHEME.test(value)) return `${value.split(':')[0]}: 协议页面禁止扩展注入`;
  return '';
}

async function listBrowserTabs() {
  const tabs = await chrome.tabs.query({});
  const windows = await chrome.windows.getAll({}).catch(() => []);
  const rows = tabs
    .filter((tab) => typeof tab.id === 'number' && tab.id >= 0)
    .map((tab) => {
      const url = String(tab.url || tab.pendingUrl || '');
      const blocker = tabInjectionBlocker(url);
      return {
        id: tab.id,
        window_id: tab.windowId,
        index: tab.index,
        title: String(tab.title || ''),
        url,
        favicon: String(tab.favIconUrl || ''),
        status: String(tab.status || ''),
        active: !!tab.active,
        pinned: !!tab.pinned,
        discarded: !!tab.discarded,
        incognito: !!tab.incognito,
        injectable: !blocker,
        blocked_reason: blocker,
      };
    });
  rows.sort((a, b) => (a.window_id - b.window_id) || (a.index - b.index));
  return {
    ok: true,
    tabs: rows,
    bound_window_id: boundWindowId,
    windows: windows.map((win) => ({
      id: win.id,
      incognito: !!win.incognito,
      focused: !!win.focused,
      state: String(win.state || ''),
    })),
  };
}

// Runs in the page's ISOLATED world. Must stay self-contained: chrome.scripting
// serialises the function, so it cannot close over anything defined above.
function collectPageSnapshot() {
  const LIMITS = { html: 600000, text: 40000, elements: 400, shadowRoots: 30, scan: 25000, value: 200 };
  const squash = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
  const clamp = (value, limit) => {
    const text = String(value ?? '');
    return text.length > limit ? text.slice(0, limit) : text;
  };
  const escapeIdent = (value) => (globalThis.CSS && CSS.escape
    ? CSS.escape(String(value))
    : String(value).replace(/[^\w-]/g, (char) => `\\${char}`));
  const attr = (node, name) => String(node.getAttribute?.(name) ?? '');
  const rectOf = (node) => {
    const rect = node.getBoundingClientRect?.();
    if (!rect) return null;
    return { x: Math.round(rect.left), y: Math.round(rect.top), w: Math.round(rect.width), h: Math.round(rect.height) };
  };
  const isVisible = (node) => {
    if (!node || !node.isConnected) return false;
    const style = globalThis.getComputedStyle ? getComputedStyle(node) : null;
    if (style && (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity) === 0)) return false;
    const rect = node.getBoundingClientRect?.();
    return !!rect && rect.width >= 1 && rect.height >= 1;
  };
  // A selector the automation steps can feed straight back into querySelector.
  // Prefer a unique id, then a short structural path with :nth-of-type.
  const cssPath = (node, root) => {
    const scope = root || node.getRootNode?.() || document;
    const parts = [];
    let current = node;
    while (current && current.nodeType === 1 && parts.length < 8) {
      const id = String(current.id || '');
      if (id && scope.querySelectorAll?.(`#${escapeIdent(id)}`).length === 1) {
        parts.unshift(`#${escapeIdent(id)}`);
        break;
      }
      let part = current.tagName.toLowerCase();
      const parent = current.parentElement;
      if (parent) {
        const twins = Array.from(parent.children).filter((child) => child.tagName === current.tagName);
        if (twins.length > 1) part += `:nth-of-type(${twins.indexOf(current) + 1})`;
      }
      parts.unshift(part);
      current = current.parentElement;
    }
    return parts.join(' > ');
  };
  const xPath = (node) => {
    const parts = [];
    let current = node;
    while (current && current.nodeType === 1 && parts.length < 12) {
      const parent = current.parentElement;
      if (!parent) {
        parts.unshift(current.tagName.toLowerCase());
        break;
      }
      const twins = Array.from(parent.children).filter((child) => child.tagName === current.tagName);
      const suffix = twins.length > 1 ? `[${twins.indexOf(current) + 1}]` : '';
      parts.unshift(`${current.tagName.toLowerCase()}${suffix}`);
      current = parent;
    }
    return `/${parts.join('/')}`;
  };
  const labelFor = (node) => {
    const aria = attr(node, 'aria-label');
    if (aria) return squash(aria);
    const labelledBy = attr(node, 'aria-labelledby');
    if (labelledBy) {
      const target = document.getElementById(labelledBy.split(/\s+/)[0]);
      if (target) return squash(target.innerText || target.textContent);
    }
    if (node.id) {
      const explicit = document.querySelector(`label[for="${escapeIdent(node.id)}"]`);
      if (explicit) return squash(explicit.innerText || explicit.textContent);
    }
    const wrapper = node.closest?.('label');
    if (wrapper) return squash(wrapper.innerText || wrapper.textContent);
    return '';
  };
  const safeValue = (node) => {
    const type = String(node.type || '').toLowerCase();
    const raw = String(node.value ?? '');
    if (!raw) return '';
    // Never write a real password into a debug log that lands on disk.
    if (type === 'password') return `***(${raw.length} 位)`;
    return clamp(raw, LIMITS.value);
  };

  const INTERACTIVE = [
    'a[href]', 'button', 'input', 'textarea', 'select', 'summary', 'label[for]',
    '[role="button"]', '[role="link"]', '[role="textbox"]', '[role="checkbox"]',
    '[role="radio"]', '[role="tab"]', '[role="menuitem"]', '[role="combobox"]',
    '[role="switch"]', '[role="option"]', '[contenteditable=""]', '[contenteditable="true"]',
    '[onclick]', '[data-testid]',
  ].join(', ');

  const describe = (node, index, root, shadowHost) => ({
    index,
    tag: String(node.tagName || '').toLowerCase(),
    type: String(node.getAttribute?.('type') || ''),
    role: attr(node, 'role'),
    id: String(node.id || ''),
    name: attr(node, 'name'),
    class: clamp(squash(node.className?.baseVal ?? node.className), 160),
    testid: attr(node, 'data-testid') || attr(node, 'data-test-id') || attr(node, 'data-qa'),
    label: clamp(labelFor(node), 160),
    text: clamp(squash(node.innerText || node.textContent || node.value), 160),
    placeholder: attr(node, 'placeholder'),
    value: safeValue(node),
    href: clamp(attr(node, 'href'), 400),
    autocomplete: attr(node, 'autocomplete'),
    inputmode: attr(node, 'inputmode'),
    disabled: !!node.disabled || attr(node, 'aria-disabled') === 'true',
    readonly: !!node.readOnly,
    required: !!node.required,
    checked: typeof node.checked === 'boolean' ? node.checked : null,
    visible: isVisible(node),
    rect: rectOf(node),
    selector: cssPath(node, root),
    xpath: shadowHost ? '' : xPath(node),
    in_shadow: !!shadowHost,
    shadow_host: shadowHost || '',
  });

  const elements = [];
  const shadowHosts = [];
  const scanRoot = (root, hostSelector) => {
    let nodes = [];
    try {
      nodes = Array.from(root.querySelectorAll(INTERACTIVE));
    } catch {
      nodes = [];
    }
    for (const node of nodes) {
      if (elements.length >= LIMITS.elements) break;
      elements.push(describe(node, elements.length, root, hostSelector));
    }
    // Open shadow roots hide the real controls on many modern pages; a snapshot
    // that stops at the light DOM would look empty and mislead the next step.
    let all = [];
    try {
      all = Array.from(root.querySelectorAll('*')).slice(0, LIMITS.scan);
    } catch {
      all = [];
    }
    for (const node of all) {
      if (node.shadowRoot && shadowHosts.length < LIMITS.shadowRoots) {
        const selector = cssPath(node, root);
        shadowHosts.push({ host: selector, in_shadow: !!hostSelector, parent_host: hostSelector || '' });
        scanRoot(node.shadowRoot, selector);
      }
    }
  };
  scanRoot(document, '');

  const forms = Array.from(document.querySelectorAll('form')).slice(0, 20).map((form, index) => ({
    index,
    id: String(form.id || ''),
    name: attr(form, 'name'),
    action: clamp(attr(form, 'action'), 400),
    method: String(form.method || ''),
    selector: cssPath(form, document),
    visible: isVisible(form),
    control_count: form.elements?.length ?? 0,
    // The login page's e-mail box shares a form with the social sign-in
    // buttons, so knowing which control submits first matters.
    submit_controls: Array.from(form.querySelectorAll('button, input[type="submit"], [type="submit"]'))
      .slice(0, 10)
      .map((node) => ({
        text: clamp(squash(node.innerText || node.textContent || node.value || attr(node, 'aria-label')), 80),
        type: String(node.getAttribute?.('type') || ''),
        selector: cssPath(node, document),
        visible: isVisible(node),
      })),
  }));

  const iframes = Array.from(document.querySelectorAll('iframe, frame')).slice(0, 20).map((frame, index) => ({
    index,
    id: String(frame.id || ''),
    name: attr(frame, 'name'),
    src: clamp(attr(frame, 'src'), 400),
    selector: cssPath(frame, document),
    visible: isVisible(frame),
    rect: rectOf(frame),
  }));

  const errors = Array.from(document.querySelectorAll('[role="alert"], [aria-invalid="true"], .error, .text-error, [data-error]'))
    .filter(isVisible)
    .slice(0, 10)
    .map((node) => clamp(squash(node.innerText || node.textContent), 300))
    .filter(Boolean);

  const storageKeys = (store) => {
    try {
      return Array.from({ length: store.length }, (_, i) => store.key(i))
        .slice(0, 60)
        .map((key) => ({ key: String(key), size: String(store.getItem(key) ?? '').length }));
    } catch {
      return [];
    }
  };

  const html = String(document.documentElement?.outerHTML || '');
  const text = String(document.body?.innerText || '');
  const active = document.activeElement;

  return {
    ok: true,
    captured_at: new Date().toISOString(),
    page: {
      url: String(location.href || ''),
      origin: String(location.origin || ''),
      path: String(location.pathname || ''),
      title: String(document.title || ''),
      ready_state: String(document.readyState || ''),
      referrer: String(document.referrer || ''),
      charset: String(document.characterSet || ''),
      lang: String(document.documentElement?.lang || ''),
      user_agent: String(navigator.userAgent || ''),
      viewport: { w: window.innerWidth, h: window.innerHeight, dpr: window.devicePixelRatio },
      scroll: { x: Math.round(window.scrollX), y: Math.round(window.scrollY), h: document.documentElement?.scrollHeight ?? 0 },
      visibility: String(document.visibilityState || ''),
      element_count: document.getElementsByTagName('*').length,
    },
    active_element: active && active !== document.body
      ? { tag: String(active.tagName || '').toLowerCase(), id: String(active.id || ''), selector: cssPath(active, document) }
      : null,
    headings: Array.from(document.querySelectorAll('h1, h2, h3'))
      .filter(isVisible)
      .slice(0, 15)
      .map((node) => clamp(squash(node.innerText || node.textContent), 200))
      .filter(Boolean),
    errors,
    elements,
    element_total: elements.length,
    element_truncated: elements.length >= LIMITS.elements,
    forms,
    iframes,
    shadow_hosts: shadowHosts,
    meta: Array.from(document.querySelectorAll('meta[name], meta[property]')).slice(0, 30).map((node) => ({
      name: attr(node, 'name') || attr(node, 'property'),
      content: clamp(attr(node, 'content'), 200),
    })),
    storage: { local: storageKeys(localStorage), session: storageKeys(sessionStorage) },
    // httpOnly cookies are invisible here by design; names alone are enough to
    // tell "logged in" from "cleared" when replaying a step.
    cookie_names: String(document.cookie || '').split(';').map((part) => squash(part.split('=')[0])).filter(Boolean).slice(0, 60),
    text: clamp(text, LIMITS.text),
    text_truncated: text.length > LIMITS.text,
    html: clamp(html, LIMITS.html),
    html_truncated: html.length > LIMITS.html,
    html_length: html.length,
  };
}

async function captureTabSnapshot(tabId) {
  const id = Number(tabId);
  if (!Number.isInteger(id) || id < 0) {
    return { ok: false, error: '请先在列表里选择一个标签页' };
  }
  const tab = await chrome.tabs.get(id).catch(() => null);
  if (!tab) {
    return { ok: false, error: `标签页 ${id} 已不存在，请刷新列表后重新选择` };
  }
  const url = String(tab.url || tab.pendingUrl || '');
  const blocker = tabInjectionBlocker(url);
  if (blocker) {
    return { ok: false, error: blocker };
  }
  let page = null;
  try {
    page = await executeInIsolatedWorld(id, collectPageSnapshot);
  } catch (error) {
    return { ok: false, error: `快照注入失败：${getErrorMessage(error)}` };
  }
  if (!page || typeof page !== 'object') {
    return { ok: false, error: '快照返回空结果（页面可能正在跳转，稍后重试）' };
  }
  return {
    ok: true,
    snapshot: {
      ...page,
      tab: {
        id: tab.id,
        window_id: tab.windowId,
        index: tab.index,
        title: String(tab.title || ''),
        url,
        status: String(tab.status || ''),
        active: !!tab.active,
        pinned: !!tab.pinned,
        incognito: !!tab.incognito,
        favicon: String(tab.favIconUrl || ''),
      },
    },
  };
}

// --- gcash 提炼: drive the pay.153.ink console in the bound extraction tab ----
// Runs in the page's ISOLATED world; both functions must stay self-contained.

function gcashSubmitInPage(token) {
  const fillValue = (node, value) => {
    const prototype = node instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
    node.focus();
    if (setter) setter.call(node, ''); else node.value = '';
    node.dispatchEvent(new Event('input', { bubbles: true }));
    if (setter) setter.call(node, String(value ?? '')); else node.value = String(value ?? '');
    node.dispatchEvent(new Event('input', { bubbles: true }));
    node.dispatchEvent(new Event('change', { bubbles: true }));
    node.dispatchEvent(new Event('blur', { bubbles: true }));
  };
  const input = document.querySelector('#token');
  if (!input) {
    return { ok: false, error: '未找到 Access Token 输入框（#token）——绑定的「153 提炼」标签页可能不在 pay.153.ink 提炼页上' };
  }
  const button = document.querySelector('#submitButton');
  if (!button) {
    return { ok: false, error: '未找到「开始提炼」按钮（#submitButton）' };
  }
  if (button.disabled) {
    return { ok: false, error: '「开始提炼」按钮当前不可点击（上一个任务可能仍在运行）' };
  }
  const value = String(token || '');
  if (!value) {
    return { ok: false, error: 'accessToken 为空，拒绝提交' };
  }
  fillValue(input, value);
  if (String(input.value || '') !== value) {
    return { ok: false, error: 'Access Token 写入输入框后未生效' };
  }
  button.scrollIntoView({ block: 'center' });
  const rect = button.getBoundingClientRect();
  // The caller performs the actual click through CDP; only report where it is.
  return {
    ok: true,
    token_length: value.length,
    url: String(location.href || ''),
    click_point: { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 },
  };
}

function gcashProbeInPage() {
  const squash = (value) => String(value ?? '').replace(/\s+/g, ' ').trim();
  const node = (selector) => document.querySelector(selector);
  const text = (selector) => {
    const found = node(selector);
    return found ? squash(found.innerText || found.textContent) : '';
  };
  const visible = (element) => {
    if (!element || !element.isConnected) return false;
    if (element.hasAttribute?.('hidden')) return false;
    const style = getComputedStyle(element);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    const rect = element.getBoundingClientRect();
    return rect.width >= 1 && rect.height >= 1;
  };
  const percentOf = (value) => {
    const match = /(-?\d+(?:\.\d+)?)\s*%/.exec(String(value || ''));
    return match ? Number(match[1]) : null;
  };
  const bar = node('#progressBar');
  const percent = percentOf(bar ? bar.style.width : '') ?? percentOf(text('#progressValue'));
  const panel = node('#resultPanel');
  const resultVisible = visible(panel);
  const resultValue = node('#resultValue');
  const openResult = node('#openResult');
  const badge = node('#statusBadge');
  return {
    ok: true,
    page_ready: !!node('#token') && !!node('#submitButton'),
    percent,
    progress_text: text('#progressText'),
    progress_stage: text('#progressStage'),
    status_badge: text('#statusBadge'),
    status_class: badge ? squash(badge.className) : '',
    running: visible(node('#cancelButton')),
    result_visible: resultVisible,
    // Only trust the result fields while the panel is actually shown: a failed
    // run leaves the PREVIOUS run's link sitting inside #resultValue behind
    // hidden="", so reading it unconditionally would report a stale success.
    result_value: resultVisible && resultValue ? String(resultValue.value || '') : '',
    result_link: resultVisible && openResult ? String(openResult.getAttribute('href') || '') : '',
    result_session: resultVisible ? text('#resultSession') : '',
    log_tail: Array.from(document.querySelectorAll('#logBox .log-row')).slice(-6).map((row) => squash(row.innerText || row.textContent)).filter(Boolean),
    url: String(location.href || ''),
  };
}

async function runGcashAction(payload) {
  const action = String(payload?.action || '');
  const tab = await resolveTargetTab(payload);
  await foregroundPinnedTab(tab, payload);
  const blocker = tabInjectionBlocker(String(tab.url || tab.pendingUrl || ''));
  if (blocker) {
    return { ok: false, error: `「153 提炼」标签页无法注入：${blocker}` };
  }
  const result = action === 'gcash_submit'
    ? await executeInIsolatedWorld(tab.id, gcashSubmitInPage, [String(payload?.token || '')])
    : await executeInIsolatedWorld(tab.id, gcashProbeInPage);
  if (!result || typeof result !== 'object') {
    return { ok: false, error: `${action} 返回空结果（页面可能正在跳转）` };
  }
  // The page only located「开始提炼」; the click itself goes through CDP so it
  // carries isTrusted=true like every other click this extension performs.
  if (action === 'gcash_submit' && result.ok && result.click_point) {
    try {
      await clickTrustedPoint(tab.id, result.click_point.x, result.click_point.y);
    } catch (error) {
      return { ok: false, error: `可信点击「开始提炼」失败：${getErrorMessage(error)}` };
    }
  }
  return { ...result, tab_url: String(tab.url || '') };
}

// --------------------------------------------------- trusted click transport
// Synthetic clicks (`node.dispatchEvent(new MouseEvent('click'))`) carry
// `isTrusted === false`, which any anti-bot script reads in one line. Every
// click this extension performs must therefore come from the browser itself,
// i.e. CDP `Input.dispatchMouseEvent`.
//
// The page steps are one long injected function that finds an element and
// clicks it inline, so the click cannot simply "return" to the service worker.
// Instead the injected code posts the target's viewport coordinates to a
// per-step channel and awaits an acknowledgement; a pump running here picks
// those up WHILE the step is still executing and issues the real CDP click.
// One debugger session is held for the whole step so the clicks do not
// attach/detach (and flash the infobar) once per click.
async function attachDebuggerOnce(tabId) {
  const target = { tabId };
  let attached = false;
  // Reuse (and never release) a session the fingerprint module is holding —
  // see withDebuggerSession.
  const borrowed = fingerprintTabs.has(tabId);
  if (!borrowed) {
    try {
      await chrome.debugger.attach(target, '1.3');
      attached = true;
    } catch (error) {
      if (!/Another debugger is already attached/i.test(getErrorMessage(error))) {
        throw error;
      }
    }
  }
  return {
    send: (method, params = {}) => chrome.debugger.sendCommand(target, method, params),
    release: async () => {
      if (!attached) return;
      try {
        await chrome.debugger.detach(target);
      } catch {}
      reapplyFingerprintAfterRelease(tabId);
    },
  };
}

async function dispatchTrustedClick(cdp, x, y) {
  const base = { x, y, pointerType: 'mouse' };
  await cdp.send('Input.dispatchMouseEvent', { ...base, type: 'mouseMoved', button: 'none', buttons: 0 });
  await cdp.send('Input.dispatchMouseEvent', { ...base, type: 'mousePressed', button: 'left', buttons: 1, clickCount: 1 });
  await delay(70);
  await cdp.send('Input.dispatchMouseEvent', { ...base, type: 'mouseReleased', button: 'left', buttons: 0, clickCount: 1 });
}

async function dispatchTrustedKey(cdp, key) {
  // Only the keys the flow actually needs; a real keypress is what makes a form
  // submit, which a synthetic KeyboardEvent never does.
  const KEYS = {
    Enter: { code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' },
    Tab: { code: 'Tab', windowsVirtualKeyCode: 9 },
    Backspace: { code: 'Backspace', windowsVirtualKeyCode: 8 },
    Delete: { code: 'Delete', windowsVirtualKeyCode: 46 },
  };
  const spec = KEYS[key];
  if (!spec) throw new Error(`不支持的按键：${key}`);
  const common = { key, code: spec.code, windowsVirtualKeyCode: spec.windowsVirtualKeyCode, nativeVirtualKeyCode: spec.windowsVirtualKeyCode };
  await cdp.send('Input.dispatchKeyEvent', { ...common, type: 'keyDown', ...(spec.text ? { text: spec.text } : {}) });
  await delay(40);
  await cdp.send('Input.dispatchKeyEvent', { ...common, type: 'keyUp' });
}

// Real typing. fillValue() writes .value with the native setter and fires
// synthetic input/change events, whose isTrusted is FALSE — the same tell that
// gets synthetic clicks flagged. Everything a human types (email, password,
// OTP, name/age) must come through here instead.
//
// Character-by-character keyDown/char/keyUp rather than Input.insertText: the
// latter behaves like an IME commit and never produces key events, which some
// forms (and any keystroke-based scoring) notice.
const TYPE_KEY_CODES = {
  ' ': { code: 'Space', vk: 32 },
  '@': { code: 'Digit2', vk: 50 },
  '.': { code: 'Period', vk: 190 },
  '-': { code: 'Minus', vk: 189 },
  '_': { code: 'Minus', vk: 189 },
  '+': { code: 'Equal', vk: 187 },
};

function typeKeySpec(char) {
  const known = TYPE_KEY_CODES[char];
  if (known) return known;
  if (/[a-z]/i.test(char)) return { code: `Key${char.toUpperCase()}`, vk: char.toUpperCase().charCodeAt(0) };
  if (/[0-9]/.test(char)) return { code: `Digit${char}`, vk: char.charCodeAt(0) };
  return { code: '', vk: 0 };
}

async function dispatchTrustedText(cdp, text) {
  for (const char of String(text ?? '')) {
    const spec = typeKeySpec(char);
    const common = {
      key: char,
      code: spec.code,
      windowsVirtualKeyCode: spec.vk,
      nativeVirtualKeyCode: spec.vk,
    };
    await cdp.send('Input.dispatchKeyEvent', { ...common, type: 'keyDown', text: char, unmodifiedText: char });
    await cdp.send('Input.dispatchKeyEvent', { ...common, type: 'keyUp' });
    // Human-ish cadence. Zero delay is itself a signal, and React-controlled
    // inputs occasionally drop characters typed faster than a render.
    await delay(18 + Math.floor(Math.random() * 45));
  }
}

// Select-all so the next keystroke replaces whatever is in the field, using a
// real Ctrl/Cmd+A rather than node.value = ''.
async function dispatchTrustedSelectAll(cdp) {
  const modifier = 2; // Ctrl on Windows/Linux, which Chrome maps for CDP.
  const common = { key: 'a', code: 'KeyA', windowsVirtualKeyCode: 65, nativeVirtualKeyCode: 65, modifiers: modifier };
  await cdp.send('Input.dispatchKeyEvent', { ...common, type: 'keyDown' });
  await cdp.send('Input.dispatchKeyEvent', { ...common, type: 'keyUp' });
  await delay(30);
}

function startTrustedClickPump(tabId, channel) {
  let stopped = false;
  let session = null;
  const ready = (async () => {
    try {
      session = await attachDebuggerOnce(tabId);
      await session.send('Page.bringToFront').catch(() => {});
      return true;
    } catch (error) {
      session = null;
      return false;
    }
  })();

  const loop = (async () => {
    const usable = await ready;
    // Tell the page whether trusted clicks are actually available. Without this
    // a failed attach would silently hang every click instead of letting the
    // step report a real error.
    await executeInMainWorld(tabId, (ch, ok) => {
      const bucket = (window[ch] = window[ch] || { pending: [], done: {}, seq: 0 });
      bucket.cdp = ok;
    }, [channel, usable]).catch(() => {});
    while (!stopped) {
      if (!usable) {
        await delay(120);
        continue;
      }
      let job = null;
      try {
        job = await executeInMainWorld(tabId, (ch) => {
          const bucket = window[ch];
          if (!bucket || !bucket.pending.length) return null;
          return bucket.pending.shift();
        }, [channel]);
      } catch {
        // Frame torn down mid-navigation; the step handles that itself.
      }
      if (job && Number.isFinite(job.x) && Number.isFinite(job.y)) {
        let outcome = 'ok';
        let point = { x: job.x, y: job.y };
        // 关键：坐标是注入侧在 100~300ms 之前算的，期间元素可能被滚动/动画挪走。
        // 派发前用标记重新量一次，并确认那个点上最顶层的元素确实是目标本身——
        // 否则就是在往空白（或遮挡层）上点，而 CDP 会照样报成功。
        if (job.sel) {
          // 遮挡/消失都是**瞬时**状态：刚导航完的页面还在做视图过渡（旧视图淡出层
          // 压在新视图上）、字体回流、弹层收起……只看一眼就判死，会把一个本来点得
          // 中的按钮判成"被遮挡"，整单作废（实测 logs/codex-2ffe475cee4fb8bb73aa7c70
          // -1d27c48f：同一个账号第一遍死在这里，隔 3 分钟重跑一遍一次就过）。
          // 所以这里重量多次、每次间隔一点，真的一直被挡住才回 covered。
          let fresh = null;
          for (let probe = 0; probe < 12; probe += 1) {
            fresh = await executeInMainWorld(tabId, (selector) => {
              const node = document.querySelector(selector);
              if (!node) return { gone: true };
              const rect = node.getBoundingClientRect();
              if (!rect || (!rect.width && !rect.height)) return { gone: true };
              const x = rect.left + rect.width / 2;
              const y = rect.top + rect.height / 2;
              if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) return { gone: true };
              const top = document.elementFromPoint(x, y);
              const covered = !top || !(top === node || node.contains(top) || top.contains(node));
              return { x, y, covered, blocker: covered ? (top?.tagName || '') + (top?.className ? '.' + String(top.className).slice(0, 60) : '') : '' };
            }, [job.sel]).catch(() => null);
            if (fresh && !fresh.gone && !fresh.covered) break;
            await delay(150);
          }
          if (fresh?.gone) {
            outcome = 'gone';
          } else if (fresh?.covered) {
            outcome = 'covered';
            // 说清楚被谁挡住了：不然日志里只有"被遮挡"，下次还得从头猜。
            console.warn('[cdpc] click blocked by', fresh.blocker);
          } else if (fresh && Number.isFinite(fresh.x)) {
            point = { x: fresh.x, y: fresh.y };
          }
        }
        if (outcome === 'ok') {
          try {
            await dispatchTrustedClick(session, point.x, point.y);
          } catch {
            outcome = 'failed';
          }
        }
        await executeInMainWorld(tabId, (ch, id, done) => {
          const bucket = window[ch];
          if (bucket) bucket.done[id] = done;
        }, [channel, job.id, outcome]).catch(() => {});
        continue;
      }
      if (job && job.key) {
        let ok = true;
        try {
          await dispatchTrustedKey(session, String(job.key));
        } catch {
          ok = false;
        }
        await executeInMainWorld(tabId, (ch, id, done) => {
          const bucket = window[ch];
          if (bucket) bucket.done[id] = done ? 'ok' : 'failed';
        }, [channel, job.id, ok]).catch(() => {});
        continue;
      }
      // Real typing: the field was already focused by a trusted click, so all
      // this has to do is clear it and send genuine keystrokes.
      if (job && typeof job.text === 'string') {
        let ok = true;
        try {
          if (job.clear) {
            await dispatchTrustedSelectAll(session);
            await dispatchTrustedKey(session, 'Delete');
          }
          await dispatchTrustedText(session, job.text);
        } catch {
          ok = false;
        }
        await executeInMainWorld(tabId, (ch, id, done) => {
          const bucket = window[ch];
          if (bucket) bucket.done[id] = done ? 'ok' : 'failed';
        }, [channel, job.id, ok]).catch(() => {});
        continue;
      }
      await delay(90);
    }
  })();

  return async () => {
    stopped = true;
    try {
      await loop;
    } catch {}
    // Leave no trace of the channel on the page.
    await executeInMainWorld(tabId, (ch) => {
      try {
        delete window[ch];
      } catch {}
    }, [channel]).catch(() => {});
    if (session) await session.release();
  };
}

async function executePageStep(step) {
  const tab = await resolveTargetTab(step);
  await foregroundPinnedTab(tab, step);
  const action = String(step?.action || '');
  const isFinalize = action === 'finalize_and_get_callback';
  // Every click inside the injected step is routed through this channel to the
  // CDP pump above, so nothing this step does carries isTrusted=false.
  const clickChannel = `__cdpc_${Math.random().toString(36).slice(2, 10)}`;
  const stopClickPump = startTrustedClickPump(tab.id, clickChannel);
  step = { ...step, __cdp_channel: clickChannel };
  try {
    return await runPageStepLoop(tab, step, action, isFinalize);
  } finally {
    await stopClickPump();
  }
}

async function runPageStepLoop(tab, step, action, isFinalize) {
  // finalize survives several cross-page navigations; each one can surface as
  // EITHER a thrown "Frame with ID X was removed" OR a null executeScript
  // result. Recover the callback if we reached it, otherwise re-inject on the
  // next page until this outer deadline.
  const finalizeDeadline = Date.now() + Math.max(60000, Number(step?.timeout_ms) || 180000);
  while (true) {
  try {
    const result = await executeInMainWorld(
      tab.id,
      async (input) => {
      const summarizePageState = (document, location) => {
        const bodyText = String(document.body?.innerText || '').replace(/\s+/g, ' ').trim();
        const active = document.activeElement;
        const isVisible = (node) => {
        // NOT offsetParent-based: the CSSOM spec makes offsetParent null for any
        // position:fixed element, so a modal dialog (chatgpt.com's "Log in or
        // sign up" chooser) and everything inside it would read as invisible —
        // which is exactly why "Continue with email" could never be found.
        if (!node || !node.isConnected || node.disabled) return false;
        const rect = node.getBoundingClientRect?.();
        if (!rect || rect.width <= 0 || rect.height <= 0) return false;
        const style = node.ownerDocument?.defaultView?.getComputedStyle?.(node);
        if (!style) return true;
        return style.visibility !== 'hidden' && style.display !== 'none' && Number(style.opacity) !== 0;
      };
        const collect = (selectors, mapper, limit = 8) => Array.from(document.querySelectorAll(selectors))
          .filter(isVisible)
          .slice(0, limit)
          .map(mapper);
        return {
          url: String(location.href || ''),
          title: String(document.title || ''),
          body_preview: bodyText.slice(0, 500),
          active_tag: active?.tagName || '',
          active_type: active?.getAttribute?.('type') || '',
          headings: collect('h1, h2, h3', (node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim()).filter(Boolean),
          buttons: collect(
            'button, input[type="submit"], input[type="button"], [role="button"]',
            (node) => ({
              text: String(node.innerText || node.textContent || node.value || node.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim(),
              type: String(node.getAttribute?.('type') || ''),
              id: String(node.id || ''),
            }),
          ).filter((item) => item.text || item.id),
          inputs: collect(
            'input, textarea, select',
            (node) => ({
              tag: String(node.tagName || '').toLowerCase(),
              type: String(node.getAttribute?.('type') || ''),
              name: String(node.getAttribute?.('name') || ''),
              id: String(node.id || ''),
              autocomplete: String(node.getAttribute?.('autocomplete') || ''),
              placeholder: String(node.getAttribute?.('placeholder') || ''),
            }),
          ),
        };
      };
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const previewText = () => String(document.body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 500);
      const isVisible = (node) => {
        // NOT offsetParent-based: the CSSOM spec makes offsetParent null for any
        // position:fixed element, so a modal dialog (chatgpt.com's "Log in or
        // sign up" chooser) and everything inside it would read as invisible —
        // which is exactly why "Continue with email" could never be found.
        if (!node || !node.isConnected || node.disabled) return false;
        const rect = node.getBoundingClientRect?.();
        if (!rect || rect.width <= 0 || rect.height <= 0) return false;
        const style = node.ownerDocument?.defaultView?.getComputedStyle?.(node);
        if (!style) return true;
        return style.visibility !== 'hidden' && style.display !== 'none' && Number(style.opacity) !== 0;
      };
      const visibleNodes = (selectors) => Array.from(document.querySelectorAll(selectors)).filter(isVisible);
      const firstNode = (selectors) => visibleNodes(selectors)[0] || null;
      const currentUrl = () => String(location.href || '');
      const unknownPageError = (message) => {
        const error = new Error(message);
        error.__unknownPage = true;
        return error;
      };
      const buildDebugSnapshot = () => ({
        url: currentUrl(),
        title: String(document.title || ''),
        body_text: String(document.body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 4000),
        body_html: String(document.body?.innerHTML || '').replace(/\s+/g, ' ').trim().slice(0, 12000),
        headings: summarizePageState(document, location).headings || [],
        buttons: summarizePageState(document, location).buttons || [],
        inputs: summarizePageState(document, location).inputs || [],
      });
      const fillValue = (node, value) => {
        if (!node) {
          return false;
        }
        const prototype = node instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const descriptor = Object.getOwnPropertyDescriptor(prototype, 'value');
        const setter = descriptor?.set;
        node.focus();
        if (setter) {
          setter.call(node, '');
        } else {
          node.value = '';
        }
        node.dispatchEvent(new Event('input', { bubbles: true }));
        if (setter) {
          setter.call(node, String(value ?? ''));
        } else {
          node.value = String(value ?? '');
        }
        node.dispatchEvent(new Event('input', { bubbles: true }));
        node.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      };
      const trustedClick = async (node) => {
        if (!node) {
          return false;
        }
        // 遮挡/元素挪走都是瞬时状态（视图过渡、字体回流、弹层收起），SW 侧已经会
        // 重量多次；这里再包一层完整重试——重新滚动、重新量、重新排队，因为元素
        // 可能是**永久挪位**了，只重量坐标没用。一直不行才抛错。
        let lastError = null;
        for (let round = 0; round < 3; round += 1) {
          if (round) {
            await sleep(400);
          }
          try {
            const done = await trustedClickOnce(node);
            if (done) return true;
            return false;
          } catch (error) {
            const message = String(error?.message || error || '');
            // 通道不可用是配置问题，重试没有意义。
            if (message.includes('可信点击通道不可用')) throw error;
            lastError = error;
          }
        }
        throw lastError || new Error('可信点击未能完成');
      };
      const trustedClickOnce = async (node) => {
        if (!node) {
          return false;
        }
        node.scrollIntoView?.({ block: 'center', inline: 'center', behavior: 'instant' });
        // 等滚动真正停下来再取坐标。坐标是给 service worker 用的，而它要等轮询
        // (90ms) + 一次注入往返之后才真正派发，中间隔 100~300ms——元素只要还在动，
        // 点击就落空（实测：MFA 弹窗里点「Trouble scanning?」始终点不中，
        // 因为 scrollIntoView 正在滚动那个 overflow-y-auto 内容区）。
        let previous = null;
        for (let settle = 0; settle < 20; settle += 1) {
          const current = node.getBoundingClientRect?.();
          if (!current) {
            return false;
          }
          if (previous && Math.abs(current.top - previous.top) < 0.5 && Math.abs(current.left - previous.left) < 0.5) {
            break;
          }
          previous = current;
          await sleep(50);
        }
        const rect = node.getBoundingClientRect?.();
        if (!rect || (!rect.width && !rect.height)) {
          return false;
        }
        const x = rect.left + rect.width / 2;
        const y = rect.top + rect.height / 2;
        // Out of view even after scrolling (fixed overlay, zero-size wrapper):
        // a CDP click at those coordinates would hit whatever is really there.
        if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) {
          return false;
        }
        node.focus?.();
        const channel = String(input?.__cdp_channel || '');
        const bucket = channel ? (window[channel] = window[channel] || { pending: [], done: {}, seq: 0 }) : null;
        if (!bucket || bucket.cdp === false) {
          // No trusted transport: refuse rather than fall back to a synthetic
          // click, whose isTrusted=false is exactly what gets flagged.
          throw new Error('可信点击通道不可用：CDP 无法附加到该标签页（该页是否开着 DevTools？）。已拒绝退回合成点击。');
        }
        const id = (bucket.seq = (bucket.seq || 0) + 1);
        // 给目标打个一次性标记：SW 在真正派发前会用它重新量一次坐标，并确认那个
        // 点上最顶层的元素确实是它（不是被遮挡物吃掉）。x/y 只作兜底。
        const token = `t${id}_${String(Date.now() % 1000000)}`;
        try {
          node.setAttribute('data-cdpc-target', token);
        } catch (_e) {}
        bucket.pending.push({ id, x, y, sel: `[data-cdpc-target="${token}"]` });
        // The service-worker pump performs the real click while this step is
        // still awaiting here.
        const settled = await waitFor(() => bucket.done[id] || null, 15000);
        delete bucket.done[id];
        try {
          node.removeAttribute('data-cdpc-target');
        } catch (_e) {}
        if (settled === 'covered') {
          throw new Error('可信点击落空：目标点被其它元素遮挡（可能有未关闭的弹层）');
        }
        if (settled === 'gone') {
          throw new Error('可信点击落空：派发前目标元素已从页面上消失');
        }
        if (settled !== 'ok') {
          throw new Error('可信点击未能完成（CDP 未返回确认）');
        }
        await sleep(120);
        return true;
      };
      // Same transport, for real key presses. A synthetic KeyboardEvent never
      // triggers the browser's own default action anyway (forms do not submit
      // from one), so this is both more honest and more effective.
      const trustedKey = async (key, node) => {
        node?.focus?.();
        const channel = String(input?.__cdp_channel || '');
        const bucket = channel ? (window[channel] = window[channel] || { pending: [], done: {}, seq: 0 }) : null;
        if (!bucket || bucket.cdp === false) {
          throw new Error('可信按键通道不可用：CDP 无法附加到该标签页（该页是否开着 DevTools？）。');
        }
        const id = (bucket.seq = (bucket.seq || 0) + 1);
        bucket.pending.push({ id, key: String(key) });
        const settled = await waitFor(() => bucket.done[id] || null, 15000);
        delete bucket.done[id];
        if (settled !== 'ok') {
          throw new Error('可信按键未能完成（CDP 未返回确认）');
        }
        await sleep(150);
        return true;
      };
      // REAL typing, over the same CDP transport. fillValue() below writes
      // .value through the native setter and fires synthetic input/change
      // events whose isTrusted is FALSE — the exact tell that gets synthetic
      // clicks flagged. Anything a human would type must go through here.
      //
      // The field is focused with a trusted CLICK first (not node.focus(), which
      // is itself scriptable): after this the caret is really in the field, so
      // the pump only has to select-all + Delete + send genuine keystrokes.
      // Type into whatever already has focus, without clicking first. Split OTP
      // boxes auto-advance the caret, so clicking each box would fight the page.
      const trustedType = async (value, { clear = false } = {}) => {
        const channel = String(input?.__cdp_channel || '');
        const bucket = channel ? (window[channel] = window[channel] || { pending: [], done: {}, seq: 0 }) : null;
        if (!bucket || bucket.cdp === false) {
          throw new Error('可信输入通道不可用：CDP 无法附加到该标签页。已拒绝退回合成输入。');
        }
        const id = (bucket.seq = (bucket.seq || 0) + 1);
        bucket.pending.push({ id, text: String(value ?? ''), clear });
        const settled = await waitFor(() => bucket.done[id] || null, 60000);
        delete bucket.done[id];
        if (settled !== 'ok') {
          throw new Error('可信输入未能完成（CDP 未返回确认）');
        }
        await sleep(80);
        return true;
      };
      const trustedFill = async (node, value) => {
        if (!node) {
          return false;
        }
        const wanted = String(value ?? '');
        const startedUrl = currentUrl();
        const channel = String(input?.__cdp_channel || '');
        const bucket = channel ? (window[channel] = window[channel] || { pending: [], done: {}, seq: 0 }) : null;
        if (!bucket || bucket.cdp === false) {
          throw new Error('可信输入通道不可用：CDP 无法附加到该标签页（该页是否开着 DevTools？）。已拒绝退回合成输入。');
        }
        // The field can be destroyed under us: /create-account renders the form
        // and only then bounces to the "会话已结束" interstitial, so typing that
        // started on the doomed document lands a few characters and stops. That
        // is a page-lifecycle problem, NOT bad input — report it as the same
        // retryable token the interstitial uses so the caller re-navigates.
        const bailIfPageMovedOn = () => {
          if (!node.isConnected || currentUrl() !== startedUrl) {
            throw unknownPageError(
              'login_retry_click：输入过程中页面发生跳转（表单已被销毁），需要重新进入该步骤',
            );
          }
        };
        // Two attempts: a React-controlled input occasionally drops keystrokes
        // it receives faster than it re-renders.
        for (let attempt = 1; attempt <= 2; attempt += 1) {
          bailIfPageMovedOn();
          const clicked = await trustedClick(node);
          if (!clicked) {
            throw new Error('可信输入失败：无法点中目标输入框');
          }
          const id = (bucket.seq = (bucket.seq || 0) + 1);
          bucket.pending.push({ id, text: wanted, clear: true });
          const settled = await waitFor(() => bucket.done[id] || null, 60000);
          delete bucket.done[id];
          if (settled !== 'ok') {
            bailIfPageMovedOn();
            throw new Error('可信输入未能完成（CDP 未返回确认）');
          }
          await sleep(120);
          if (String(node.value ?? '') === wanted) {
            return true;
          }
          bailIfPageMovedOn();
        }
        throw new Error(
          `可信输入后取值不符（期望 ${wanted.length} 字符，实际 ${String(node.value ?? '').length} 字符）`,
        );
      };
      const formControls = (root) => Array.from((root || document).querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"], a[href]')).filter(isVisible);
      const closestForm = (node) => node?.form || node?.closest?.('form') || null;
      const phoneInput = () => firstNode('input[type="tel"], input[autocomplete="tel"], input[name*="phone" i], input[id*="phone" i]');
      const passwordInput = () => firstNode('input[type="password"], input[autocomplete="new-password"], input[autocomplete="current-password"], input[name*="password" i], input[id*="password" i]');
      const formSubmitControl = (root) => formControls(root).find((node) => {
        const tag = String(node.tagName || '').toLowerCase();
        const type = String(node.getAttribute?.('type') || '').toLowerCase();
        if (tag === 'input') {
          return type === 'submit' || type === 'button';
        }
        if (tag === 'button') {
          return type !== 'button' || !type;
        }
        return false;
      }) || null;
      const submitNearestForm = async (node) => {
        const form = closestForm(node) || firstNode('form');
        if (form) {
          const submit = formSubmitControl(form);
          if (submit) {
            return trustedClick(submit);
          }
        }
        // No submit control to click: press Enter for real. requestSubmit() and
        // a synthetic KeyboardEvent both produce isTrusted=false, which is the
        // very thing that got these submissions flagged.
        node?.focus?.();
        return trustedKey('Enter', node);
      };
      const collectCodeInputs = () => visibleNodes('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[name*="otp" i], input[id*="otp" i], input[name*="code" i], input[id*="code" i], input[maxlength="1"]');
      const visibleError = () => {
        const nodes = visibleNodes('[role="alert"], [aria-live="assertive"], .error, .text-red-500, .text-danger, .warning, [data-error]');
        return nodes.map((node) => String(
          node?.innerText ||
          node?.textContent ||
          node?.value ||
          node?.getAttribute?.('aria-label') ||
          node?.getAttribute?.('placeholder') ||
          '',
        ).replace(/\s+/g, ' ').trim()).find(Boolean) || '';
      };
      // OpenAI's full-page error / deactivation screens render the cause in an
      // <h1> + subtitle, NOT inside [role=alert]/.error, so visibleError() can't
      // see them and the caller would mis-report "未识别页面: unknown". Detect
      // them explicitly and return a message carrying an ASCII token the Python
      // side can classify (account_deactivated -> dead account, no retry;
      // openai_transient -> OpenAI server hiccup, retryable).
      const pageLevelError = () => {
        const heading = String(
          firstNode('h1')?.innerText || firstNode('h1')?.textContent || '',
        ).replace(/\s+/g, ' ').trim();
        const body = String(previewText() || '').replace(/\s+/g, ' ').trim();
        const hay = `${heading} ${body}`;
        if (/account_deactivated|账户已被删除|已被删除或停用|身份验证错误/i.test(hay)) {
          return `账号不可用 account_deactivated：${(body || heading).slice(0, 200)}`;
        }
        if (/操作超时|operation timed out|糟糕，?出错了|something went wrong|服务(暂时)?不可用|请稍后(再)?重试/i.test(hay)
          || /糟糕|出错了/.test(heading)) {
          return `openai_transient OpenAI 页面报错：${(heading || body).slice(0, 160)}`;
        }
        return '';
      };
      // OpenAI's "糟糕，出错了！/ Operation timed out" screen (pageLevelError)
      // carries a "重试 / Try again" button. When a login step lands on it —
      // e.g. password submit times out before the MFA page loads — click that
      // button and let the real step reappear instead of dying on "未找到验证码
      // 输入框". Returns true once the page recovers (readyPredicate hits or the
      // error screen is gone), false if it stays stuck.
      const tryAgainButton = () => visibleNodes('button, a').find((node) => {
        const label = String(node?.innerText || node?.textContent || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
        const ddAction = String(node?.getAttribute?.('data-dd-action-name') || '').toLowerCase();
        return ddAction === 'try again' || /^(重试|重新?试一?次|再试一次|try again|retry)$/i.test(label);
      }) || null;
      const recoverFromTransient = async (readyPredicate, rounds = 3) => {
        for (let i = 0; i < rounds; i += 1) {
          if (readyPredicate()) return true;
          if (!pageLevelError()) return true;
          const btn = tryAgainButton();
          if (!btn) return false;
          try {
            await trustedClick(btn);
          } catch (_e) {
            // Clicking may navigate and tear this frame down — that's fine, the
            // step reloads; just wait for the real page below.
          }
          await waitFor(() => readyPredicate() || (!pageLevelError() && !tryAgainButton()), 20000);
        }
        return readyPredicate() || !pageLevelError();
      };
      // An EXISTING account's login password page (/log-in/password). It is told
      // apart from the signup "set a password" page by the autocomplete/name of
      // the field: current-password vs new-password.
      const isLoginPasswordPage = () => {
        if (currentUrl().toLowerCase().includes('/log-in/password')) {
          return true;
        }
        return !!firstNode('input[autocomplete="current-password"], input[name="current-password"]')
          && !firstNode('input[autocomplete="new-password"], input[name*="new-password" i], input[id*="new-password" i]');
      };
      const isCreateAccountPasswordPage = () => {
        const href = currentUrl().toLowerCase();
        if (href.includes('/create-account/password')) {
          return true;
        }
        // NEVER mistake the login password page for the signup one: the old
        // fallback matched the bare word "password", which every password page
        // contains — so /log-in/password read as "create account password" and
        // the flow typed a freshly generated signup password into an existing
        // account's LOGIN form ("Incorrect email address or password").
        if (isLoginPasswordPage()) {
          return false;
        }
        return !!passwordInput()
          && /create an? account|create a password|set a password|创建帐?户|创建账?户|设置密码/i.test(previewText());
      };
      const isKnownPostOtpPage = () => !!(
        phoneInput() ||
        String(location.href || '').startsWith('http://localhost:1455/auth/callback') ||
        firstNode('button[name="intent"][value*="authorize" i], button[name="intent"][value*="allow" i], form button[type="submit"], a[href*="/auth/callback?code="]')
      );
      const findOtpRegistrationControl = () => {
        const intentControl = visibleNodes('button[name="intent"][value*="otp" i], input[name="intent"][value*="otp" i], button[form][name="intent"], input[form][name="intent"]').find((node) => {
          const value = String(node.getAttribute?.('value') || '').toLowerCase();
          return value.includes('otp') || value.includes('passwordless');
        });
        if (intentControl) {
          return intentControl;
        }
        const passwordInput = firstNode('input[type="password"], input[autocomplete="new-password"], input[name="password"], input[id*="password" i]');
        if (!passwordInput) {
          return null;
        }
        let ancestor = passwordInput.parentElement;
        while (ancestor && ancestor !== document.body) {
          const candidates = formControls(ancestor)
            .filter((node) => (passwordInput.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING))
            .filter((node) => node !== passwordInput);
          const preferred = candidates.filter((node) => String(node.getAttribute?.('type') || '').toLowerCase() !== 'submit');
          if (preferred.length) {
            return preferred[preferred.length - 1];
          }
          if (candidates.length) {
            return candidates[candidates.length - 1];
          }
          ancestor = ancestor.parentElement;
        }
        return null;
      };
      let usedSignupPassword = false;
      const submitSignupPassword = async (password) => {
        const signupPassword = String(password || '').trim();
        if (!signupPassword) {
          throw unknownPageError('进入 create-account/password 但未提供注册密码');
        }
        const inputNode = await waitFor(() => passwordInput(), 10000);
        if (!inputNode) {
          throw unknownPageError('进入 create-account/password 但未找到密码输入框');
        }
        await trustedFill(inputNode, signupPassword);
        usedSignupPassword = true;
        await submitNearestForm(inputNode);
        await waitFor(
          () => phoneInput() || collectCodeInputs().length || visibleError() || String(location.href || '').startsWith('http://localhost:1455/auth/callback') || !isCreateAccountPasswordPage(),
          30000,
        );
      };
      // Every in-page wait is expressed against a 30s baseline. The configured
      // 页面元素等待超时 (插件「调试」页 → 通用配置) scales all of them by the same
      // factor, so raising one number in the UI stretches the whole step
      // uniformly instead of only the calls that happened to omit a value.
      const WAIT_BASELINE_MS = 30000;
      const WAIT_SCALE = (Number(input?.element_wait_timeout_ms) || WAIT_BASELINE_MS) / WAIT_BASELINE_MS;
      const waitFor = async (predicate, timeoutMs = WAIT_BASELINE_MS) => {
        const deadline = Date.now() + Math.round(timeoutMs * WAIT_SCALE);
        while (Date.now() < deadline) {
          const value = predicate();
          if (value) {
            return value;
          }
          await sleep(250);
        }
        return null;
      };
      const submitOtp = async (code) => {
        const digits = String(code || '').trim();
        const otpInputs = collectCodeInputs();
        if (otpInputs.length >= digits.length && digits.length > 1) {
          // Split OTP boxes: type each digit for real. Typing into the first box
          // often auto-advances focus, so re-check what is focused and only fall
          // back to clicking the next box when the page did not move for us.
          for (let index = 0; index < digits.length; index += 1) {
            const box = otpInputs[index];
            if (document.activeElement === box) {
              await trustedType(digits[index]);
            } else {
              await trustedFill(box, digits[index]);
            }
          }
        } else {
          const node = firstNode('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[name*="code" i], input[id*="code" i], input[type="text"]');
          if (!node) {
            throw unknownPageError('未找到验证码输入框');
          }
          await trustedFill(node, digits);
        }
        await submitNearestForm(otpInputs[0] || document.activeElement);
      };

      // 注册完成后 chatgpt.com 会弹一个**原生 <dialog>**（"You're all set" +
      // Continue，快照 1038377940-…-192354）。它是 showModal() 打开的，会把页面其余
      // 部分置为 inert —— 不点掉它，后面所有点击都点不动（MFA 设置根本进不去）。
      // 只匹配原生 <dialog>：设置弹窗和 MFA 弹窗都是 radix 的 <div role="dialog">，
      // 绝不能被这里误关。
      const nativeBlockingDialog = () => Array.from(document.querySelectorAll('dialog'))
        .filter((node) => node.open !== false && isVisible(node))
        // 保险：绝不去关一个装着本流程自己表单的 <dialog>（MFA 录入、密码、邮箱）。
        .filter((node) => !node.querySelector('#totp_otp, #enroll-totp-modal-title, input[type="password"], input[type="email"]'))[0] || null;
      const blockingDialogLabel = () => {
        const dialog = nativeBlockingDialog();
        if (!dialog) return '';
        return String(
          dialog.getAttribute('aria-label')
          || dialog.querySelector('h1, h2, h3, p')?.innerText
          || '',
        ).replace(/\s+/g, ' ').trim().slice(0, 60);
      };
      const blockingDialogButton = (dialog) => {
        const CONFIRM_RE = /^(continue|got it|okay|ok|start|done|next|close|dismiss|继续|知道了|好的|开始|完成|下一步|关闭)$/i;
        const label = (node) => String(
          node.innerText || node.textContent || node.value || node.getAttribute?.('aria-label') || '',
        ).replace(/\s+/g, ' ').trim();
        const buttons = Array.from(dialog.querySelectorAll('button, [role="button"], input[type="submit"]'))
          .filter(isVisible);
        return buttons.find((node) => CONFIRM_RE.test(label(node)))
          || buttons.find((node) => /btn-primary/.test(String(node.className || '')))
          || (buttons.length === 1 ? buttons[0] : null);
      };
      // waitMs > 0：**先等它出现再点**。这个欢迎弹层是 React 的 blocking initial
      // modal（`[data-testid="blocking-initial-modals-done"]`），在 load 之后才画
      // 出来，而且每次整页刷新都会重新弹一次。只在被调用的那一瞬间看一眼，多半
      // 什么也看不到——然后后面每一次点击都点在被 inert 掉的页面上。实测就是这么
      // 死的：MFA 全程点空，最后却报成"点击 Authenticator app 后没弹出 MFA 弹窗"。
      // 返回点掉的弹层个数；点不掉不抛错（纯善后动作），由调用方查 nativeBlockingDialog()。
      const dismissBlockingDialog = async (waitMs = 0) => {
        let dismissed = 0;
        // 弹层可能一个接一个（欢迎 → 优惠…），逐个点掉。
        for (let round = 0; round < 3; round += 1) {
          const dialog = (waitMs > 0 && round === 0)
            ? await waitFor(() => nativeBlockingDialog(), waitMs)
            : nativeBlockingDialog();
          if (!dialog) break;
          const button = blockingDialogButton(dialog);
          if (!button) break;
          try {
            if (!await trustedClick(button)) break;
          } catch (_e) {
            break;
          }
          if (!await waitFor(() => nativeBlockingDialog() !== dialog, 10000)) break;
          dismissed += 1;
          await sleep(300);
        }
        return dismissed;
      };

        const action = String(input?.action || '');
        try {
        switch (action) {
          case 'submit_email': {
            // Two pages can stand between us and the email form, and BOTH are
            // reached by clicking a 登录 control rather than by redirecting:
            //   - auth.openai.com's "你的会话已结束" interstitial (an <a> link)
            //   - the logged-out chatgpt.com landing page ("今天有什么计划？"),
            //     whose 登录 controls are <button>s, not links. Matching only
            //     anchors made this look like a dead page while a human just
            //     clicks 登录 and proceeds — which is exactly what happens when
            //     /auth/login_with renders the app instead of redirecting.
            // So: accept links AND buttons, by href or by exact label, and never
            // hit 注册 / 免费注册 or a social provider.
            // Deliberately NOT matching a bare "继续 / Continue": the
            // "Log in or sign up" dialog's bottom Continue button submits the
            // PHONE NUMBER field, and clicking that instead of the login entry
            // would send an empty phone submission.
            const LOGIN_LABEL_RE = /^(登录|登入|登陆|log\s?in|sign\s?in)$/i;
            const SIGNUP_LABEL_RE = /注册|sign\s?up|免费|create\s?an?\s?account/i;
            const PROVIDER_LABEL_RE = /google|microsoft|apple|facebook|github|linkedin|okta|sso|saml|passkey|通行密钥|谷歌|微软|苹果|phone|tel\b|手机|电话/i;
            const nodeLabel = (node) => String(
              node?.innerText || node?.textContent || node?.value || node?.getAttribute?.('aria-label') || '',
            ).replace(/\s+/g, ' ').trim();
            // 返回**全部**登录候选，不是第一个：chatgpt.com 登出态首页上同时挂着
            // 侧边栏底部推广卡片的「Log in」和右上角 header 的「Log in」，DOM 顺序
            // 第一个不一定点得动，点不动就必须换下一个试（见下面的点击循环）。
            const loginCandidates = () => {
              const nodes = visibleNodes(
                'a[href*="/auth/login_with"], a[href*="/log-in"], a[href*="/auth/login"],'
                + ' a[data-dd-action-name*="Log in" i], button, [role="button"], [data-testid*="login" i]',
              );
              const usable = (node) => {
                const label = nodeLabel(node);
                return !SIGNUP_LABEL_RE.test(label) && !PROVIDER_LABEL_RE.test(label);
              };
              // A real link to the login endpoint is the most reliable; fall back
              // to a control whose whole label is 登录.
              const byHref = nodes.filter((node) => /login_with|\/log-in|\/auth\/login/i.test(String(node?.getAttribute?.('href') || '')) && usable(node));
              const byLabel = nodes.filter((node) => LOGIN_LABEL_RE.test(nodeLabel(node)) && usable(node) && !byHref.includes(node));
              return byHref.concat(byLabel);
            };
            const loginLink = () => loginCandidates()[0] || null;
            const emailInput = () => firstNode('input[type="email"], input[autocomplete="username"], input[name="username"], input[name="email"], input[id*="email" i]');
            // OpenAI's /log-in defaults to PHONE NUMBER entry (usernameKind=
            // phone_number): a tel box, no email box, and a "Continue with email"
            // button that switches the form over. Detect it explicitly so the
            // flow re-clicks that button instead of reporting "未识别页面".
            const phoneOnlyLoginForm = () => !emailInput()
              && !collectCodeInputs().length
              && !!firstNode('input[type="tel"], input#tel, input[autocomplete="tel"]');
            // auth.openai.com's "你的会话已结束" (is_missing_session) interstitial:
            // no form of any kind, just a 登录 control. It can show up BEFORE the
            // email form and again AFTER submitting the email, and the only way
            // through it — for a human or for us — is to click that control.
            const sessionEndedPage = () => !emailInput()
              && !collectCodeInputs().length
              && !!loginLink()
              && (/会话已结束|session (has )?ended|missing session|会话已过期|セッション.*(終了|期限)|세션.*(종료|만료)/i.test(previewText())
                || /is_missing_session/i.test(String(document.body?.innerHTML || '').slice(0, 20000)));
            // Only genuinely hopeless when there is no email form AND nothing to
            // click. Now that buttons count as login controls, the chatgpt.com
            // landing page no longer lands here — it goes to the click branch.
            const onLoginWithShell = () => /(^|\.)chatgpt\.com$/i.test(String(location.hostname || ''))
              && !emailInput()
              && !loginLink();
            // 这一步可能被**重跑**（中转页 login_retry_click、帧销毁…），而重跑时
            // 页面很可能**已经走过邮箱这一步了**：实测点回中转页的登录控件后，
            // OpenAI 直接把我们送回 /email-verification（Check your inbox +
            // 「Continue with password」），那页当然没有邮箱框——旧代码于是报
            // 「未找到邮箱输入框」，Python 当成"入口是死路"重新加载，把已经拿到的
            // 进度整个扔掉，还白烧一个取号。**没有邮箱框不等于走不通，先看看是不是
            // 已经在下一步了。**
            const alreadyPastEmail = () => {
              const url = currentUrl().toLowerCase();
              if (url.includes('/email-verification')) return 'otp';
              if (url.includes('/phone-verification') || url.includes('/add-phone')) return 'phone';
              if (isCreateAccountPasswordPage()) return 'create-account-password';
              if (isLoginPasswordPage()) return 'login-password';
              if (collectCodeInputs().length) return 'otp';
              return '';
            };
            if (!emailInput()) {
              const passed = alreadyPastEmail();
              if (passed) {
                return {
                  ok: true,
                  next_stage: passed,
                  already_submitted: true,
                  url: currentUrl(),
                  state: summarizePageState(document, location),
                  error_text: visibleError(),
                };
              }
            }
            if (onLoginWithShell()) {
              await waitFor(() => !onLoginWithShell(), 8000);
              if (onLoginWithShell()) {
                throw unknownPageError('login_with_shell：停在 chatgpt.com 且页面上既无邮箱表单也无可点的登录控件');
              }
            }
            // Getting to the email box can take two clicks, in this order:
            //   1. chatgpt.com's top-right "Log in" (or the "你的会话已结束" link)
            //   2. in the "Log in or sign up" dialog that opens, "Continue with
            //      email" — the dialog defaults to PHONE NUMBER entry and has no
            //      email field at all until that is clicked.
            // The dialog's own bottom "Continue" button submits the phone number,
            // so it must never be mistaken for a login control (see
            // LOGIN_LABEL_RE, which deliberately does not match a bare
            // "Continue").
            const emailSwitchControl = () => visibleNodes('button, a, [role="button"], [role="tab"]').find((node) => {
              const label = nodeLabel(node);
              return /continue with email|use email|使用邮箱|改用邮箱|邮箱登录|电子邮件|メールで続行|メールアドレス|이메일/i.test(label)
                && !/手机|电话|phone|sms|電話/i.test(label);
            }) || null;
            // chatgpt.com renders its header late and, behind a proxy, may never
            // report "load complete" at all — so never assume the controls are
            // already there. Wait for one to exist, click it, and keep going
            // until the email box appears, instead of giving up because a
            // control was missing on the first look.
            // 点击结果必须逐条记下来回传：这一步一旦点不动，Python 侧只看得到
            // 「页面还停在登录中转页」，从日志里完全看不出"到底点了谁、点没点出去"。
            const clickLog = [];
            let clickedAny = false;
            const tried = new Set();
            for (let round = 0; round < 8 && !emailInput(); round += 1) {
              const ready = await waitFor(
                () => emailInput() || emailSwitchControl() || loginLink(),
                round === 0 ? 30000 : 10000,
              );
              if (!ready || emailInput()) break;
              // The chooser dialog wins: it is the last hop before the email box.
              const control = emailSwitchControl()
                || loginCandidates().find((node) => !tried.has(node))
                || null;
              if (!control || tried.has(control)) break;
              tried.add(control);
              const label = (nodeLabel(control) || String(control.tagName || '')).slice(0, 32);
              // **必须检查 trustedClick 的返回值**：元素没尺寸 / 滚动后仍在视口外时
              // 它是**静默返回 false**（不抛错，也没派发任何事件）。旧代码把返回值扔
              // 掉，于是"一次都没点出去"和"点了但页面没反应"长得一模一样，后面照样
              // 白等 20s + 30s——实测整整 53s 里页面上没有任何动静，日志里也只有一条
              // unknown_page（logs/codex-658182f8a2ac35e245ad95b0-c019bdbd-a1.log）。
              let landed = false;
              try {
                landed = await trustedClick(control);
                clickLog.push(`${label}=${landed ? 'clicked' : 'not-dispatched'}`);
              } catch (error) {
                const message = String(error?.message || error || '');
                clickLog.push(`${label}=${message.slice(0, 48)}`);
                // 点击导致跨域跳转会把本帧一起销毁 —— 那是**点成功了**，等下一页即可。
                // 但"可信点击落空"（被遮挡/目标消失）意味着这一下根本没派发出去，
                // 等 20s 毫无意义，直接换下一个候选控件。
                landed = !message.includes('可信点击落空');
              }
              if (!landed) continue;
              clickedAny = true;
              // Either the email box appears directly (auth.openai.com) or the
              // chooser dialog does (chatgpt.com) — both end this round.
              await waitFor(() => emailInput() || emailSwitchControl(), 20000);
            }
            const clickReport = clickLog.length ? clickLog.join(' / ') : '没有找到任何可点的登录控件';
            const inputNode = await waitFor(
              () => firstNode('input[type="email"], input[autocomplete="username"], input[name="username"], input[name="email"], input[id*="email" i]'),
              // 一次都没真正点出去时，再等 30s 也只是把失败推迟半分钟。
              clickedAny ? 30000 : 5000,
            );
            if (!inputNode) {
              // Still no form, but a 登录 control is on screen — typically we got
              // bounced back to auth.openai.com's "你的会话已结束" page. Clicking it
              // again is exactly what a human does, and each click is a fresh
              // request that carries more session context than the last. Say so
              // with a distinct token so the caller re-runs this step (which
              // starts by clicking) instead of writing the page off.
              if (loginLink()) {
                throw unknownPageError(`login_retry_click：页面仍停在「你的会话已结束」，还有可点的登录控件，需要再点一次（本轮点击：${clickReport}）`);
              }
              // 兜底：等待期间页面才走到下一步（慢代理下很常见）。
              const passed = alreadyPastEmail();
              if (passed) {
                return {
                  ok: true,
                  next_stage: passed,
                  already_submitted: true,
                  url: currentUrl(),
                  state: summarizePageState(document, location),
                  error_text: visibleError(),
                };
              }
              throw unknownPageError(`未找到邮箱输入框（本轮点击：${clickReport}）`);
            }
            // /create-account can paint the form and only THEN bounce to the
            // "会话已结束" interstitial. Typing into that doomed document lands a
            // couple of characters and dies, so make sure the page has stopped
            // moving before touching the field.
            {
              let settleUrl = currentUrl();
              for (let settle = 0; settle < 6; settle += 1) {
                await sleep(200);
                const now = currentUrl();
                if (now === settleUrl && inputNode.isConnected) break;
                settleUrl = now;
              }
              if (!inputNode.isConnected || sessionEndedPage()) {
                throw unknownPageError('login_retry_click：邮箱表单在输入前被替换成了中转页，需要重新进入该步骤');
              }
            }
            await trustedFill(inputNode, input.email);
            // CRITICAL: ChatGPT's welcome/login page puts the email field and the
            // social-login buttons ("继续使用 Google/Microsoft/Apple") in the same
            // form. submitNearestForm() clicks the FIRST submit control in that
            // form, which is often the Google button — the page then navigates to
            // Google's login and no OTP email is ever sent (looks like "OTP 超时").
            // Pick the email "继续/Continue" control explicitly and never a social
            // provider; fall back to Enter on the input.
            const SOCIAL_RE = /google|microsoft|apple|facebook|github|linkedin|okta|sso|saml|passkey|通行密钥|phone|tel\b|电话|手机|谷歌|微软|苹果/i;
            // "Continue with <anything>" is always a METHOD SWITCH (Google, Apple,
            // phone…), never the email form's submit. On the English UI the phone
            // variant slipped past SOCIAL_RE (which only listed 电话/手机号) and
            // CONTINUE_RE matched its "Continue…" prefix, so this button got
            // clicked as if it were the email submit — which is exactly how the
            // flow ended up parked on /log-in?usernameKind=phone_number.
            const CONTINUE_WITH_RE = /^(continue|log ?in|sign ?in|继续|登录)\s*(with|使用|用)\b/i;
            const notSocial = (node) => {
              const label = String(node?.innerText || node?.textContent || node?.value || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              const href = String(node?.getAttribute?.('href') || '');
              const action = String(node?.getAttribute?.('data-dd-action-name') || '');
              const provider = String(node?.getAttribute?.('data-provider') || node?.getAttribute?.('name') || '');
              if (CONTINUE_WITH_RE.test(label)) {
                return false;
              }
              return !SOCIAL_RE.test(`${label} ${href} ${action} ${provider}`);
            };
            const emailForm = closestForm(inputNode) || firstNode('form');
            const candidates = formControls(emailForm || document).filter(notSocial);
            const CONTINUE_RE = /^(continue|next|log ?in|sign ?in|submit|继续|下一步|登录|确定)/i;
            const emailSubmit = candidates.find((node) => {
              const label = String(node?.innerText || node?.textContent || node?.value || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              return CONTINUE_RE.test(label);
            }) || candidates.find((node) => {
              const tag = String(node.tagName || '').toLowerCase();
              const type = String(node.getAttribute?.('type') || '').toLowerCase();
              if (tag === 'input') return type === 'submit';
              if (tag === 'button') return type === 'submit' || !type;
              return false;
            }) || null;
            if (emailSubmit) {
              await trustedClick(emailSubmit);
            } else {
              await trustedKey('Enter', inputNode);
            }
            let nextStep = await waitFor(() => {
              // Strong signals first: real code inputs or the /email-verification
              // URL mean an OTP email was actually sent. The create-account/password
              // page itself carries the words "一次性验证码 / one-time", so it must be
              // matched BEFORE the loose text fallback — otherwise we would report
              // "OTP sent" and the caller starts polling the mailbox while the page
              // is still sitting on create-account/password (no email exists yet).
              if (collectCodeInputs().length || currentUrl().toLowerCase().includes('/email-verification')) return 'otp';
              if (isCreateAccountPasswordPage()) return 'create-account-password';
              // Landed on a third-party identity provider => the wrong (social)
              // button was submitted. Never report this as "OTP sent", or the
              // caller would poll the mailbox for 90s for a mail that never comes.
              if (/accounts\.google\.|login\.microsoftonline\.|appleid\.apple\.|facebook\.com|github\.com\/login/i.test(currentUrl())) return 'social';
              // Existing accounts that sign in with a password land on the
              // password page here. Without this check NOTHING below matches it
              // (no code inputs, no /email-verification, no "验证码" text), so the
              // poll burned the full 30s timeout before the caller could type the
              // password — the "输入密码前卡很久" symptom. Must stay AFTER the
              // create-account-password check: that signup page also has a
              // password input and needs its own stage.
              // Reported distinctly from a generic password page: reaching an
              // EXISTING account's login form means the address is already
              // registered, which the 注册 flow must abandon rather than retry.
              if (isLoginPasswordPage()) return 'login-password';
              if (firstNode('input[type="password"], input[autocomplete="current-password"], input[name="password"]')) return 'password';
              if (/verification|验证码|otp|one-time|認証コード|確認コード|ワンタイム|인증|código|vérification|verifizierung/i.test(previewText())) return 'otp';
              // Submitting the email can bounce straight back to the
              // "你的会话已结束" interstitial. That is NOT a dead end and NOT an
              // OTP: the 登录 control is right there and must be clicked again.
              // Checked last so a real OTP/password page always wins.
              if (sessionEndedPage()) return 'session_ended';
              // The login page can flip itself back to PHONE NUMBER entry (its
              // default), leaving no email box at all — /log-in?usernameKind=
              // phone_number. There is nothing wrong with the account here, the
              // form just needs "Continue with email" clicked again.
              if (phoneOnlyLoginForm()) return 'phone_form';
              if (visibleError()) return 'error';
              return '';
            }, 30000);
            if (nextStep === 'social') {
              throw unknownPageError(`openai_risk_block：提交邮箱后被带到第三方登录页（${currentUrl().slice(0, 120)}），这是风控拦截，未发送邮箱验证码`);
            }
            if (nextStep === 'phone_form') {
              // Same recovery token as the interstitial: the caller re-runs this
              // step, whose click loop starts by pressing "Continue with email".
              throw unknownPageError('login_retry_click：页面切回了手机号登录表单，需要重新点「Continue with email」切回邮箱模式');
            }
            if (nextStep === 'session_ended') {
              // Could also be a transient paint while the real next page loads,
              // so give the good signals a short grace period before deciding.
              const late = await waitFor(() => {
                if (collectCodeInputs().length || currentUrl().toLowerCase().includes('/email-verification')) return 'otp';
                if (isCreateAccountPasswordPage()) return 'create-account-password';
                if (firstNode('input[type="password"], input[autocomplete="current-password"], input[name="password"]')) return 'password';
                return '';
              }, 6000);
              if (!late) {
                // Same token the pre-form path uses: the caller re-runs this step,
                // which begins by clicking 登录 — i.e. it re-enters the login flow
                // instead of writing the page off as unknown.
                throw unknownPageError('login_retry_click：提交邮箱后又回到「你的会话已结束」，需要重新点击登录进入流程');
              }
              nextStep = late;
            }
            // Report the detected stage back to the caller. When it is
            // create-account-password the caller triggers the one-time-code
            // registration (CDP trusted click) to actually send the OTP before
            // waiting for it — we must NOT claim the OTP was sent here.
            return {
              ok: true,
              next_stage: nextStep || '',
              state: summarizePageState(document, location),
              used_signup_password: usedSignupPassword,
              error_text: visibleError(),
            };
          }
          case 'submit_password': {
            const inputNode = await waitFor(
              () => firstNode('input[type="password"], input[autocomplete="current-password"], input[name="password"], input[id*="password" i]'),
              30000,
            );
            if (!inputNode) {
              throw unknownPageError('未找到密码输入框');
            }
            await trustedFill(inputNode, input.password);
            await submitNearestForm(inputNode);
            await waitFor(() => /mfa|authenticator|two-factor|验证器|二步/i.test(previewText()) || collectCodeInputs().length || visibleError() || pageLevelError(), 30000);
            // Password submit can time out into the "糟糕，出错了 / Operation timed
            // out" screen before the MFA page loads. Click 重试 so the next step
            // (submit_mfa_totp) finds the code page instead of an error screen.
            if (pageLevelError()) {
              await recoverFromTransient(() => collectCodeInputs().length || /mfa|authenticator|two-factor|验证器|二步/i.test(previewText()) || visibleError());
            }
            break;
          }
          case 'submit_email_otp':
          case 'submit_phone_otp':
          case 'submit_mfa_totp': {
            const codeReady = () => collectCodeInputs().length || firstNode('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[name*="code" i], input[id*="code" i]');
            await waitFor(() => codeReady() || pageLevelError(), 30000);
            // A transient "Operation timed out / 重试" screen can replace the code
            // step (e.g. after password submit). Click 重试 and let the code page
            // come back; only if it stays stuck surface the openai_transient token
            // so the scheduler retries instead of failing on "未找到验证码输入框".
            if (!codeReady() && pageLevelError()) {
              await recoverFromTransient(codeReady);
            }
            if (!codeReady() && pageLevelError()) {
              throw unknownPageError(pageLevelError());
            }
            await submitOtp(input.code);
            if (action === 'submit_email_otp') {
              let stage = await waitFor(() => {
                if (isCreateAccountPasswordPage()) return 'create-account-password';
                if (phoneInput()) return 'phone';
                // The signup flow's next step. Reported explicitly so the 注册
                // path can drive it; the OAuth path ignores unknown stages and
                // used to see this page as the generic 'post-otp'.
                if (currentUrl().toLowerCase().includes('/about-you')) return 'about-you';
                if (String(location.href || '').startsWith('http://localhost:1455/auth/callback')) return 'callback';
                // OpenAI full-page error / account_deactivated screen — surface
                // the real cause instead of "未识别页面: unknown".
                if (pageLevelError()) return 'error';
                // Still parked on the email OTP step? A wrong/expired code keeps
                // the code inputs on screen and only paints "代码不正确" after a
                // network round-trip. The email-verification page ALSO always has
                // a "继续" submit button, so isKnownPostOtpPage() would falsely
                // report success on the very first poll — before the error shows —
                // and the caller would march on to the phone step on a dead page.
                // Wait out the round-trip: surface the error once it renders, and
                // never treat "still on the code step" as post-OTP.
                const onEmailOtpStep = collectCodeInputs().length
                  && currentUrl().toLowerCase().includes('/email-verification');
                if (onEmailOtpStep) {
                  return visibleError() ? 'error' : '';
                }
                if (visibleError()) return 'error';
                if (isKnownPostOtpPage()) return 'post-otp';
                return '';
              }, 30000);
              if (!stage) {
                throw unknownPageError('邮箱 OTP 后停留在未识别页面阶段: unknown');
              }
              return {
                ok: true,
                next_stage: stage,
                state: summarizePageState(document, location),
                used_signup_password: usedSignupPassword,
                error_text: visibleError() || pageLevelError(),
              };
            }
            if (action === 'submit_phone_otp') {
              // Mirror the email-OTP guard: the phone-verification code page
              // ALWAYS has a "继续" submit button and keeps the code input on
              // screen (often cleared) after a wrong/expired SMS code, only
              // painting the error after a network round-trip. NEVER treat
              // "still on /phone-verification" as success — otherwise the caller
              // marks the number complete, logs "手机号验证通过", and finalize
              // then spins clicking 继续 on an empty field ("需要填写验证码")
              // until it times out. Only report advancement once the page truly
              // leaves the phone step.
              const phoneStage = await waitFor(() => {
                if (String(location.href || '').startsWith('http://localhost:1455/auth/callback')) return 'callback';
                const href = currentUrl().toLowerCase();
                if (href.includes('/about-you')) return 'about-you';
                if (href.includes('/consent') || href.includes('/sign-in-with-chatgpt') || href.includes('/oauth/authorize')) return 'authorize';
                const onPhoneOtpStep = collectCodeInputs().length && href.includes('/phone-verification');
                if (onPhoneOtpStep) {
                  return visibleError() ? 'error' : '';
                }
                if (visibleError()) return 'error';
                if (!collectCodeInputs().length && !href.includes('/phone-verification')) return 'post-otp';
                return '';
              }, 30000);
              const phoneErr = visibleError();
              if (!phoneStage || phoneStage === 'error') {
                // Still stuck on the phone step -> tell the caller to cancel this
                // number and retry with a fresh one (error_text drives the retry).
                return {
                  ok: true,
                  next_stage: phoneStage || 'phone-stuck',
                  error_text: phoneErr || '手机验证码未通过：页面仍停留在 phone-verification',
                  state: summarizePageState(document, location),
                };
              }
              return {
                ok: true,
                next_stage: phoneStage,
                error_text: '',
                state: summarizePageState(document, location),
              };
            }
            await waitFor(() => phoneInput() || visibleError() || String(location.href || '').startsWith('http://localhost:1455/auth/callback'), 30000);
            break;
          }
          case 'submit_signup_password': {
            await submitSignupPassword(input.password);
            const stage = await waitFor(() => {
              if (isCreateAccountPasswordPage()) return 'create-account-password';
              if (phoneInput()) return 'phone';
              if (collectCodeInputs().length || /verification|验证码|otp|one-time/i.test(previewText()) || currentUrl().toLowerCase().includes('/email-verification')) return 'otp';
              if (String(location.href || '').startsWith('http://localhost:1455/auth/callback')) return 'callback';
              if (visibleError()) return 'error';
              if (isKnownPostOtpPage()) return 'post-otp';
              return '';
            }, 30000);
            if (!['phone', 'callback', 'post-otp', 'otp', 'error'].includes(String(stage || ''))) {
              throw unknownPageError(`自动设置密码后停留在未识别页面阶段: ${String(stage || 'unknown')}`);
            }
            if (stage === 'create-account-password') {
              throw unknownPageError('自动设置密码后仍停留在 create-account/password');
            }
            return {
              ok: true,
              next_stage: stage,
              state: summarizePageState(document, location),
              used_signup_password: usedSignupPassword,
              error_text: visibleError(),
            };
          }
          case 'continue_with_password': {
            // /email-verification offers a "Continue with password" link: during
            // signup it leads to /create-account/password, during a re-auth
            // challenge to /log-in/password. It is NOT always rendered — some
            // variants of that page only offer Continue with Google/Apple — so
            // report its absence as data instead of burning the whole element
            // budget waiting for something that will never appear.
            // Prefer the link that explicitly points at the SIGNUP password page.
            // On the signup /email-verification its href is literally
            // /create-account/password (snapshot 1038377682-...-180239); the
            // login-flow variant of the same page points at /log-in/password.
            // Matching the href first means we can never take the login branch
            // just because both pages label the link the same way.
            const passwordSwitchByHref = () => visibleNodes('a[href*="/create-account/password"]')[0] || null;
            const passwordSwitchByLabel = () => visibleNodes('a, button, [role="button"]').find((node) => {
              const label = String(node?.innerText || node?.textContent || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              return /^(continue with password|use password instead|sign in with password|使用密码(登录|继续|验证)?|改用密码)/i.test(label);
            }) || null;
            const passwordSwitch = () => passwordSwitchByHref() || passwordSwitchByLabel();
            await waitFor(() => passwordSwitch() || pageLevelError(), 12000);
            const link = passwordSwitch();
            if (!link) {
              return {
                ok: true,
                next_stage: '',
                password_switch_missing: true,
                state: summarizePageState(document, location),
                error_text: pageLevelError(),
              };
            }
            await trustedClick(link);
            const stage = await waitFor(() => {
              const href = currentUrl().toLowerCase();
              if (href.includes('/create-account/password')) return 'create-account-password';
              if (href.includes('/log-in/password')) return 'login-password';
              if (pageLevelError()) return 'error';
              // URL first: both destinations show a password box, and only the
              // URL says which of the two we are on.
              if (passwordInput()) return 'password';
              if (visibleError()) return 'error';
              return '';
            }, 30000);
            if (!stage) {
              throw unknownPageError('点击「Continue with password」后停留在未识别页面');
            }
            return {
              ok: true,
              next_stage: stage,
              state: summarizePageState(document, location),
              error_text: visibleError() || pageLevelError(),
            };
          }
          case 'submit_about_you': {
            // /about-you will NOT submit until both fields are valid, and a bare
            // click on a half-filled form is a silent no-op (see the same trap in
            // finalize_and_get_callback).
            const nameInput = await waitFor(() => firstNode('input[name="name"], input[autocomplete="name"], input[id$="-name"]'), 20000);
            const ageInput = firstNode('input[name="age"], input[id$="-age"], input[type="number"][inputmode="numeric"]');
            const birthdayHidden = firstNode('input[type="hidden"][name="birthday"]');
            if (!nameInput && !ageInput && !birthdayHidden) {
              throw unknownPageError('未找到 /about-you 的姓名 / 年龄 / 生日输入框');
            }
            if (nameInput) await trustedFill(nameInput, String(input.full_name || 'Alex Morgan'));
            if (ageInput) {
              await trustedFill(ageInput, String(input.age || 27));
            } else if (birthdayHidden) {
              // Birthday variant: three spinbutton divs (MM/DD/YYYY) + hidden input.
              // Derive a plausible birthday from age (age years before today).
              const age = Number(input.age) || 27;
              const today = new Date();
              const birthYear = today.getFullYear() - age;
              const birthMonth = 1 + Math.floor(Math.random() * 12); // 1..12
              const birthDay = 1 + Math.floor(Math.random() * 28);   // 1..28 (safe for all months)
              const monthStr = String(birthMonth).padStart(2, '0');
              const dayStr = String(birthDay).padStart(2, '0');
              const yearStr = String(birthYear);
              // Find the three spinbutton divs by role. Order is MM, DD, YYYY per the snapshot.
              const spinbuttons = visibleNodes('div[role="spinbutton"][contenteditable="true"]');
              if (spinbuttons.length >= 3) {
                await trustedFill(spinbuttons[0], monthStr);  // month
                await trustedFill(spinbuttons[1], dayStr);    // day
                await trustedFill(spinbuttons[2], yearStr);   // year
              }
            }
            await sleep(400);
            const FINISH_RE = /^(finish creating account|create account|continue|完成(帐户|账户)?创建|继续)/i;
            const finish = formControls(closestForm(nameInput || ageInput) || document).find((node) => {
              const label = String(node?.innerText || node?.textContent || node?.value || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              return FINISH_RE.test(label);
            }) || formSubmitControl(closestForm(nameInput || ageInput) || firstNode('form'));
            if (!finish) {
              throw unknownPageError('未找到 /about-you 的「Finish creating account」按钮');
            }
            await trustedClick(finish);
            // Submitting navigates to chatgpt.com, which tears this frame down —
            // the caller treats that as "went through" and confirms via the
            // session endpoint. Only wait long enough to catch a validation
            // error that keeps us on the page.
            const stage = await waitFor(() => {
              const href = currentUrl().toLowerCase();
              if (/^https?:\/\/([^/]*\.)?chatgpt\.com/.test(href)) return 'chatgpt';
              if (pageLevelError()) return 'error';
              if (href.includes('/about-you')) return visibleError() ? 'error' : '';
              return 'left-about-you';
            }, 20000);
            return {
              ok: true,
              next_stage: stage || 'about-you',
              state: summarizePageState(document, location),
              error_text: visibleError() || pageLevelError(),
            };
          }
          case 'submit_phone': {
            // OpenAI's add-phone page may offer SMS and WhatsApp channels.
            // Hero/smsbower can only receive SMS, so always force the SMS
            // radio before submitting; a WhatsApp delivery would time out.
            const WHATSAPP_KEYWORD = /whatsapp/i;
            const smsRadio = () => firstNode('input[type="radio"][value="sms"][name^="segmented-control-"], input[type="radio"][value="sms"]');
            const whatsappRadio = () => firstNode('input[type="radio"][value="whatsapp"][name^="segmented-control-"], input[type="radio"][value="whatsapp"]');
            const phoneErrorNode = () => visibleNodes(
              '[aria-live="polite"] li, [aria-live="assertive"] li, [aria-live="polite"], [aria-live="assertive"], .react-aria-FieldError, ._hiddenErrorsContainer_f5i74_38, [role="alert"], .text-red-500, .text-danger, [data-error]',
            ).map((node) => String(node?.innerText || node?.textContent || '').replace(/\s+/g, ' ').trim()).find(Boolean) || '';
            const whatsappDeliveryOnly = () => {
              // Single-channel page that silently switched to WhatsApp: no
              // usable SMS radio, but the body now mentions WhatsApp delivery.
              if (smsRadio()) return false;
              return visibleNodes('p, div, span').some(
                (node) => WHATSAPP_KEYWORD.test(String(node?.innerText || node?.textContent || '')),
              );
            };

            // A previous attempt may have already submitted a number and left
            // the page on the code-entry step (e.g. its SMS timed out and the
            // number was cancelled). Re-submitting a phone here would hang
            // waiting for a phone input that no longer exists, so first walk the
            // page back to the phone-entry step via the in-page affordance
            // (SPA navigation, no reload — a hard reload would tear down this
            // injected context). If none exists, report it so the caller can
            // re-navigate through the bridge and retry.
            if (!phoneInput() && collectCodeInputs().length) {
              const backControl = formControls(document).find((node) => {
                const label = String(node?.innerText || node?.textContent || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
                return /different phone|another (phone|number)|edit (phone|number)|change (phone|number)|use a different|其他手机|更换号码|换个号码|使用其他|返回|上一步|go back/i.test(label);
              });
              if (backControl) {
                await trustedClick(backControl);
                await waitFor(() => phoneInput(), 15000);
              }
              if (!phoneInput()) {
                return {
                  ok: false,
                  error: '停留在验证码输入页，无法返回手机号输入步骤',
                  needs_phone_page: true,
                  state: summarizePageState(document, location),
                  snapshot: buildDebugSnapshot(),
                };
              }
            }

            const inputNode = await waitFor(
              () => phoneInput(),
              30000,
            );
            if (!inputNode) {
              throw unknownPageError('未找到手机号输入框');
            }
            await trustedFill(inputNode, input.phone_number);
            const smsChannel = smsRadio();
            if (smsChannel) {
              if (!smsChannel.checked) {
                await trustedClick(smsChannel);
              }
            } else if (whatsappRadio()) {
              // Only a WhatsApp radio is offered — cannot receive via SMS.
              return {
                ok: true,
                channel_error: 'whatsapp',
                error_text: 'WhatsApp',
                state: summarizePageState(document, location),
              };
            }
            await submitNearestForm(inputNode);
            await waitFor(
              () => collectCodeInputs().length || phoneErrorNode() || whatsappDeliveryOnly(),
              30000,
            );
            // Reaching the code-entry step means SMS delivery was accepted.
            if (collectCodeInputs().length) {
              break;
            }
            const submitError = phoneErrorNode();
            if (whatsappDeliveryOnly() || (submitError && WHATSAPP_KEYWORD.test(submitError))) {
              return {
                ok: true,
                channel_error: 'whatsapp',
                error_text: submitError || 'WhatsApp',
                state: summarizePageState(document, location),
              };
            }
            if (submitError) {
              // Any non-WhatsApp red error: caller treats the number as
              // occupied and re-acquires without inspecting the text.
              return {
                ok: true,
                channel_error: 'other',
                error_text: submitError,
                state: summarizePageState(document, location),
              };
            }
            break;
          }
          case 'finalize_and_get_callback': {
            const deadline = Date.now() + Math.max(30000, Number(input.timeout_ms) || 120000);
            // The final onboarding step (/about-you) requires a full name + age
            // and will NOT submit until both fields are valid — a bare click on
            // "完成帐户创建" is a silent no-op, so without filling them first the
            // loop below just spins until timeout. Fill once when the page shows.
            let aboutYouFilled = false;
            const fillAboutYou = async () => {
              const nameInput = firstNode('input[name="name"], input[autocomplete="name"], input[id$="-name"]');
              const ageInput = firstNode('input[name="age"], input[id$="-age"], input[type="number"][inputmode="numeric"]');
              const birthdayHidden = firstNode('input[type="hidden"][name="birthday"]');
              if (!nameInput && !ageInput && !birthdayHidden) {
                return false;
              }
              if (nameInput && !String(nameInput.value || '').trim()) {
                await trustedFill(nameInput, String(input.full_name || 'Alex Morgan'));
              }
              if (ageInput && !String(ageInput.value || '').trim()) {
                await trustedFill(ageInput, String(input.age || 27));
              } else if (birthdayHidden && !String(birthdayHidden.value || '').trim()) {
                // Birthday variant: derive a plausible birthday from age.
                const age = Number(input.age) || 27;
                const today = new Date();
                const birthYear = today.getFullYear() - age;
                const birthMonth = 1 + Math.floor(Math.random() * 12);
                const birthDay = 1 + Math.floor(Math.random() * 28);
                const monthStr = String(birthMonth).padStart(2, '0');
                const dayStr = String(birthDay).padStart(2, '0');
                const yearStr = String(birthYear);
                const spinbuttons = visibleNodes('div[role="spinbutton"][contenteditable="true"]');
                if (spinbuttons.length >= 3) {
                  await trustedFill(spinbuttons[0], monthStr);
                  await trustedFill(spinbuttons[1], dayStr);
                  await trustedFill(spinbuttons[2], yearStr);
                }
              }
              return true;
            };
            const submittedPages = new Set();
            while (Date.now() < deadline) {
              const currentUrl = String(location.href || '');
              if (currentUrl.startsWith('http://localhost:1455/auth/callback')) {
                return { ok: true, callback_url: currentUrl, state: summarizePageState(document, location), error_text: visibleError() };
              }
              const link = visibleNodes('a[href^="http://localhost:1455/auth/callback"], a[href*="/auth/callback?code="]')[0];
              if (link?.href) {
                return { ok: true, callback_url: String(link.href), state: summarizePageState(document, location), error_text: visibleError() };
              }
              if (currentUrl.toLowerCase().includes('/about-you')) {
                const hadFields = await fillAboutYou();
                if (hadFields && !aboutYouFilled) {
                  aboutYouFilled = true;
                  await sleep(400);
                }
              }
              // CRITICAL: the consent page's verifier is SINGLE-USE. Clicking
              // "继续" submits it and redirects to the callback with a code, but a
              // second click re-submits the spent verifier and the callback comes
              // back as access_denied "consent verifier already used". So submit
              // each page URL at most once, then wait for the redirect instead of
              // spamming the button every 500ms.
              const pageKey = currentUrl.split('#')[0];
              if (submittedPages.has(pageKey)) {
                await sleep(700);
                continue;
              }
              // Prefer an explicit primary "继续 / Continue / Allow / Authorize"
              // action (the consent page at /sign-in-with-chatgpt/codex/consent
              // needs this button clicked to redirect to the callback). Fall back
              // to the form's submit control, then any first control.
              const PRIMARY_RE = /^(continue|allow|authorize|accept|agree|next|继续|允许|授权|同意|完成)/i;
              const primaryAction = formControls(document).find((node) => {
                const label = String(node?.innerText || node?.textContent || node?.value || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
                return PRIMARY_RE.test(label);
              });
              const button = primaryAction || formSubmitControl(firstNode('form')) || formControls(document)[0];
              if (button) {
                submittedPages.add(pageKey);
                await trustedClick(button);
                // Give the redirect time to land before doing anything else, so
                // we never re-click a page mid-navigation.
                await waitFor(
                  () => String(location.href || '') !== currentUrl
                    || String(location.href || '').startsWith('http://localhost:1455/auth/callback'),
                  6000,
                );
              } else {
                await sleep(500);
              }
            }
            return { ok: false, error: '等待回调超时', state: summarizePageState(document, location), snapshot: buildDebugSnapshot(), error_text: visibleError() };
          }
          case 'dismiss_blocking_dialog': {
            const dismissed = await dismissBlockingDialog(Number(input?.wait_ms) || 0);
            return {
              ok: true,
              dismissed: dismissed > 0,
              dismissed_count: dismissed,
              still_blocked: !!nativeBlockingDialog(),
              blocking_label: blockingDialogLabel(),
              state: summarizePageState(document, location),
            };
          }
          case 'open_mfa_enroll': {
            // chatgpt.com/#settings/Security → 「Security and login」→ 打开
            // 「Authenticator app」。testid 都是稳定的（快照 …-030356）。
            // 排除原生 <dialog>：注册后的欢迎弹层不是设置弹窗，别把它当成"设置已打开"。
            const settingsDialog = () => visibleNodes('[role="dialog"]')
              .find((node) => node.tagName !== 'DIALOG') || null;
            const securityTab = () => firstNode('[data-testid="security-tab"]')
              || visibleNodes('button, [role="tab"]').find((node) => {
                const label = String(node?.innerText || node?.textContent || '').replace(/\s+/g, ' ').trim();
                return /^(security and login|安全(与|和)登录|安全和登录)$/i.test(label);
              }) || null;
            const authenticatorToggle = () => firstNode('[data-testid="mfa-authenticator-toggle"]')
              || visibleNodes('button, [role="switch"], [role="button"]').find((node) => {
                const label = String(node?.innerText || node?.textContent || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
                return /authenticator app|验证器(应用|App)?|身份验证器/i.test(label);
              }) || null;
            const enrollDialog = () => firstNode('[aria-labelledby="enroll-totp-modal-title"]')
              || (firstNode('#totp_otp') ? settingsDialog() : null);
            // 挑战：页面被带离 chatgpt.com（去 auth.openai.com 重新验证身份）。
            const onChallenge = () => !/^https?:\/\/([^/]*\.)?chatgpt\.com/i.test(currentUrl());

            // 先清掉挡路的原生弹层（"You're all set"）：它 showModal() 打开，会把
            // 页面其余部分置为 inert，不关掉下面每一次点击都点空。**必须等它出现**
            // ——我们刚导航过来是整页刷新，弹层在 load 之后才画出来，进来看一眼就
            // 走等于没看（血的教训：全程点空，最后报成"没弹出 MFA 弹窗"）。
            // 之后每次点击前都再清一遍：路由切换、挑战验证回来都可能让它再弹。
            const blocked = () => !!nativeBlockingDialog();
            const unblock = async (waitMs = 0) => {
              try {
                return await dismissBlockingDialog(waitMs);
              } catch (_e) {
                return 0;
              }
            };
            await unblock(8000);
            // chrome.tabs.update 到只差 hash 的地址不一定能让 SPA 路由响应——实测
            // 落回 https://chatgpt.com/（hash 都没了），设置弹窗根本没开。所以先在
            // 页内把 hash 设上：这是导航，不是伪造用户手势，不违反可信操作的约束。
            const routeToSettings = async () => {
              try {
                // 已经是 #settings 却没渲染时，先清掉再设，否则同值赋值不触发路由。
                if (/#settings/i.test(currentUrl())) {
                  location.hash = '';
                }
                location.hash = '#settings/Security';
              } catch (_e) {}
              return waitFor(() => settingsDialog() || /#settings/i.test(currentUrl()), 8000);
            };
            if (!settingsDialog() && !onChallenge() && !/#settings/i.test(currentUrl())) {
              await routeToSettings();
            }
            let ready = await waitFor(() => settingsDialog() || enrollDialog() || onChallenge(), 30000);
            if (!ready && blocked()) {
              // 等待期间才弹出来的欢迎弹层：点掉、重走一次路由再等，别直接判死。
              await unblock(0);
              await routeToSettings();
              ready = await waitFor(() => settingsDialog() || enrollDialog() || onChallenge(), 20000);
            }
            if (!ready) {
              throw unknownPageError(
                blocked()
                  ? `欢迎弹层「${blockingDialogLabel()}」未能关闭，整页被 inert，打不开设置（${currentUrl().slice(0, 120)}）`
                  : `未能打开设置弹窗（${currentUrl().slice(0, 120)}）`,
              );
            }
            if (!enrollDialog() && !onChallenge()) {
              const tab = await waitFor(() => securityTab(), 15000);
              if (tab) {
                await unblock();
                // 点不中要报出来，别把"没点中"混成"页面上没这个开关"。
                if (!await trustedClick(securityTab() || tab)) {
                  throw unknownPageError('「Security and login」点击未生效（坐标落空或被遮挡）');
                }
              }
              const toggle = await waitFor(() => authenticatorToggle() || enrollDialog() || onChallenge(), 20000);
              if (!toggle) {
                if (blocked()) {
                  throw unknownPageError(`欢迎弹层「${blockingDialogLabel()}」未能关闭，整页被 inert，看不到设置项（${currentUrl().slice(0, 80)}）`);
                }
                // 把页面上真实存在的控件带回去，否则只看到"没找到开关"无从下手。
                throw unknownPageError(
                  `设置页里没有找到「Authenticator app」开关（${currentUrl().slice(0, 80)}）`
                  + `，当前可见按钮：${summarizePageState(document, location).buttons.map((item) => item.text).filter(Boolean).slice(0, 10).join(' | ').slice(0, 240)}`,
                );
              }
              if (!enrollDialog() && !onChallenge()) {
                await unblock();
                const target = authenticatorToggle();
                if (target && !await trustedClick(target)) {
                  throw unknownPageError('「Authenticator app」点击未生效（坐标落空或被遮挡）');
                }
              }
            }
            const stage = await waitFor(() => {
              if (enrollDialog()) return 'dialog';
              if (onChallenge()) return 'challenge';
              if (visibleError()) return 'error';
              return '';
            }, 30000);
            if (!stage) {
              // 弹层还在 = 刚才那一串点击全是点在 inert 页面上，如实报出来，
              // 别再拿"没弹出 MFA 弹窗"糊弄——那句话把真因藏了整整一轮。
              if (blocked()) {
                throw unknownPageError(`欢迎弹层「${blockingDialogLabel()}」未能关闭，整页被 inert，点击全部落空（${currentUrl().slice(0, 120)}）`);
              }
              throw unknownPageError(`点击「Authenticator app」后既没弹出 MFA 弹窗也没进入验证（${currentUrl().slice(0, 120)}）`);
            }
            return {
              ok: true,
              next_stage: stage,
              url: currentUrl(),
              state: summarizePageState(document, location),
              error_text: stage === 'error' ? visibleError() : '',
            };
          }
          case 'mfa_password_challenge': {
            // 开启 MFA 时 OpenAI 可能要求重新验证身份：先落到 /email-verification，
            // 底部「Continue with password」→ /log-in/password，用刚生成的密码验证。
            // 注意这里要的**正是** /log-in/password（我们拥有这个账号的密码），
            // 和注册阶段"绝不能走登录密码页"是相反的诉求。
            const passwordSwitch = () => visibleNodes('a[href*="/log-in/password"]')[0]
              || visibleNodes('a, button, [role="button"]').find((node) => {
                const label = String(node?.innerText || node?.textContent || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
                return /^(continue with password|use password instead|使用密码(登录|继续|验证)?|改用密码)/i.test(label);
              }) || null;
            const passwordBox = () => firstNode('input[type="password"], input[autocomplete="current-password"], input[name="current-password"], input[name="password"]');
            if (!passwordBox() && passwordSwitch()) {
              await trustedClick(passwordSwitch());
            }
            const box = await waitFor(() => passwordBox(), 30000);
            if (!box) {
              throw unknownPageError(`验证挑战页上没有密码输入框（${currentUrl().slice(0, 120)}）`);
            }
            await trustedFill(box, input.password);
            // 同样别把作用域钉死在 closestForm 上：OpenAI 的弹窗/表单经常把提交
            // 按钮放在 form 外面（MFA 的 Verify 就是这样）。先在 form 里找，找不到
            // 再退到整个文档。
            const challengeSubmit = () => {
              const SUBMIT_RE = /^(continue|next|submit|log ?in|sign ?in|继续|下一步|确定|登录)$/i;
              const inForm = formControls(closestForm(box) || document).find((node) => {
                const label = String(node?.innerText || node?.textContent || node?.value || '').replace(/\s+/g, ' ').trim();
                return SUBMIT_RE.test(label);
              });
              if (inForm) return inForm;
              return formControls(document).find((node) => {
                const label = String(node?.innerText || node?.textContent || node?.value || '').replace(/\s+/g, ' ').trim();
                return SUBMIT_RE.test(label);
              }) || formSubmitControl(closestForm(box) || firstNode('form')) || null;
            };
            const submit = challengeSubmit();
            if (submit) {
              if (!await trustedClick(submit)) {
                await trustedKey('Enter', box);
              }
            } else {
              await trustedKey('Enter', box);
            }
            const stage = await waitFor(() => {
              if (/^https?:\/\/([^/]*\.)?chatgpt\.com/i.test(currentUrl())) return 'chatgpt';
              if (visibleError()) return 'error';
              if (pageLevelError()) return 'error';
              return '';
            }, 40000);
            return {
              ok: true,
              next_stage: stage || '',
              url: currentUrl(),
              state: summarizePageState(document, location),
              error_text: visibleError() || pageLevelError(),
            };
          }
          case 'mfa_reveal_secret': {
            // 弹窗默认显示二维码；「Trouble scanning?」才把 Base32 密钥显示出来
            // （快照 …-035428：div[role=button][aria-label="Copy code"]）。
            // 这串密钥 OpenAI **只显示这一次**，所以这一步要往死里试：点 → 等 →
            // 再点，最多 3 轮（以前点成功一次就 break，等于只试了一次）；仍然读不到
            // 就把 otpauth:// 和二维码线索一起带回去，由 Python 解码或转人工。
            // read_only：只读不点，给"人工介入"时轮询用，免得和人抢着点。
            const readOnly = !!input?.read_only;
            const BASE32_RE = /^[A-Z2-7]{16,64}$/;
            const enrollScope = () => firstNode('[aria-labelledby="enroll-totp-modal-title"]')
              || document.querySelector('#totp_otp')?.closest('[role="dialog"]')
              || firstNode('[role="dialog"]')
              || document.body;
            const normalizeSecret = (value) => String(value || '').replace(/[\s-]+/g, '').trim().toUpperCase();
            // 必须含 2-7 里的数字：Base32 字母表就是 A-Z2-7，只判字母的话
            // "AUTHENTICATORAPP" 这种纯文本长串也会命中。
            const looksLikeSecret = (value) => {
              const text = normalizeSecret(value);
              return BASE32_RE.test(text) && /[2-7]/.test(text) ? text : '';
            };
            const troubleButton = () => visibleNodes('button, [role="button"], a').find((node) => {
              const label = String(node?.innerText || node?.textContent || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              return /^(trouble scanning\??|can'?t scan|cannot scan|enter (the )?code manually|无法扫描|扫描不了|手动输入)/i.test(label);
            }) || null;
            const secretNode = () => {
              const box = enrollScope();
              // 先认明确的控件，再退到"扫弹窗里的叶子节点"——OpenAI 换了 class 名
              // 也不至于整步失败。
              const preferred = Array.from(box.querySelectorAll(
                '[role="button"][aria-label="Copy code" i], [title="Copy code" i],'
                + ' [data-testid*="secret" i], [data-testid*="copy" i], code, pre, .font-mono,'
                + ' input[readonly], textarea[readonly]',
              ));
              for (const node of preferred) {
                const hit = looksLikeSecret(node.value ?? (node.innerText || node.textContent))
                  || looksLikeSecret(node.getAttribute?.('aria-label'))
                  || looksLikeSecret(node.getAttribute?.('data-clipboard-text'));
                if (hit) return hit;
              }
              for (const node of Array.from(box.querySelectorAll('*'))) {
                if (node.children.length) continue;
                const hit = looksLikeSecret(node.innerText || node.textContent);
                if (hit) return hit;
              }
              return '';
            };
            // 二维码里编的就是 otpauth://totp/...?secret=XXXX。DOM 里直接有就不用
            // 解图了；React 把它当 prop 传给二维码组件时 DOM 上看不到，翻一下 props。
            const otpauthUri = () => {
              const box = enrollScope();
              const direct = String(box.innerHTML || '').match(/otpauth:\/\/totp\/[^\s"'<>\\]+/i);
              if (direct) return direct[0].replace(/&amp;/gi, '&');
              for (const node of Array.from(box.querySelectorAll('img, canvas, svg, div'))) {
                for (const key of Object.keys(node)) {
                  if (!/^__reactProps|^__reactFiber/.test(key)) continue;
                  try {
                    const props = node[key]?.memoizedProps ?? node[key];
                    const found = JSON.stringify(props).match(/otpauth:\/\/totp\/[^\s"'\\]+/i);
                    if (found) return found[0];
                  } catch (_e) {}
                }
              }
              return '';
            };
            const report = (secret) => ({
              ok: true,
              secret,
              otpauth: secret ? '' : otpauthUri(),
              has_qr: !!enrollScope().querySelector('canvas, svg, img'),
              read_only: readOnly,
              state: summarizePageState(document, location),
            });

            let secret = secretNode();
            if (!secret && !readOnly) {
              const trouble = await waitFor(() => troubleButton() || secretNode(), 20000);
              if (!trouble) {
                // 入口都没有：把 otpauth/二维码线索带回去，让上层去解码或转人工，
                // 别直接抛错把账号判成"2FA 开不了"。
                return report('');
              }
              // 点不中要报出来（踩坑 #22）；但"点中了却没出密钥"也要**继续重试**，
              // 以前点成功一次就 break，等于只试了一次。
              for (let attempt = 1; attempt <= 3 && !secret; attempt += 1) {
                const button = troubleButton();
                if (!button) break;
                let clicked = false;
                try {
                  clicked = await trustedClick(button);
                } catch (_e) {
                  clicked = false;
                }
                await waitFor(() => secretNode(), clicked ? 8000 : 2000);
                secret = secretNode();
                if (!secret) await sleep(600);
              }
            }
            if (!secret) {
              secret = secretNode();
            }
            return report(secret);
          }
          case 'mfa_submit_code': {
            const codeBox = await waitFor(() => firstNode('#totp_otp, input[name="totp"], input[name="totp_otp"], input[autocomplete="one-time-code"]'), 20000);
            if (!codeBox) {
              throw unknownPageError('MFA 弹窗里没有找到验证码输入框');
            }
            await trustedFill(codeBox, input.code);
            // 「Verify」在 <form> **外面**的弹窗 footer 里（HTML 实证：</form> 早于
            // 该按钮闭合），所以绝不能按 closestForm(codeBox) 的作用域去找——那样
            // 永远找不到。按整个弹窗（拿不到就整个文档）找，并且**每次都重新查**：
            // 6 位没填满前按钮是 disabled，会被 isVisible 过滤掉。
            const VERIFY_RE = /^(verify|confirm|continue|submit|验证|确认|确定|提交)$/i;
            const enrollDialog = () => firstNode('[aria-labelledby="enroll-totp-modal-title"]')
              || codeBox.closest?.('[role="dialog"]')
              || null;
            const verifyButton = () => formControls(enrollDialog() || document).find((node) => {
              const label = String(node?.innerText || node?.textContent || node?.value || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              return VERIFY_RE.test(label);
            }) || null;
            const found = await waitFor(() => verifyButton(), 15000);
            if (!found) {
              throw unknownPageError(
                'MFA 弹窗里没有找到「Verify」按钮，当前可见按钮：'
                + formControls(enrollDialog() || document)
                  .map((node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim())
                  .filter(Boolean).slice(0, 10).join(' | ').slice(0, 200),
              );
            }
            // 点不中要重试并报出来，别把"没点中"混成"验证码不对"。
            let clicked = false;
            for (let attempt = 1; attempt <= 3 && !clicked; attempt += 1) {
              const button = verifyButton();
              if (!button) break;
              clicked = await trustedClick(button);
              if (!clicked) await sleep(400);
            }
            if (!clicked) {
              throw unknownPageError('「Verify」按钮点击未生效（坐标落空或被遮挡）');
            }
            // 成功的唯一判据：验证码弹层消失。
            // 绝不能拿 visibleError() 当判据——成功后 OpenAI 会在 [role=alert] /
            // [aria-live] 区域弹一句「Authenticator app enabled」，那是**成功提示**，
            // 被当成错误就会把一个已经开好的 2FA 误报成"验证码未通过"。
            const codeStillThere = () => !!firstNode('#totp_otp, input[name="totp"], input[name="totp_otp"]');
            const stage = await waitFor(() => {
              if (!codeStillThere()) return 'done';
              // 弹层还在时才看错误——这时的报错才是真的没通过。
              if (visibleError()) return 'error';
              return '';
            }, 30000);
            const stillOpen = codeStillThere();
            return {
              ok: true,
              next_stage: stage || '',
              verified: !stillOpen,
              state: summarizePageState(document, location),
              // 只有弹层还在（= 真没过）时才回报错误文本。
              error_text: stillOpen ? visibleError() : '',
            };
          }
          case 'click_signup_link': {
            // /log-in/password carries `Don't have an account? <a
            // href="/create-account">Sign up</a>` (snapshot 1038377682-...-175759).
            // Clicking it is the way back into the SIGNUP flow — far better than
            // declaring the account dead. Note the sibling "Log in" link on
            // /create-account/password points the other way, so match on the
            // href, not just the label.
            const signupLink = () => visibleNodes('a[href], button, [role="button"]').find((node) => {
              const href = String(node?.getAttribute?.('href') || '');
              const label = String(node?.innerText || node?.textContent || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              if (/\/log-in/i.test(href)) return false;
              return /\/create-account(\?|$|#)/i.test(href) || /^(sign\s?up|注册|免费注册)$/i.test(label);
            }) || null;
            await waitFor(() => signupLink() || pageLevelError(), 12000);
            const link = signupLink();
            if (!link) {
              return {
                ok: true,
                next_stage: '',
                signup_link_missing: true,
                state: summarizePageState(document, location),
                error_text: pageLevelError(),
              };
            }
            await trustedClick(link);
            const hasEmailBox = () => !!firstNode('input[type="email"], input[autocomplete="username"], input[name="username"], input[name="email"], input[id*="email" i]');
            const stage = await waitFor(() => {
              const href = currentUrl().toLowerCase();
              if (href.includes('/create-account/password')) return 'create-account-password';
              // The signup email form — what we actually want.
              if (href.includes('/create-account')) return hasEmailBox() ? 'create-account' : '';
              if (href.includes('/email-verification')) return 'otp';
              if (pageLevelError()) return 'error';
              return '';
            }, 30000);
            if (!stage) {
              throw unknownPageError(`点击「Sign up」后没有落到注册页（${currentUrl().slice(0, 120)}）`);
            }
            return {
              ok: true,
              next_stage: stage,
              state: summarizePageState(document, location),
              error_text: visibleError() || pageLevelError(),
            };
          }
          case 'probe_plus_offer': {
            // Read-only: does chatgpt.com/#pricing offer this fresh account the
            // 1-month Plus trial? Snapshot evidence (1038377914-20260811-172955)
            // shows it as a HEADING — "Try Plus free for 1 month" — next to the
            // "LIMITED TIME" plan card. Nothing here clicks anything.
            const OFFER_RE = /try\s+plus\s+free\s+for\s+1\s+month|免费试用\s*plus\s*1\s*个月|plus\s+免费\s*1\s*个月/i;
            const headingTexts = () => Array.from(document.querySelectorAll('h1, h2, h3, h4'))
              .filter(isVisible)
              .map((node) => String(node.innerText || node.textContent || '').replace(/\s+/g, ' ').trim())
              .filter(Boolean);
            // The pricing view is rendered by the SPA after the hash change, so
            // wait for the plan cards before deciding "no offer" — answering too
            // early would mark every account ineligible.
            const priced = await waitFor(() => {
              const text = previewText();
              if (OFFER_RE.test(text) || headingTexts().some((item) => OFFER_RE.test(item))) return 'offer';
              // Plan page is up but without the trial banner.
              if (/chatgpt plus|your current plan|当前方案|升级方案/i.test(text)) return 'priced';
              return '';
            }, 30000);
            const headings = headingTexts();
            const matched = headings.find((item) => OFFER_RE.test(item)) || '';
            const eligible = priced === 'offer' || !!matched;
            return {
              ok: true,
              // null (not false) when the pricing page never rendered — the
              // caller must be able to tell "no offer" from "could not check".
              plus_trial: priced ? eligible : null,
              pricing_rendered: !!priced,
              matched_text: matched.slice(0, 120),
              url: currentUrl(),
              headings: headings.slice(0, 12),
            };
          }
          case 'probe_stage': {
            // Side-effect-free: wait for the page to settle into either the phone
            // entry step OR a step that is already PAST phone, so the caller only
            // acquires an SMS number when OpenAI actually asks for a phone. An
            // already-verified account re-doing OAuth skips phone entirely and
            // lands on the consent/authorize page or the callback URL directly.
            const isCallback = () => String(location.href || '').startsWith('http://localhost:1455/auth/callback');
            const authorizeControl = () => firstNode('button[name="intent"][value*="authorize" i], button[name="intent"][value*="allow" i], a[href*="/auth/callback?code="]');
            const isConsentUrl = () => {
              const href = currentUrl().toLowerCase();
              return href.includes('/consent') || href.includes('/sign-in-with-chatgpt') || href.includes('/oauth/authorize');
            };
            const resolved = await waitFor(() => {
              if (isCallback()) return 'callback';
              if (phoneInput()) return 'phone';
              const href = currentUrl().toLowerCase();
              if (href.includes('/about-you')) return 'about-you';
              if (isConsentUrl() || authorizeControl()) return 'authorize';
              if (collectCodeInputs().length) return 'code';
              return '';
            }, Math.max(5000, Number(input.timeout_ms) || 20000));
            return {
              ok: true,
              stage: resolved || 'unknown',
              has_phone_input: !!phoneInput(),
              state: summarizePageState(document, location),
              error_text: visibleError(),
            };
          }
          case 'snapshot_dom':
            return {
              ok: true,
              state: summarizePageState(document, location),
              snapshot: {
                url: currentUrl(),
                title: String(document.title || ''),
                body_text: String(document.body?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 4000),
                body_html: String(document.body?.innerHTML || '').replace(/\s+/g, ' ').trim().slice(0, 12000),
              },
              error_text: visibleError(),
            };
          default:
            throw new Error(`不支持的页面动作: ${action}`);
        }
        return {
          ok: true,
          state: summarizePageState(document, location),
          used_signup_password: usedSignupPassword,
          error_text: visibleError(),
        };
      } catch (error) {
        return {
          ok: false,
          error: String(error?.message || error || '页面动作失败'),
          unknown_page: !!error?.__unknownPage,
          state: summarizePageState(document, location),
          snapshot: buildDebugSnapshot(),
          used_signup_password: usedSignupPassword,
          error_text: visibleError(),
        };
      }
    },
    [step],
  );
    if (result && typeof result === 'object') {
      return result;
    }
    // A null executeScript result means the injected frame vanished mid-run.
    // For finalize that is the forward-navigation teardown — recover or retry.
    if (isFinalize) {
      const recovered = await recoverFinalizeCallback(tab.id);
      if (recovered) {
        return recovered;
      }
      if (Date.now() >= finalizeDeadline) {
        return { ok: false, error: '收尾流程等待回调超时' };
      }
      continue;
    }
    return { ok: false, error: '页面动作返回空结果' };
  } catch (error) {
    const message = getErrorMessage(error);
    const frameRemoved = /Frame with ID \d+ was removed|No frame with id/i.test(message);
    if (frameRemoved && isFinalize) {
      // Same forward-navigation teardown, thrown instead of returning null.
      const recovered = await recoverFinalizeCallback(tab.id);
      if (recovered) {
        return recovered;
      }
      if (Date.now() >= finalizeDeadline) {
        return { ok: false, error: '收尾流程等待回调超时' };
      }
      continue;
    }
    if (frameRemoved && ['submit_email_otp', 'submit_signup_password'].includes(action)) {
      await delay(1200);
      const inspected = await inspectAuthFlowStage(tab.id).catch(() => null);
      if (inspected?.ok) {
        return {
          ok: true,
          next_stage: String(inspected.stage || ''),
          state: inspected.state || null,
          snapshot: inspected.snapshot || null,
          error_text: inspected.error_text || '',
        };
      }
    }
    throw error;
  }
  }
}

async function performBridgeRequest(request) {
  const kind = String(request?.kind || '');
  const payload = request?.payload && typeof request.payload === 'object' ? request.payload : {};
  switch (kind) {
    case 'navigate':
      return navigateActiveTab(payload);
    case 'reload':
      return reloadTargetTab(payload);
    case 'tab_url':
      // Cheap, injection-free URL read used to watch the gcash payment tab.
      return readTabUrl(payload);
    case 'cleanup':
      // Worker-driven, synchronous browser wipe before an account starts, so a
      // serial pipeline never carries the previous account's cookies/session
      // into the next (which makes OpenAI show /choose-an-account).
      return cleanupBrowserState(payload.origins, payload);
    case 'proxy_apply':
      // One proxy per account, chosen by the scheduler's round-robin. Applies
      // browser-wide (address bar, fetch, XHR) until the next account swaps it.
      return applyProxyConfig(payload.proxy);
    case 'page_fetch':
      // Worker-driven in-page fetch (cookies included) — e.g. read
      // chatgpt.com/api/auth/session with the just-logged-in session.
      return runPageFetch(payload);
    case 'page_action':
      if (String(payload.action || '') === 'snapshot_dom') {
        return captureDomSnapshot(payload);
      }
      if (String(payload.action || '').startsWith('gcash_')) {
        return runGcashAction(payload);
      }
      if (String(payload.action || '') === 'activate_passwordless_signup') {
        return activatePasswordlessSignupWithCdp();
      }
      if (String(payload.action || '') === 'mfa_capture_qr') {
        return captureMfaQr(payload);
      }
      return executePageStep(payload);
    default:
      return { ok: false, error: `未知桥接请求类型: ${kind}` };
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    setBoundWindowId(message?.windowId);
    switch (message?.type) {
      case 'cleanup-browser-state':
        {
          const result = await cleanupBrowserState(message.origins);
          sendResponse(result && typeof result === 'object' ? result : { ok: false, error: '扩展后台返回空结果' });
        }
        return;
      case 'run-page-request':
        {
          const result = await runPageFetch(message.request || {});
          sendResponse(result && typeof result === 'object' ? result : { ok: false, error: '扩展后台返回空结果' });
        }
        return;
      case 'perform-bridge-request':
        {
          const result = await performBridgeRequest(message.request || {});
          sendResponse(result && typeof result === 'object' ? result : { ok: false, error: '扩展后台返回空结果' });
        }
        return;
      case 'list-tabs':
        {
          const result = await listBrowserTabs();
          sendResponse(result && typeof result === 'object' ? result : { ok: false, error: '扩展后台返回空结果' });
        }
        return;
      case 'capture-tab-snapshot':
        {
          const result = await captureTabSnapshot(message.tabId);
          sendResponse(result && typeof result === 'object' ? result : { ok: false, error: '扩展后台返回空结果' });
        }
        return;
      case 'apply-proxy':
        {
          // Used by the 代理 page to turn the pool off immediately (and to
          // preview a proxy) without waiting for the next account to start.
          const result = await applyProxyConfig(message.proxy);
          sendResponse(result && typeof result === 'object' ? result : { ok: false, error: '扩展后台返回空结果' });
        }
        return;
      case 'get-active-proxy':
        {
          const proxy = await loadActiveProxy();
          sendResponse({ ok: true, proxy: proxy ? { id: proxy.id, label: proxy.label, scheme: proxy.scheme, country_code: proxy.country_code, timezone: proxy.timezone } : null });
        }
        return;
      case 'get-fingerprint':
        sendResponse({ ok: true, fingerprint: await fingerprintStatus() });
        return;
      case 'set-fingerprint':
        {
          // Applied browser-wide right here: every open tab gets the overrides
          // now, not at the next account.
          const result = await setFingerprintConfig(message.fingerprint);
          sendResponse({ ok: true, fingerprint: result });
        }
        return;
      case 'inspect-fingerprint':
        {
          // Read back what a page ACTUALLY sees, so "时区已对齐" is something the
          // operator can verify instead of take on trust.
          let tab = null;
          try {
            tab = await getActiveTab();
          } catch (error) {
            sendResponse({ ok: false, error: getErrorMessage(error) });
            return;
          }
          const seen = await executeInMainWorld(tab.id, () => {
            const offset = new Date().getTimezoneOffset();
            return {
              url: String(location.href || ''),
              timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
              timezone_offset_minutes: offset,
              date_string: new Date().toString(),
              language: navigator.language || '',
              languages: (navigator.languages || []).join(','),
              webdriver: !!navigator.webdriver,
            };
          }).catch((error) => ({ error: getErrorMessage(error) }));
          const proxy = await loadActiveProxy();
          sendResponse({
            ok: true,
            page: seen || {},
            fingerprint: await fingerprintStatus(),
            proxy: proxy ? { label: proxy.label, country_code: proxy.country_code, timezone: proxy.timezone } : null,
          });
        }
        return;
      default:
        sendResponse({ ok: false, error: '未知扩展消息类型' });
    }
  })().catch((error) => {
    sendResponse({ ok: false, error: String(error?.message || error || '扩展执行失败') });
  });
  return true;
});
