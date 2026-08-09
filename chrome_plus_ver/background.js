const DEFAULT_CLEANUP_ORIGINS = [
  'https://chatgpt.com',
  'https://auth.openai.com',
  'https://openai.com',
  'https://platform.openai.com',
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

async function getActiveTab() {
  // Prefer the active tab of the side panel's own window. Otherwise switching
  // focus to another window (e.g. a normal window while a run is driving an
  // incognito one) would hijack the active tab there. Fall back to the focused
  // window only when the bound window is gone or has no active tab.
  if (typeof boundWindowId === 'number') {
    const [pinned] = await chrome.tabs.query({ active: true, windowId: boundWindowId }).catch(() => []);
    if (pinned && typeof pinned.id === 'number') {
      return pinned;
    }
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || typeof tab.id !== 'number') {
    throw new Error('未找到当前活动标签页');
  }
  return tab;
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
  return tab;
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
  try {
    await chrome.debugger.attach(target, '1.3');
    attached = true;
  } catch (error) {
    const message = getErrorMessage(error);
    if (!/Another debugger is already attached/i.test(message)) {
      throw error;
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
    }
  }
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

async function removeCookiesForOrigins(origins) {
  const domains = [...new Set(origins.map((origin) => new URL(origin).hostname))];
  for (const domain of domains) {
    const cookies = await chrome.cookies.getAll({ domain });
    for (const cookie of cookies) {
      const scheme = cookie.secure ? 'https' : 'http';
      const host = cookie.domain.startsWith('.') ? cookie.domain.slice(1) : cookie.domain;
      const url = `${scheme}://${host}${cookie.path || '/'}`;
      try {
        await chrome.cookies.remove({ url, name: cookie.name, storeId: cookie.storeId });
      } catch {}
    }
  }
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
  return { ok: true, cleared_origins: cleanupOrigins };
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

async function navigateActiveTab(payload) {
  const tab = await resolveTargetTab(payload);
  await chrome.tabs.update(tab.id, { url: String(payload?.url || '') });
  const updated = await waitForTabComplete(tab.id);
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
      const isVisible = (node) => !!node && node.isConnected && !node.disabled && node.offsetParent !== null;
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
  const options = {
    bubbles: true, cancelable: true, composed: true, view: window,
    clientX: rect.left + rect.width / 2, clientY: rect.top + rect.height / 2, button: 0, buttons: 1,
  };
  button.dispatchEvent(new PointerEvent('pointerdown', options));
  button.dispatchEvent(new MouseEvent('mousedown', options));
  button.dispatchEvent(new PointerEvent('pointerup', options));
  button.dispatchEvent(new MouseEvent('mouseup', options));
  button.click();
  return { ok: true, token_length: value.length, url: String(location.href || '') };
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
  return { ...result, tab_url: String(tab.url || '') };
}

async function executePageStep(step) {
  const tab = await resolveTargetTab(step);
  const action = String(step?.action || '');
  const isFinalize = action === 'finalize_and_get_callback';
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
        const isVisible = (node) => !!node && node.isConnected && !node.disabled && node.offsetParent !== null;
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
      const isVisible = (node) => !!node && node.isConnected && !node.disabled && node.offsetParent !== null;
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
        node.scrollIntoView?.({ block: 'center', inline: 'center' });
        const rect = node.getBoundingClientRect?.();
        const centerX = rect ? rect.left + rect.width / 2 : 0;
        const centerY = rect ? rect.top + rect.height / 2 : 0;
        const target = document.elementFromPoint?.(centerX, centerY) || node;
        const options = {
          bubbles: true,
          cancelable: true,
          composed: true,
          view: window,
          clientX: centerX,
          clientY: centerY,
          button: 0,
          buttons: 1,
        };
        target.focus?.();
        ['pointerover', 'mouseover', 'pointerdown', 'mousedown'].forEach((type) => {
          target.dispatchEvent(new MouseEvent(type, options));
        });
        ['pointerup', 'mouseup', 'click'].forEach((type) => {
          target.dispatchEvent(new MouseEvent(type, options));
        });
        if (target !== node) {
          node.focus?.();
        }
        node.click?.();
        await sleep(200);
        return true;
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
          if (typeof form.requestSubmit === 'function') {
            form.requestSubmit();
            await sleep(200);
            return true;
          }
          form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
          await sleep(200);
          return true;
        }
        node?.focus?.();
        node?.dispatchEvent?.(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
        node?.dispatchEvent?.(new KeyboardEvent('keyup', { key: 'Enter', bubbles: true }));
        await sleep(200);
        return true;
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
      const isCreateAccountPasswordPage = () => {
        const text = previewText();
        const href = currentUrl().toLowerCase();
        return href.includes('/create-account/password') || (!!passwordInput() && /create account|password|创建|设置/.test(text.toLowerCase()));
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
        if (!fillValue(inputNode, signupPassword)) {
          throw unknownPageError('进入 create-account/password 但未找到密码输入框');
        }
        usedSignupPassword = true;
        await submitNearestForm(inputNode);
        await waitFor(
          () => phoneInput() || collectCodeInputs().length || visibleError() || String(location.href || '').startsWith('http://localhost:1455/auth/callback') || !isCreateAccountPasswordPage(),
          30000,
        );
      };
      const waitFor = async (predicate, timeoutMs = 30000) => {
        const deadline = Date.now() + timeoutMs;
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
          otpInputs.slice(0, digits.length).forEach((node, index) => fillValue(node, digits[index]));
        } else {
          const node = firstNode('input[inputmode="numeric"], input[autocomplete="one-time-code"], input[name*="code" i], input[id*="code" i], input[type="text"]');
          if (!fillValue(node, digits)) {
            throw unknownPageError('未找到验证码输入框');
          }
        }
        await submitNearestForm(otpInputs[0] || document.activeElement);
      };

        const action = String(input?.action || '');
        try {
        switch (action) {
          case 'submit_email': {
            // After a cookie wipe the page may show a "你的会话已结束 / session
            // ended" interstitial that has NO email form — only a "登录" link
            // (href .../auth/login_with or /log-in) that must be clicked to reach
            // the email-entry page. Click it first if present, then wait for the
            // email input to appear.
            const loginLink = () => visibleNodes('a[href*="/auth/login_with"], a[href*="/log-in"], a[data-dd-action-name*="Log in" i]').find((node) => {
              const label = String(node?.innerText || node?.textContent || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              return /登录|log ?in|sign ?in|继续|continue/i.test(label) || /login_with|log-in/i.test(String(node?.getAttribute?.('href') || ''));
            }) || null;
            const emailInput = () => firstNode('input[type="email"], input[autocomplete="username"], input[name="username"], input[name="email"], input[id*="email" i]');
            if (!emailInput() && loginLink()) {
              try {
                await trustedClick(loginLink());
                await waitFor(() => emailInput(), 20000);
              } catch (_e) {
                // The link may navigate cross-origin and tear down this frame;
                // if so the email form is loading in the new page — just wait.
                await waitFor(() => emailInput(), 20000);
              }
            }
            const inputNode = await waitFor(
              () => firstNode('input[type="email"], input[autocomplete="username"], input[name="username"], input[name="email"], input[id*="email" i]'),
              30000,
            );
            if (!fillValue(inputNode, input.email)) {
              throw unknownPageError('未找到邮箱输入框');
            }
            // CRITICAL: ChatGPT's welcome/login page puts the email field and the
            // social-login buttons ("继续使用 Google/Microsoft/Apple") in the same
            // form. submitNearestForm() clicks the FIRST submit control in that
            // form, which is often the Google button — the page then navigates to
            // Google's login and no OTP email is ever sent (looks like "OTP 超时").
            // Pick the email "继续/Continue" control explicitly and never a social
            // provider; fall back to Enter on the input.
            const SOCIAL_RE = /google|microsoft|apple|facebook|github|linkedin|okta|sso|saml|passkey|通行密钥|电话|手机号|谷歌|微软|苹果/i;
            const notSocial = (node) => {
              const label = String(node?.innerText || node?.textContent || node?.value || node?.getAttribute?.('aria-label') || '').replace(/\s+/g, ' ').trim();
              const href = String(node?.getAttribute?.('href') || '');
              const action = String(node?.getAttribute?.('data-dd-action-name') || '');
              const provider = String(node?.getAttribute?.('data-provider') || node?.getAttribute?.('name') || '');
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
              inputNode.focus?.();
              inputNode.dispatchEvent?.(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
              inputNode.dispatchEvent?.(new KeyboardEvent('keyup', { key: 'Enter', bubbles: true }));
              await sleep(300);
            }
            const nextStep = await waitFor(() => {
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
              if (firstNode('input[type="password"], input[autocomplete="current-password"], input[name="password"]')) return 'password';
              if (/verification|验证码|otp|one-time/i.test(previewText())) return 'otp';
              if (visibleError()) return 'error';
              return '';
            }, 30000);
            if (nextStep === 'social') {
              throw unknownPageError(`提交邮箱后被带到第三方登录页（${currentUrl().slice(0, 120)}），未发送邮箱验证码`);
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
            if (!fillValue(inputNode, input.password)) {
              throw unknownPageError('未找到密码输入框');
            }
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
            if (!fillValue(inputNode, input.phone_number)) {
              throw unknownPageError('未找到手机号输入框');
            }
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
            const fillAboutYou = () => {
              const nameInput = firstNode('input[name="name"], input[autocomplete="name"], input[id$="-name"]');
              const ageInput = firstNode('input[name="age"], input[id$="-age"], input[type="number"][inputmode="numeric"]');
              if (!nameInput && !ageInput) {
                return false;
              }
              if (nameInput && !String(nameInput.value || '').trim()) {
                fillValue(nameInput, String(input.full_name || 'Alex Morgan'));
              }
              if (ageInput && !String(ageInput.value || '').trim()) {
                fillValue(ageInput, String(input.age || 27));
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
                const hadFields = fillAboutYou();
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
    case 'tab_url':
      // Cheap, injection-free URL read used to watch the gcash payment tab.
      return readTabUrl(payload);
    case 'cleanup':
      // Worker-driven, synchronous browser wipe before an account starts, so a
      // serial pipeline never carries the previous account's cookies/session
      // into the next (which makes OpenAI show /choose-an-account).
      return cleanupBrowserState(payload.origins, payload);
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
      default:
        sendResponse({ ok: false, error: '未知扩展消息类型' });
    }
  })().catch((error) => {
    sendResponse({ ok: false, error: String(error?.message || error || '扩展执行失败') });
  });
  return true;
});
