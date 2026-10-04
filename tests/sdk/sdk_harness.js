// Runs the real SDK file inside a minimal stubbed browser environment and prints a JSON report.
// Usage: node sdk_harness.js <path-to-sdk> <scenario>
const fs = require('fs');
const vm = require('vm');
const [sdkPath, scenario] = process.argv.slice(2);
const code = fs.readFileSync(sdkPath, 'utf8');

function makeEnv({ fetchImpl, key = 'wix_pk_testkey', storageBlocked = false, search = '?token=abc&x=1', attrs = {} }) {
  const listeners = {}, docListeners = {};
  const scriptEl = { getAttribute: (n) => ({ 'data-key': key, 'data-endpoint': 'https://api.test/v1/ingest', 'data-flush-ms': '999999', ...attrs })[n] ?? null };
  const mkStore = () => { if (storageBlocked) return { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };
    const m = {}; return { getItem: (k) => m[k] ?? null, setItem: (k, v) => { m[k] = v; } }; };
  const loc = { pathname: '/checkout', search, href: 'https://shop.example.com/checkout' + search };
  const history = { pushState(s, t, url) { loc.href = 'https://shop.example.com' + url; loc.pathname = url.split('?')[0]; loc.search = url.includes('?') ? '?' + url.split('?')[1] : ''; }, replaceState() {} };
  const sent = [];
  const win = {
    document: null, location: loc, history, navigator: { userAgent: 'TestUA/1.0', language: 'en-US', webdriver: false },
    innerWidth: 1000, innerHeight: 700, performance: { getEntriesByType: () => [{ loadEventEnd: 321 }] },
    crypto: { getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = (i * 7 + 3) % 256; return a; } },
    localStorage: mkStore(), sessionStorage: mkStore(),
    addEventListener: (t, f) => { (listeners[t] = listeners[t] || []).push(f); },
    fetch: (url, opts) => { sent.push({ url, opts }); return fetchImpl(url, opts); },
    console, Date, JSON, URL, Uint8Array, Math, Object,
  };
  const doc = { currentScript: scriptEl, referrer: 'https://www.google.com/search?q=secret', visibilityState: 'visible',
    querySelector: () => scriptEl, addEventListener: (t, f) => { (docListeners[t] = docListeners[t] || []).push(f); } };
  win.document = doc; win.window = win;
  win.setInterval = () => 1; win.setTimeout = () => 1;
  const ctx = vm.createContext({ ...win, window: win, document: doc, navigator: win.navigator, location: loc, history,
    performance: win.performance, setInterval: win.setInterval, setTimeout: win.setTimeout, URL, Uint8Array });
  return { ctx, win, doc, sent, listeners, docListeners };
}
const ok = () => Promise.resolve({ ok: true, status: 202 });
const run = (env) => vm.runInContext(code, env.ctx);
const bodies = (env) => env.sent.flatMap((s) => JSON.parse(s.opts.body).events);
const out = {};

if (scenario === 'happy') {
  const env = makeEnv({ fetchImpl: ok }); run(env);
  env.docListeners['click'].forEach((f) => { f(); f(); }); env.docListeners['keydown'].forEach((f) => f({ key: 'p' }));
  env.win.history.pushState({}, '', '/receipt?card=4111');
  env.win.WebIntelX.flush();
  out.sent = env.sent.length; out.headers = env.sent[0].opts.headers; out.credentials = env.sent[0].opts.credentials;
  out.events = bodies(env); out.api = Object.keys(env.win.WebIntelX);
} else if (scenario === 'include_query') {
  const env = makeEnv({ fetchImpl: ok, attrs: { 'data-include-query': 'true' } }); run(env); env.win.WebIntelX.flush();
  out.events = bodies(env);
} else if (scenario === 'fetch_rejects') {
  const env = makeEnv({ fetchImpl: () => Promise.reject(new Error('offline')) });
  let threw = false; try { run(env); env.win.WebIntelX.flush(); } catch (e) { threw = true; }
  out.threw = threw;
} else if (scenario === 'fetch_throws') {
  const env = makeEnv({ fetchImpl: () => { throw new Error('boom'); } });
  let threw = false; try { run(env); env.win.WebIntelX.flush(); env.win.WebIntelX.identify('x'); } catch (e) { threw = true; }
  out.threw = threw;
} else if (scenario === 'breaker') {
  const env = makeEnv({ fetchImpl: () => Promise.resolve({ ok: false, status: 500 }) }); run(env);
  (async () => {
    for (let i = 0; i < 8; i++) { env.win.WebIntelX.flush(); await new Promise((r) => setImmediate(r));
      env.win.history.pushState({}, '', '/p' + i); }
    out.sent = env.sent.length; console.log(JSON.stringify(out));
  })();
  return;
} else if (scenario === 'storage_blocked') {
  const env = makeEnv({ fetchImpl: ok, storageBlocked: true }); let threw = false;
  try { run(env); env.win.WebIntelX.flush(); } catch (e) { threw = true; }
  out.threw = threw; out.events = bodies(env);
} else if (scenario === 'placeholder_key') {
  const env = makeEnv({ fetchImpl: ok, key: 'YOUR_INGESTION_KEY' }); run(env);
  out.loaded = !!env.win.WebIntelX; out.sent = env.sent.length;
} else if (scenario === 'double_load') {
  const env = makeEnv({ fetchImpl: ok }); run(env); run(env); env.win.WebIntelX.flush(); out.events = bodies(env);
}
console.log(JSON.stringify(out));
