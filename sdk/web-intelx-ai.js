/*! WebIntelX AI browser SDK v0.2.0
 *  Lightweight first-party telemetry collector.
 *  Design rules (PRD §10, §33, §35):
 *   - The data-key is a LIMITED-SCOPE ingestion identifier, never a high-privilege secret.
 *   - Never throws into the host page; every failure is swallowed (optional debug logging).
 *   - Minimal collection: no form values, no key contents, no element text, no cookies,
 *     no URL query string unless data-include-query="true" is set by the site owner.
 *   - Bounded queue + circuit breaker so a failing backend cannot degrade the site.
 */
(function () {
  'use strict';
  try {
    if (typeof window === 'undefined' || !window.document) return;
    if (window.WebIntelX && window.WebIntelX.__loaded) return;

    var script = document.currentScript ||
      document.querySelector('script[data-key][src*="web-intelx-ai"]');
    if (!script) return;
    var KEY = script.getAttribute('data-key');
    var ENDPOINT = script.getAttribute('data-endpoint');
    if (!KEY || !ENDPOINT || KEY === 'YOUR_INGESTION_KEY') return;

    var CFG = {
      debug: script.getAttribute('data-debug') === 'true',
      includeQuery: script.getAttribute('data-include-query') === 'true',
      flushMs: parseInt(script.getAttribute('data-flush-ms'), 10) || 5000,
      maxBatch: 20,
      maxQueue: 200,
      breakerFailures: 5,
      breakerPauseMs: 60000
    };

    function dbg() {
      if (CFG.debug && window.console) { try { console.debug.apply(console, ['[WebIntelX]'].concat([].slice.call(arguments))); } catch (e) {} }
    }
    function guard(fn) {
      return function () { try { return fn.apply(this, arguments); } catch (e) { dbg('error', e && e.message); } };
    }

    // ---- identifiers (storage may be blocked -> in-memory fallback) -------------------------
    function rand(n) {
      var out = '', chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
      try {
        var a = new Uint8Array(n); window.crypto.getRandomValues(a);
        for (var i = 0; i < n; i++) out += chars[a[i] % chars.length];
      } catch (e) { for (var j = 0; j < n; j++) out += chars[Math.floor(Math.random() * chars.length)]; }
      return out;
    }
    function store(kind, name, make) {
      var mem = store.mem || (store.mem = {});
      try {
        var s = window[kind]; var v = s.getItem(name);
        if (!v) { v = make(); s.setItem(name, v); }
        return v;
      } catch (e) { return mem[name] || (mem[name] = make()); }
    }
    var sessionId = store('sessionStorage', 'wix_sid', function () { return 's-' + rand(16); });
    var visitorId = store('localStorage', 'wix_vid', function () { return 'v-' + rand(16); });
    var userId = null; // set only if the site owner calls WebIntelX.identify() (authorized use)

    // ---- queue / transport -----------------------------------------------------------------
    var queue = [], failures = 0, pausedUntil = 0, timer = null;

    function enqueue(ev) {
      if (queue.length >= CFG.maxQueue) queue.shift();
      queue.push(ev);
      if (queue.length >= CFG.maxBatch) flush();
    }

    function flush() {
      if (!queue.length || Date.now() < pausedUntil) return;
      var batch = queue.splice(0, CFG.maxBatch);
      try {
        var p = window.fetch(ENDPOINT, {
          method: 'POST', mode: 'cors', credentials: 'omit', keepalive: true,
          headers: { 'Content-Type': 'application/json', 'X-WebIntelX-Key': KEY },
          body: JSON.stringify({ events: batch })
        });
        p.then(function (r) {
          if (r && r.ok) { failures = 0; return; }
          onFailure(r && r.status);
        }, function () { onFailure('network'); });
      } catch (e) { onFailure('exception'); }
    }
    function onFailure(why) {
      failures++;
      dbg('send failed', why);
      if (failures >= CFG.breakerFailures) { pausedUntil = Date.now() + CFG.breakerPauseMs; failures = 0; queue.length = 0; }
    }

    // ---- event builders --------------------------------------------------------------------
    function pathOf() {
      return window.location.pathname + (CFG.includeQuery ? window.location.search : '');
    }
    function base(type, extra) {
      var ev = {
        event_type: type, source: 'sdk', timestamp: new Date().toISOString(),
        session_id: sessionId, user_id: userId || visitorId,
        user_agent: (navigator.userAgent || '').slice(0, 512), attributes: {}
      };
      for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) ev[k] = extra[k];
      return ev;
    }
    function loadMs() {
      try {
        var nav = performance.getEntriesByType && performance.getEntriesByType('navigation')[0];
        if (nav && nav.loadEventEnd > 0) return Math.round(nav.loadEventEnd);
        if (performance.timing && performance.timing.loadEventEnd > 0)
          return performance.timing.loadEventEnd - performance.timing.navigationStart;
      } catch (e) {}
      return null;
    }
    function referrerHost() {
      try { return document.referrer ? new URL(document.referrer).hostname : null; } catch (e) { return null; }
    }

    var pageSeq = 0, pageStart = Date.now();
    var counters = { clicks: 0, key_events: 0, scroll_events: 0, mouse_moves: 0 };
    function resetCounters() { counters.clicks = counters.key_events = counters.scroll_events = counters.mouse_moves = 0; }

    var trackPageView = guard(function () {
      pageSeq++; pageStart = Date.now(); resetCounters();
      enqueue(base('page_view', {
        method: 'GET', endpoint: pathOf(),
        attributes: {
          page_seq: pageSeq, load_ms: loadMs(), referrer_host: referrerHost(),
          webdriver: !!navigator.webdriver, language: navigator.language || null,
          viewport: [window.innerWidth || 0, window.innerHeight || 0]
        }
      }));
    });

    // One aggregated, content-free interaction summary per page (counts only).
    var sendInteractionSummary = guard(function () {
      if (!pageSeq) return;
      enqueue(base('interaction', {
        attributes: {
          page_seq: pageSeq, clicks: counters.clicks, key_events: counters.key_events,
          scroll_events: counters.scroll_events, mouse_moves: counters.mouse_moves,
          dwell_ms: Date.now() - pageStart
        }
      }));
      resetCounters();
    });

    // ---- listeners (passive, count only) ---------------------------------------------------
    var opt = { passive: true, capture: true };
    document.addEventListener('click', guard(function () { counters.clicks++; }), opt);
    document.addEventListener('keydown', guard(function () { counters.key_events++; }), opt); // key identity never read
    document.addEventListener('scroll', guard(function () { counters.scroll_events++; }), opt);
    document.addEventListener('mousemove', guard(function () { counters.mouse_moves++; }), opt);

    var onHide = guard(function () { sendInteractionSummary(); flush(); });
    document.addEventListener('visibilitychange', guard(function () { if (document.visibilityState === 'hidden') onHide(); }));
    window.addEventListener('pagehide', onHide);

    // SPA navigation: wrap history methods defensively, always delegating to the originals.
    function onRouteChange() { sendInteractionSummary(); trackPageView(); }
    ['pushState', 'replaceState'].forEach(function (m) {
      try {
        var orig = window.history[m];
        window.history[m] = function () {
          var before = window.location.href;
          var out = orig.apply(this, arguments);
          if (window.location.href !== before) guard(onRouteChange)();
          return out;
        };
      } catch (e) {}
    });
    window.addEventListener('popstate', guard(onRouteChange));

    timer = setInterval(guard(flush), CFG.flushMs);

    // ---- public API ------------------------------------------------------------------------
    window.WebIntelX = {
      __loaded: true, version: '0.2.0',
      flush: guard(flush),
      // Only call with an identifier you are authorised to share (e.g. an internal account id, not an email).
      identify: guard(function (id) { userId = id ? String(id).slice(0, 128) : null; })
    };

    trackPageView();
    dbg('initialised');
  } catch (e) { /* never break the host page */ }
})();
