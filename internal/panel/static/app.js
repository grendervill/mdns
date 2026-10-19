/* mdns panel behaviour.
 *
 * Three small jobs, vanilla JS: the tooltip for the chart segments, the
 * live statistics poller and the live feed (EventSource). There is no
 * framework, so nothing here injects a <style> element or sets a style
 * attribute in HTML — the page's strict CSP ("default-src 'self'") holds.
 */
(function () {
  'use strict';

  /* ---- chart tooltip --------------------------------------------- */

  var tip = document.getElementById('tip');

  if (tip) {
    // Delegated on the document, not bound to the rings themselves: the
    // statistics poller below replaces the diagrams' nodes every couple
    // of seconds, and per-element listeners would die with them. A swap
    // therefore keeps hover and keyboard tooltips working.
    var ringAt = function (node) {
      if (!node || !node.closest) {
        return null;
      }
      return node.closest('.pie .ring');
    };

    // The text is built from text nodes, never from innerHTML: a
    // segment label is a query string (a domain, a client address).
    var showTip = function (ring, ev) {
      var label = ring.getAttribute('data-label');
      if (!label) {
        return;
      }
      var value = ring.getAttribute('data-value') || '';
      var hint = ring.getAttribute('data-click') ? ' — клик: история с фильтром' : '';

      tip.textContent = '';
      var name = document.createElement('b');
      name.textContent = label;
      tip.appendChild(name);
      tip.appendChild(document.createTextNode(' · ' + value + hint));

      tip.style.opacity = '1';
      if (ev) {
        tip.style.left = (ev.clientX + 14) + 'px';
        tip.style.top = (ev.clientY + 12) + 'px';
      } else {
        // Keyboard focus: anchor the tip to the segment.
        var box = ring.getBoundingClientRect();
        tip.style.left = box.left + 'px';
        tip.style.top = (box.top - 8) + 'px';
      }
    };
    var hideTip = function () {
      tip.style.opacity = '0';
    };

    document.addEventListener('mouseover', function (ev) {
      var ring = ringAt(ev.target);
      if (ring) {
        showTip(ring, ev);
      }
    });
    document.addEventListener('mousemove', function (ev) {
      var ring = ringAt(ev.target);
      if (ring) {
        showTip(ring, ev);
      }
    });
    document.addEventListener('mouseout', function (ev) {
      var ring = ringAt(ev.target);
      if (!ring) {
        return;
      }
      if (ev.relatedTarget && ev.relatedTarget.nodeType && ring.contains(ev.relatedTarget)) {
        return;
      }
      hideTip();
    });
    document.addEventListener('focusin', function (ev) {
      var ring = ringAt(ev.target);
      if (ring) {
        showTip(ring, null);
      }
    });
    document.addEventListener('focusout', function (ev) {
      if (ringAt(ev.target)) {
        hideTip();
      }
    });
  }

  /* ---- live statistics -------------------------------------------- */

  // The server renders the all-time gauges into #stats-gauges and the
  // period summary and diagrams into #stats-block, with the period form
  // between them so a poll never resets it. Poll the fragment with the
  // page's own query string, so the selected period carries over, and
  // swap both blocks. Hidden tabs do no work, requests never overlap and
  // a failure degrades quietly into the next tick.
  var STATS_INTERVAL = 2000;
  // A hung request would otherwise keep statsBusy set forever and stop
  // every later tick.
  var STATS_TIMEOUT = 5000;
  var statsBlock = document.getElementById('stats-block');
  var statsGauges = document.getElementById('stats-gauges');

  if (statsBlock && window.fetch) {
    var statsBusy = false;

    var refreshStats = function () {
      if (document.hidden || statsBusy) {
        return;
      }
      statsBusy = true;
      var ctrl = window.AbortController ? new AbortController() : null;
      var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, STATS_TIMEOUT) : null;

      fetch('/panel/stats' + window.location.search, {
        credentials: 'same-origin',
        cache: 'no-store',
        signal: ctrl ? ctrl.signal : undefined
      }).then(function (resp) {
        // A redirect means the session ended: keep the last good block
        // rather than swapping in the login page.
        if (!resp.ok || resp.redirected) {
          throw new Error('stats: request failed');
        }
        return resp.text();
      }).then(function (html) {
        var tmp = document.createElement('div');
        tmp.innerHTML = html;
        var gauges = tmp.querySelector('[data-stats="gauges"]');
        var range = tmp.querySelector('[data-stats="range"]');
        if (!gauges || !range) {
          return;
        }
        // The gauges contain no focusable elements, so they can always
        // refresh. The donuts carry links: replacing them under the
        // keyboard would drop focus mid-tab, so that part waits until
        // the focus has moved on.
        if (statsGauges) {
          statsGauges.innerHTML = gauges.innerHTML;
        }
        if (!statsBlock.contains(document.activeElement)) {
          statsBlock.innerHTML = range.innerHTML;
        }
      }).catch(function () {
        // Quiet on purpose: the next tick retries.
      }).finally(function () {
        if (timer) {
          clearTimeout(timer);
        }
        statsBusy = false;
      });
    };

    setInterval(refreshStats, STATS_INTERVAL);
  }

  /* ---- live feed -------------------------------------------------- */

  // FEED_MAX mirrors the server's feedSize (internal/panel/status.go):
  // the DOM holds the newest 30 rows, no matter how fast they arrive.
  var FEED_MAX = 30;

  var feed = document.getElementById('feed');
  if (!feed || !window.EventSource) {
    return;
  }

  var paused = false;
  var pauseBtn = document.getElementById('feed-pause');
  var clearBtn = document.getElementById('feed-clear');
  var feedState = document.getElementById('feed-state');

  var trim = function () {
    while (feed.children.length > FEED_MAX) {
      feed.removeChild(feed.lastElementChild);
    }
  };

  var dropPlaceholder = function () {
    var placeholder = feed.querySelector('.empty');
    if (placeholder) {
      feed.removeChild(placeholder);
    }
  };

  // The server sends one <div class="q">…</div> per new query; the
  // newest goes on top.
  var prependRow = function (html) {
    var tmp = document.createElement('div');
    tmp.innerHTML = html;
    var row = tmp.firstChild;
    if (!row) {
      return;
    }
    dropPlaceholder();
    feed.insertBefore(row, feed.firstChild);
    trim();
  };

  var replaceRows = function (html) {
    feed.innerHTML = html;
    trim();
  };

  // An empty snapshot means the server buffer has no queries. Replacing
  // the rows with "" would wipe the placeholder and leave the box blank,
  // so restore the same line the server renders into an empty feed.
  var showPlaceholder = function () {
    feed.textContent = '';
    var row = document.createElement('div');
    row.className = 'q empty';
    row.textContent = 'Пока нет запросов';
    feed.appendChild(row);
  };

  var es = new EventSource('/panel/events');
  es.addEventListener('open', function () {
    if (feedState) {
      feedState.hidden = true;
      feedState.textContent = '';
    }
  });
  es.addEventListener('error', function () {
    // EventSource retries on its own; until it does, say so plainly.
    // textContent keeps the CSP-safe promise (no innerHTML here).
    if (feedState) {
      feedState.textContent = 'соединение потеряно — обновите страницу';
      feedState.hidden = false;
    }
  });
  es.addEventListener('snapshot', function (ev) {
    if (!paused) {
      if (ev.data && ev.data.trim() !== '') {
        replaceRows(ev.data);
      } else {
        showPlaceholder();
      }
    }
  });
  es.addEventListener('row', function (ev) {
    if (!paused) {
      prependRow(ev.data);
    }
  });

  if (pauseBtn) {
    // Pausing freezes the view: rows that arrive while paused are
    // dropped here rather than queued. Nothing is lost on the server —
    // its buffer keeps the newest 30, so a reload (or "Продолжить")
    // picks the feed back up.
    pauseBtn.addEventListener('click', function () {
      paused = !paused;
      pauseBtn.textContent = paused ? 'Продолжить' : 'Пауза';
      pauseBtn.setAttribute('aria-pressed', paused ? 'true' : 'false');
    });
  }

  if (clearBtn) {
    // Clearing is purely visual: the server buffer is untouched, so the
    // rows come back on the next snapshot (for example after a reload).
    clearBtn.addEventListener('click', function () {
      feed.textContent = '';
    });
  }
})();
