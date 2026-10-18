/* mdns panel behaviour.
 *
 * Two small jobs, no framework: the tooltip for the chart segments and
 * the live feed. The page's CSP is "default-src 'self'", so nothing
 * here may create a <style> element or set a style attribute in HTML.
 *
 * htmx 2 injects a <style> for its request indicators at
 * DOMContentLoaded unless includeIndicatorStyles is false. This script
 * is deferred, so it runs before that injection; the two rules htmx
 * would add live in app.css instead.
 */
if (window.htmx && window.htmx.config) {
  window.htmx.config.includeIndicatorStyles = false;
}

(function () {
  'use strict';

  /* ---- chart tooltip --------------------------------------------- */

  var tip = document.getElementById('tip');

  if (tip) {
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

    var rings = document.querySelectorAll('.pie .ring');
    Array.prototype.forEach.call(rings, function (ring) {
      ring.addEventListener('mousemove', function (ev) { showTip(ring, ev); });
      ring.addEventListener('mouseleave', hideTip);
      ring.addEventListener('focus', function () { showTip(ring, null); });
      ring.addEventListener('blur', hideTip);
    });
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

  var es = new EventSource('/panel/events');
  es.addEventListener('snapshot', function (ev) {
    if (!paused) {
      replaceRows(ev.data);
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
