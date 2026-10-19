/* mdns panel: the live request screen.
 *
 * The page is server-rendered, so it already works with scripting off.
 * This script only keeps it current: it opens the SSE stream, prepends
 * the streamed <tr> fragments, trims to the server's bound and offers
 * pause/clear. User-controlled text arrives already escaped inside the
 * fragments; innerHTML is used for those trusted rows only, exactly like
 * app.js's feed. No inline styles, so the strict CSP holds.
 */
(function () {
  'use strict';

  /* LIVE_MAX mirrors liveFeedSize (internal/panel/live.go): the table
   * holds the newest 100 rows no matter how fast they arrive. */
  var LIVE_MAX = 100;

  var rows = document.getElementById('live-rows');
  if (!rows || !window.EventSource) {
    return;
  }

  var paused = false;
  var pauseBtn = document.getElementById('live-pause');
  var clearBtn = document.getElementById('live-clear');
  var state = document.getElementById('live-state');

  var trim = function () {
    while (rows.children.length > LIVE_MAX) {
      rows.removeChild(rows.lastElementChild);
    }
  };

  var dropPlaceholder = function () {
    var placeholder = rows.querySelector('.empty');
    if (placeholder) {
      rows.removeChild(placeholder);
    }
  };

  var showPlaceholder = function () {
    rows.textContent = '';
    var tr = document.createElement('tr');
    tr.className = 'empty';
    var td = document.createElement('td');
    td.setAttribute('colspan', '8');
    td.textContent = 'Пока нет запросов';
    tr.appendChild(td);
    rows.appendChild(tr);
  };

  // The server sends one <tr>…</tr> per query. A tbody is the right
  // parsing context for table rows, so no wrapper table is needed.
  var prependRow = function (html) {
    var tmp = document.createElement('tbody');
    tmp.innerHTML = html;
    var row = tmp.firstElementChild;
    if (!row) {
      return;
    }
    dropPlaceholder();
    rows.insertBefore(row, rows.firstChild);
    trim();
  };

  var replaceRows = function (html) {
    rows.innerHTML = html;
    trim();
  };

  var es = new EventSource('/panel/live/events');

  es.addEventListener('open', function () {
    if (state) {
      state.hidden = true;
      state.textContent = '';
    }
  });
  es.addEventListener('error', function () {
    // EventSource retries on its own; until it does, say so plainly.
    if (state) {
      state.textContent = 'соединение потеряно — обновите страницу';
      state.hidden = false;
    }
  });
  es.addEventListener('snapshot', function (ev) {
    if (paused) {
      return;
    }
    if (ev.data && ev.data.trim() !== '') {
      replaceRows(ev.data);
    } else {
      showPlaceholder();
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
    // its ring keeps the newest 100, so a reload picks the table up.
    pauseBtn.addEventListener('click', function () {
      paused = !paused;
      pauseBtn.textContent = paused ? 'Продолжить' : 'Пауза';
      pauseBtn.setAttribute('aria-pressed', paused ? 'true' : 'false');
    });
  }

  if (clearBtn) {
    // Clearing is purely visual: the server ring is untouched, so the
    // rows come back on the next snapshot (for example after a reload).
    clearBtn.addEventListener('click', showPlaceholder);
  }
})();
