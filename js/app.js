/*!
 * app.js — UI layer for the SDDL viewer
 *
 * Renders the parse result into cards and tables. All DOM is built with
 * createElement / textContent; user-supplied SDDL never goes through
 * innerHTML, so the page cannot be script-injected via the input box.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  var input = $('sddl-input');
  var statusEl = $('status');
  var outputEl = $('output');
  var tooltip = $('tooltip');

  var lastResult = null;
  var lastError = null;
  var renderTimer = null;

  /* ------------------------------------------------------------------ *
   * Tiny DOM helpers
   * ------------------------------------------------------------------ */
  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text != null) n.textContent = String(text);
    return n;
  }

  function append(parent) {
    for (var i = 1; i < arguments.length; i++) {
      var c = arguments[i];
      if (c) parent.appendChild(c);
    }
    return parent;
  }

  // Elements carrying a tooltip
  function withTip(node, title, en, desc) {
    node.setAttribute('data-tip-title', title || '');
    node.setAttribute('data-tip-en', en || '');
    node.setAttribute('data-tip-desc', desc || '');
    node.classList.add('has-tip');
    return node;
  }

  /* ------------------------------------------------------------------ *
   * Tooltip
   * ------------------------------------------------------------------ */
  var tipTarget = null;

  function showTip(target, x, y) {
    var title = target.getAttribute('data-tip-title');
    var en = target.getAttribute('data-tip-en');
    var desc = target.getAttribute('data-tip-desc');
    if (!title && !desc) return;

    tooltip.textContent = '';
    if (title) tooltip.appendChild(el('div', 'tt-title', title));
    if (en) tooltip.appendChild(el('div', 'tt-en', en));
    if (desc) tooltip.appendChild(el('div', 'tt-desc', desc));

    tooltip.classList.add('show');
    positionTip(x, y);
  }

  function positionTip(x, y) {
    var pad = 14;
    var r = tooltip.getBoundingClientRect();
    var left = x + pad;
    var top = y + pad;

    if (left + r.width > window.innerWidth - 8) left = x - r.width - pad;
    if (top + r.height > window.innerHeight - 8) top = y - r.height - pad;

    tooltip.style.left = Math.max(8, left) + 'px';
    tooltip.style.top = Math.max(8, top) + 'px';
  }

  function hideTip() {
    tooltip.classList.remove('show');
    tipTarget = null;
  }

  document.addEventListener('mousemove', function (e) {
    var t = e.target.closest ? e.target.closest('.has-tip') : null;
    if (t) {
      tipTarget = t;
      showTip(t, e.clientX, e.clientY);
    } else if (tipTarget) {
      hideTip();
    }
  });

  document.addEventListener('mouseleave', hideTip);
  window.addEventListener('scroll', hideTip, true);

  /* ------------------------------------------------------------------ *
   * Rendering: error
   * ------------------------------------------------------------------ */
  function renderError(err, text) {
    statusEl.textContent = '';

    var box = el('div', 'error-box');
    append(box, el('div', 'err-title', 'Parse error'));
    append(box, el('div', 'err-msg', err.message));

    if (err.hint) append(box, el('div', 'err-hint', err.hint));

    if (typeof err.position === 'number' && text) {
      var from = Math.max(0, err.position - 40);
      var to = Math.min(text.length, err.position + 40);
      var before = (from > 0 ? '…' : '') + text.slice(from, err.position);
      var after = text.slice(err.position, to) + (to < text.length ? '…' : '');
      var loc = el('div', 'err-loc');
      loc.appendChild(document.createTextNode(before));
      var caret = el('span', 'caret', '▲');
      loc.appendChild(caret);
      loc.appendChild(document.createTextNode(after));
      append(box, loc);
    }

    statusEl.appendChild(box);
    outputEl.textContent = '';
  }

  /* ------------------------------------------------------------------ *
   * Rendering: warnings
   * ------------------------------------------------------------------ */
  function renderWarnings(warnings) {
    if (!warnings || !warnings.length) return;
    var box = el('div', 'warn-list');
    append(box, el('div', 'warn-title', warnings.length === 1 ? '1 warning' : warnings.length + ' warnings'));
    var ul = el('ul');
    warnings.forEach(function (w) { ul.appendChild(el('li', null, w)); });
    append(box, ul);
    statusEl.appendChild(box);
  }

  /* ------------------------------------------------------------------ *
   * Rendering: summary strip
   * ------------------------------------------------------------------ */
  function renderSummary(result) {
    var dacl = result.dacl;
    if (!dacl) return;

    var counts = { allow: 0, deny: 0, audit: 0, label: 0, other: 0 };
    dacl.aces.forEach(function (a) {
      var k = a.type.kind;
      if (counts[k] == null) counts[k] = 0;
      counts[k]++;
    });

    var strip = el('div', 'summary');

    function stat(cls, n, label) {
      var s = el('div', 'stat ' + cls);
      append(s, el('div', 'n', n));
      append(s, el('div', 'k', label));
      return s;
    }

    append(strip, stat('', dacl.aces.length, 'DACL ACEs'));
    if (counts.allow) append(strip, stat('allow', counts.allow, 'Allow'));
    if (counts.deny) append(strip, stat('deny', counts.deny, 'Deny'));
    if (counts.audit) append(strip, stat('audit', counts.audit, 'Audit'));
    if (counts.label) append(strip, stat('label', counts.label, 'Label'));
    if (counts.attr) append(strip, stat('other', counts.attr, 'Attribute'));
    if (result.sacl) append(strip, stat('audit', result.sacl.aces.length, 'SACL ACEs'));

    outputEl.appendChild(strip);
  }

  /* ------------------------------------------------------------------ *
   * Rendering: owner / group principal
   * ------------------------------------------------------------------ */
  function renderPrincipal(letter, label, sid) {
    var card = el('div', 'card');
    var head = el('div', 'card-head');
    var h2 = el('h2');
    append(h2, el('span', 'section-token', letter + ':'));
    append(h2, document.createTextNode(label));
    append(head, h2);
    append(card, head);

    var body = el('div', 'card-body');
    var wrap = el('div', 'principal');
    var who = el('div', 'who');

    var nameRow = el('div', 'name');
    append(nameRow, document.createTextNode(sid.name || '—'));
    if (!sid.resolved && sid.kind !== 'empty') {
      append(nameRow, el('span', 'unresolved', 'unresolved'));
    }
    append(who, nameRow);

    if (sid.account) append(who, el('div', 'acct', sid.account));
    if (sid.desc) append(who, el('div', 'note', sid.desc));

    append(wrap, who);

    if (sid.sid) {
      var box = el('div', 'sidbox');
      append(box, el('span', 'lbl', 'SID'));
      append(box, document.createTextNode(sid.sid));
      append(wrap, box);
    }

    append(body, wrap);
    append(card, body);
    return card;
  }

  /* ------------------------------------------------------------------ *
   * Rendering: ACL card
   * ------------------------------------------------------------------ */
  function typeBadge(type) {
    var b = el('span', 'badge ' + (type.kind || 'other'));
    append(b, document.createTextNode(type.name));
    if (type.code) append(b, el('span', 'code', type.code));
    if (type.en) withTip(b, type.name, type.en, type.desc);
    return b;
  }

  function renderTrustee(sid) {
    var cell = el('div', 'trustee');

    var nameRow = el('div', 't-name');
    append(nameRow, document.createTextNode(sid.name || '—'));
    if (!sid.resolved && sid.kind !== 'empty') {
      append(nameRow, el('span', 'unresolved', 'unresolved'));
    }
    append(cell, nameRow);

    if (sid.account) append(cell, el('div', 't-acct', sid.account));
    if (sid.sid) append(cell, el('div', 't-sid', sid.sid));

    if (sid.desc) withTip(cell, sid.name, sid.sid, sid.desc);
    return cell;
  }

  function renderRights(ace) {
    var cell = el('div');

    if (!ace.rights || (!ace.rights.items.length && !ace.rights.isHex && !ace.rights.unknown.length)) {
      append(cell, el('div', 'rights-empty', 'No access rights'));
      return cell;
    }

    var list = el('div', 'rights-list');

    ace.rights.items.forEach(function (r) {
      var row = el('div', 'right-item');
      append(row, el('span', 'r-code', r.code));
      append(row, el('span', 'r-name', r.name));
      append(row, el('span', 'r-en', r.en));
      withTip(row, r.name, r.en, r.desc + '  (' + SDDL.hex(r.mask) + ')');
      append(list, row);
    });

    ace.rights.unknown.forEach(function (code) {
      var row = el('div', 'right-item');
      var c = el('span', 'r-code', code);
      c.style.color = 'var(--deny)';
      c.style.background = 'var(--deny-bg)';
      append(row, c);
      append(row, el('span', 'r-name', 'Unknown code'));
      append(list, row);
    });

    append(cell, list);

    // Raw mask plus decoded bits
    var hexLine = el('div', 'rights-hex');
    append(hexLine, document.createTextNode('Mask ' + ace.rights.hex));

    var contexts = SDDL.inferContexts(ace.rights);
    var bits = SDDL.decodeMask(ace.rights.mask, contexts);
    if (bits.length) {
      var bitsWrap = el('div');
      bitsWrap.style.marginTop = '4px';
      bits.forEach(function (b) {
        var span = el('span', 'bit', b.name);
        withTip(span, b.name, '', b.desc);
        append(bitsWrap, span);
      });
      append(hexLine, bitsWrap);
    }

    append(cell, hexLine);
    return cell;
  }

  function renderFlags(ace) {
    var cell = el('div', 'flags-cell');

    if (!ace.flags.length) {
      append(cell, el('span', 'none', 'None'));
      return cell;
    }

    ace.flags.forEach(function (f) {
      var line = el('div', 'flag-line');
      append(line, el('span', 'f-code', f.code));
      append(line, el('span', 'f-name', f.name));
      withTip(line, f.name, f.en, f.desc);
      append(cell, line);
    });

    return cell;
  }

  function renderAceDetail(ace) {
    var hasDetail = ace.objectGuid || ace.inheritObjectGuid || ace.condition ||
      ace.resourceAttribute || ace.warnings.length || ace.errors.length;
    if (!hasDetail) return null;

    var box = el('div', 'ace-detail');

    function row(label, value, cls) {
      var r = el('div', 'd-row');
      append(r, el('span', 'd-lbl', label));
      append(r, el('span', 'd-val' + (cls ? ' ' + cls : ''), value));
      append(box, r);
    }

    if (ace.objectGuid) {
      row('Object GUID', ace.objectGuid.guid + (ace.objectGuid.name ? '  ·  ' + ace.objectGuid.name : ''));
    }
    if (ace.inheritObjectGuid) {
      row('Inherit GUID', ace.inheritObjectGuid.guid + (ace.inheritObjectGuid.name ? '  ·  ' + ace.inheritObjectGuid.name : ''));
    }
    if (ace.condition) row('Condition', ace.condition, 'cond');
    if (ace.resourceAttribute) row('Attribute', ace.resourceAttribute, 'cond');

    ace.errors.forEach(function (e) {
      append(box, el('div', 'ace-note err', e));
    });
    ace.warnings.forEach(function (w) {
      append(box, el('div', 'ace-note', w));
    });

    return box;
  }

  function renderAcl(letter, label, acl) {
    var card = el('div', 'card');

    // ---- head ----
    var head = el('div', 'card-head');
    var h2 = el('h2');
    append(h2, el('span', 'section-token', letter + ':'));
    append(h2, document.createTextNode(label));

    var sub = el('span', 'sub');
    sub.textContent = acl.aces.length + (acl.aces.length === 1 ? ' ACE' : ' ACEs');
    append(h2, sub);
    append(head, h2);

    var copyBtn = el('button', null, 'Copy section');
    copyBtn.type = 'button';
    copyBtn.addEventListener('click', function () {
      copyToClipboard(sectionText(letter, acl), copyBtn);
    });
    append(head, copyBtn);
    append(card, head);

    // ---- body ----
    var body = el('div', 'card-body');

    // Control flags
    if (acl.flags.length) {
      var flagRow = el('div', 'flag-row');
      acl.flags.forEach(function (f) {
        var chip = el('span', 'flag-chip' + (f.code === 'NO_ACCESS_CONTROL' ? ' danger' : ''));
        append(chip, el('span', 'fc-code', f.code));
        append(chip, el('span', 'fc-name', f.name));
        withTip(chip, f.name, f.en, f.desc);
        append(flagRow, chip);
      });
      append(body, flagRow);
    } else if (!acl.empty) {
      append(body, el('div', 'no-flags', 'No ACL control flags'));
    }

    // Empty ACL note
    if (acl.empty) {
      var note = el('div', 'no-flags');
      note.style.fontStyle = 'normal';
      note.style.color = 'var(--warn)';
      if (acl.flags.some(function (f) { return f.code === 'NO_ACCESS_CONTROL'; })) {
        note.textContent = 'NULL ACL — every principal has full access to this object.';
      } else {
        note.textContent = 'Empty ACL — no principal is granted access, so everyone is denied.';
      }
      append(body, note);
    }

    // ACE table
    if (acl.aces.length) {
      var wrap = el('div', 'ace-table-wrap');
      var table = el('table', 'ace');

      var thead = el('thead');
      var hr = el('tr');
      ['#', 'Type', 'Trustee', 'Access rights', 'Inheritance'].forEach(function (h) {
        append(hr, el('th', null, h));
      });
      append(thead, hr);
      append(table, thead);

      var tbody = el('tbody');
      acl.aces.forEach(function (ace) {
        var tr = el('tr');
        append(tr, el('td', 'col-num', ace.index));

        var typeCell = el('td');
        typeCell.setAttribute('data-label', 'Type');
        append(typeCell, typeBadge(ace.type));
        append(tr, typeCell);

        var trusteeCell = el('td');
        trusteeCell.setAttribute('data-label', 'Trustee');
        append(trusteeCell, renderTrustee(ace.sid));
        append(tr, trusteeCell);

        var rightsCell = el('td');
        rightsCell.setAttribute('data-label', 'Access rights');
        append(rightsCell, renderRights(ace));
        var detail = renderAceDetail(ace);
        if (detail) append(rightsCell, detail);
        append(tr, rightsCell);

        var flagsCell = el('td');
        flagsCell.setAttribute('data-label', 'Inheritance');
        append(flagsCell, renderFlags(ace));
        append(tr, flagsCell);

        append(tbody, tr);
      });

      append(table, tbody);
      append(wrap, table);
      append(body, wrap);
    }

    append(card, body);
    return card;
  }

  function sectionText(letter, acl) {
    var s = letter + ':' + (acl.flagRaw || '');
    acl.aces.forEach(function (a) { s += a.raw; });
    return s;
  }

  /* ------------------------------------------------------------------ *
   * Rendering: highlighted source
   * ------------------------------------------------------------------ */
  function renderHighlight(result) {
    var card = el('div', 'card');
    var head = el('div', 'card-head');
    var h2 = el('h2');
    append(h2, document.createTextNode('Source'));
    append(h2, el('span', 'sub', 'parsed tokens'));
    append(head, h2);
    append(card, head);

    var body = el('div', 'card-body');
    var view = el('div', 'highlight-view');

    var text = result.text;
    var marks = [];

    function mark(start, end, cls) {
      if (start == null || end == null || end <= start) return;
      marks.push({ start: start, end: end, cls: cls });
    }

    // Sections and their contents
    function markSidSection(sid) {
      if (!sid || sid.start == null) return;
      mark(sid.start - 2, sid.start, 'hl-section');
      mark(sid.start, sid.end, sid.resolved ? 'hl-sid' : 'hl-unknown');
    }

    markSidSection(result.owner);
    markSidSection(result.group);

    [['D', result.dacl], ['S', result.sacl]].forEach(function (pair) {
      var letter = pair[0];
      var acl = pair[1];
      if (!acl) return;
      mark(acl.start, acl.start + 2, 'hl-section');
      if (acl.flagRaw) mark(acl.start + 2, acl.start + 2 + acl.flagRaw.length, 'hl-flag');

      acl.aces.forEach(function (ace) {
        mark(ace.start, ace.start + 1, 'hl-paren');
        mark(ace.end - 1, ace.end, 'hl-paren');

        var pos = ace.start + 1;
        var kind = ace.type.kind;
        var typeCls = kind === 'allow' ? 'hl-type-allow'
          : kind === 'deny' ? 'hl-type-deny'
          : kind === 'audit' ? 'hl-type-audit'
          : kind === 'label' ? 'hl-type-label'
          : 'hl-type-other';
        mark(pos, pos + (ace.fields[0] || '').length, typeCls);
        pos += (ace.fields[0] || '').length + 1;

        mark(pos, pos + (ace.fields[1] || '').length, 'hl-aceflags');
        pos += (ace.fields[1] || '').length + 1;

        mark(pos, pos + (ace.fields[2] || '').length, 'hl-rights');
        pos += (ace.fields[2] || '').length + 1;

        var g1 = (ace.fields[3] || '').length;
        mark(pos, pos + g1, 'hl-guid');
        pos += g1 + 1;

        var g2 = (ace.fields[4] || '').length;
        mark(pos, pos + g2, 'hl-guid');
        pos += g2 + 1;

        var sidLen = (ace.fields[5] || '').length;
        mark(pos, pos + sidLen, ace.sid.resolved ? 'hl-sid' : 'hl-unknown');
      });
    });

    // Build the highlighted output from non-overlapping marks
    marks.sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    var flat = [];
    var cursor = 0;
    marks.forEach(function (m) {
      if (m.start < cursor) return; // skip overlaps
      flat.push(m);
      cursor = m.end;
    });

    var at = 0;
    flat.forEach(function (m) {
      if (m.start > at) view.appendChild(document.createTextNode(text.slice(at, m.start)));
      append(view, el('span', m.cls, text.slice(m.start, m.end)));
      at = m.end;
    });
    if (at < text.length) view.appendChild(document.createTextNode(text.slice(at)));

    append(body, view);
    append(card, body);
    return card;
  }

  /* ------------------------------------------------------------------ *
   * Rendering: result
   * ------------------------------------------------------------------ */
  function render(result) {
    statusEl.textContent = '';
    outputEl.textContent = '';

    if (!result.ok) {
      renderError(result.error, result.text);
      return;
    }

    renderWarnings(result.warnings);
    renderSummary(result);

    var frag = document.createDocumentFragment();

    if (result.owner) frag.appendChild(renderPrincipal('O', 'Owner', result.owner));
    if (result.group) frag.appendChild(renderPrincipal('G', 'Primary group', result.group));
    if (result.dacl) frag.appendChild(renderAcl('D', 'Discretionary access control list', result.dacl));
    if (result.sacl) frag.appendChild(renderAcl('S', 'System access control list', result.sacl));

    frag.appendChild(renderHighlight(result));

    outputEl.appendChild(frag);
  }

  function renderEmpty() {
    statusEl.textContent = '';
    outputEl.textContent = '';
    var box = el('div', 'empty-state');
    append(box, el('div', 'big', '⌘'));
    append(box, el('div', null, 'Paste an SDDL string above to decode it.'));
    var line = el('div');
    append(line, document.createTextNode('Try '));
    append(line, el('code', null, 'O:BAG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)'));
    append(box, line);
    outputEl.appendChild(box);
  }

  /* ------------------------------------------------------------------ *
   * Parse loop (debounced)
   * ------------------------------------------------------------------ */
  function runParse() {
    var text = input.value;
    if (!text.trim()) {
      lastResult = null;
      lastError = null;
      renderEmpty();
      return;
    }

    try {
      lastResult = SDDL.parse(text);
      lastError = lastResult.ok ? null : lastResult.error;
      render(lastResult);
    } catch (e) {
      lastError = e;
      lastResult = null;
      renderError(e, text);
    }
  }

  function scheduleParse() {
    clearTimeout(renderTimer);
    renderTimer = setTimeout(runParse, 120);
  }

  input.addEventListener('input', scheduleParse);

  /* ------------------------------------------------------------------ *
   * Buttons
   * ------------------------------------------------------------------ */
  function copyToClipboard(text, btn) {
    var done = function () {
      if (!btn) return;
      var old = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(function () { btn.textContent = old; }, 1200);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  }

  function fallbackCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
    done();
  }

  $('btn-copy').addEventListener('click', function () {
    if (input.value) copyToClipboard(input.value, this);
  });

  $('btn-clear').addEventListener('click', function () {
    input.value = '';
    input.focus();
    runParse();
  });

  $('btn-paste').addEventListener('click', function () {
    var btn = this;
    if (navigator.clipboard && navigator.clipboard.readText) {
      navigator.clipboard.readText().then(function (text) {
        if (!text) return;
        input.value = text.trim();
        runParse();
      }, function () {
        btn.textContent = 'Press ⌘V';
        setTimeout(function () { btn.textContent = 'Paste'; }, 1500);
        input.focus();
      });
    } else {
      input.focus();
    }
  });

  $('btn-csv').addEventListener('click', function () {
    if (!lastResult || !lastResult.ok) return;
    // UTF-8 BOM so Excel detects the encoding on double-click
    var csv = SDDLCsv.toCsv(lastResult, { bom: true, eol: '\r\n' });
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'sddl-aces.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });

  $('btn-download').addEventListener('click', function () {
    if (!lastResult) return;
    var data = JSON.stringify(stripPositions(lastResult), null, 2);
    var blob = new Blob([data], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'sddl-parsed.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  });

  // Drop offsets and redundant lookups so the JSON stays readable
  function stripPositions(result) {
    var copy = JSON.parse(JSON.stringify(result, function (k, v) {
      if (k === 'start' || k === 'end' || k === 'pos' || k === 'fields') return undefined;
      return v;
    }));
    if (copy.error) {
      copy.error = { message: copy.error.message, hint: copy.error.hint, position: copy.error.position };
    }
    return copy;
  }

  /* ------------------------------------------------------------------ *
   * Examples
   * ------------------------------------------------------------------ */
  function buildExamples() {
    var box = $('examples');
    SDDLData.EXAMPLES.forEach(function (ex) {
      var b = el('button', null, ex.name);
      b.type = 'button';
      b.title = ex.sddl;
      b.addEventListener('click', function () {
        input.value = ex.sddl;
        runParse();
      });
      append(box, b);
    });
  }

  /* ------------------------------------------------------------------ *
   * Keyboard shortcuts
   * ------------------------------------------------------------------ */
  document.addEventListener('keydown', function (e) {
    var mod = e.metaKey || e.ctrlKey;
    if (mod && e.key === 'Enter') {
      e.preventDefault();
      runParse();
    }
  });

  /* ------------------------------------------------------------------ *
   * Boot
   * ------------------------------------------------------------------ */
  buildExamples();

  var params = new URLSearchParams(location.search);
  var initial = params.get('sddl');
  if (initial) {
    input.value = initial;
    runParse();
  } else {
    renderEmpty();
  }
})();
