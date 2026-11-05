/* DomainScope – Kernfunktionen (Vanilla JS, ohne Abhängigkeiten) */
(function () {
    'use strict';
    var DS = window.DS = window.DS || {};
    var $ = function (s, r) { return (r || document).querySelector(s); };
    var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
    var csrf = function () { var m = $('meta[name="csrf-token"]'); return m ? m.content : ''; };
    DS.csrf = csrf;

    /* ---------- Toasts ---------- */
    DS.toast = function (msg, type, ms) {
        var box = $('#toasts'); if (!box) return;
        var t = document.createElement('div');
        t.className = 'toast ' + (type || '');
        t.textContent = msg;
        box.appendChild(t);
        setTimeout(function () { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(function () { t.remove(); }, 320); }, ms || 4500);
    };

    /* ---------- Fortschrittsbalken ---------- */
    var bar;
    DS.progress = function (on) {
        if (!bar) { bar = document.createElement('div'); bar.className = 'progress-overlay'; document.body.appendChild(bar); }
        if (on) { bar.style.opacity = '1'; bar.style.width = '70%'; }
        else { bar.style.width = '100%'; setTimeout(function () { bar.style.opacity = '0'; bar.style.width = '0'; }, 300); }
    };

    /* ---------- Theme & Sidebar ---------- */
    var root = document.documentElement;
    function setTheme(t) { root.setAttribute('data-theme', t); try { localStorage.setItem('ds-theme', t); } catch (e) {} updateThemeIcon(); }
    function updateThemeIcon() { /* Icon bleibt generisch (Sonne); Zustand über aria-pressed */
        var b = $('#theme-toggle'); if (b) b.setAttribute('aria-pressed', root.getAttribute('data-theme') === 'light' ? 'true' : 'false');
    }
    var tt = $('#theme-toggle');
    if (tt) { tt.addEventListener('click', function () { setTheme(root.getAttribute('data-theme') === 'light' ? 'dark' : 'light'); }); updateThemeIcon(); }
    var st = $('#sidebar-toggle');
    if (st) {
        st.addEventListener('click', function () {
            var c = root.classList.toggle('sidebar-collapsed');
            st.setAttribute('aria-expanded', c ? 'false' : 'true');
            try { localStorage.setItem('ds-sidebar', c ? 'collapsed' : 'expanded'); } catch (e) {}
        });
    }
    var mm = $('#mobile-menu'), bd = $('#sidebar-backdrop');
    if (mm) mm.addEventListener('click', function () { root.classList.add('sidebar-open'); });
    if (bd) bd.addEventListener('click', function () { root.classList.remove('sidebar-open'); });

    /* ---------- Kopieren ---------- */
    document.addEventListener('click', function (e) {
        var el = e.target.closest('.copyable'); if (!el) return;
        var text = el.getAttribute('data-copy') || el.textContent;
        var done = function () { el.classList.add('copied'); DS.toast('Kopiert: ' + (text.length > 60 ? text.slice(0, 57) + '…' : text), 'ok', 1800); setTimeout(function () { el.classList.remove('copied'); }, 900); };
        if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done, fallback); } else { fallback(); }
        function fallback() {
            var ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
            document.body.appendChild(ta); ta.select();
            try { document.execCommand('copy'); done(); } catch (err) { DS.toast('Kopieren nicht möglich', 'err'); }
            ta.remove();
        }
    });

    /* ---------- Tabellen: Sortieren & Filtern ---------- */
    function cellValue(td) {
        var v = td.getAttribute('data-sort-value'); if (v === null) v = td.textContent.trim();
        return v;
    }
    document.addEventListener('click', function (e) {
        var th = e.target.closest('table.sortable th[data-sort]'); if (!th) return;
        var table = th.closest('table'), idx = th.cellIndex;
        var asc = th.getAttribute('aria-sort') !== 'ascending';
        $$('th', table).forEach(function (h) { h.removeAttribute('aria-sort'); });
        th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');
        var tbody = table.tBodies[0];
        var rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (a, b) {
            var x = cellValue(a.cells[idx]), y = cellValue(b.cells[idx]);
            var nx = parseFloat(x), ny = parseFloat(y);
            var r = (!isNaN(nx) && !isNaN(ny) && /^-?[\d.]+$/.test(x) && /^-?[\d.]+$/.test(y)) ? nx - ny : x.localeCompare(y, 'de', { numeric: true, sensitivity: 'base' });
            return asc ? r : -r;
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
    });
    function applyFilter(table, q, col, val) {
        q = (q || '').toLowerCase();
        Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
            var ok = q === '' || row.textContent.toLowerCase().indexOf(q) !== -1;
            if (ok && col && val) { var c = row.querySelector('[data-col="' + col + '"]'); ok = c && c.textContent.toLowerCase().indexOf(val) !== -1; }
            row.classList.toggle('is-hidden', !ok);
        });
    }
    document.addEventListener('input', function (e) {
        var inp = e.target.closest('[data-table-filter]'); if (!inp) return;
        var table = $(inp.getAttribute('data-table-filter')); if (table) applyFilter(table, inp.value, table._col, table._val);
    });
    document.addEventListener('click', function (e) {
        var chip = e.target.closest('[data-filter-col]'); if (!chip) return;
        var card = chip.closest('.card'); var table = card && $('table.sortable', card); if (!table) return;
        table._col = chip.getAttribute('data-filter-col'); table._val = chip.getAttribute('data-filter-val').toLowerCase();
        $$('[data-filter-col]', card).forEach(function (c) { c.classList.toggle('on', c === chip && table._val !== ''); });
        var f = $('[data-table-filter]', card); applyFilter(table, f ? f.value : '', table._col, table._val);
    });

    /* ---------- Formulare per fetch (Prüfmodule) ---------- */
    DS.refreshPanel = function () {
        if (typeof DS.reloadTab === 'function' && $('#tab-panel')) { DS.reloadTab(); } else { window.location.reload(); }
    };
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (form.hasAttribute('data-confirm') && !window.confirm(form.getAttribute('data-confirm'))) { e.preventDefault(); return; }
        if (!form.hasAttribute('data-ajax-run') || !window.fetch) return;
        e.preventDefault();
        var btn = form.querySelector('button[type="submit"]');
        var label = btn ? btn.innerHTML : '';
        if (btn) { btn.setAttribute('aria-busy', 'true'); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Läuft …'; }
        DS.progress(true);
        var data = new FormData(form);
        fetch(form.action, { method: 'POST', body: data, headers: { 'X-Requested-With': 'fetch', 'X-CSRF-Token': csrf(), 'Accept': 'application/json' }, credentials: 'same-origin' })
            .then(function (r) { return r.json().catch(function () { return { ok: false, message: 'Unerwartete Antwort (HTTP ' + r.status + ')' }; }); })
            .then(function (j) {
                DS.toast(j.message || (j.ok ? 'Fertig' : 'Fehlgeschlagen'), j.ok ? 'ok' : (j.status === 'partial' ? 'warn' : 'err'), 6000);
                DS.refreshPanel();
            })
            .catch(function () { DS.toast('Netzwerkfehler – Anfrage nicht abgeschlossen.', 'err'); })
            .then(function () { DS.progress(false); if (btn) { btn.removeAttribute('aria-busy'); btn.disabled = false; btn.innerHTML = label; } });
    });

    /* ---------- Berichte: Formular → URL ---------- */
    document.addEventListener('click', function (e) {
        var b = e.target.closest('.report-form button[data-fmt]'); if (!b) return;
        e.preventDefault();
        var f = b.closest('form'); var fmt = b.getAttribute('data-fmt');
        var url = '/reports/' + encodeURIComponent(f.getAttribute('data-report-type')) + '/' + encodeURIComponent(f.elements.domain.value) + (fmt === 'html' ? '' : '?format=' + fmt);
        window.location.href = url;
    });

    /* ---------- Globale Suche ---------- */
    var gs = $('#global-search'), box = $('#search-suggest'), timer, sel = -1;
    if (gs && box && window.fetch) {
        gs.addEventListener('input', function () {
            clearTimeout(timer);
            var q = gs.value.trim();
            if (q.length < 2) { box.hidden = true; return; }
            timer = setTimeout(function () {
                fetch('/api/search?q=' + encodeURIComponent(q), { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
                    .then(function (r) { return r.json(); }).then(function (j) {
                        box.innerHTML = ''; sel = -1;
                        (j.items || []).forEach(function (it) {
                            var a = document.createElement('a'); a.href = it.url;
                            var t = document.createElement('span'); t.className = 'stype'; t.textContent = it.type;
                            var l = document.createElement('span'); l.textContent = it.label;
                            a.appendChild(t); a.appendChild(l); box.appendChild(a);
                        });
                        box.hidden = !(j.items && j.items.length);
                    }).catch(function () { box.hidden = true; });
            }, 180);
        });
        gs.addEventListener('keydown', function (e) {
            var items = $$('a', box); if (box.hidden || !items.length) return;
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault(); sel = (sel + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
                items.forEach(function (a, i) { a.classList.toggle('sel', i === sel); });
            } else if (e.key === 'Enter' && sel >= 0) { e.preventDefault(); window.location.href = items[sel].href; }
            else if (e.key === 'Escape') { box.hidden = true; }
        });
        document.addEventListener('click', function (e) { if (!e.target.closest('.global-search')) box.hidden = true; });
    }
    document.addEventListener('keydown', function (e) {
        if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) && gs) { e.preventDefault(); gs.focus(); }
    });

    /* ---------- Lookup-Formulare: Ladezustand ---------- */
    document.addEventListener('submit', function (e) {
        var f = e.target;
        if (f.id === 'lookup-form' || f.id === 'dns-form') {
            var b = f.querySelector('button[type="submit"]'); if (b) { b.innerHTML = '<span class="spinner"></span> Läuft …'; b.setAttribute('aria-busy', 'true'); }
            DS.progress(true);
        }
    });
})();
