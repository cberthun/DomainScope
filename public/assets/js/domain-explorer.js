/* Domain-Detailseite: Tabs laden per fetch (Fallback: normale Links) */
(function () {
    'use strict';
    var tabs = document.getElementById('domain-tabs'), panel = document.getElementById('tab-panel');
    if (!tabs || !panel || !window.fetch) return;
    var base = tabs.getAttribute('data-base'), host = tabs.getAttribute('data-host') || '';
    var current = (tabs.querySelector('.tab.active') || {}).getAttribute ? tabs.querySelector('.tab.active').getAttribute('data-tab') : 'overview';
    var skeleton = '<div class="card"><div class="card-body"><div class="skeleton skeleton-line" style="width:40%"></div><div class="skeleton skeleton-line"></div><div class="skeleton skeleton-line" style="width:80%"></div><div class="skeleton skeleton-block"></div></div></div>';

    function load(tab, push) {
        panel.classList.add('loading');
        if (push !== false) panel.innerHTML = skeleton;
        var url = base + '/tab/' + encodeURIComponent(tab) + (host ? '?host=' + encodeURIComponent(host) : '');
        return fetch(url, { headers: { 'X-Requested-With': 'fetch' }, credentials: 'same-origin' })
            .then(function (r) {
                if (r.status === 401 || r.redirected) { window.location.reload(); return null; }
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.text();
            })
            .then(function (html) {
                if (html === null) return;
                panel.innerHTML = html; panel.classList.remove('loading');
                current = tab;
                Array.prototype.forEach.call(tabs.querySelectorAll('.tab'), function (t) {
                    var on = t.getAttribute('data-tab') === tab;
                    t.classList.toggle('active', on); t.setAttribute('aria-selected', on ? 'true' : 'false');
                });
                if (push) {
                    var q = '?tab=' + encodeURIComponent(tab) + (host ? '&host=' + encodeURIComponent(host) : '');
                    history.pushState({ tab: tab }, '', base + q);
                }
            })
            .catch(function (err) {
                panel.classList.remove('loading');
                panel.innerHTML = '<div class="alert alert-error">Der Tab konnte nicht geladen werden (' + err.message + '). <a href="' + base + '?tab=' + tab + '">Seite neu laden</a></div>';
            });
    }

    tabs.addEventListener('click', function (e) {
        var a = e.target.closest('.tab'); if (!a || e.metaKey || e.ctrlKey || e.shiftKey) return;
        e.preventDefault();
        var t = a.getAttribute('data-tab'); if (t === current) return;
        load(t, true);
    });
    window.addEventListener('popstate', function (e) {
        var t = (e.state && e.state.tab) || new URLSearchParams(location.search).get('tab') || 'overview';
        load(t, false);
    });
    window.DS = window.DS || {};
    window.DS.reloadTab = function () { return load(current, false); };
})();
