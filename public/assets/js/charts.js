/* Minimale SVG-Diagramme (Balken) für das Dashboard */
(function () {
    'use strict';
    var NS = 'http://www.w3.org/2000/svg';
    Array.prototype.forEach.call(document.querySelectorAll('[data-chart="bars"]'), function (el) {
        var values, labels;
        try { values = JSON.parse(el.getAttribute('data-values') || '[]'); labels = JSON.parse(el.getAttribute('data-labels') || '[]'); } catch (e) { return; }
        if (!values.length) return;
        var w = 280, h = 64, gap = 3, n = values.length, bw = (w - gap * (n - 1)) / n;
        var max = Math.max.apply(null, values.concat([1]));
        var svg = document.createElementNS(NS, 'svg');
        svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h); svg.setAttribute('preserveAspectRatio', 'none');
        svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Balkendiagramm: ' + values.join(', '));
        values.forEach(function (v, i) {
            var bh = Math.max(v > 0 ? 3 : 1, (v / max) * (h - 4));
            var r = document.createElementNS(NS, 'rect');
            r.setAttribute('class', 'bar'); r.setAttribute('x', i * (bw + gap)); r.setAttribute('y', h - bh);
            r.setAttribute('width', bw); r.setAttribute('height', bh); r.setAttribute('rx', 1.5);
            if (v === 0) r.setAttribute('opacity', '.25');
            var t = document.createElementNS(NS, 'title'); t.textContent = (labels[i] || '') + ': ' + v;
            r.appendChild(t); svg.appendChild(r);
        });
        el.appendChild(svg);
    });
})();
