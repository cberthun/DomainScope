/* Beziehungsgraph des Inventars: einfache Kräfte-Simulation in SVG (ohne Bibliothek) */
(function () {
    'use strict';
    var svg = document.getElementById('asset-graph'); if (!svg || !window.fetch) return;
    var NS = 'http://www.w3.org/2000/svg';
    var COLORS = { domain: '#5b8def', subdomain: '#7aa5ff', ip: '#3fb97c', server: '#e0a23c', vps: '#e0a23c', mailserver: '#d6336c', webserver: '#9a7fd1',
        reverse_proxy: '#9a7fd1', tunnel: '#e5534b', nameserver: '#4fb3bf', certificate: '#8e97a6', application: '#c9a227', external_service: '#8e97a6' };
    var focus = parseInt(svg.getAttribute('data-focus') || '0', 10);

    fetch(svg.getAttribute('data-src'), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            var wrap = svg.parentNode, empty = wrap.querySelector('.graph-empty');
            if (!data.nodes.length || !data.edges.length) { if (empty) empty.hidden = false; return; }
            var W = svg.clientWidth || 800, H = svg.clientHeight || 420;
            svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
            var byId = {};
            var nodes = data.nodes.filter(function (n) { return data.edges.some(function (e) { return e.from === n.id || e.to === n.id; }); });
            nodes.forEach(function (n, i) {
                var a = (i / nodes.length) * Math.PI * 2;
                n.x = W / 2 + Math.cos(a) * W * 0.3; n.y = H / 2 + Math.sin(a) * H * 0.3; n.vx = 0; n.vy = 0; byId[n.id] = n;
            });
            var edges = data.edges.filter(function (e) { return byId[e.from] && byId[e.to]; });

            var gE = document.createElementNS(NS, 'g'), gL = document.createElementNS(NS, 'g'), gN = document.createElementNS(NS, 'g');
            svg.appendChild(gE); svg.appendChild(gL); svg.appendChild(gN);
            var lines = edges.map(function (e) {
                var l = document.createElementNS(NS, 'line'); l.setAttribute('class', 'edge' + (e.confirmed ? '' : ' unconfirmed'));
                var t = document.createElementNS(NS, 'title'); t.textContent = e.relation + (e.confirmed ? ' (manuell bestätigt)' : ' (automatisch beobachtet)'); l.appendChild(t);
                gE.appendChild(l); return l;
            });
            var labels = edges.map(function (e) { var t = document.createElementNS(NS, 'text'); t.setAttribute('class', 'edge-label'); t.setAttribute('text-anchor', 'middle'); t.textContent = e.relation; gL.appendChild(t); return t; });
            var els = nodes.map(function (n) {
                var g = document.createElementNS(NS, 'g'); g.setAttribute('class', 'node' + (n.id === focus ? ' focus' : ''));
                var c = document.createElementNS(NS, 'circle'); c.setAttribute('r', n.id === focus ? 11 : 8); c.setAttribute('fill', COLORS[n.type] || '#8e97a6');
                var t = document.createElementNS(NS, 'text'); t.setAttribute('x', 13); t.setAttribute('y', 4); t.textContent = n.name.length > 28 ? n.name.slice(0, 27) + '…' : n.name;
                var tt = document.createElementNS(NS, 'title'); tt.textContent = n.name + ' (' + (data.types[n.type] || n.type) + ')' + (n.address ? ' – ' + n.address : '');
                g.appendChild(c); g.appendChild(t); g.appendChild(tt); gN.appendChild(g);
                g.addEventListener('click', function () { window.location.href = '/inventory/' + n.id; });
                // Ziehen
                g.addEventListener('pointerdown', function (ev) {
                    ev.preventDefault(); g.setPointerCapture(ev.pointerId); n.fixed = true; alpha = 0.6;
                    var move = function (m) { var p = pt(m); n.x = p.x; n.y = p.y; }, up = function () { n.fixed = false; g.removeEventListener('pointermove', move); g.removeEventListener('pointerup', up); };
                    g.addEventListener('pointermove', move); g.addEventListener('pointerup', up);
                });
                return g;
            });
            function pt(ev) { var r = svg.getBoundingClientRect(); return { x: (ev.clientX - r.left) * W / r.width, y: (ev.clientY - r.top) * H / r.height }; }

            var alpha = 1, ticks = 0;
            function step() {
                var i, j, a, b, dx, dy, d2, d, f;
                for (i = 0; i < nodes.length; i++) for (j = i + 1; j < nodes.length; j++) {
                    a = nodes[i]; b = nodes[j]; dx = b.x - a.x; dy = b.y - a.y; d2 = dx * dx + dy * dy + 0.01; d = Math.sqrt(d2);
                    f = 2600 / d2; dx = dx / d * f; dy = dy / d * f; a.vx -= dx; a.vy -= dy; b.vx += dx; b.vy += dy;
                }
                edges.forEach(function (e) {
                    a = byId[e.from]; b = byId[e.to]; dx = b.x - a.x; dy = b.y - a.y; d = Math.sqrt(dx * dx + dy * dy) || 1;
                    f = (d - 110) * 0.02; dx = dx / d * f; dy = dy / d * f; a.vx += dx; a.vy += dy; b.vx -= dx; b.vy -= dy;
                });
                nodes.forEach(function (n) {
                    n.vx += (W / 2 - n.x) * 0.004; n.vy += (H / 2 - n.y) * 0.004;
                    if (!n.fixed) { n.x += n.vx * alpha; n.y += n.vy * alpha; }
                    n.vx *= 0.82; n.vy *= 0.82;
                    n.x = Math.max(16, Math.min(W - 16, n.x)); n.y = Math.max(16, Math.min(H - 16, n.y));
                });
            }
            function draw() {
                nodes.forEach(function (n, i) { els[i].setAttribute('transform', 'translate(' + n.x.toFixed(1) + ',' + n.y.toFixed(1) + ')'); });
                edges.forEach(function (e, i) {
                    var a = byId[e.from], b = byId[e.to];
                    lines[i].setAttribute('x1', a.x); lines[i].setAttribute('y1', a.y); lines[i].setAttribute('x2', b.x); lines[i].setAttribute('y2', b.y);
                    labels[i].setAttribute('x', (a.x + b.x) / 2); labels[i].setAttribute('y', (a.y + b.y) / 2 - 3);
                });
            }
            function loop() {
                step(); draw(); alpha = Math.max(0.05, alpha * 0.985); ticks++;
                if (ticks < 600 || alpha > 0.06) requestAnimationFrame(loop);
            }
            if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) { for (var k = 0; k < 300; k++) step(); draw(); } else { loop(); }
        })
        .catch(function () { var e = svg.parentNode.querySelector('.graph-empty'); if (e) { e.textContent = 'Graph konnte nicht geladen werden.'; e.hidden = false; } });
})();
