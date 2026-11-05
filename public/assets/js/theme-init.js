/* Läuft vor dem Rendern: verhindert Flackern bei Theme/Sidebar-Zustand. */
(function () {
    try {
        var t = localStorage.getItem('ds-theme');
        if (!t) { t = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'; }
        document.documentElement.setAttribute('data-theme', t === 'light' ? 'light' : 'dark');
        if (localStorage.getItem('ds-sidebar') === 'collapsed') { document.documentElement.classList.add('sidebar-collapsed'); }
    } catch (e) { /* localStorage nicht verfügbar */ }
})();
