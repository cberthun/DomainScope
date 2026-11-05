/* DNS Explorer: Typauswahl, Ergebnisfilter nach Status */
(function () {
    'use strict';
    var form = document.getElementById('dns-form'); if (!form) return;
    var common = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
    form.addEventListener('click', function (e) {
        var b = e.target.closest('[data-types]'); if (!b) return;
        var all = b.getAttribute('data-types') === 'all';
        Array.prototype.forEach.call(form.querySelectorAll('input[name="types[]"]'), function (c) {
            c.checked = all ? true : common.indexOf(c.value) !== -1;
        });
    });
    // Mindestens ein Typ und ein Resolver müssen gewählt sein
    form.addEventListener('submit', function (e) {
        if (!form.querySelector('input[name="types[]"]:checked')) { e.preventDefault(); form.querySelector('input[name="types[]"]').checked = true; form.requestSubmit(); }
    });
})();
