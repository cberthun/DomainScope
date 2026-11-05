<?php
/**
 * @var array $domain
 * @var array $subdomains
 * @var array $scans
 */
use DomainScope\Security\Csrf;
$base = '/subdomains/' . rawurlencode($domain['name']);
$present = array_filter($subdomains, static fn($s) => $s['status'] === 'present');
?>
<section class="card">
    <div class="card-body">
        <form method="post" action="<?= e($base) ?>/scan" class="form-inline" data-ajax-run>
            <?= Csrf::field() ?>
            <label class="check"><input type="checkbox" name="resolve" value="1" checked> Gefundene Hosts per DNS auflösen (begrenzt auf <?= \DomainScope\Support\Settings::int('subdomain_resolve_limit') ?>)</label>
            <button class="btn btn-primary" type="submit"><?= icon('play') ?> Passiven Scan starten</button>
            <?php if ($subdomains): ?>
                <a class="btn" href="<?= e($base) ?>/export?format=csv"><?= icon('download') ?> CSV</a>
                <a class="btn" href="<?= e($base) ?>/export?format=json"><?= icon('download') ?> JSON</a>
            <?php endif; ?>
        </form>
        <p class="muted small">Quellen: Certificate-Transparency-Logs (crt.sh, Cert Spotter). Es werden keine Verbindungen zur Zieldomain aufgebaut und keine Namen durchprobiert. <strong>Ein passiver Fund beweist nicht, dass die Subdomain aktuell existiert oder erreichbar ist.</strong></p>
    </div>
</section>

<?php if (!$subdomains): ?>
    <div class="card"><div class="card-body"><?= ui_empty('git-branch', 'Noch keine Subdomains erfasst', 'Starten Sie einen passiven Scan über Certificate-Transparency-Daten.') ?></div></div>
<?php else: ?>
    <section class="card">
        <header class="card-header"><h3><?= count($present) ?> Subdomains <span class="muted small">(<?= count($subdomains) - count($present) ?> nicht mehr gefunden)</span></h3>
            <div class="chips">
                <button type="button" class="chip chip-btn" data-filter-col="status" data-filter-val="">Alle</button>
                <button type="button" class="chip chip-btn" data-filter-col="status" data-filter-val="neu">Neu</button>
                <button type="button" class="chip chip-btn" data-filter-col="status" data-filter-val="nicht mehr gefunden">Nicht mehr gefunden</button>
            </div>
        </header>
        <div class="card-body flush">
            <?= ui_table_open('sub-table', ['Hostname', 'Status', 'Auflösung', 'IP-Adressen', 'Quellen', 'Zert. bis', 'Zuerst gesehen', 'Zuletzt gesehen']) ?>
            <?php foreach ($subdomains as $s): ?>
                <tr>
                    <td class="mono"><a href="/domain/<?= e(rawurlencode($domain['name'])) ?>?host=<?= e(rawurlencode($s['hostname'])) ?>"><?= e($s['hostname']) ?></a></td>
                    <td data-col="status"><?= $s['status'] === 'missing' ? badge('nicht mehr gefunden', 'warn') : ($s['is_new'] ? badge('neu', 'info') : badge('gefunden', 'neutral')) ?></td>
                    <td><?= match ($s['resolved_status'] ?? '') {
                        'resolves' => badge('löst auf', 'ok'), 'nxdomain' => badge('NXDOMAIN', 'neutral'), 'dangling_cname' => badge('CNAME ohne Ziel', 'warn'),
                        'nodata' => badge('keine A/AAAA', 'neutral'), 'error' => badge('Fehler', 'unknown'), default => '<span class="muted small">nicht aufgelöst</span>' } ?>
                        <?= $s['resolved_cname'] ? '<div class="small mono muted">→ ' . e($s['resolved_cname']) . '</div>' : '' ?></td>
                    <td class="small mono"><?= $s['resolved_ips'] ? implode('<br>', array_map(static fn($ip) => '<a href="/ip/' . e(rawurlencode($ip)) . '">' . e($ip) . '</a>', array_slice($s['resolved_ips'], 0, 4))) : '–' ?></td>
                    <td class="small"><?= e(implode(', ', $s['sources'])) ?></td>
                    <td class="mono small"><?= e(fmt_dt($s['cert_not_after'], 'd.m.Y')) ?></td>
                    <td class="mono small"><?= e(fmt_dt($s['first_seen'], 'd.m.Y')) ?></td>
                    <td class="mono small"><?= e(fmt_dt($s['last_seen'], 'd.m.Y')) ?></td>
                </tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        </div>
    </section>
<?php endif; ?>

<?php if ($scans): ?>
<section class="card">
    <header class="card-header"><h3>Scan-Verlauf (Vergleich zwischen Scans)</h3></header>
    <div class="card-body flush">
        <table class="table compact"><thead><tr><th>Zeit</th><th>Quellen</th><th class="num">Gefunden</th><th class="num">Neu</th><th class="num">Nicht mehr gefunden</th><th>Hinweise</th></tr></thead><tbody>
        <?php foreach ($scans as $sc): ?>
            <tr><td class="mono small"><?= e(fmt_dt($sc['scanned_at'], 'd.m.Y H:i')) ?></td><td class="small"><?= e(implode(', ', $sc['sources'])) ?></td>
                <td class="num"><?= (int) $sc['found_count'] ?></td><td class="num"><?= (int) $sc['new_count'] ?></td><td class="num"><?= (int) $sc['missing_count'] ?></td>
                <td class="small"><?= $sc['errors'] ? badge('Teilfehler: ' . implode(', ', array_keys($sc['errors'])), 'warn') : '' ?></td></tr>
        <?php endforeach; ?>
        </tbody></table>
        <p class="muted small pad">„Nicht mehr gefunden“ wird nur bewertet, wenn alle Quellen im Scan erfolgreich waren.</p>
    </div>
</section>
<?php endif; ?>

<?php $tk = $takeover['data']['hosts'] ?? []; if ($tk): ?>
<section class="card">
    <header class="card-header"><h3>Subdomain-Takeover-Prüfung</h3><span class="muted small"><?= ui_freshness($takeover['checked_at']) ?></span></header>
    <div class="card-body flush">
        <table class="table compact"><thead><tr><th>Host</th><th>CNAME-Ziel</th><th>Anbieter</th><th>Ergebnis</th><th>Begründung</th></tr></thead><tbody>
        <?php foreach ($tk as $host => $t): ?>
            <tr><td class="mono"><?= e($host) ?></td><td class="mono small"><?= e($t['cname']) ?></td><td class="small"><?= e($t['provider'] ?? '–') ?></td>
                <td><?= match ($t['status']) { 'vulnerable' => badge('mögliche Übernahme', 'fail'), 'dangling' => badge('Ziel existiert nicht', 'warn'), 'provider' => badge('Anbieter, unauffällig', 'ok'), default => badge('kein Befund', 'neutral') } ?></td>
                <td class="small"><?= e($t['evidence']) ?></td></tr>
        <?php endforeach; ?>
        </tbody></table>
        <p class="muted small pad">Indizien, kein Ausnutzbarkeitsnachweis: Geprüft werden NXDOMAIN des CNAME-Ziels und typische Fehlerseiten bekannter Anbieter (<?= count(\DomainScope\Services\Subdomains\TakeoverChecker::PROVIDERS) ?> Anbieter-Muster; max. 25 Hosts je Scan).</p>
    </div>
</section>
<?php endif; ?>

<?php if (!empty($ct)): ?>
<section class="card">
    <header class="card-header"><h3>Certificate-Transparency-Zertifikate <span class="count"><?= count($ct) ?></span></h3></header>
    <div class="card-body flush">
        <?= ui_table_open('ct-table', ['Erkannt', 'Aussteller', 'Namen', 'Gültig ab', 'Gültig bis', 'Seriennummer', 'Status']) ?>
        <?php foreach ($ct as $c): ?>
            <tr><td class="small" data-sort-value="<?= e($c['first_seen']) ?>"><?= e(fmt_dt($c['first_seen'], 'd.m.Y')) ?></td>
                <td class="small"><?= e($c['issuer']) ?></td>
                <td class="small mono"><?= e(implode(', ', array_slice($c['names_list'], 0, 3))) ?><?= count($c['names_list']) > 3 ? ' +' . (count($c['names_list']) - 3) : '' ?></td>
                <td class="mono small"><?= e(fmt_dt($c['not_before'], 'd.m.Y')) ?></td><td class="mono small"><?= e(fmt_dt($c['not_after'], 'd.m.Y')) ?></td>
                <td class="mono small"><?= e(substr((string) $c['serial'], 0, 16)) ?>…</td>
                <td><?= $c['baseline'] ? badge('Ausgangsbestand', 'neutral') : ($c['known_issuer'] ? badge('neu', 'info') : badge('neu · unbekannte CA', 'warn')) ?></td></tr>
        <?php endforeach; ?>
        <?= ui_table_close() ?>
        <p class="muted small pad">Der erste Scan bildet den Ausgangsbestand. Neue Zertifikate werden als Finding gemeldet; von einer für die Domain bisher unbekannten CA ausgestellte mit höherer Stufe.</p>
    </div>
</section>
<?php endif; ?>
