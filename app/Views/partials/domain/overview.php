<?php
/**
 * @var array $domain
 * @var string $host
 * @var int $staleHours
 * @var ?array $registration
 * @var ?array $email
 * @var ?array $dnssec
 * @var array $tlsChecks
 * @var ?array $http
 * @var ?array $dnsSnap
 * @var array $ips
 * @var array $findings
 * @var int $subCount
 * @var ?array $consistency
 */
$base = '/domain/' . rawurlencode($domain['name']);
$never = $domain['last_checked_at'] === null;
?>
<?php if ($never): ?>
    <div class="alert alert-info">
        Für diese Domain liegen noch keine Prüfdaten vor. Mit „Alles prüfen“ werden DNS, RDAP, E-Mail-Sicherheit, TLS, DNSSEC, HTTP und IP-Daten abgerufen und gespeichert.
    </div>
<?php endif; ?>

<div class="grid grid-3">
    <section class="card">
        <header class="card-header"><h3><?= icon('file-text') ?> Registrierung</h3><a class="btn btn-ghost btn-sm" href="<?= e($base) ?>?tab=registration">Details</a></header>
        <div class="card-body">
            <?php if (!$registration): ?><p class="muted">Noch nicht abgerufen.</p><?= ui_run_button($domain, 'registration', 'Abrufen') ?>
            <?php else: $d = $registration; $days = days_until($d['expires_at'] ? $d['expires_at'] . ' UTC' : null); ?>
                <?= ui_kv([
                    ['Registrar', e($d['registrar'] ?? '–')],
                    ['Registriert', e(fmt_dt($d['registered_at'], 'd.m.Y'))],
                    ['Läuft ab', e(fmt_dt($d['expires_at'], 'd.m.Y')) . ' ' . ui_days_badge($days)],
                    ['Quelle', badge(strtoupper($d['source']), 'info') . ' ' . ui_freshness($d['fetched_at'], $staleHours)],
                ], 'kv-compact') ?>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <header class="card-header"><h3><?= icon('network') ?> DNS</h3><a class="btn btn-ghost btn-sm" href="<?= e($base) ?>?tab=dns">Details</a></header>
        <div class="card-body">
            <?php if (!$dnsSnap): ?><p class="muted">Noch kein Snapshot.</p><?= ui_run_button($domain, 'dns', 'Snapshot erstellen') ?>
            <?php else:
                $recs = \DomainScope\Repositories\DnsSnapshotRepository::records((int) $dnsSnap['id']); ?>
                <?= ui_kv([
                    ['A', ui_record_values($recs, 'A')], ['AAAA', ui_record_values($recs, 'AAAA')],
                    ['NS', ui_record_values($recs, 'NS')], ['MX', ui_record_values($recs, 'MX')],
                    ['Snapshot', ui_freshness($dnsSnap['taken_at'], $staleHours)],
                ], 'kv-compact') ?>
                <?php if ($consistency && $consistency['status'] === 'warn'): ?><div class="alert alert-warn small"><?= e($consistency['summary']) ?></div><?php endif; ?>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <header class="card-header"><h3><?= icon('shield-check') ?> DNSSEC</h3><a class="btn btn-ghost btn-sm" href="<?= e($base) ?>?tab=dnssec">Details</a></header>
        <div class="card-body">
            <?php if (!$dnssec): ?><p class="muted">Noch nicht geprüft.</p><?= ui_run_button($domain, 'dnssec', 'Prüfen') ?>
            <?php else: $a = $dnssec['data'];
                $labels = ['signed' => 'Signiert, Kette konsistent', 'unsigned' => 'Nicht signiert', 'broken' => 'Gebrochene Kette', 'dnskey_only' => 'DNSKEY ohne DS', 'present' => 'Records vorhanden']; ?>
                <p><?= ui_pill($dnssec['status'], $labels[$a['state']] ?? $a['state']) ?></p>
                <?php if ($a['state'] === 'signed'): ?>
                    <p class="muted small">Validierung: <?= e(match ($a['validation']['level']) {
                        'partial_local_plus_resolver' => 'DS↔DNSKEY und DNSKEY-Signatur lokal geprüft; Resolver bestätigen (AD)',
                        'partial_local' => 'DS↔DNSKEY und DNSKEY-Signatur lokal geprüft',
                        'resolver_only' => 'nur durch Resolver-AD-Flag bestätigt', default => 'nur Records ausgelesen' }) ?></p>
                <?php endif; ?>
                <?= ui_freshness($dnssec['checked_at'], $staleHours) ?>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <header class="card-header"><h3><?= icon('mail') ?> E-Mail-Sicherheit</h3><a class="btn btn-ghost btn-sm" href="<?= e($base) ?>?tab=email">Details</a></header>
        <div class="card-body">
            <?php if (!$email): ?><p class="muted">Noch nicht geprüft.</p><?= ui_run_button($domain, 'email', 'Prüfen') ?>
            <?php else: ?>
                <ul class="status-list">
                    <?php foreach ($email['data']['checks'] as $id => $c): ?>
                        <li><span><?= e($c['title']) ?></span><?= ui_pill($c['status']) ?></li>
                    <?php endforeach; ?>
                </ul>
                <?= ui_freshness($email['checked_at'], $staleHours) ?>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <header class="card-header"><h3><?= icon('lock') ?> TLS-Zertifikate</h3><a class="btn btn-ghost btn-sm" href="<?= e($base) ?>?tab=tls">Details</a></header>
        <div class="card-body">
            <?php if (!$tlsChecks): ?><p class="muted">Noch nicht geprüft.</p><?= ui_run_button($domain, 'tls', 'Prüfen') ?>
            <?php else: ?>
                <ul class="status-list">
                    <?php foreach ($tlsChecks as $c): ?>
                        <li><span class="mono"><?= e($c['host']) ?></span>
                            <?php if ($c['status'] === 'unreachable'): ?><?= ui_pill('error', 'nicht erreichbar') ?>
                            <?php else: ?><?= ui_days_badge($c['not_after'] ? days_until($c['not_after'] . ' UTC') : null) ?> <?= $c['status'] === 'invalid' ? badge('Befund', 'fail') : '' ?><?php endif; ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </section>

    <section class="card">
        <header class="card-header"><h3><?= icon('globe') ?> HTTP & Infrastruktur</h3><a class="btn btn-ghost btn-sm" href="<?= e($base) ?>?tab=http">Details</a></header>
        <div class="card-body">
            <?= ui_kv([
                ['HTTPS', $http ? ($http['data']['https']['reachable'] ? badge('HTTP ' . $http['data']['https']['status'], $http['data']['https']['status'] < 400 ? 'ok' : 'warn') : badge('nicht erreichbar', 'unknown')) : '<span class="muted">nicht geprüft</span>'],
                ['Subdomains', '<a href="' . e($base) . '?tab=subdomains">' . $subCount . ' (passiv)</a>'],
                ['IP-Adressen', '<a href="' . e($base) . '?tab=ips">' . count(array_unique(array_column($ips, 'address'))) . '</a>'],
            ], 'kv-compact') ?>
        </div>
    </section>
</div>

<section class="card">
    <header class="card-header"><h3><?= icon('alert-triangle') ?> Offene Findings</h3><a class="btn btn-ghost btn-sm" href="<?= e($base) ?>?tab=findings">Alle</a></header>
    <div class="card-body flush">
        <?php if (!$findings): ?>
            <?= ui_empty('circle-check', 'Keine offenen Findings', $never ? 'Es wurde noch keine Prüfung durchgeführt.' : 'Bei der letzten Auswertung wurden keine Befunde festgestellt.') ?>
        <?php else: ?>
            <ul class="problem-list">
                <?php foreach ($findings as $f): ?>
                    <li><?= sev_badge($f['severity']) ?> <a href="/findings/<?= (int) $f['id'] ?>"><?= e($f['title']) ?></a> <span class="muted small"><?= e($f['category']) ?></span></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </div>
</section>
