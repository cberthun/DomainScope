<?php
/**
 * @var string $ip
 * @var ?array $row
 * @var array $cls
 * @var array $domains
 * @var array $tls
 * @var ?string $error
 * @var int $staleHours
 */
use DomainScope\Security\Csrf;
$rdap = $row['rdap_data'] ?? null;
?>
<?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>
<section class="card domain-head">
    <div class="card-body domain-head-body">
        <div>
            <div class="domain-title mono"><?= e($ip) ?></div>
            <div class="muted small">IPv<?= str_contains($ip, ':') ? '6' : '4' ?> · <?= $cls['public'] ? badge('öffentlich', 'ok') : badge($cls['label'], 'warn') ?> <?= $row ? '· ' . ui_freshness($row['checked_at'], $staleHours) : '' ?></div>
        </div>
        <form method="post" action="/ip/<?= e(rawurlencode($ip)) ?>/refresh" class="inline"><?= Csrf::field() ?>
            <button class="btn btn-primary" type="submit"><?= icon('refresh') ?> Neu abfragen</button></form>
    </div>
</section>

<?php if (!$cls['public']): ?>
    <div class="alert alert-info">Diese Adresse ist <strong><?= e($cls['label']) ?></strong> und im öffentlichen Internet nicht routbar. BGP-, ASN- und RDAP-Daten existieren dafür nicht; es erfolgt keine Verbindung zu dieser Adresse (SSRF-Schutz).</div>
<?php endif; ?>

<?php if ($row): ?>
<div class="grid grid-2">
    <section class="card">
        <header class="card-header"><h3>Routing & ASN <span class="badge badge-info">BGP</span></h3></header>
        <div class="card-body">
            <?php if ($row['asn']): ?>
                <?= ui_kv([
                    ['Origin-AS', '<span class="mono">AS' . (int) $row['asn'] . '</span>'],
                    ['Organisation / Netzwerk', e($row['as_name'] ?? '–')],
                    ['Announced Präfix', copyable($row['prefix'] ?? '–')],
                    ['Land (Registry laut BGP-Zuordnung)', e($row['country'] ?? '–') . ' <span class="muted small">(' . e($row['registry'] ?? '') . ')</span>'],
                ], 'kv-compact') ?>
                <p class="muted small">Quelle: Team Cymru IP-to-ASN (DNS). Zeigt, welche AS die Adresse aktuell im BGP-Routing announced – nicht, wem die Adresse registriert ist.</p>
            <?php else: ?><p class="muted">Keine BGP-Origin-Daten ermittelt.</p><?php endif; ?>
        </div>
    </section>
    <section class="card">
        <header class="card-header"><h3>Registrierung <span class="badge badge-info">RDAP</span></h3></header>
        <div class="card-body">
            <?php if ($rdap): ?>
                <?= ui_kv([
                    ['Netzname', e($rdap['name'] ?? '–')],
                    ['Handle', e($rdap['handle'] ?? '–')],
                    ['Netzbereich', '<span class="mono">' . e($rdap['range'] ?? '–') . '</span>'],
                    ['CIDR', copyable($rdap['cidr'] ?? '–')],
                    ['Land (Registrierung)', e($rdap['country'] ?? '–')],
                    ['Inhaber / Kontakte', e(implode(', ', $rdap['registrant'] ?? []) ?: '–')],
                    ['Quelle', '<span class="mono small">' . e($rdap['source_url'] ?? '') . '</span>'],
                ], 'kv-compact') ?>
                <p class="muted small">Die Registrierung bei einem Regional Internet Registry sagt nichts über den aktuellen Betreiber oder Standort der Hardware aus.</p>
            <?php else: ?><p class="muted">Keine RDAP-Registrierungsdaten (nicht öffentlich oder Dienst nicht erreichbar).</p><?php endif; ?>
        </div>
    </section>
</div>

<section class="card">
    <header class="card-header"><h3>Reverse-DNS (PTR)</h3></header>
    <div class="card-body"><?= $row['reverse_dns'] ? copyable($row['reverse_dns']) : '<span class="muted">Kein PTR-Record gefunden.</span>' ?>
        <p class="muted small">Name: <span class="mono"><?= e((string) \DomainScope\Validation\IpClassifier::reverseName($ip)) ?></span></p></div>
</section>

<section class="card">
    <header class="card-header"><h3>Zugeordnete Domains & Hosts</h3></header>
    <div class="card-body flush">
        <?php if (!$domains): ?><p class="muted pad">Dieser Adresse sind keine gespeicherten Domains zugeordnet.</p><?php else: ?>
            <table class="table compact"><thead><tr><th>Host</th><th>Domain</th><th>Typ</th><th>Zuletzt gesehen</th></tr></thead><tbody>
            <?php foreach ($domains as $d): ?>
                <tr><td class="mono"><?= e($d['hostname']) ?></td><td><?= ui_domain_link($d['domain_name']) ?></td><td><span class="badge badge-type"><?= e($d['record_type']) ?></span></td><td class="small"><?= e(time_ago($d['last_seen'])) ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        <?php endif; ?>
    </div>
</section>

<?php if ($tls): ?>
<section class="card">
    <header class="card-header"><h3>Zertifikate, die von dieser Adresse ausgeliefert wurden</h3></header>
    <div class="card-body flush">
        <table class="table compact"><thead><tr><th>Host</th><th>Status</th><th>Läuft ab</th><th>Fingerprint</th></tr></thead><tbody>
        <?php foreach ($tls as $t): ?>
            <tr><td><a class="mono" href="/tls/<?= e(rawurlencode($t['domain_name'])) ?>"><?= e($t['host']) ?>:<?= (int) $t['port'] ?></a></td><td><?= e($t['status']) ?></td>
                <td class="mono small"><?= e(fmt_dt($t['not_after'], 'd.m.Y')) ?></td><td class="mono small"><?= e(substr((string) $t['fingerprint_sha256'], 0, 20)) ?>…</td></tr>
        <?php endforeach; ?>
        </tbody></table>
    </div>
</section>
<?php endif; ?>

<section class="card"><div class="card-body small muted">
    <strong>Datenquellen:</strong> <?= e(implode(' · ', $row['data_sources'] ?? [])) ?><br>
    <strong>Geolokalisierung:</strong> Wird bewusst nicht geschätzt. Länderangaben stammen aus Registry-/BGP-Daten und sind kein Beweis für den physischen Standort eines Servers.
</div></section>
<?php endif; ?>
