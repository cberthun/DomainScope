<?php
/**
 * @var array $domain
 * @var ?array $registration  Zeile aus registration_snapshots (data dekodiert)
 * @var array $history
 * @var int $staleHours
 */
?>
<div class="toolbar">
    <form method="post" action="/rdap/<?= e(rawurlencode($domain['name'])) ?>/refresh" class="inline" data-ajax-run>
        <?= \DomainScope\Security\Csrf::field() ?>
        <button class="btn btn-primary btn-sm" type="submit"><?= icon('refresh') ?> Jetzt abrufen</button>
    </form>
</div>
<?php if (!$registration): ?>
    <div class="card"><div class="card-body"><?= ui_empty('file-text', 'Noch keine Registrierungsdaten', 'RDAP wird bevorzugt über die IANA-Bootstrap-Daten abgefragt; WHOIS dient als Fallback für TLDs ohne RDAP (Einstellungen).') ?></div></div>
<?php else:
    $d = $registration['data'];
    $days = days_until($registration['expires_at'] ? $registration['expires_at'] . ' UTC' : null); ?>
    <div class="grid grid-2">
        <section class="card">
            <header class="card-header"><h3>Registrierung</h3><?= ui_freshness($registration['fetched_at'], $staleHours) ?></header>
            <div class="card-body">
                <?= ui_kv([
                    ['Registrar', e($registration['registrar'] ?? '–') . (!empty($d['registrar_iana_id']) ? ' <span class="muted small">(IANA-ID ' . e($d['registrar_iana_id']) . ')</span>' : '')],
                    ['Registriert am', e(fmt_dt($registration['registered_at'], 'd.m.Y H:i')) . ' ' . tz_label()],
                    ['Letzte Änderung', e(fmt_dt($registration['changed_at'], 'd.m.Y H:i')) . ' ' . tz_label()],
                    ['Läuft ab am', e(fmt_dt($registration['expires_at'], 'd.m.Y H:i')) . ' ' . tz_label() . ' ' . ui_days_badge($days)],
                    ['Status', $registration['statuses'] ? implode(' ', array_map(static fn($s) => badge((string) $s, 'neutral'), $registration['statuses'])) : '<span class="muted">nicht angegeben</span>'],
                    ['DNSSEC (Registry)', $registration['dnssec_signed'] === null ? '<span class="muted">keine Angabe</span>' : ($registration['dnssec_signed'] ? badge('delegationSigned', 'ok') : badge('nicht signiert', 'neutral'))],
                    ['Quelle', badge(strtoupper($registration['source']), 'info') . ' <span class="mono small">' . e($registration['source_url'] ?? '') . '</span>'],
                    ['Abruf', e(fmt_dt($registration['fetched_at'], 'd.m.Y H:i:s')) . ' ' . tz_label()],
                ]) ?>
            </div>
        </section>
        <section class="card">
            <header class="card-header"><h3>Nameserver laut Registry</h3></header>
            <div class="card-body">
                <?php if ($registration['nameservers']): ?>
                    <ul class="plain-list"><?php foreach ($registration['nameservers'] as $ns): ?><li><?= copyable($ns) ?></li><?php endforeach; ?></ul>
                <?php else: ?><p class="muted">Keine Nameserver gemeldet.</p><?php endif; ?>
                <?php if (!empty($d['ds_data'])): ?>
                    <div class="subhead">DS-Daten (Registry)</div>
                    <ul class="plain-list"><?php foreach ($d['ds_data'] as $ds): ?><li><?= copyable($ds) ?></li><?php endforeach; ?></ul>
                <?php endif; ?>
            </div>
        </section>
    </div>

    <?php if (!empty($d['entities'])): ?>
    <section class="card">
        <header class="card-header"><h3>Kontakte / Entitäten</h3></header>
        <div class="card-body flush">
            <table class="table compact"><thead><tr><th>Rolle</th><th>Name</th><th>Hinweis</th></tr></thead><tbody>
            <?php foreach ($d['entities'] as $en): ?>
                <tr><td><?= e(implode(', ', $en['roles'])) ?></td><td><?= e($en['name'] ?? '–') ?><?= !empty($en['email']) ? ' · <span class="mono small">' . e($en['email']) . '</span>' : '' ?></td>
                    <td><?= !empty($en['redacted']) || ($en['name'] ?? null) === null ? badge('redigiert / nicht öffentlich', 'neutral') : '' ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
            <p class="muted small pad">Registrant-Daten sind aufgrund der DSGVO bei den meisten Registries redigiert oder werden nicht veröffentlicht.</p>
        </div>
    </section>
    <?php endif; ?>

    <?php if (!empty($d['events'])): ?>
    <section class="card">
        <header class="card-header"><h3>Registrierungsereignisse</h3></header>
        <div class="card-body flush">
            <table class="table compact"><thead><tr><th>Ereignis</th><th>Zeitpunkt (Ortszeit)</th><th>Quelle</th></tr></thead><tbody>
            <?php foreach ($d['events'] as $ev): ?>
                <tr><td><?= e($ev['action']) ?></td><td class="mono small"><?= e(fmt_dt($ev['date'], 'd.m.Y H:i:s')) ?></td><td><?= e(($ev['from'] ?? '') === 'registrar' ? 'Registrar' : 'Registry') ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        </div>
    </section>
    <?php endif; ?>

    <?php foreach (($d['notes'] ?? []) as $n): ?><div class="alert alert-info small"><?= e($n) ?></div><?php endforeach; ?>
    <?php if (!empty($d['raw'])): ?>
        <details class="card"><summary class="card-header">WHOIS-Rohdaten (unvertrauenswürdige Fremddaten, nur Anzeige)</summary><pre class="code"><?= e($d['raw']) ?></pre></details>
    <?php endif; ?>

    <?php if (count($history) > 1): ?>
    <section class="card">
        <header class="card-header"><h3>Verlauf der Registrierungsdaten</h3></header>
        <div class="card-body flush">
            <table class="table compact"><thead><tr><th>Abruf</th><th>Registrar</th><th>Läuft ab</th><th>Status</th><th>Nameserver</th></tr></thead><tbody>
            <?php foreach ($history as $h): ?>
                <tr><td class="mono small"><?= e(fmt_dt($h['fetched_at'], 'd.m.Y H:i')) ?></td><td><?= e($h['registrar'] ?? '–') ?></td>
                    <td class="mono small"><?= e(fmt_dt($h['expires_at'], 'd.m.Y')) ?></td><td class="small"><?= e(implode(', ', $h['statuses'])) ?></td>
                    <td class="small mono"><?= e(implode(', ', $h['nameservers'])) ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        </div>
    </section>
    <?php endif; ?>
<?php endif; ?>
