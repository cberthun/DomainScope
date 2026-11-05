<?php
/**
 * @var array $rows
 * @var int $staleHours
 */
echo \DomainScope\Support\View::partial('partials/domain_picker', ['action' => '/rdap', 'label' => 'Registrierung abrufen', 'placeholder' => 'Domain eingeben, z. B. example.com']);
?>
<section class="card">
    <header class="card-header"><h2>Registrierungsdaten gespeicherter Domains</h2></header>
    <div class="card-body flush">
        <?php if (!$rows): ?>
            <?= ui_empty('file-text', 'Noch keine Registrierungsdaten', 'RDAP-Endpunkte werden anhand der IANA-Bootstrap-Daten ermittelt; WHOIS ist ein optionaler Fallback.') ?>
        <?php else: ?>
            <?= ui_table_open('rdap-table', ['Domain', 'Registrar', 'Läuft ab', 'Restlaufzeit', 'Status', 'Quelle', 'Abruf']) ?>
            <?php foreach ($rows as $x): $days = $x['expires_at'] ? days_until($x['expires_at'] . ' UTC') : null; ?>
                <tr><td><a class="mono" href="/rdap/<?= e(rawurlencode($x['domain_name'])) ?>"><?= e($x['domain_name']) ?></a></td>
                    <td><?= e($x['registrar'] ?? '–') ?></td>
                    <td class="mono small" data-sort-value="<?= e((string) $x['expires_at']) ?>"><?= e(fmt_dt($x['expires_at'], 'd.m.Y')) ?></td>
                    <td data-sort-value="<?= $days ?? 99999 ?>"><?= ui_days_badge($days) ?></td>
                    <td class="small"><?= e(implode(', ', array_slice($x['statuses'], 0, 3))) ?></td>
                    <td><?= badge(strtoupper($x['source']), 'info') ?></td>
                    <td><?= ui_freshness($x['fetched_at'], $staleHours) ?></td></tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>
<section class="card"><div class="card-body small muted">
    <strong>Datenquellen:</strong> RDAP (bevorzugt) über die offiziellen IANA-Bootstrap-Daten (<span class="mono">data.iana.org/rdap</span>), je TLD der zuständige Endpunkt; bei „Thin“-Registries wird zusätzlich der Registrar-RDAP-Dienst abgefragt.
    WHOIS (Port 43) dient nur als Fallback für TLDs ohne RDAP und lässt sich in den Einstellungen abschalten. Registrant-Daten sind häufig redigiert; Rate-Limits der Registries werden beachtet und ausgewiesen.
</div></section>
