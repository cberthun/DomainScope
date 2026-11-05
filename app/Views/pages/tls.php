<?php
/**
 * @var array $checks
 * @var int[] $warn
 * @var int $staleHours
 */
echo \DomainScope\Support\View::partial('partials/domain_picker', ['action' => '/tls', 'label' => 'Zertifikat prüfen', 'placeholder' => 'Domain eingeben, z. B. example.com']);
?>
<section class="card">
    <div class="card-body">
        <form method="get" action="/tls/check" class="form-inline">
            <label class="field grow"><span>Einzelnen Host/Subdomain prüfen</span><input class="input mono" name="host" placeholder="mail.example.com" required maxlength="253" spellcheck="false"></label>
            <label class="field"><span>Port</span><select class="select" name="port"><?php foreach ([443, 465, 993, 995, 8443] as $p): ?><option><?= $p ?></option><?php endforeach; ?></select></label>
            <button class="btn" type="submit"><?= icon('lock') ?> Host prüfen</button>
        </form>
    </div>
</section>
<section class="card">
    <header class="card-header"><h2>Bekannte Zertifikate</h2><span class="muted small">Warnschwellen: <?= e(implode(' / ', $warn)) ?> Tage</span></header>
    <div class="card-body flush">
        <?php if (!$checks): ?>
            <?= ui_empty('lock', 'Noch keine Zertifikate erfasst', 'TLS-Prüfungen führen echte Handshakes durch und speichern Zertifikat, Kette und Protokoll.') ?>
        <?php else: ?>
            <?= ui_table_open('cert-table', ['Host', 'Status', 'Läuft ab', 'Restlaufzeit', 'Aussteller', 'Schlüssel', 'Protokoll', 'Geprüft']) ?>
            <?php foreach ($checks as $c): $days = $c['not_after'] ? days_until($c['not_after'] . ' UTC') : null; ?>
                <tr>
                    <td><a class="mono" href="/tls/<?= e(rawurlencode($c['domain_name'])) ?>"><?= e($c['host']) ?>:<?= (int) $c['port'] ?></a></td>
                    <td><?= match ($c['status']) { 'ok' => ui_pill('ok', 'gültig'), 'invalid' => ui_pill('fail', 'Problem'), default => ui_pill('error', 'nicht erreichbar') } ?></td>
                    <td class="mono small" data-sort-value="<?= e((string) $c['not_after']) ?>"><?= e(fmt_dt($c['not_after'], 'd.m.Y')) ?></td>
                    <td data-sort-value="<?= $days ?? 99999 ?>"><?= $c['status'] === 'unreachable' ? '–' : ui_days_badge($days) ?></td>
                    <td class="small"><?= e(preg_replace('/^.*CN=/', '', (string) $c['issuer'])) ?></td>
                    <td class="small mono"><?= e(trim(($c['key_type'] ?? '') . ' ' . ($c['key_bits'] ?? ''))) ?></td>
                    <td class="small mono"><?= e($c['protocol'] ?? '–') ?></td>
                    <td><?= ui_freshness($c['checked_at'], $staleHours) ?></td>
                </tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>
