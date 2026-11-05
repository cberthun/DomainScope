<?php
/**
 * @var array $domain
 * @var array $checks  CertificateRepository::latestForDomain()
 * @var int $staleHours
 */
use DomainScope\Security\Csrf;
$warn = \DomainScope\Support\Settings::days('cert_warn_days');
?>
<section class="card">
    <div class="card-body">
        <form method="post" action="/domain/<?= e(rawurlencode($domain['name'])) ?>/run/tls" class="form-inline" data-ajax-run>
            <?= Csrf::field() ?>
            <label class="field grow"><span>Host (leer = Domain und www)</span>
                <input class="input mono" type="text" name="host" placeholder="<?= e($domain['name']) ?>" maxlength="253" spellcheck="false"></label>
            <label class="field"><span>Port</span>
                <select class="select" name="port"><?php foreach ([443, 465, 993, 995, 8443] as $p): ?><option value="<?= $p ?>"><?= $p ?></option><?php endforeach; ?></select></label>
            <button class="btn btn-primary" type="submit"><?= icon('play') ?> Zertifikat prüfen</button>
        </form>
        <p class="muted small">Warnschwellen (Einstellungen): <?= e(implode(', ', $warn)) ?> Tage. Geprüft wird mit SNI, Hostnamen-Abgleich und Vertrauensprüfung gegen das CA-Bundle.</p>
    </div>
</section>

<?php if (!$checks): ?>
    <div class="card"><div class="card-body"><?= ui_empty('lock', 'Noch keine TLS-Prüfung', 'Das Zertifikat wird per echtem TLS-Handshake abgerufen.') ?></div></div>
<?php endif; ?>

<?php foreach ($checks as $c):
    $d = $c['details'] ?: [];
    $cert = $d['certificate'] ?? null;
    $days = $c['not_after'] ? days_until($c['not_after'] . ' UTC') : null; ?>
    <section class="card tls-card tls-<?= e($c['status']) ?>">
        <header class="card-header">
            <h3 class="mono"><?= e($c['host']) ?>:<?= (int) $c['port'] ?></h3>
            <div class="row gap">
                <?php if ($c['status'] === 'ok'): ?><?= ui_pill('ok', 'Gültig') ?>
                <?php elseif ($c['status'] === 'invalid'): ?><?= ui_pill('fail', 'Zertifikatsproblem') ?>
                <?php else: ?><?= ui_pill('error', 'Nicht erreichbar') ?><?php endif; ?>
                <?= ui_freshness($c['checked_at'], $staleHours) ?>
            </div>
        </header>
        <div class="card-body">
            <?php if ($c['status'] === 'unreachable'): ?>
                <div class="alert alert-warn">Es konnte keine TLS-Verbindung aufgebaut werden (<?= e(match ($d['error_stage'] ?? '') { 'dns' => 'Namensauflösung', 'connect' => 'TCP-Verbindung', 'handshake' => 'TLS-Handshake', 'blocked' => 'Ziel gesperrt (SSRF-Schutz)', default => 'unbekannt' }) ?>): <?= e($c['error']) ?><br>
                    <span class="small">Das ist kein Zertifikatsbefund – der Host ist lediglich nicht über TLS erreichbar.</span></div>
            <?php else: ?>
                <?php if ($d['expired'] ?? false): ?><div class="alert alert-error">Das Zertifikat ist abgelaufen.</div><?php endif; ?>
                <?php if (($d['hostname_match'] ?? true) === false): ?><div class="alert alert-error">Der Hostname <span class="mono"><?= e($c['host']) ?></span> ist im Zertifikat nicht enthalten (weder SAN noch CN).</div><?php endif; ?>
                <?php if (($d['chain_trusted'] ?? true) === false): ?><div class="alert alert-error">Vertrauenskette ungültig: <?= e($d['trust_error'] ?? '') ?></div><?php endif; ?>
                <div class="grid grid-2">
                    <?= ui_kv([
                        ['Subject', copyable($c['subject'])],
                        ['Aussteller', copyable($c['issuer'])],
                        ['Seriennummer', copyable($c['serial'])],
                        ['SHA-256-Fingerprint', copyable(implode(':', str_split(strtoupper((string) $c['fingerprint_sha256']), 2)), implode(':', str_split(strtoupper((string) $c['fingerprint_sha256']), 2)))],
                        ['Gültig ab', '<span class="mono">' . e(fmt_dt($c['not_before'], 'd.m.Y H:i')) . ' ' . tz_label() . '</span>'],
                        ['Gültig bis', '<span class="mono">' . e(fmt_dt($c['not_after'], 'd.m.Y H:i')) . ' ' . tz_label() . '</span> ' . ui_days_badge($days)],
                    ], 'kv-compact') ?>
                    <?= ui_kv([
                        ['Öffentlicher Schlüssel', e(($c['key_type'] ?? '?') . ' ' . ($c['key_bits'] ?? '') . ' Bit' . (!empty($cert['key_curve']) ? ' (' . $cert['key_curve'] . ')' : ''))],
                        ['Signaturalgorithmus', e($c['signature_algorithm'] ?? '–')],
                        ['TLS-Protokoll', e($c['protocol'] ?? '–') . ($c['cipher'] ? ' · <span class="mono small">' . e($c['cipher']) . '</span>' : '')],
                        ['Hostname-Prüfung', ($d['hostname_match'] ?? null) === null ? '–' : (($d['hostname_match']) ? badge('passt', 'ok') : badge('passt nicht', 'fail'))],
                        ['Vertrauenskette', ($d['chain_trusted'] ?? null) === null ? '–' : (($d['chain_trusted']) ? badge('vertrauenswürdig', 'ok') : badge('nicht vertrauenswürdig', 'fail'))],
                        ['Verbindung', 'IP <a class="mono" href="/ip/' . e(rawurlencode((string) $c['ip'])) . '">' . e($c['ip']) . '</a> · ' . (int) ($d['ms'] ?? 0) . ' ms'],
                    ], 'kv-compact') ?>
                </div>
                <div class="subhead">Subject Alternative Names (<?= count($c['sans']) ?>)</div>
                <div class="chips"><?php foreach (array_slice($c['sans'], 0, 40) as $san): ?><span class="chip mono"><?= e($san) ?></span><?php endforeach; ?><?php if (count($c['sans']) > 40): ?><span class="muted small">+<?= count($c['sans']) - 40 ?> weitere</span><?php endif; ?></div>
                <?php if (!empty($d['chain'])): ?>
                    <div class="subhead">Zertifikatskette (vom Server geliefert: <?= count($d['chain']) ?>)</div>
                    <ol class="chain">
                        <?php foreach ($d['chain'] as $i => $ch): ?>
                            <li><span class="mono"><?= e($ch['subject']) ?></span>
                                <span class="muted small">ausgestellt von <?= e($ch['issuer_cn'] ?? $ch['issuer']) ?> · gültig bis <?= e(fmt_dt($ch['not_after'], 'd.m.Y')) ?> · <?= e($ch['key_type'] ?? '') ?> <?= e((string) ($ch['key_bits'] ?? '')) ?><?= $ch['self_signed'] ? ' · selbstsigniert' : '' ?><?= $ch['is_ca'] ? ' · CA' : '' ?></span></li>
                        <?php endforeach; ?>
                    </ol>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </section>
<?php endforeach; ?>
