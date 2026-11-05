<?php
/**
 * @var array $domain
 * @var ?array $email  Zeile aus module_results (data = EmailSecurityService::run)
 * @var int $staleHours
 */
use DomainScope\Security\Csrf;
$sel = $domain['dkim_selectors'] ?? '';
?>
<section class="card">
    <div class="card-body">
        <form method="post" action="/domain/<?= e(rawurlencode($domain['name'])) ?>/run/email" class="form-inline" data-ajax-run>
            <?= Csrf::field() ?>
            <label class="field grow"><span>Bekannte DKIM-Selektoren (kommagetrennt)</span>
                <input class="input mono" type="text" name="selectors" value="<?= e($sel) ?>" placeholder="z. B. google, selector1, s1" maxlength="500" spellcheck="false"></label>
            <label class="check" title="Prüft zusätzlich eine begrenzte Liste (~30) gängiger Selektornamen. Ein Nichtfund beweist nicht, dass kein DKIM existiert."><input type="checkbox" name="autoscan" value="1" <?= \DomainScope\Support\Settings::bool('dkim_autoscan') ? 'checked' : '' ?>> Begrenzte Selektor-Suche</label>
            <button class="btn btn-primary" type="submit"><?= icon('play') ?> Prüfen</button>
        </form>
    </div>
</section>

<?php if (!$email): ?>
    <div class="card"><div class="card-body"><?= ui_empty('mail', 'Noch keine E-Mail-Prüfung', 'SPF, DKIM, DMARC, MX/PTR, MTA-STS, TLS-RPT und BIMI werden live über DNS und HTTPS ausgewertet.') ?></div></div>
<?php else:
    $r = $email['data']; $checks = $r['checks']; ?>
    <div class="summary-bar">
        <?= ui_freshness($email['checked_at'], $staleHours) ?>
        <span class="pill pill-ok"><?= (int) $r['tally']['pass'] ?> in Ordnung</span>
        <span class="pill pill-warn"><?= (int) $r['tally']['warn'] ?> Warnungen</span>
        <span class="pill pill-fail"><?= (int) $r['tally']['fail'] ?> Fehler</span>
        <span class="pill pill-neutral"><?= (int) $r['tally']['none'] ?> nicht konfiguriert</span>
        <?php if (!empty($r['tally']['error'])): ?><span class="pill pill-unknown"><?= (int) $r['tally']['error'] ?> nicht prüfbar</span><?php endif; ?>
        <span class="muted small"><?= (int) $r['dns_queries'] ?> DNS-Abfragen · <?= (int) $r['duration_ms'] ?> ms</span>
    </div>
    <?php if (!($r['receives_mail'] ?? true)): ?>
        <div class="alert alert-info small">Die Domain scheint keine E-Mails zu empfangen (Null-MX oder kein MX/A-Record). Fehlende Absender-Policies werden dann niedriger bewertet; ein „v=spf1 -all“ und ein DMARC-Record mit p=reject schützen vor Missbrauch als Absenderdomain.</div>
    <?php endif; ?>

    <?php
    // SPF mit Lookup-Zähler und Baum
    $spf = $checks['spf'];
    echo ui_check_card($spf);
    if (!empty($spf['tree'])): ?>
        <details class="card"><summary class="card-header">SPF-Auflösung: Include-/Redirect-Baum (<?= (int) $spf['lookups'] ?> von 10 Lookups)</summary>
            <div class="card-body">
                <div class="meter" role="img" aria-label="<?= (int) $spf['lookups'] ?> von 10 DNS-Lookups"><span class="meter-fill <?= $spf['lookups'] > 10 ? 'meter-fail' : ($spf['lookups'] >= 9 ? 'meter-warn' : 'meter-ok') ?>" style="width: <?= min(100, (int) $spf['lookups'] * 10) ?>%"></span></div>
                <?= ui_spf_tree($spf['tree']) ?>
            </div>
        </details>
    <?php endif;

    // DKIM-Selektoren
    $dkim = $checks['dkim'];
    echo ui_check_card($dkim);
    if (!empty($dkim['selectors'])): ?>
        <details class="card" <?= $dkim['found'] ? 'open' : '' ?>><summary class="card-header">DKIM-Selektoren (<?= count($dkim['selectors']) ?>)</summary>
            <div class="card-body flush">
                <table class="table compact"><thead><tr><th>Selektor</th><th>Ergebnis</th><th>Schlüssel</th><th>Flags</th></tr></thead><tbody>
                <?php foreach ($dkim['selectors'] as $s): ?>
                    <tr><td class="mono"><?= e($s['selector']) ?></td>
                        <td><?= match ($s['state'] ?? '') { 'found' => badge('gefunden', 'ok'), 'missing' => badge('nicht vorhanden', 'neutral'), default => badge('Abfragefehler', 'unknown') } ?></td>
                        <td class="mono small"><?php if (!empty($s['key'])): ?><?= e(strtoupper((string) $s['key']['type'])) ?> <?= $s['key']['bits'] ? (int) $s['key']['bits'] . ' Bit' : '' ?> · FP <?= e($s['key']['fingerprint'] ?? '') ?><?= !empty($s['key']['revoked']) ? ' (widerrufen)' : '' ?><?php endif; ?></td>
                        <td class="mono small"><?= e(isset($s['tags']['t']) ? 't=' . $s['tags']['t'] : '') ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
            </div>
        </details>
    <?php endif;

    echo ui_check_card($checks['dmarc']);

    // MX / PTR
    $mx = $checks['mx'];
    echo ui_check_card($mx);
    if (!empty($mx['hosts'])): ?>
        <details class="card" open><summary class="card-header">Mailserver & Reverse-DNS</summary>
            <div class="card-body flush">
                <table class="table compact"><thead><tr><th class="num">Prio</th><th>Host</th><th>Adressen</th><th>PTR / FCrDNS</th></tr></thead><tbody>
                <?php foreach ($mx['hosts'] as $h): ?>
                    <tr><td class="num mono"><?= (int) $h['priority'] ?></td><td class="mono"><?= e($h['host']) ?></td>
                        <td><?= $h['addresses'] ? implode('<br>', array_map(static fn($a) => '<a class="mono" href="/ip/' . e(rawurlencode($a)) . '">' . e($a) . '</a>', $h['addresses'])) : '<span class="muted">–</span>' ?></td>
                        <td class="small"><?php foreach ($h['ptr'] as $p): ?><div><span class="mono"><?= e(implode(', ', $p['names']) ?: 'kein PTR') ?></span> <?= $p['names'] ? ($p['fcrdns'] ? badge('FCrDNS ✓', 'ok') : badge('FCrDNS ✗', 'warn')) : badge('fehlt', 'neutral') ?></div><?php endforeach; ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
            </div>
        </details>
    <?php endif;

    echo ui_check_card($checks['mta-sts']);
    echo ui_check_card($checks['tls-rpt']);
    echo ui_check_card($checks['bimi']);
    ?>
    <section class="card">
        <header class="card-header"><h3>Hinweise zur Aussagekraft</h3></header>
        <div class="card-body"><ul class="plain-list small"><?php foreach ($r['limitations'] as $l): ?><li><?= icon('info') ?> <?= e($l) ?></li><?php endforeach; ?></ul>
            <p class="muted small">„Technischer Befund“ bezeichnet einen Verstoß gegen Standards bzw. Fehlkonfiguration, „Best Practice“ eine optionale Empfehlung. Fehlende optionale Features gelten nicht als Sicherheitslücke.</p></div>
    </section>
<?php endif; ?>
