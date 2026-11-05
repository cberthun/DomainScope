<?php
/**
 * @var array $domain
 * @var ?array $dnssec  Zeile aus module_results (data = DnssecService::analyze)
 * @var int $staleHours
 */
$stateLabels = ['signed' => 'Signiert – DS und DNSKEY konsistent', 'unsigned' => 'Nicht signiert', 'broken' => 'Gebrochene Vertrauenskette', 'dnskey_only' => 'DNSKEY ohne DS im Parent', 'present' => 'Records vorhanden (Digest nicht prüfbar)'];
$valLabels = [
    'none' => 'Keine DNSSEC-Validierung anwendbar (Zone nicht signiert).',
    'records_only' => 'Es wurden nur Records ausgelesen. Eine erfolgreiche Validierung wird nicht behauptet.',
    'resolver_only' => 'Die Validierung wurde ausschließlich von öffentlichen Resolvern bestätigt (AD-Flag). Lokal wurde keine Signatur geprüft.',
    'partial_local' => 'Lokal kryptografisch geprüft: DS↔DNSKEY-Digest und die Signatur über das DNSKEY-RRset. Die Kette bis zur Root wurde nicht lokal geprüft.',
    'partial_local_plus_resolver' => 'Lokal kryptografisch geprüft: DS↔DNSKEY-Digest und die Signatur über das DNSKEY-RRset. Zusätzlich bestätigen validierende Resolver (AD-Flag) die gesamte Kette bis zur Root – diese Aussage ist resolverabhängig.',
];
?>
<div class="toolbar">
    <?= ui_run_button($domain, 'dnssec', 'DNSSEC jetzt prüfen', [], 'btn btn-primary btn-sm', 'play') ?>
</div>
<?php if (!$dnssec): ?>
    <div class="card"><div class="card-body"><?= ui_empty('shield-check', 'Noch keine DNSSEC-Prüfung', 'Geprüft werden DS, DNSKEY, RRSIG, NSEC/NSEC3 sowie Parent-/Child-Delegation mit direkten Abfragen der autoritativen Nameserver.') ?></div></div>
<?php else:
    $a = $dnssec['data']; ?>
    <section class="card">
        <header class="card-header"><h3>Ergebnis für <span class="mono"><?= e($a['zone']) ?></span></h3><?= ui_freshness($dnssec['checked_at'], $staleHours) ?></header>
        <div class="card-body stack-sm">
            <p><?= ui_pill($dnssec['status'], $stateLabels[$a['state']] ?? $a['state']) ?></p>
            <div class="layers">
                <div class="layer <?= ($a['ds'] || $a['dnskey']) ? 'layer-on' : '' ?>"><strong>1 · Records vorhanden</strong><span><?= count($a['ds']) ?> DS · <?= count($a['dnskey']) ?> DNSKEY · <?= count($a['rrsig']) ?> RRSIG</span></div>
                <div class="layer <?= $a['state'] === 'signed' ? 'layer-on' : '' ?>"><strong>2 · Konfiguration plausibel</strong><span><?= $a['state'] === 'signed' ? 'DS passt zu einem DNSKEY, Algorithmen zulässig' : 'nicht erfüllt / nicht anwendbar' ?></span></div>
                <div class="layer <?= str_starts_with($a['validation']['level'], 'partial') ? 'layer-on' : '' ?>"><strong>3 · Kryptografisch validiert</strong><span><?= str_starts_with($a['validation']['level'], 'partial') ? 'DNSKEY-RRset lokal verifiziert' : 'nicht lokal verifiziert' ?></span></div>
            </div>
            <p class="small"><?= icon('info') ?> <?= e($valLabels[$a['validation']['level']] ?? '') ?></p>
        </div>
    </section>

    <?php if ($a['findings']): ?>
    <section class="card">
        <header class="card-header"><h3>Befunde</h3></header>
        <div class="card-body"><ul class="check-findings">
            <?php foreach ($a['findings'] as $f): $ic = ['fail' => 'circle-x', 'warn' => 'alert-triangle', 'info' => 'info'][$f['level']] ?? 'info'; ?>
                <li class="cf cf-<?= e($f['level']) ?>"><?= icon($ic) ?><div><div><?= e($f['message']) ?></div><?php if (!empty($f['recommendation'])): ?><div class="cf-meta"><strong>Empfehlung:</strong> <?= e($f['recommendation']) ?></div><?php endif; ?></div></li>
            <?php endforeach; ?>
        </ul></div>
    </section>
    <?php endif; ?>

    <div class="grid grid-2">
        <section class="card">
            <header class="card-header"><h3>DS-Records (Parent)</h3></header>
            <div class="card-body flush">
                <?php if (!$a['ds']): ?><p class="muted pad">Kein DS-Record im Parent gefunden.</p><?php else: ?>
                    <table class="table compact"><thead><tr><th>Key-Tag</th><th>Alg.</th><th>Digest</th><th>Match</th></tr></thead><tbody>
                    <?php foreach ($a['ds'] as $d): ?>
                        <tr><td class="mono"><?= (int) $d['keytag'] ?></td><td class="small"><?= e($d['algorithm_name']) ?></td>
                            <td><span class="small"><?= e($d['digest_type_name']) ?></span><br><?= copyable($d['digest'], substr($d['digest'], 0, 16) . '…') ?></td>
                            <td><?= $d['unverifiable'] ? badge('nicht prüfbar', 'unknown') : ($d['matches_dnskey'] ? badge('✓ DNSKEY passt', 'ok') : badge('✗ kein DNSKEY', 'fail')) ?></td></tr>
                    <?php endforeach; ?>
                    </tbody></table>
                <?php endif; ?>
            </div>
        </section>
        <section class="card">
            <header class="card-header"><h3>DNSKEY (Zone)</h3></header>
            <div class="card-body flush">
                <?php if (!$a['dnskey']): ?><p class="muted pad">Keine DNSKEY-Records geliefert.</p><?php else: ?>
                    <table class="table compact"><thead><tr><th>Rolle</th><th>Key-Tag</th><th>Algorithmus</th><th>Bits</th></tr></thead><tbody>
                    <?php foreach ($a['dnskey'] as $k): ?>
                        <tr><td><?= e($k['role']) ?> <span class="muted small">(<?= (int) $k['flags'] ?>)</span></td><td class="mono"><?= (int) $k['keytag'] ?></td>
                            <td class="small"><?= e($k['algorithm_name']) ?> <?= $k['strength'] === 'ok' ? '' : badge($k['strength'] === 'deprecated' ? 'veraltet' : 'unsicher', $k['strength'] === 'deprecated' ? 'warn' : 'fail') ?></td>
                            <td class="num"><?= $k['bits'] ? (int) $k['bits'] : '–' ?></td></tr>
                    <?php endforeach; ?>
                    </tbody></table>
                <?php endif; ?>
            </div>
        </section>
    </div>

    <?php if ($a['rrsig']): ?>
    <section class="card">
        <header class="card-header"><h3>RRSIG über das DNSKEY-RRset</h3></header>
        <div class="card-body flush">
            <table class="table compact"><thead><tr><th>Key-Tag</th><th>Algorithmus</th><th>Gültig ab</th><th>Läuft ab</th><th>Signatur</th></tr></thead><tbody>
            <?php foreach ($a['rrsig'] as $s): ?>
                <tr><td class="mono"><?= (int) $s['keytag'] ?></td><td class="small"><?= e($s['algorithm']) ?></td>
                    <td class="mono small"><?= e(fmt_dt($s['inception'], 'd.m.Y H:i')) ?></td>
                    <td class="mono small"><?= e(fmt_dt($s['expiration'], 'd.m.Y H:i')) ?> <?= $s['expired'] ? badge('abgelaufen', 'fail') : ($s['hours_left'] !== null && $s['hours_left'] < 48 ? badge('< 48 h', 'warn') : '') ?></td>
                    <td><?php if ($s['crypto'] === null): ?><?= badge('Signer-Key fehlt', 'warn') ?><?php elseif ($s['crypto']['valid'] === true): ?><?= badge('✓ kryptografisch gültig', 'ok') ?><?php elseif ($s['crypto']['valid'] === false): ?><?= badge('✗ ungültig', 'fail') ?><?php else: ?><?= badge('nicht prüfbar', 'unknown') ?> <span class="muted small"><?= e($s['crypto']['reason']) ?></span><?php endif; ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        </div>
    </section>
    <?php endif; ?>

    <?php if ($a['denial']): ?>
    <section class="card">
        <header class="card-header"><h3>Nachweis der Nichtexistenz (Denial of Existence)</h3></header>
        <div class="card-body">
            <?= ui_kv([
                ['Verfahren', $a['denial']['mechanism'] ? badge($a['denial']['mechanism'], 'info') : '<span class="muted">nicht ermittelbar (Zone unsigniert oder keine Autorität-Daten)</span>'],
                ['Abfrage', '<span class="mono small">' . e($a['denial']['probe']) . '</span> → ' . e((string) $a['denial']['rcode'])],
                ['NSEC3-Iterationen', $a['denial']['nsec3_iterations'] !== null ? (int) $a['denial']['nsec3_iterations'] : '–'],
            ], 'kv-compact') ?>
        </div>
    </section>
    <?php endif; ?>

    <section class="card">
        <header class="card-header"><h3>Resolver-Sicht</h3></header>
        <div class="card-body flush">
            <table class="table compact"><thead><tr><th>Resolver</th><th>Antwort (SOA)</th><th>mit CD-Flag</th><th>AD-Flag</th><th>Validierungsfehler</th></tr></thead><tbody>
            <?php foreach ($a['resolvers'] as $r): ?>
                <tr><td><?= e(cfg("app.dns.resolvers.{$r['resolver']}.label", $r['resolver'])) ?></td><td><?= e($r['status']) ?></td><td><?= e($r['status_cd']) ?></td>
                    <td><?= $r['ad'] ? badge('gesetzt', 'ok') : badge('nicht gesetzt', 'neutral') ?></td>
                    <td><?= $r['validation_failure'] ? badge('ja – bogus', 'fail') : badge('nein', 'neutral') ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
            <p class="muted small pad">Das AD-Flag zeigt, dass der jeweilige Resolver die Antwort selbst als validiert betrachtet. Verschiedene Resolver können sich unterscheiden.</p>
        </div>
    </section>

    <?php if ($a['delegation']): $dl = $a['delegation']; ?>
    <section class="card">
        <header class="card-header"><h3>Delegation: Parent- und Child-Zone</h3></header>
        <div class="card-body stack-sm">
            <?= ui_kv([
                ['Parent-Zone', '<span class="mono">' . e($dl['parent']) . '</span>'],
                ['NS laut Parent', $dl['parent_view'] ? implode('<br>', array_map(static fn($n) => copyable($n), $dl['parent_view']['ns'])) . '<div class="muted small">befragt: ' . e($dl['parent_view']['server']) . ' (' . e($dl['parent_view']['ip']) . ', ' . e(strtoupper($dl['parent_view']['via'])) . ')</div>' : '<span class="muted">Parent-Server nicht direkt abfragbar</span>'],
                ['NS laut Zone', $dl['child_ns'] ? implode('<br>', array_map(static fn($n) => copyable($n), $dl['child_ns'])) : '<span class="muted">keine</span>'],
            ], 'kv-compact') ?>
            <?php if ($dl['servers']): ?>
                <table class="table compact"><thead><tr><th>Nameserver</th><th>IP</th><th>Erreichbar</th><th>Autoritativ</th><th>SOA-Serial</th><th class="num">ms</th></tr></thead><tbody>
                <?php foreach ($dl['servers'] as $s): ?>
                    <tr><td class="mono"><?= e($s['host']) ?></td><td class="mono small"><?= e($s['ip'] ?? '–') ?></td>
                        <td><?= $s['reachable'] ? badge('ja', 'ok') : badge('nein', 'fail') ?></td>
                        <td><?= $s['authoritative'] === null ? '–' : ($s['authoritative'] ? badge('AA', 'ok') : badge('nicht autoritativ', 'warn')) ?></td>
                        <td class="mono"><?= $s['serial'] !== null ? (int) $s['serial'] : '–' ?></td><td class="num"><?= $s['ms'] !== null ? (int) $s['ms'] : '–' ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
            <?php endif; ?>
        </div>
    </section>
    <?php endif; ?>

    <section class="card"><div class="card-body"><ul class="plain-list small"><?php foreach ($a['limitations'] as $l): ?><li><?= icon('info') ?> <?= e($l) ?></li><?php endforeach; ?></ul></div></section>
<?php endif; ?>
