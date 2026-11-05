<?php
/**
 * @var array $form
 * @var ?array $lookup
 * @var ?string $error
 * @var ?string $registrable
 * @var array $query
 */
use DomainScope\Services\DNS\DnsTypes;

$resolvers = (array) cfg('app.dns.resolvers');
$name = $lookup['name'] ?? ($_GET['name'] ?? '');
?>
<section class="card card-hero">
    <div class="card-body">
        <form method="get" action="/dns" class="stack" id="dns-form">
            <div class="lookup-form">
                <label class="lookup-input"><?= icon('search') ?>
                    <input class="input input-lg" type="text" name="name" value="<?= e($name) ?>" placeholder="example.com, _dmarc.example.com oder IP-Adresse (Reverse-Lookup)" required maxlength="2048" spellcheck="false" autocomplete="off"></label>
                <button class="btn btn-primary btn-lg" type="submit"><?= icon('play') ?> Abfragen</button>
            </div>
            <fieldset class="chip-group"><legend>Record-Typen</legend>
                <?php foreach (DnsTypes::EXPLORER as $t): ?>
                    <label class="chip-check"><input type="checkbox" name="types[]" value="<?= e($t) ?>" <?= in_array($t, $form['types'], true) ? 'checked' : '' ?>><span><?= e($t) ?></span></label>
                <?php endforeach; ?>
                <button type="button" class="btn btn-ghost btn-sm" data-types="all">Alle</button>
                <button type="button" class="btn btn-ghost btn-sm" data-types="common">Gängige</button>
            </fieldset>
            <fieldset class="chip-group"><legend>Resolver (Mehrfachauswahl = Vergleich)</legend>
                <?php foreach ($resolvers as $key => $res): ?>
                    <label class="chip-check"><input type="checkbox" name="resolvers[]" value="<?= e($key) ?>" <?= in_array($key, $form['resolvers'], true) ? 'checked' : '' ?>><span><?= e($res['label']) ?></span></label>
                <?php endforeach; ?>
                <label class="chip-check" title="DNSSEC OK: fordert RRSIG/NSEC-Daten an"><input type="checkbox" name="do" value="1" <?= $form['flags']['do'] ? 'checked' : '' ?>><span>DO (DNSSEC-Daten)</span></label>
                <label class="chip-check" title="Checking Disabled: Antwort trotz fehlgeschlagener DNSSEC-Validierung"><input type="checkbox" name="cd" value="1" <?= $form['flags']['cd'] ? 'checked' : '' ?>><span>CD (Validierung aus)</span></label>
            </fieldset>
        </form>
    </div>
</section>

<?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>

<?php if ($lookup): ?>
    <div class="toolbar">
        <span class="muted small">Abfrage <span class="mono"><?= e($lookup['query_name']) ?></span> · <?= e(fmt_dt($lookup['checked_at'], 'H:i:s')) ?> <?= e(tz_label()) ?><?= $lookup['note'] ? ' · ' . e($lookup['note']) : '' ?></span>
        <span class="spacer"></span>
        <a class="btn btn-sm" href="/dns/export?<?= e(http_build_query($query + ['format' => 'json'])) ?>"><?= icon('download') ?> JSON</a>
        <a class="btn btn-sm" href="/dns/export?<?= e(http_build_query($query + ['format' => 'csv'])) ?>"><?= icon('download') ?> CSV</a>
        <?php if ($registrable): ?>
            <a class="btn btn-sm btn-primary" href="/domain/<?= e(rawurlencode($registrable)) ?>?tab=dns&host=<?= e(rawurlencode($lookup['name'])) ?>"><?= icon('database') ?> Als Domain speichern & Snapshot</a>
        <?php endif; ?>
    </div>

    <?php if ($lookup['comparison']): ?>
    <section class="card">
        <header class="card-header"><h3><?= icon('git-compare') ?> Resolver-Vergleich</h3></header>
        <div class="card-body flush">
            <table class="table compact"><thead><tr><th>Typ</th><th>Ergebnis</th><th>Details</th></tr></thead><tbody>
            <?php foreach ($lookup['comparison'] as $type => $c): ?>
                <tr><td><span class="badge badge-type"><?= e($type) ?></span></td>
                    <td><?= !$c['comparable'] ? badge('nicht vergleichbar (Resolver-Fehler)', 'unknown') : ($c['consistent'] ? badge('identisch', 'ok') : badge('Abweichung', 'warn')) ?></td>
                    <td class="small">
                        <?php if ($c['comparable'] && !$c['consistent']): foreach ($c['missing_in'] as $res => $miss): if ($miss): ?>
                            <div>Fehlt bei <strong><?= e($res) ?></strong>: <span class="mono"><?= e(implode(' | ', array_map(static fn($x) => mb_strimwidth($x, 0, 70, '…'), $miss))) ?></span></div>
                        <?php endif; endforeach; endif; ?>
                    </td></tr>
            <?php endforeach; ?>
            </tbody></table>
            <p class="muted small pad">Abweichungen bei A/AAAA sind bei Geo-/Load-Balancing-DNS normal. Abweichungen bei NS, MX oder TXT deuten eher auf Propagation oder inkonsistente Nameserver hin.</p>
        </div>
    </section>
    <?php endif; ?>

    <?php foreach ($lookup['results'] as $resolver => $byType): ?>
        <section class="card">
            <header class="card-header"><h3><?= e($resolvers[$resolver]['label'] ?? $resolver) ?></h3></header>
            <div class="card-body stack">
                <?php foreach ($byType as $type => $res): ?>
                    <div class="dns-result" data-status="<?= e($res['status']) ?>">
                        <div class="dns-result-head">
                            <span class="badge badge-type"><?= e($type) ?></span>
                            <?= match ($res['status']) {
                                'ok' => ui_pill('ok', count(array_filter($res['answer'], static fn($a) => $a['type'] === $type)) . ' Antwort(en)'),
                                'nodata' => ui_pill('none', 'NODATA'), 'nxdomain' => ui_pill('fail', 'NXDOMAIN'), 'servfail' => ui_pill('fail', 'SERVFAIL'),
                                'refused' => ui_pill('fail', 'REFUSED'), 'timeout' => ui_pill('error', 'Timeout'), default => ui_pill('error', 'Fehler') } ?>
                            <span class="muted small mono"><?= $res['rcode_name'] ? e($res['rcode_name']) : '' ?> · <?= (int) $res['ms'] ?> ms<?= !empty($res['cached']) ? ' · Cache' : '' ?></span>
                            <span class="flags"><?php foreach ($res['flags'] as $f => $on): if ($on): ?><span class="flag" title="<?= e(['AD' => 'Authentic Data (Resolver hat DNSSEC validiert)', 'CD' => 'Checking Disabled', 'RA' => 'Recursion Available', 'RD' => 'Recursion Desired', 'TC' => 'Truncated'][$f]) ?>"><?= e($f) ?></span><?php endif; endforeach; ?></span>
                        </div>
                        <?php if (!in_array($res['status'], ['ok'], true)): ?>
                            <p class="small dns-explain"><?= icon('info') ?> <?= e($res['explanation']) ?><?= $res['error'] ? ' <span class="muted">(' . e($res['error']) . ')</span>' : '' ?></p>
                        <?php endif; ?>
                        <?php if ($res['answer']): ?>
                            <?= ui_table_open('t-' . substr(md5($resolver . $type), 0, 8), ['Name', 'Typ', 'TTL', 'Daten'], false) ?>
                            <?php foreach ($res['answer'] as $a): ?>
                                <tr><td class="mono small"><?= e($a['name']) ?></td><td><span class="badge badge-type"><?= e($a['type']) ?></span></td><td class="num mono"><?= (int) $a['ttl'] ?></td><td class="wrap"><?= copyable($a['data']) ?></td></tr>
                            <?php endforeach; ?>
                            <?= ui_table_close() ?>
                        <?php endif; ?>
                        <?php if ($res['authority'] || $res['additional']): ?>
                            <details class="sub-details"><summary>Authority (<?= count($res['authority']) ?>) · Additional (<?= count($res['additional']) ?>)</summary>
                                <table class="table compact"><tbody>
                                <?php foreach (['Authority' => $res['authority'], 'Additional' => $res['additional']] as $sec => $recs): foreach ($recs as $a): ?>
                                    <tr><td class="muted small"><?= $sec ?></td><td class="mono small"><?= e($a['name']) ?></td><td><span class="badge badge-type"><?= e($a['type']) ?></span></td><td class="num mono"><?= (int) $a['ttl'] ?></td><td class="wrap"><?= copyable($a['data']) ?></td></tr>
                                <?php endforeach; endforeach; ?>
                                </tbody></table>
                            </details>
                        <?php endif; ?>
                        <?php if ($res['raw']): ?>
                            <details class="sub-details"><summary>Rohdaten (JSON des Resolvers)</summary><pre class="code"><?= e(json_encode($res['raw'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></pre></details>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        </section>
    <?php endforeach; ?>
<?php elseif (!$error): ?>
    <div class="card"><div class="card-body"><?= ui_empty('network', 'DNS-Abfrage starten', 'Echte Abfragen über DNS-over-HTTPS (Cloudflare, Google, Quad9) mit TTL, Antwortzeit, Rcode, Flags, Authority/Additional und Rohdaten. NXDOMAIN, SERVFAIL, REFUSED, Timeout und „keine Daten“ werden unterschieden.') ?></div></div>
<?php endif; ?>
