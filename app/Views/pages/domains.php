<?php
/** @var array $domains */
/** @var int $staleHours */
use DomainScope\Security\Csrf;
?>
<section class="card card-hero">
    <div class="card-body">
        <form method="post" action="/domains/lookup" class="lookup-form" id="lookup-form">
            <?= Csrf::field() ?>
            <label class="lookup-input">
                <?= icon('search') ?>
                <input class="input input-lg" type="text" name="target" id="lookup-target" placeholder="example.com, sub.example.com, https://example.com/pfad oder 203.0.113.7" autocomplete="off" spellcheck="false" required maxlength="2048" autofocus>
            </label>
            <button type="submit" class="btn btn-primary btn-lg"><?= icon('play') ?> Analysieren</button>
            <label class="check"><input type="checkbox" name="autorun" value="1" checked> Neue Domain sofort vollständig prüfen</label>
        </form>
        <p class="muted small">Eingaben werden normalisiert: URLs werden auf den Host reduziert, internationalisierte Domains (IDN) in Punycode umgewandelt, Subdomains der registrierbaren Domain zugeordnet und IP-Adressen an die IP-Analyse weitergeleitet.</p>
    </div>
</section>

<section class="card">
    <header class="card-header"><h2>Gespeicherte Domains <span class="count"><?= count($domains) ?></span></h2></header>
    <div class="card-body flush">
        <?php if (!$domains): ?>
            <?= ui_empty('globe', 'Noch keine Domains', 'Oben eine Domain eingeben, um sie zu analysieren und zu speichern.') ?>
        <?php else: ?>
            <?= ui_table_open('domain-table', ['Domain', 'TLD', 'Letzte Prüfung', 'Subdomains', 'Findings', 'Überwacht']) ?>
            <?php foreach ($domains as $d): ?>
                <tr>
                    <td data-sort-value="<?= e($d['name']) ?>"><?= ui_domain_link($d['name'], $d['unicode_name']) ?><?= $d['unicode_name'] !== $d['name'] ? ' <span class="muted small mono">' . e($d['name']) . '</span>' : '' ?></td>
                    <td class="mono">.<?= e($d['tld']) ?></td>
                    <td data-sort-value="<?= e((string) $d['last_checked_at']) ?>"><?= ui_freshness($d['last_checked_at'], $staleHours) ?></td>
                    <td class="num"><?= (int) $d['subdomain_count'] ?></td>
                    <td class="num" data-sort-value="<?= (int) $d['open_findings'] ?>"><?= (int) $d['open_findings'] ?><?= $d['serious_findings'] > 0 ? ' <span class="badge sev-high">' . (int) $d['serious_findings'] . ' schwer</span>' : '' ?></td>
                    <td><?= $d['monitored'] ? badge('Ja', 'ok') : badge('Nein', 'neutral') ?></td>
                </tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>
