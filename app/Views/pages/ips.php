<?php
/**
 * @var array $ips
 * @var string $q
 * @var int $staleHours
 * @var array $asns
 */
?>
<section class="card card-hero">
    <div class="card-body">
        <form method="get" action="/ips/go" class="lookup-form">
            <label class="lookup-input"><?= icon('search') ?>
                <input class="input input-lg" type="text" name="ip" placeholder="IPv4- oder IPv6-Adresse, z. B. 203.0.113.7 oder 2001:db8::1" required maxlength="100" spellcheck="false" autocomplete="off"></label>
            <button class="btn btn-primary btn-lg" type="submit"><?= icon('play') ?> Analysieren</button>
        </form>
        <p class="muted small">Registrierung (RIR/RDAP), BGP-Routing (Origin-AS), ASN-Zuordnung und Geolokalisierung sind verschiedene Dinge und werden getrennt dargestellt. DomainScope schätzt keine Geolokalisierung; angezeigt werden nur Ländercodes aus Registry- und BGP-Daten.</p>
    </div>
</section>
<?php if ($asns): ?>
<section class="card">
    <header class="card-header"><h3>Häufigste Netze (ASN)</h3></header>
    <div class="card-body"><div class="chips"><?php foreach ($asns as $a): ?><a class="chip" href="/ips?q=<?= e(rawurlencode((string) $a['as_name'])) ?>">AS<?= (int) $a['asn'] ?> · <?= e(mb_strimwidth((string) $a['as_name'], 0, 40, '…')) ?> <strong><?= (int) $a['n'] ?></strong></a><?php endforeach; ?></div></div>
</section>
<?php endif; ?>
<section class="card">
    <header class="card-header"><h2>Bekannte IP-Adressen <span class="count"><?= count($ips) ?></span></h2>
        <form method="get" action="/ips" class="inline"><input class="input input-sm" type="search" name="q" value="<?= e($q) ?>" placeholder="Filter (IP, AS, rDNS)" maxlength="100"></form></header>
    <div class="card-body flush">
        <?php if (!$ips): ?>
            <?= ui_empty('server', 'Keine IP-Adressen', 'IP-Adressen werden aus DNS-Snapshots und Subdomain-Auflösungen übernommen oder hier manuell analysiert.') ?>
        <?php else: ?>
            <?= ui_table_open('ips-table', ['IP-Adresse', 'Typ', 'ASN', 'Netzwerk', 'Präfix', 'Reverse-DNS', 'Hosts', 'Geprüft']) ?>
            <?php foreach ($ips as $ip): ?>
                <tr><td><a class="mono" href="/ip/<?= e(rawurlencode($ip['address'])) ?>"><?= e($ip['address']) ?></a></td>
                    <td class="small">IPv<?= (int) $ip['version'] ?><?= $ip['classification'] !== 'public' ? ' · ' . badge($ip['classification'], 'warn') : '' ?></td>
                    <td class="mono small" data-sort-value="<?= (int) $ip['asn'] ?>"><?= $ip['asn'] ? 'AS' . (int) $ip['asn'] : '–' ?></td>
                    <td class="small"><?= e($ip['as_name'] ?? '–') ?></td><td class="mono small"><?= e($ip['prefix'] ?? '–') ?></td>
                    <td class="mono small"><?= e($ip['reverse_dns'] ?? '–') ?></td><td class="num"><?= (int) $ip['host_count'] ?></td>
                    <td><?= $ip['checked_at'] ? ui_freshness($ip['checked_at'], $staleHours * 7) : '<span class="muted">nicht angereichert</span>' ?></td></tr>
            <?php endforeach; ?>
            <?= ui_table_close() ?>
        <?php endif; ?>
    </div>
</section>
