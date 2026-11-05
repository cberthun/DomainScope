<?php
/**
 * @var array $s
 * @var array $env
 */
use DomainScope\Security\Csrf;
$yes = static fn(bool $b) => $b ? badge('ja', 'ok') : badge('nein', 'warn');
?>
<div class="grid grid-main">
<section class="card">
    <header class="card-header"><h2>Prüfungen & Schwellwerte</h2></header>
    <div class="card-body">
        <form method="post" action="/settings" class="form-grid">
            <?= Csrf::field() ?>
            <label class="field"><span>Warnschwellen Zertifikate (Tage)</span><input class="input mono" name="cert_warn_days" value="<?= e($s['cert_warn_days']) ?>" required><small>z. B. 30,14,7 – engster Wert = „Hoch“</small></label>
            <label class="field"><span>Warnschwellen Domain-Ablauf (Tage)</span><input class="input mono" name="domain_warn_days" value="<?= e($s['domain_warn_days']) ?>" required></label>
            <label class="field"><span>Daten gelten als veraltet nach (Stunden)</span><input class="input mono" name="stale_hours" value="<?= e($s['stale_hours']) ?>" required></label>
            <label class="field"><span>DNS-Cache-Dauer (Sekunden, 0 = aus)</span><input class="input mono" name="cache_ttl" value="<?= e($s['cache_ttl']) ?>" required></label>
            <label class="field"><span>TLS-Ports der Standardprüfung</span><input class="input mono" name="tls_ports" value="<?= e($s['tls_ports']) ?>" required><small>erlaubt: 443, 465, 993, 995, 8443</small></label>
            <label class="field"><span>Max. aufzulösende Subdomains pro Scan</span><input class="input mono" name="subdomain_resolve_limit" value="<?= e($s['subdomain_resolve_limit']) ?>" required></label>
            <label class="field span-2"><span>Standard-DKIM-Selektoren (für alle Domains)</span><input class="input mono" name="dkim_selectors" value="<?= e($s['dkim_selectors']) ?>" placeholder="z. B. google, selector1, selector2"></label>
            <fieldset class="span-2 stack-sm"><legend>Optionale, aktive Funktionen</legend>
                <label class="check"><input type="checkbox" name="whois_fallback" value="1" <?= $s['whois_fallback'] === '1' ? 'checked' : '' ?>> WHOIS-Fallback (Port 43) für TLDs ohne RDAP</label>
                <label class="check"><input type="checkbox" name="subdomain_resolve" value="1" <?= $s['subdomain_resolve'] === '1' ? 'checked' : '' ?>> Gefundene Subdomains per DNS auflösen (begrenzt)</label>
                <label class="check"><input type="checkbox" name="dkim_autoscan" value="1" <?= $s['dkim_autoscan'] === '1' ? 'checked' : '' ?>> Begrenzte DKIM-Selektorsuche (~30 gängige Namen) standardmäßig aktivieren</label>
                <label class="check"><input type="checkbox" name="starttls_check" value="1" <?= ($s['starttls_check'] ?? '0') === '1' ? 'checked' : '' ?>> STARTTLS-Test der MX-Server (SMTP Port 25) bei jeder Härtungsprüfung – ausgehender Port 25 ist bei vielen Providern gesperrt</label>
                <p class="muted small">Es gibt keine Brute-Force-Enumeration, keine Portscans und keine Exploit-Funktionen. Aktive Verbindungen gehen nur zu den Hosts eigener Domains (TLS, HTTP, MTA-STS, BIMI) und nur zu öffentlichen Adressen.</p>
            </fieldset>
            <div class="span-2"><button class="btn btn-primary" type="submit">Speichern</button></div>
        </form>
    </div>
</section>

<div class="stack">
    <section class="card">
        <header class="card-header"><h3>Umgebung</h3></header>
        <div class="card-body">
            <?= ui_kv([
                ['PHP', '<span class="mono">' . e($env['php']) . '</span> (' . e($env['sapi']) . ')'],
                ['Datenbank', $env['db'] ? '<span class="mono">' . e($env['db']) . '</span>' : badge('keine Verbindung', 'fail')],
                ['Zeitzone', e($env['tz'])],
                ['HTTPS', $yes($env['https'])],
                ['Storage beschreibbar', $yes($env['storage'] && $env['cache_writable'])],
                ['CA-Bundle', $env['ca'] ? badge('vorhanden', 'ok') : badge('fehlt', 'fail')],
                ['Public-Suffix-Liste', $env['psl'] ? e(time_ago($env['psl'])) : badge('fehlt', 'fail')],
                ['IANA-RDAP-Bootstrap', $env['rdap'] ? e(time_ago($env['rdap'])) . ' <span class="muted small">(wird nach 7 Tagen erneuert)</span>' : badge('fehlt', 'warn')],
                ['IP-Allowlist', $env['auth_ip'] ? e(implode(', ', $env['auth_ip'])) : '<span class="muted">nicht gesetzt</span>'],
                ['Standard-Resolver', e($env['resolvers'][$env['default_resolver']]['label'] ?? '')],
            ], 'kv-compact') ?>
            <div class="subhead">PHP-Erweiterungen</div>
            <div class="chips"><?php foreach ($env['ext'] as [$name, $on]): ?><span class="chip <?= $on ? 'chip-ok' : ($name === 'intl' ? 'chip-off' : 'chip-bad') ?>"><?= $on ? '✓' : '–' ?> <?= e($name) ?></span><?php endforeach; ?></div>
            <p class="muted small">intl ist optional (IDN/Punycode werden in PHP selbst umgesetzt).</p>
        </div>
    </section>
    <section class="card">
        <header class="card-header"><h3>Wartung</h3></header>
        <div class="card-body">
            <form method="post" action="/settings/purge-cache"><?= Csrf::field() ?><button class="btn" type="submit"><?= icon('trash') ?> DNS-Cache leeren</button></form>
            <p class="muted small">Zugangsdaten (Benutzername/Passwort-Hash), IP-Allowlist und Datenbankzugang werden bewusst nicht in der Oberfläche gespeichert, sondern in der <span class="mono">.env</span> (Passwort ändern: <span class="mono">php bin/setup.php</span>).</p>
        </div>
    </section>
</div>
</div>
