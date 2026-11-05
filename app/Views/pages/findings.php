<?php
/**
 * @var array $findings
 * @var array $filter
 * @var array $domains
 * @var array $counts
 * @var array $rules
 */
$modules = ['email' => 'E-Mail', 'tls' => 'TLS', 'dnssec' => 'DNSSEC/Delegation', 'registration' => 'Registrierung', 'dns' => 'DNS', 'subdomains' => 'Subdomains', 'http' => 'HTTP'];
?>
<div class="sev-summary">
    <?php foreach (['critical', 'high', 'medium', 'low', 'info', 'unknown'] as $s): ?>
        <a class="sev-tile sev-<?= e($s) ?><?= $filter['severity'] === $s ? ' active' : '' ?>" href="/findings?status=active&severity=<?= e($s) ?>"><strong><?= (int) $counts[$s] ?></strong><span><?= e(severity_label($s)) ?></span></a>
    <?php endforeach; ?>
</div>

<section class="card">
    <header class="card-header">
        <form method="get" action="/findings" class="form-inline compact">
            <input class="input input-sm" type="search" name="q" value="<?= e($filter['q']) ?>" placeholder="Suchen …" maxlength="100">
            <select class="select input-sm" name="status"><?php foreach (['active' => 'Offen/bestätigt', 'open' => 'Offen', 'acknowledged' => 'Bestätigt', 'ignored' => 'Ignoriert', 'resolved' => 'Behoben', '' => 'Alle'] as $k => $l): ?><option value="<?= e((string) $k) ?>" <?= $filter['status'] === (string) $k ? 'selected' : '' ?>><?= e($l) ?></option><?php endforeach; ?></select>
            <select class="select input-sm" name="severity"><option value="">Alle Schweregrade</option><?php foreach (['critical', 'high', 'medium', 'low', 'info', 'unknown'] as $s): ?><option value="<?= e($s) ?>" <?= $filter['severity'] === $s ? 'selected' : '' ?>><?= e(severity_label($s)) ?></option><?php endforeach; ?></select>
            <select class="select input-sm" name="module"><option value="">Alle Bereiche</option><?php foreach ($modules as $k => $l): ?><option value="<?= e($k) ?>" <?= $filter['module'] === $k ? 'selected' : '' ?>><?= e($l) ?></option><?php endforeach; ?></select>
            <select class="select input-sm" name="domain_id"><option value="">Alle Domains</option><?php foreach ($domains as $d): ?><option value="<?= (int) $d['id'] ?>" <?= (int) $filter['domain_id'] === (int) $d['id'] ? 'selected' : '' ?>><?= e($d['unicode_name']) ?></option><?php endforeach; ?></select>
            <button class="btn btn-sm" type="submit"><?= icon('filter') ?> Filtern</button>
        </form>
    </header>
    <div class="card-body flush"><?= \DomainScope\Support\View::partial('partials/findings_table', ['findings' => $findings, 'showDomain' => true]) ?></div>
</section>

<details class="card">
    <summary class="card-header"><h3>Regelwerk & Bewertungsgrundlage</h3></summary>
    <div class="card-body">
        <p class="small">Findings entstehen ausschließlich aus tatsächlichen Prüfresultaten nach nachvollziehbaren Regeln; es gibt keinen pauschalen Gesamt-Score. Fehlende Informationen (z. B. nicht erreichbare Quellen) werden als „Unbekannt“ oder „Information“ geführt, nie automatisch als Sicherheitslücke. Auszug der Regeln:</p>
        <table class="table compact"><thead><tr><th>Regel</th><th>Bereich</th><th>Schweregrad</th><th>Begründung</th></tr></thead><tbody>
        <?php foreach ($rules as $id => [$mod, $sev, $why]): ?>
            <tr><td class="mono small"><?= e($id) ?></td><td><?= e($mod) ?></td><td class="small"><?= e($sev) ?></td><td class="small"><?= e($why) ?></td></tr>
        <?php endforeach; ?>
        </tbody></table>
    </div>
</details>
