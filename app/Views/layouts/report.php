<?php
/**
 * @var array $report
 * @var bool $print
 */
$q = $_SERVER['REQUEST_URI'] ?? '';
$base = strtok($q, '?');
?>
<!doctype html>
<html lang="de" data-theme="light">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow">
    <title><?= e($report['title']) ?></title>
    <link rel="stylesheet" href="/assets/css/app.css">
    <link rel="stylesheet" href="/assets/css/components.css">
    <link rel="stylesheet" href="/assets/css/report.css">
</head>
<body class="report">
<div class="report-bar no-print">
    <a class="btn btn-sm" href="/reports">← Berichte</a>
    <a class="btn btn-sm" href="<?= e($base) ?>?format=json"><?= icon('download') ?> JSON</a>
    <a class="btn btn-sm" href="<?= e($base) ?>?format=csv"><?= icon('download') ?> CSV</a>
    <button class="btn btn-sm btn-primary" type="button" id="print-btn"><?= icon('printer') ?> Drucken / PDF</button>
</div>
<main class="report-page">
    <header class="report-head">
        <h1><?= e($report['title']) ?></h1>
        <p class="muted">Erstellt am <?= e(fmt_dt($report['generated_at'], 'd.m.Y H:i')) ?> (<?= e(date_default_timezone_get()) ?>) mit DomainScope</p>
    </header>
    <?php foreach ($report['sections'] as $s): ?>
        <section class="report-section">
            <h2><?= e($s['title']) ?></h2>
            <?php if (!empty($s['note'])): ?><p class="small muted"><?= e($s['note']) ?></p><?php endif; ?>
            <?php if (!$s['rows']): ?>
                <p class="muted">Keine Daten.</p>
            <?php else: ?>
                <table class="table compact"><thead><tr><?php foreach ($s['columns'] as $c): ?><th><?= e($c) ?></th><?php endforeach; ?></tr></thead><tbody>
                <?php foreach ($s['rows'] as $row): ?><tr><?php foreach ($row as $cell): ?><td class="wrap"><?= e($cell) ?></td><?php endforeach; ?></tr><?php endforeach; ?>
                </tbody></table>
            <?php endif; ?>
        </section>
    <?php endforeach; ?>
    <section class="report-section">
        <h2>Datenquellen</h2>
        <ul><?php foreach ($report['sources'] as $src): ?><li><?= e($src) ?></li><?php endforeach; ?></ul>
        <h2>Bekannte Einschränkungen</h2>
        <ul><?php foreach ($report['limitations'] as $l): ?><li><?= e($l) ?></li><?php endforeach; ?></ul>
    </section>
</main>
<script src="/assets/js/report.js" defer></script>
</body>
</html>
