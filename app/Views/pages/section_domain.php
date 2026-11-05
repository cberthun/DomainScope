<?php
/**
 * @var array $domain
 * @var string $body
 * @var int $staleHours
 */
?>
<div class="section-switch">
    <span class="mono"><?= e($domain['unicode_name']) ?></span>
    <span class="muted small">zuletzt vollständig geprüft: <?= ui_freshness($domain['last_checked_at'], $staleHours) ?></span>
    <a class="btn btn-ghost btn-sm" href="/domain/<?= e(rawurlencode($domain['name'])) ?>"><?= icon('globe') ?> Domain-Detailseite</a>
</div>
<?= $body ?>
