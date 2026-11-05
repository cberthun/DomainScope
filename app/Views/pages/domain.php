<?php
/**
 * @var array $domain
 * @var string $host
 * @var string $tab
 * @var array $tabs
 * @var string $panel
 * @var array $counts
 * @var int $staleHours
 */
use DomainScope\Security\Csrf;
$base = '/domain/' . rawurlencode($domain['name']);
$hostQuery = $host !== $domain['name'] ? ['host' => $host] : [];
?>
<section class="domain-head card">
    <div class="card-body domain-head-body">
        <div>
            <div class="domain-title mono"><?= e($domain['unicode_name']) ?></div>
            <div class="muted small">
                <?php if ($domain['unicode_name'] !== $domain['name']): ?>Punycode <?= copyable($domain['name']) ?> · <?php endif; ?>
                Public Suffix <span class="mono">.<?= e($domain['public_suffix']) ?></span> · Zuletzt geprüft <?= ui_freshness($domain['last_checked_at'], $staleHours) ?>
            </div>
            <?php if ($host !== $domain['name']): ?>
                <div class="host-focus"><?= icon('git-branch') ?> Fokus-Host: <span class="mono"><?= e($host) ?></span> <a href="<?= e($base) ?>?tab=<?= e($tab) ?>">zurück zur Domain</a></div>
            <?php endif; ?>
        </div>
        <div class="domain-actions">
            <?php if ((int) ($counts['total'] ?? 0) > 0): ?>
                <a class="btn btn-ghost" href="<?= e($base) ?>?tab=findings"><?= icon('alert-triangle') ?> <?= (int) $counts['total'] ?> Findings<?= (int) $counts['serious'] ? ' (' . (int) $counts['serious'] . ' schwer)' : '' ?></a>
            <?php endif; ?>
            <form method="post" action="<?= e($base) ?>/monitor" class="inline">
                <?= Csrf::field() ?><input type="hidden" name="monitored" value="<?= $domain['monitored'] ? '0' : '1' ?>">
                <button class="btn btn-ghost" type="submit" title="Regelmäßige Prüfung per Cron"><?= icon('eye') ?> <?= $domain['monitored'] ? 'Überwachung aus' : 'Überwachen' ?></button>
            </form>
            <form method="post" action="<?= e($base) ?>/runall" class="inline" data-ajax-run>
                <?= Csrf::field() ?>
                <button class="btn btn-primary" type="submit"><?= icon('refresh') ?> Alles prüfen</button>
            </form>
        </div>
    </div>
</section>

<div class="tabs" role="tablist" id="domain-tabs" data-base="<?= e($base) ?>" data-host="<?= e($host !== $domain['name'] ? $host : '') ?>">
    <?php foreach ($tabs as $key => [$label, $ico]): ?>
        <a class="tab<?= $tab === $key ? ' active' : '' ?>" role="tab" data-tab="<?= e($key) ?>" aria-selected="<?= $tab === $key ? 'true' : 'false' ?>"
           href="<?= e(url($base, ['tab' => $key] + $hostQuery)) ?>"><?= icon($ico) ?><span><?= e($label) ?></span></a>
    <?php endforeach; ?>
</div>
<div class="tab-panel" id="tab-panel" role="tabpanel" aria-live="polite"><?= $panel ?></div>
