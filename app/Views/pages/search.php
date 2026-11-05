<?php
/**
 * @var string $q
 * @var array $hits
 * @var \DomainScope\Validation\Target $target
 */
?>
<?php if (!$target->valid()): ?><div class="alert alert-info">„<?= e($q) ?>“ ist kein gültiger Domainname oder keine IP-Adresse – es wird in den gespeicherten Daten gesucht.</div><?php endif; ?>
<?php if (!$hits): ?>
    <div class="card"><div class="card-body"><?= ui_empty('search', 'Keine Treffer', 'Für „' . $q . '“ wurden in Domains, Subdomains, IPs, Assets und Findings keine Einträge gefunden.') ?></div></div>
<?php endif; ?>
<?php foreach ($hits as $group => $rows): ?>
    <section class="card">
        <header class="card-header"><h3><?= e($group) ?> <span class="count"><?= count($rows) ?></span></h3></header>
        <div class="card-body flush"><ul class="plain-list">
            <?php foreach ($rows as $row): ?><li class="pad-sm"><a href="<?= e($row['url']) ?>"><?= e($row['label']) ?></a> <span class="muted small"><?= e($row['sub'] ?? '') ?></span></li><?php endforeach; ?>
        </ul></div>
    </section>
<?php endforeach; ?>
