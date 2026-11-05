<?php /** @var string $what */ ?>
<div class="empty">
    <?= icon('circle-help') ?>
    <h2><?= e($what) ?> nicht gefunden</h2>
    <p class="muted">Der angeforderte Eintrag existiert nicht oder wurde gelöscht.</p>
    <a class="btn" href="/domains">Zum Domain Explorer</a>
</div>
