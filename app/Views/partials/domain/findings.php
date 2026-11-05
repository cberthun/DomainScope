<?php /** @var array $findings */ ?>
<section class="card">
    <header class="card-header"><h3>Findings dieser Domain</h3></header>
    <div class="card-body flush"><?= \DomainScope\Support\View::partial('partials/findings_table', ['findings' => $findings, 'showDomain' => false]) ?></div>
</section>
