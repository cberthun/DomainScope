<?php
/**
 * @var string $action  Ziel-URL (GET, Parameter "domain")
 * @var string $label
 */
$placeholder ??= 'Domain oder URL eingeben …';
?>
<section class="card card-hero">
    <div class="card-body">
        <form method="get" action="<?= e($action) ?>" class="lookup-form">
            <label class="lookup-input"><?= icon('search') ?>
                <input class="input input-lg" type="text" name="domain" placeholder="<?= e($placeholder) ?>" required maxlength="2048" spellcheck="false" autocomplete="off"></label>
            <button class="btn btn-primary btn-lg" type="submit"><?= icon('play') ?> <?= e($label) ?></button>
        </form>
    </div>
</section>
