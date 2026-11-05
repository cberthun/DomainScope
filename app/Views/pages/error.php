<?php /** @var int $status */ /** @var string $title */ /** @var string $message */ /** @var ?string $detail */ ?>
<div class="login-card card error-card">
    <div class="error-code"><?= (int) $status ?></div>
    <h1><?= e($title) ?></h1>
    <p><?= e($message) ?></p>
    <?php if ($detail): ?><pre class="code"><?= e($detail) ?></pre><?php endif; ?>
    <a class="btn" href="/">Zum Dashboard</a>
</div>
