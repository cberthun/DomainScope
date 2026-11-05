<?php
/** @var ?string $error */
/** @var bool $locked */
use DomainScope\Security\Csrf;
?>
<div class="login-card card">
    <div class="login-brand">
        <img class="brand-mark" src="/assets/images/logo.png" alt="" width="28" height="28">
        <div><div class="brand-name">DomainScope</div><div class="muted small">Privates Infrastruktur-Dashboard</div></div>
    </div>
    <?php if ($error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>
    <form method="post" action="/login" class="stack" autocomplete="on">
        <?= Csrf::field() ?>
        <label class="field"><span>Benutzername</span>
            <input class="input" type="text" name="username" autocomplete="username" required autofocus maxlength="100"></label>
        <label class="field"><span>Passwort</span>
            <input class="input" type="password" name="password" autocomplete="current-password" required maxlength="500"></label>
        <button class="btn btn-primary" type="submit" <?= $locked ? 'disabled' : '' ?>>Anmelden</button>
        <?php if ($locked): ?><p class="muted small">Zu viele Fehlversuche – bitte einige Minuten warten.</p><?php endif; ?>
    </form>
</div>
