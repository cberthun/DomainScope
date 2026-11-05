<?php
/** @var ?string $error */
/** @var bool $locked */
use DomainScope\Security\Csrf;
?>
<div class="login-card card">
    <div class="login-brand">
        <img class="brand-mark" src="/assets/images/logo.png" alt="" width="28" height="28">
        <div><div class="brand-name">Zwei-Faktor-Code</div><div class="muted small">Code der Authenticator-App oder Wiederherstellungscode</div></div>
    </div>
    <?php if ($error): ?><div class="alert alert-error" role="alert"><?= e($error) ?></div><?php endif; ?>
    <form method="post" action="/login/2fa" class="stack" autocomplete="off">
        <?= Csrf::field() ?>
        <label class="field"><span>Code</span>
            <input class="input mono" type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus maxlength="20" placeholder="123456"></label>
        <button class="btn btn-primary" type="submit" <?= $locked ? 'disabled' : '' ?>>Bestätigen</button>
        <a class="muted small" href="/login">Abbrechen</a>
    </form>
</div>
