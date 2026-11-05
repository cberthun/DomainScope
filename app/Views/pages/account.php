<?php
/**
 * @var bool $totp
 * @var int $codesLeft
 * @var ?string $setupSecret
 * @var ?string $setupUri
 * @var ?array $newCodes
 * @var string $user
 * @var bool $keyOk
 */
use DomainScope\Security\Csrf;
?>
<?php if ($newCodes): ?>
<section class="card card-danger">
    <header class="card-header"><h3>Wiederherstellungscodes – jetzt sichern</h3></header>
    <div class="card-body stack-sm">
        <p class="small">Jeder Code funktioniert genau einmal, falls das Authenticator-Gerät nicht verfügbar ist. Sie werden <strong>nur jetzt</strong> angezeigt.</p>
        <div class="chips"><?php foreach ($newCodes as $c): ?><?= copyable($c) ?> <?php endforeach; ?></div>
    </div>
</section>
<?php endif; ?>

<div class="grid grid-2">
<section class="card">
    <header class="card-header"><h3><?= icon('key') ?> Passwort ändern</h3></header>
    <div class="card-body">
        <form method="post" action="/account/password" class="stack-sm" autocomplete="off">
            <?= Csrf::field() ?>
            <label class="field"><span>Aktuelles Passwort</span><input class="input" type="password" name="current_password" autocomplete="current-password" required maxlength="500"></label>
            <label class="field"><span>Neues Passwort (mind. 12 Zeichen)</span><input class="input" type="password" name="new_password" autocomplete="new-password" required minlength="12" maxlength="500"></label>
            <label class="field"><span>Neues Passwort wiederholen</span><input class="input" type="password" name="new_password2" autocomplete="new-password" required minlength="12" maxlength="500"></label>
            <div><button class="btn btn-primary" type="submit">Passwort ändern</button></div>
            <p class="muted small">Benutzer: <span class="mono"><?= e($user) ?></span>. Das Passwort wird als Hash in der Datenbank gespeichert und hat Vorrang vor dem Wert in der <span class="mono">.env</span>.</p>
        </form>
    </div>
</section>

<section class="card">
    <header class="card-header"><h3><?= icon('shield-check') ?> Zwei-Faktor-Login (TOTP)</h3><?= $totp ? badge('aktiv', 'ok') : badge('nicht aktiv', 'neutral') ?></header>
    <div class="card-body stack-sm">
        <?php if ($totp): ?>
            <p class="small">Beim Login wird zusätzlich der Code Ihrer Authenticator-App verlangt. Verbleibende Wiederherstellungscodes: <strong><?= (int) $codesLeft ?></strong>.</p>
            <form method="post" action="/account/2fa/recovery" class="form-inline" autocomplete="off"><?= Csrf::field() ?>
                <label class="field grow"><span>Passwort</span><input class="input" type="password" name="current_password" required maxlength="500"></label>
                <button class="btn" type="submit">Neue Wiederherstellungscodes</button></form>
            <hr>
            <form method="post" action="/account/2fa/disable" class="stack-sm" autocomplete="off"><?= Csrf::field() ?>
                <label class="field"><span>Passwort</span><input class="input" type="password" name="current_password" required maxlength="500"></label>
                <label class="field"><span>Aktueller Code oder Wiederherstellungscode</span><input class="input mono" name="code" required maxlength="20" inputmode="numeric"></label>
                <div><button class="btn btn-danger" type="submit">2FA deaktivieren</button></div></form>
        <?php elseif ($setupSecret): ?>
            <p class="small">1. In der Authenticator-App (z. B. Aegis, 2FAS, Google/Microsoft Authenticator) ein Konto per <strong>manueller Eingabe</strong> hinzufügen:</p>
            <?= ui_kv([['Schlüssel', copyable($setupSecret, implode(' ', str_split($setupSecret, 4)))], ['Typ', 'zeitbasiert (TOTP), 6 Stellen, 30 s, SHA-1'], ['otpauth-URI', copyable((string) $setupUri, 'URI kopieren')]], 'kv-compact') ?>
            <p class="small">2. Den angezeigten 6-stelligen Code eingeben, um die Einrichtung abzuschließen:</p>
            <form method="post" action="/account/2fa/enable" class="form-inline" autocomplete="off"><?= Csrf::field() ?>
                <label class="field grow"><span>Code</span><input class="input mono" name="code" inputmode="numeric" required maxlength="8" autofocus></label>
                <button class="btn btn-primary" type="submit">Aktivieren</button></form>
        <?php else: ?>
            <p class="small">Schützt den Zugang zusätzlich zum Passwort. Empfohlen, sobald die Anwendung aus dem Internet erreichbar ist.</p>
            <?php if (!$keyOk): ?><div class="alert alert-warn small">APP_KEY fehlt in der <span class="mono">.env</span> – <span class="mono">php bin/setup.php</span> ausführen.</div><?php endif; ?>
            <form method="post" action="/account/2fa/start"><?= Csrf::field() ?><button class="btn btn-primary" type="submit" <?= $keyOk ? '' : 'disabled' ?>>Einrichtung starten</button></form>
        <?php endif; ?>
    </div>
</section>
</div>
