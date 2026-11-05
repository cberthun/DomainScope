<?php
/** @var array $domain */
use DomainScope\Security\Csrf;
$base = '/domain/' . rawurlencode($domain['name']);
?>
<section class="card">
    <header class="card-header"><h3>Notizen & DKIM-Selektoren</h3></header>
    <div class="card-body">
        <form method="post" action="<?= e($base) ?>/notes" class="stack">
            <?= Csrf::field() ?>
            <label class="field"><span>Eigene Notizen</span><textarea class="textarea" name="notes" rows="6" maxlength="5000"><?= e($domain['notes'] ?? '') ?></textarea></label>
            <label class="field"><span>Bekannte DKIM-Selektoren (kommagetrennt)</span><input class="input mono" name="selectors" value="<?= e($domain['dkim_selectors']) ?>" maxlength="500"></label>
            <div><button class="btn btn-primary" type="submit">Speichern</button></div>
        </form>
    </div>
</section>
<section class="card card-danger">
    <header class="card-header"><h3>Domain löschen</h3></header>
    <div class="card-body">
        <p class="small">Entfernt die Domain samt Snapshots, Prüfergebnissen, Subdomains und Findings unwiderruflich aus der Datenbank. Die Domain selbst ist davon nicht betroffen.</p>
        <form method="post" action="<?= e($base) ?>/delete" class="form-inline">
            <?= Csrf::field() ?>
            <label class="field grow"><span>Zur Bestätigung den Domainnamen eingeben: <span class="mono"><?= e($domain['name']) ?></span></span><input class="input mono" name="confirm" autocomplete="off" required></label>
            <button class="btn btn-danger" type="submit"><?= icon('trash') ?> Endgültig löschen</button>
        </form>
    </div>
</section>
