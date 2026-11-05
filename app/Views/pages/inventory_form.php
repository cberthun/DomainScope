<?php
/**
 * @var ?array $asset
 * @var array $preset
 * @var array $domains
 */
use DomainScope\Repositories\AssetRepository;
use DomainScope\Security\Csrf;
$action = $asset ? '/inventory/' . (int) $asset['id'] : '/inventory';
?>
<section class="card">
    <div class="card-body">
        <form method="post" action="<?= e($action) ?>" class="form-grid">
            <?= Csrf::field() ?>
            <label class="field"><span>Name *</span><input class="input" name="name" value="<?= e($preset['name']) ?>" required maxlength="200"></label>
            <label class="field"><span>Typ</span><select class="select" name="type"><?php foreach (AssetRepository::TYPES as $k => $l): ?><option value="<?= e($k) ?>" <?= $preset['type'] === $k ? 'selected' : '' ?>><?= e($l) ?></option><?php endforeach; ?></select></label>
            <label class="field"><span>Adresse / Hostname</span><input class="input mono" name="address" value="<?= e($preset['address'] ?? '') ?>" maxlength="253" spellcheck="false"></label>
            <label class="field"><span>Anbieter</span><input class="input" name="provider" value="<?= e($preset['provider'] ?? '') ?>" maxlength="150" placeholder="z. B. Hetzner, IONOS, Cloudflare"></label>
            <label class="field"><span>Umgebung</span><select class="select" name="environment"><?php foreach (AssetRepository::ENVIRONMENTS as $k => $l): ?><option value="<?= e($k) ?>" <?= ($preset['environment'] ?? '') === $k ? 'selected' : '' ?>><?= e($l) ?></option><?php endforeach; ?></select></label>
            <label class="field"><span>Zugehörige Domain</span><select class="select" name="domain_id"><option value="">–</option><?php foreach ($domains as $d): ?><option value="<?= (int) $d['id'] ?>" <?= (int) ($preset['domain_id'] ?? 0) === (int) $d['id'] ? 'selected' : '' ?>><?= e($d['unicode_name']) ?></option><?php endforeach; ?></select></label>
            <label class="field span-2"><span>Tags (kommagetrennt)</span><input class="input" name="tags" value="<?= e($preset['tags'] ?? '') ?>" maxlength="500"></label>
            <label class="field span-2"><span>Beschreibung</span><textarea class="textarea" name="description" rows="3" maxlength="5000"><?= e($preset['description'] ?? '') ?></textarea></label>
            <label class="field span-2"><span>Eigene Notizen (keine Passwörter oder Schlüssel!)</span><textarea class="textarea" name="notes" rows="5" maxlength="10000"><?= e($preset['notes'] ?? '') ?></textarea></label>
            <div class="span-2 row gap">
                <button class="btn btn-primary" type="submit">Speichern</button>
                <a class="btn" href="<?= $asset ? '/inventory/' . (int) $asset['id'] : '/inventory' ?>">Abbrechen</a>
            </div>
        </form>
    </div>
</section>
