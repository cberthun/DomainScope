<?php
/**
 * @var array $f
 * @var array $events
 */
use DomainScope\Security\Csrf;
$eventLabels = ['created' => 'Erstmals festgestellt', 'reopened' => 'Erneut aufgetreten', 'auto_resolved' => 'Automatisch als behoben markiert', 'severity_changed' => 'Schweregrad geändert',
    'status_open' => 'Wieder geöffnet', 'status_acknowledged' => 'Bestätigt', 'status_ignored' => 'Ignoriert', 'status_resolved' => 'Manuell als behoben markiert'];
?>
<div class="grid grid-main">
    <section class="card">
        <header class="card-header"><h2><?= sev_badge($f['severity']) ?> <?= e($f['title']) ?></h2>
            <?= match ($f['status']) { 'open' => badge('offen', 'warn'), 'acknowledged' => badge('bestätigt', 'info'), 'ignored' => badge('ignoriert', 'neutral'), default => badge('behoben', 'ok') } ?></header>
        <div class="card-body stack">
            <?= ui_kv([
                ['Kategorie', e($f['category'])],
                ['Betroffenes Asset', ($f['domain_name'] ? ui_domain_link($f['domain_name']) : '–') . ($f['subject'] ? ' · <span class="mono">' . e($f['subject']) . '</span>' : '')],
                ['Regel', '<span class="mono">' . e($f['rule_id']) . '</span>'],
                ['Datenquelle', e($f['source'])],
                ['Erstmals', e(fmt_dt($f['first_seen'], 'd.m.Y H:i')) . ' ' . tz_label()], ['Zuletzt bestätigt', e(fmt_dt($f['last_seen'], 'd.m.Y H:i')) . ' ' . tz_label() . ' (' . e(time_ago($f['last_seen'])) . ')'],
                ['Behoben', $f['resolved_at'] ? e(fmt_dt($f['resolved_at'], 'd.m.Y H:i')) . ' ' . tz_label() : '–'],
            ], 'kv-compact') ?>
            <div><div class="subhead">Technische Begründung</div><p><?= e($f['reasoning']) ?></p></div>
            <div><div class="subhead">Handlungsempfehlung</div><p><?= e($f['recommendation']) ?></p></div>
            <?php if (!empty($f['evidence'])): ?>
                <div><div class="subhead">Beobachtete Daten</div><pre class="code"><?= e(json_encode($f['evidence'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></pre></div>
            <?php endif; ?>
        </div>
    </section>
    <div class="stack">
        <section class="card">
            <header class="card-header"><h3>Status ändern</h3></header>
            <div class="card-body">
                <form method="post" action="/findings/<?= (int) $f['id'] ?>/status" class="stack-sm">
                    <?= Csrf::field() ?>
                    <label class="field"><span>Notiz (optional)</span><input class="input" name="note" maxlength="200"></label>
                    <div class="row gap wrap-row">
                        <?php foreach (['acknowledged' => ['Bestätigen', 'check'], 'ignored' => ['Ignorieren', 'eye'], 'resolved' => ['Als behoben', 'circle-check'], 'open' => ['Wieder öffnen', 'refresh']] as $st => [$lbl, $ic]): if ($f['status'] !== $st): ?>
                            <button class="btn btn-sm" type="submit" name="status" value="<?= e($st) ?>"><?= icon($ic) ?> <?= e($lbl) ?></button>
                        <?php endif; endforeach; ?>
                    </div>
                    <p class="muted small">Manuell als „behoben“ oder „ignoriert“ markierte Findings werden bei der nächsten Prüfung erneut geöffnet bzw. weiter geführt, wenn der Befund weiterhin besteht (ignorierte bleiben ignoriert).</p>
                </form>
            </div>
        </section>
        <section class="card">
            <header class="card-header"><h3>Historie</h3></header>
            <div class="card-body">
                <ol class="timeline"><?php foreach ($events as $e): ?>
                    <li><span class="tl-dot"></span><div><div><?= e($eventLabels[$e['event']] ?? $e['event']) ?></div><?php if ($e['detail']): ?><div class="muted small"><?= e($e['detail']) ?></div><?php endif; ?><div class="muted small"><?= e(fmt_dt($e['created_at'], 'd.m.Y H:i')) ?> <?= e(tz_label()) ?></div></div></li>
                <?php endforeach; ?></ol>
            </div>
        </section>
    </div>
</div>
