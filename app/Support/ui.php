<?php
declare(strict_types=1);

/** Wiederverwendbare Darstellungshelfer (liefern HTML, Werte werden escaped). */

function ui_status_label(string $status): string
{
    return match ($status) {
        'pass', 'ok' => 'OK', 'warn', 'partial' => 'Warnung', 'fail', 'failed' => 'Fehler', 'none' => 'Nicht konfiguriert',
        'error' => 'Nicht prüfbar', 'unknown' => 'Unbekannt', 'running' => 'Läuft', default => $status,
    };
}

function ui_status_class(string $status): string
{
    return match ($status) {
        'pass', 'ok' => 'ok', 'warn', 'partial' => 'warn', 'fail', 'failed' => 'fail', 'none' => 'neutral',
        'error', 'unknown' => 'unknown', default => 'neutral',
    };
}

function ui_pill(string $status, ?string $label = null): string
{
    $icon = match (ui_status_class($status)) {
        'ok' => 'circle-check', 'warn' => 'alert-triangle', 'fail' => 'circle-x', default => 'circle-help',
    };
    return '<span class="pill pill-' . ui_status_class($status) . '">' . icon($icon) . e($label ?? ui_status_label($status)) . '</span>';
}

/** @param array<int,array{0:string,1:string}|array{label:string,value:string}> $rows value ist bereits HTML */
function ui_kv(array $rows, string $class = ''): string
{
    $html = '<dl class="kv ' . e($class) . '">';
    foreach ($rows as $row) {
        $label = $row['label'] ?? $row[0];
        $value = $row['value'] ?? $row[1];
        $html .= '<div><dt>' . e($label) . '</dt><dd>' . $value . '</dd></div>';
    }
    return $html . '</dl>';
}

function ui_empty(string $icon, string $title, string $text = '', string $actionHtml = ''): string
{
    return '<div class="empty">' . icon($icon) . '<h3>' . e($title) . '</h3>' . ($text !== '' ? '<p class="muted">' . e($text) . '</p>' : '') . $actionHtml . '</div>';
}

function ui_freshness(?string $checkedAt, int $staleHours = 48): string
{
    if (!$checkedAt) {
        return '<span class="fresh fresh-never" title="Noch nie geprüft">' . icon('clock') . 'nie geprüft</span>';
    }
    $ts = strtotime($checkedAt . ' UTC') ?: 0;
    $age = time() - $ts;
    $stale = $age > $staleHours * 3600;
    return '<span class="fresh ' . ($stale ? 'fresh-stale' : 'fresh-ok') . '" title="' . e(fmt_dt($checkedAt, 'd.m.Y H:i:s')) . ' ' . date_default_timezone_get() . ($stale ? ' – Daten können veraltet sein' : '') . '">'
        . icon('clock') . e(time_ago($checkedAt)) . ($stale ? ' · veraltet' : '') . '</span>';
}

/** Ergebnis eines E-Mail-Checks als Karte. @param array<string,mixed> $c */
function ui_check_card(array $c): string
{
    $cls = ui_status_class($c['status']);
    $html = '<section class="card check-card check-' . $cls . '" id="check-' . e($c['id']) . '">';
    $html .= '<header class="card-header"><h3>' . e($c['title']) . '</h3>' . ui_pill($c['status']) . '</header>';
    $html .= '<div class="card-body stack-sm"><p>' . e($c['summary']) . '</p>';
    if (!empty($c['record'])) {
        $html .= '<div class="record-box"><span class="record-label">Record</span>' . copyable($c['record']) . '</div>';
    }
    if (!empty($c['details'])) {
        $html .= ui_kv(array_map(static fn($d) => [$d['label'], '<span class="mono">' . e($d['value']) . '</span>'], $c['details']), 'kv-compact');
    }
    if (!empty($c['findings'])) {
        $html .= '<ul class="check-findings">';
        foreach ($c['findings'] as $f) {
            $ic = match ($f['level']) { 'pass' => 'circle-check', 'warn' => 'alert-triangle', 'fail' => 'circle-x', default => 'info' };
            $html .= '<li class="cf cf-' . e($f['level']) . '">' . icon($ic) . '<div><div>' . e($f['message']) . '</div>';
            if (!empty($f['impact'])) {
                $html .= '<div class="cf-meta"><strong>Auswirkung:</strong> ' . e($f['impact']) . '</div>';
            }
            if (!empty($f['recommendation'])) {
                $html .= '<div class="cf-meta"><strong>Empfehlung:</strong> ' . e($f['recommendation']) . '</div>';
            }
            $html .= '<span class="badge badge-' . ($f['kind'] === 'bestpractice' ? 'info' : 'neutral') . ' cf-kind">' . ($f['kind'] === 'bestpractice' ? 'Best Practice' : 'Technischer Befund') . '</span></div></li>';
        }
        $html .= '</ul>';
    }
    return $html . '</div></section>';
}

/** Rekursive Darstellung des SPF-Baums. @param array<string,mixed> $node */
function ui_spf_tree(array $node): string
{
    $html = '<div class="spf-node"><div class="spf-head"><span class="mono">' . e($node['domain']) . '</span>';
    if (!empty($node['error'])) {
        $html .= ' <span class="badge badge-fail">' . e($node['error']) . '</span>';
    }
    $html .= '</div>';
    if (!empty($node['record'])) {
        $html .= '<div class="spf-record mono small muted">' . e($node['record']) . '</div>';
    }
    if (!empty($node['terms'])) {
        $html .= '<ul class="spf-terms">';
        foreach ($node['terms'] as $t) {
            $cls = !empty($t['unreachable']) ? ' spf-unreachable' : '';
            $html .= '<li class="' . trim($cls) . '"><span class="mono">' . e($t['raw']) . '</span>';
            if (!empty($t['lookups'])) {
                $html .= ' <span class="badge badge-neutral" title="zählt zum 10-Lookup-Limit">1 Lookup</span>';
            }
            if (!empty($t['unreachable'])) {
                $html .= ' <span class="muted small">(nach „all“ – wird nicht ausgewertet)</span>';
            }
            if (!empty($t['note'])) {
                $html .= ' <span class="muted small">' . e($t['note']) . '</span>';
            }
            if (!empty($t['children'])) {
                $html .= ui_spf_tree($t['children']);
            }
            $html .= '</li>';
        }
        $html .= '</ul>';
    }
    return $html . '</div>';
}

function ui_days_badge(?int $days): string
{
    if ($days === null) {
        return badge('–', 'neutral');
    }
    if ($days < 0) {
        return badge('abgelaufen seit ' . abs($days) . ' Tg.', 'fail');
    }
    $kind = $days <= 7 ? 'fail' : ($days <= 30 ? 'warn' : 'ok');
    return badge($days . ' Tage', $kind);
}

/** Sortier-/filterbare Tabelle: Kopfzeile aus [key => label]. */
function ui_table_open(string $id, array $columns, bool $filter = true): string
{
    $html = '';
    if ($filter) {
        $html .= '<div class="table-tools"><label class="input-icon">' . icon('filter') . '<input type="search" class="input input-sm" placeholder="Tabelle filtern …" data-table-filter="#' . e($id) . '" aria-label="Tabelle filtern"></label></div>';
    }
    $html .= '<div class="table-wrap"><table class="table sortable" id="' . e($id) . '"><thead><tr>';
    foreach ($columns as $c) {
        $html .= '<th scope="col" data-sort>' . e($c) . '</th>';
    }
    return $html . '</tr></thead><tbody>';
}

function ui_table_close(): string
{
    return '</tbody></table></div>';
}

function ui_domain_link(string $name, string $unicode = ''): string
{
    return '<a class="mono" href="/domain/' . e(rawurlencode($name)) . '">' . e($unicode ?: $name) . '</a>';
}

/** Formular-Button, der ein Prüfmodul für eine Domain startet (per JS ohne Reload, sonst klassisches POST). @param array<string,string> $fields */
function ui_run_button(array $domain, string $module, string $label = 'Jetzt prüfen', array $fields = [], string $class = 'btn btn-sm', string $icon = 'refresh'): string
{
    $html = '<form method="post" action="/domain/' . e(rawurlencode($domain['name'])) . '/run/' . e($module) . '" class="inline" data-ajax-run>'
        . \DomainScope\Security\Csrf::field();
    foreach ($fields as $k => $v) {
        $html .= '<input type="hidden" name="' . e($k) . '" value="' . e($v) . '">';
    }
    return $html . '<button type="submit" class="' . e($class) . '">' . icon($icon) . e($label) . '</button></form>';
}

/** Alle Records eines Typs als kopierbare Liste. @param array<int,array<string,mixed>> $records */
function ui_record_values(array $records, string $type): string
{
    $vals = array_values(array_filter($records, static fn($r) => $r['type'] === $type));
    if (!$vals) {
        return '<span class="muted">–</span>';
    }
    return implode('<br>', array_map(static fn($r) => copyable($r['data']), array_slice($vals, 0, 6))) . (count($vals) > 6 ? '<br><span class="muted small">+' . (count($vals) - 6) . ' weitere</span>' : '');
}
