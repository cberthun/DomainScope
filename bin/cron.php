<?php
declare(strict_types=1);

/**
 * Regelmäßige Prüfung der überwachten Domains (nur über die Kommandozeile).
 *
 * Aufruf:  php bin/cron.php [--interval=6] [--force] [--domain=example.com] [--modules=dns,email,...] [--subdomains] [--quiet]
 * Crontab (alle 30 Minuten): 0,30 * * * * /usr/bin/php /pfad/zu/domainscope/bin/cron.php --quiet
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require dirname(__DIR__) . '/app/bootstrap.php';

use DomainScope\Jobs\ModuleRunner;
use DomainScope\Repositories\DomainRepository;
use DomainScope\Support\{Database, DataSources, Logger};
use DomainScope\Validation\Target;

$opts = [];
foreach (array_slice($argv, 1) as $a) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $a, $m)) {
        $opts[$m[1]] = $m[2] ?? '1';
    }
}
$quiet = isset($opts['quiet']);
$say = static function (string $msg) use ($quiet): void {
    if (!$quiet) {
        echo '[' . date('H:i:s') . '] ' . $msg . "\n";
    }
};

// Einfache Sperre gegen parallele Läufe
$lock = fopen(cfg('app.paths.storage') . '/cron.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    $say('Ein anderer Cron-Lauf ist noch aktiv – Abbruch.');
    exit(0);
}

try {
    $interval = max(0, (float) ($opts['interval'] ?? 6)) * 3600;
    $force = isset($opts['force']);
    if (!empty($opts['domain'])) {
        $t = Target::parse($opts['domain']);
        $d = $t->registrable ? DomainRepository::find($t->registrable) : null;
        $domains = $d ? [$d] : [];
        if (!$d) {
            $say('Domain nicht gefunden: ' . $opts['domain']);
        }
        $force = true;
    } else {
        $domains = DomainRepository::monitored();
    }
    $modules = !empty($opts['modules']) ? array_values(array_intersect(explode(',', $opts['modules']), array_keys(ModuleRunner::MODULES))) : ['dns', 'registration', 'email', 'tls', 'dnssec', 'http', 'ips'];
    $runner = new ModuleRunner();
    $done = 0;
    foreach ($domains as $d) {
        $age = $d['last_checked_at'] ? time() - (strtotime($d['last_checked_at'] . ' UTC') ?: 0) : PHP_INT_MAX;
        if (!$force && $age < $interval) {
            $say("{$d['name']}: übersprungen (zuletzt vor " . round($age / 3600, 1) . ' h geprüft)');
            continue;
        }
        $mods = $modules;
        // Registrierung selten abrufen (Rate-Limits der Registries): höchstens alle 24 h, außer --force
        if (!$force && in_array('registration', $mods, true)) {
            $lastReg = Database::value('SELECT MAX(fetched_at) FROM registration_snapshots WHERE domain_id = ?', [$d['id']]);
            if ($lastReg && strtotime($lastReg . ' UTC') > time() - 86400) {
                $mods = array_values(array_diff($mods, ['registration']));
            }
        }
        // Subdomain-Scan höchstens täglich bzw. wenn explizit angefordert
        $lastScan = Database::value('SELECT MAX(scanned_at) FROM subdomain_scans WHERE domain_id = ?', [$d['id']]);
        if (isset($opts['subdomains']) && (!$lastScan || $force || strtotime($lastScan . ' UTC') < time() - 86400)) {
            $mods[] = 'subdomains';
        }
        $say("{$d['name']}: Prüfung (" . implode(', ', $mods) . ')');
        $res = $runner->runAll($d, 'cron', $mods);
        foreach ($res['results'] as $m => $r) {
            $say(sprintf('    %-14s %-5s %s', $m, $r['ok'] ? 'ok' : 'FEHL', $r['message']));
        }
        $done++;
    }
    DataSources::flush();
    $say("Fertig: $done von " . count($domains) . ' Domain(s) geprüft.');
    Logger::info("Cron: $done Domain(s) geprüft");
} catch (Throwable $e) {
    Logger::exception($e);
    fwrite(STDERR, 'Fehler: ' . $e->getMessage() . "\n");
    exit(1);
} finally {
    flock($lock, LOCK_UN);
}
