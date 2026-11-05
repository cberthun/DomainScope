<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Services\Http\CurlSupport;
use DomainScope\Support\{Cache, Config, Database, Request, Response, Settings};

final class SettingsController extends Controller
{
    private const DAY_LISTS = ['cert_warn_days', 'domain_warn_days'];
    private const BOOLS = ['whois_fallback', 'dkim_autoscan', 'subdomain_resolve', 'starttls_check'];

    public function index(Request $r): Response
    {
        $data = Config::get('app.paths.data');
        $age = static fn(string $f) => is_file("$data/$f") ? gmdate('Y-m-d H:i:s', (int) filemtime("$data/$f")) : null;
        $dbVersion = null;
        try {
            $dbVersion = (string) Database::value('SELECT VERSION()');
        } catch (\Throwable) {
        }
        return $this->page('settings', [
            'title' => 'Einstellungen', 'section' => 'settings', 'breadcrumbs' => [['Einstellungen']],
            's' => Settings::all(),
            'env' => [
                'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'db' => $dbVersion,
                'ext' => array_map(static fn($e) => [$e, extension_loaded($e)], ['curl', 'openssl', 'pdo_mysql', 'mbstring', 'json', 'intl']),
                'ca' => CurlSupport::caBundle(), 'psl' => $age('public_suffix_list.dat'), 'rdap' => $age('rdap-dns.json'),
                'storage' => is_writable((string) Config::get('app.paths.storage')), 'cache_writable' => is_writable((string) Config::get('app.paths.cache')),
                'https' => $r->isHttps(), 'auth_ip' => (array) Config::get('app.auth.ip_allowlist', []),
                'resolvers' => (array) Config::get('app.dns.resolvers'), 'default_resolver' => Config::get('app.dns.default_resolver'),
                'tz' => date_default_timezone_get(),
            ],
        ]);
    }

    public function save(Request $r): Response
    {
        $errors = [];
        $values = [];
        foreach (self::DAY_LISTS as $k) {
            $raw = array_filter(array_map('trim', explode(',', $r->str($k))), static fn($v) => $v !== '');
            $ok = $raw !== [] && count(array_filter($raw, static fn($v) => ctype_digit($v) && (int) $v >= 1 && (int) $v <= 365)) === count($raw);
            if ($ok) {
                $nums = array_unique(array_map('intval', $raw));
                rsort($nums);
                $values[$k] = implode(',', $nums);
            } else {
                $errors[] = ($k === 'cert_warn_days' ? 'Zertifikats-' : 'Domain-') . 'Warnschwellen: kommagetrennte Tage zwischen 1 und 365 angeben.';
            }
        }
        foreach (['stale_hours' => [1, 8760], 'cache_ttl' => [0, 86400], 'subdomain_resolve_limit' => [0, 500]] as $k => [$min, $max]) {
            $v = $r->str($k);
            if (ctype_digit($v) && (int) $v >= $min && (int) $v <= $max) {
                $values[$k] = (string) (int) $v;
            } else {
                $errors[] = "$k: Wert zwischen $min und $max erforderlich.";
            }
        }
        $ports = array_filter(array_map('trim', explode(',', $r->str('tls_ports'))), static fn($v) => $v !== '');
        $allowed = [443, 465, 993, 995, 8443];
        if ($ports !== [] && count(array_filter($ports, static fn($p) => ctype_digit($p) && in_array((int) $p, $allowed, true))) === count($ports)) {
            $values['tls_ports'] = implode(',', array_unique(array_map('intval', $ports)));
        } else {
            $errors[] = 'TLS-Ports: erlaubt sind ' . implode(', ', $allowed) . '.';
        }
        foreach (self::BOOLS as $k) {
            $values[$k] = $r->str($k) === '1' ? '1' : '0';
        }
        $sel = (new \DomainScope\Services\EmailSecurity\DkimAnalyzer(new \DomainScope\Services\DNS\DnsLookup(new \DomainScope\Services\DNS\DohClient())))->cleanSelectors(explode(',', $r->str('dkim_selectors')));
        $values['dkim_selectors'] = implode(',', $sel);

        if ($errors) {
            foreach ($errors as $e) {
                $this->flash('error', $e);
            }
            return $this->redirect('/settings');
        }
        foreach ($values as $k => $v) {
            Settings::set($k, $v);
        }
        $this->flash('success', 'Einstellungen gespeichert.');
        return $this->redirect('/settings');
    }

    public function purgeCache(Request $r): Response
    {
        $n = Cache::purge();
        $this->flash('success', "$n Cache-Einträge gelöscht.");
        return $this->redirect('/settings');
    }
}
