<?php
declare(strict_types=1);

use DomainScope\Controllers\{AccountController, AuthController, DashboardController, DnsController, DnssecController, DomainController, EmailController, FindingsController,
    InventoryController, IpController, MonitoringController, RdapController, ReportController, SearchController, SettingsController,
    SubdomainController, TlsController};
use DomainScope\Support\Router;

return static function (Router $r): void {
    $r->get('/login', [AuthController::class, 'form'], ['public' => true]);
    $r->post('/login', [AuthController::class, 'login'], ['public' => true]);
    $r->post('/logout', [AuthController::class, 'logout']);
    $r->get('/login/2fa', [AuthController::class, 'form2fa'], ['public' => true]);
    $r->post('/login/2fa', [AuthController::class, 'verify2fa'], ['public' => true]);
    $r->get('/account', [AccountController::class, 'index']);
    $r->post('/account/password', [AccountController::class, 'password']);
    $r->post('/account/2fa/start', [AccountController::class, 'start2fa']);
    $r->post('/account/2fa/enable', [AccountController::class, 'enable2fa']);
    $r->post('/account/2fa/disable', [AccountController::class, 'disable2fa']);
    $r->post('/account/2fa/recovery', [AccountController::class, 'recovery']);

    $r->get('/', [DashboardController::class, 'index']);

    // Domain Explorer
    $r->get('/domains', [DomainController::class, 'index']);
    $r->post('/domains/lookup', [DomainController::class, 'lookup']);
    $r->get('/domain/{domain}', [DomainController::class, 'show']);
    $r->get('/domain/{domain}/tab/{tab:[a-z]+}', [DomainController::class, 'tab']);
    $r->post('/domain/{domain}/run/{module:[a-z]+}', [DomainController::class, 'run']);
    $r->post('/domain/{domain}/runall', [DomainController::class, 'runAll']);
    $r->post('/domain/{domain}/monitor', [DomainController::class, 'monitor']);
    $r->post('/domain/{domain}/notes', [DomainController::class, 'notes']);
    $r->post('/domain/{domain}/delete', [DomainController::class, 'delete']);

    // DNS Explorer
    $r->get('/dns', [DnsController::class, 'index']);
    $r->get('/dns/export', [DnsController::class, 'export']);
    $r->get('/dns/snapshots', [DnsController::class, 'snapshots']);
    $r->get('/dns/compare', [DnsController::class, 'compare']);

    // RDAP & WHOIS
    $r->get('/rdap', [RdapController::class, 'index']);
    $r->get('/rdap/{domain}', [RdapController::class, 'show']);
    $r->post('/rdap/{domain}/refresh', [RdapController::class, 'refresh']);

    // Subdomains
    $r->get('/subdomains', [SubdomainController::class, 'index']);
    $r->get('/subdomains/{domain}', [SubdomainController::class, 'show']);
    $r->post('/subdomains/{domain}/scan', [SubdomainController::class, 'scan']);
    $r->get('/subdomains/{domain}/export', [SubdomainController::class, 'export']);

    // IP & ASN
    $r->get('/ips', [IpController::class, 'index']);
    $r->get('/ips/go', [IpController::class, 'go']);
    $r->get('/ip/{ip:[0-9a-fA-F:.]+}', [IpController::class, 'show']);
    $r->post('/ip/{ip:[0-9a-fA-F:.]+}/refresh', [IpController::class, 'refresh']);

    // E-Mail-Sicherheit
    $r->get('/email', [EmailController::class, 'index']);
    $r->get('/email/{domain}', [EmailController::class, 'show']);
    $r->post('/email/{domain}/run', [EmailController::class, 'run']);

    // TLS
    $r->get('/tls', [TlsController::class, 'index']);
    $r->get('/tls/check', [TlsController::class, 'check']);
    $r->get('/tls/{domain}', [TlsController::class, 'show']);
    $r->post('/tls/{domain}/run', [TlsController::class, 'run']);

    // DNSSEC & Delegation
    $r->get('/dnssec', [DnssecController::class, 'index']);
    $r->get('/dnssec/{domain}', [DnssecController::class, 'show']);
    $r->post('/dnssec/{domain}/run', [DnssecController::class, 'run']);

    // Inventar
    $r->get('/inventory', [InventoryController::class, 'index']);
    $r->get('/inventory/new', [InventoryController::class, 'form']);
    $r->get('/inventory/graph', [InventoryController::class, 'graph']);
    $r->post('/inventory', [InventoryController::class, 'store']);
    $r->post('/inventory/import', [InventoryController::class, 'import']);
    $r->post('/inventory/link/{rid:\d+}/confirm', [InventoryController::class, 'confirmLink']);
    $r->post('/inventory/link/{rid:\d+}/delete', [InventoryController::class, 'unlink']);
    $r->get('/inventory/{id:\d+}', [InventoryController::class, 'show']);
    $r->get('/inventory/{id:\d+}/edit', [InventoryController::class, 'form']);
    $r->post('/inventory/{id:\d+}', [InventoryController::class, 'update']);
    $r->post('/inventory/{id:\d+}/delete', [InventoryController::class, 'delete']);
    $r->post('/inventory/{id:\d+}/link', [InventoryController::class, 'link']);

    // Monitoring
    $r->get('/monitoring', [MonitoringController::class, 'index']);
    $r->post('/monitoring/run', [MonitoringController::class, 'run']);

    // Findings
    $r->get('/findings', [FindingsController::class, 'index']);
    $r->get('/findings/{id:\d+}', [FindingsController::class, 'show']);
    $r->post('/findings/{id:\d+}/status', [FindingsController::class, 'status']);

    // Berichte
    $r->get('/reports', [ReportController::class, 'index']);
    $r->get('/reports/{type:[a-z-]+}/{domain}', [ReportController::class, 'show']);

    // Einstellungen
    $r->get('/settings', [SettingsController::class, 'index']);
    $r->post('/settings', [SettingsController::class, 'save']);
    $r->post('/settings/purge-cache', [SettingsController::class, 'purgeCache']);

    // Suche
    $r->get('/search', [SearchController::class, 'go']);
    $r->get('/api/search', [SearchController::class, 'suggest']);
};
