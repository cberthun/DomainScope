<?php
/**
 * @var string $title
 * @var string $content
 * @var array $breadcrumbs
 * @var string $section
 * @var string[] $scripts
 * @var string $actions
 * @var array $flash
 * @var string $path
 */

use DomainScope\Security\Csrf;

$nav = [
    ['Übersicht', [
        ['/', 'dashboard', 'Dashboard', 'dashboard'],
        ['/domains', 'globe', 'Domain Explorer', 'domains'],
    ]],
    ['Analyse', [
        ['/dns', 'network', 'DNS Explorer', 'dns'],
        ['/rdap', 'file-text', 'RDAP & WHOIS', 'rdap'],
        ['/subdomains', 'git-branch', 'Subdomain Intelligence', 'subdomains'],
        ['/ips', 'server', 'IP & ASN Intelligence', 'ips'],
        ['/email', 'mail', 'E-Mail-Sicherheit', 'email'],
        ['/tls', 'lock', 'SSL/TLS-Zertifikate', 'tls'],
        ['/dnssec', 'shield-check', 'DNSSEC & Delegation', 'dnssec'],
    ]],
    ['Betrieb', [
        ['/inventory', 'package', 'Infrastruktur-Inventar', 'inventory'],
        ['/monitoring', 'activity', 'Monitoring & Verlauf', 'monitoring'],
        ['/findings', 'alert-triangle', 'Findings', 'findings'],
        ['/reports', 'bar-chart', 'Berichte', 'reports'],
        ['/settings', 'settings', 'Einstellungen', 'settings'],
        ['/account', 'key', 'Konto & Sicherheit', 'account'],
    ]],
];
?>
<!doctype html>
<html lang="de" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow">
    <meta name="csrf-token" content="<?= e(Csrf::token()) ?>">
    <title><?= e($title) ?> · DomainScope</title>
    <script src="/assets/js/theme-init.js"></script>
    <link rel="stylesheet" href="/assets/css/app.css">
    <link rel="stylesheet" href="/assets/css/components.css">
    <link rel="icon" href="/assets/images/logo.png" type="image/png">
</head>
<body class="app">
<a class="skip-link" href="#main">Zum Inhalt springen</a>
<div class="shell" id="shell">
    <aside class="sidebar" id="sidebar" aria-label="Hauptnavigation">
        <div class="sidebar-head">
            <a href="/" class="brand" aria-label="DomainScope Startseite">
                <img class="brand-mark" src="/assets/images/logo.png" alt="" width="28" height="28">
                <span class="brand-name">DomainScope</span>
            </a>
        </div>
        <nav class="nav">
            <?php foreach ($nav as [$group, $items]): ?>
                <div class="nav-group">
                    <div class="nav-title"><?= e($group) ?></div>
                    <?php foreach ($items as [$href, $ico, $label, $key]): ?>
                        <a class="nav-item<?= $section === $key ? ' active' : '' ?>" href="<?= e($href) ?>" title="<?= e($label) ?>"<?= $section === $key ? ' aria-current="page"' : '' ?>>
                            <?= icon($ico) ?><span class="nav-label"><?= e($label) ?></span>
                        </a>
                    <?php endforeach; ?>
                </div>
            <?php endforeach; ?>
        </nav>
        <div class="sidebar-foot">
            <button type="button" class="nav-item" id="sidebar-toggle" title="Navigation ein-/ausklappen" aria-expanded="true">
                <?= icon('panel-left') ?><span class="nav-label">Einklappen</span>
            </button>
            <form method="post" action="/logout">
                <?= Csrf::field() ?>
                <button type="submit" class="nav-item" title="Abmelden"><?= icon('log-out') ?><span class="nav-label">Abmelden</span></button>
            </form>
        </div>
    </aside>
    <div class="sidebar-backdrop" id="sidebar-backdrop"></div>

    <div class="main">
        <header class="topbar">
            <button type="button" class="icon-btn mobile-only" id="mobile-menu" aria-label="Menü öffnen"><?= icon('menu') ?></button>
            <form class="global-search" action="/search" method="get" role="search" autocomplete="off">
                <?= icon('search') ?>
                <input type="search" name="q" id="global-search" placeholder="Domain, URL, IP, Subdomain, Asset suchen …  ( / )" aria-label="Globale Suche" spellcheck="false" maxlength="2048">
                <div class="search-suggest" id="search-suggest" hidden></div>
            </form>
            <div class="topbar-actions">
                <button type="button" class="icon-btn" id="theme-toggle" aria-label="Farbschema wechseln" title="Dunkel/Hell"><?= icon('sun') ?></button>
            </div>
        </header>

        <main class="content" id="main">
            <?php if ($breadcrumbs): ?>
                <nav class="breadcrumbs" aria-label="Brotkrumen">
                    <a href="/"><?= icon('home') ?></a>
                    <?php foreach ($breadcrumbs as $i => $bc): ?>
                        <?= icon('chevron-right') ?>
                        <?php if (!empty($bc[1]) && $i < count($breadcrumbs) - 1): ?><a href="<?= e($bc[1]) ?>"><?= e($bc[0]) ?></a>
                        <?php else: ?><span aria-current="page"><?= e($bc[0]) ?></span><?php endif; ?>
                    <?php endforeach; ?>
                </nav>
            <?php endif; ?>
            <div class="page-header">
                <h1><?= e($title) ?></h1>
                <?php if ($actions !== ''): ?><div class="page-actions"><?= $actions ?></div><?php endif; ?>
            </div>
            <?php foreach ($flash as $f): ?>
                <div class="alert alert-<?= e($f['type']) ?>" role="status"><?= e($f['message']) ?></div>
            <?php endforeach; ?>
            <?= $content ?>
            <footer class="app-footer">made with &hearts; by <a href="https://github.com/cberthun" rel="noopener">cberthun</a> · <a href="https://github.com/cberthun/domainscope" rel="noopener">AGPL-3.0</a></footer>
        </main>
    </div>
</div>
<div class="toasts" id="toasts" aria-live="polite"></div>
<script src="/assets/js/app.js" defer></script>
<?php foreach ($scripts as $s): ?><script src="/assets/js/<?= e($s) ?>" defer></script>
<?php endforeach; ?>
</body>
</html>
