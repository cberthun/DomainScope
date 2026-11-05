<?php /** @var string $title */ /** @var string $content */ ?>
<!doctype html>
<html lang="de" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow">
    <title><?= e($title) ?> · DomainScope</title>
    <script src="/assets/js/theme-init.js"></script>
    <link rel="stylesheet" href="/assets/css/app.css">
    <link rel="stylesheet" href="/assets/css/components.css">
    <link rel="icon" href="/assets/images/logo.png" type="image/png">
</head>
<body class="bare">
<main class="bare-main"><?= $content ?></main>
<footer class="app-footer">made with &hearts; by <a href="https://github.com/cberthun" rel="noopener">cberthun</a> · <a href="https://github.com/cberthun/domainscope" rel="noopener">AGPL-3.0</a></footer>
</body>
</html>
