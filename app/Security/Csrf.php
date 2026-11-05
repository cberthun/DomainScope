<?php
declare(strict_types=1);

namespace DomainScope\Security;

use DomainScope\Support\Request;

final class Csrf
{
    public static function token(): string
    {
        if (empty($_SESSION['_csrf'])) {
            $_SESSION['_csrf'] = bin2hex(random_bytes(32));
        }
        return (string) $_SESSION['_csrf'];
    }

    public static function field(): string
    {
        return '<input type="hidden" name="_csrf" value="' . e(self::token()) . '">';
    }

    public static function verify(Request $request): bool
    {
        $sent = (string) ($request->post['_csrf'] ?? $request->header('X-CSRF-Token'));
        $known = (string) ($_SESSION['_csrf'] ?? '');
        return $known !== '' && $sent !== '' && hash_equals($known, $sent);
    }
}
