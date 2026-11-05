<?php
declare(strict_types=1);

namespace DomainScope\Security;

use DomainScope\Support\Config;
use DomainScope\Support\Database;
use DomainScope\Support\Request;

/** Einzelnutzer-Authentifizierung (Passwort + optional TOTP). */
final class Auth
{
    public static function configured(): bool
    {
        return Credentials::passwordHash() !== '';
    }

    public static function check(): bool
    {
        if (empty($_SESSION['auth_user'])) {
            return false;
        }
        $idle = (int) Config::get('app.auth.idle_timeout', 3600);
        if ($idle > 0 && isset($_SESSION['last_activity']) && time() - (int) $_SESSION['last_activity'] > $idle) {
            Session::destroy();
            return false;
        }
        $_SESSION['last_activity'] = time();
        return true;
    }

    public static function ipAllowed(Request $request): bool
    {
        $list = (array) Config::get('app.auth.ip_allowlist', []);
        return $list === [] || in_array($request->ip(), $list, true);
    }

    public static function isLockedOut(string $ip): bool
    {
        try {
            $window = gmdate('Y-m-d H:i:s', time() - (int) Config::get('app.auth.lockout_seconds', 900));
            $n = (int) Database::value('SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND attempted_at >= ?', [$ip, $window]);
            return $n >= (int) Config::get('app.auth.max_attempts', 5);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Passwortschritt. Liefert true nur bei vollständigem Login. Ist 2FA aktiv, wird bei korrektem Passwort
     * stattdessen "pending_2fa" in der Session gesetzt (siehe pending2fa()) und false geliefert.
     */
    public static function attempt(Request $request, string $username, string $password): bool
    {
        $hash = Credentials::passwordHash();
        $expectedUser = (string) Config::get('app.auth.username', 'admin');
        $userOk = hash_equals($expectedUser, $username);
        // password_verify wird immer ausgeführt (konstanter Zeitaufwand)
        $passOk = $hash !== '' && password_verify($password, $hash);
        if ($userOk && $passOk) {
            if (Credentials::totpEnabled()) {
                session_regenerate_id(true);
                $_SESSION['pending_2fa'] = ['user' => $expectedUser, 'at' => time()];
                return false;
            }
            self::complete($request, $expectedUser);
            return true;
        }
        self::recordFailure($request);
        return false;
    }

    public static function pending2fa(): bool
    {
        $p = $_SESSION['pending_2fa'] ?? null;
        return is_array($p) && time() - (int) $p['at'] < 300;
    }

    /** Zweiter Schritt: TOTP-Code oder Wiederherstellungscode. */
    public static function verifySecondFactor(Request $request, string $code): bool
    {
        if (!self::pending2fa()) {
            return false;
        }
        $ok = false;
        $secret = Credentials::decryptSecret();
        if ($secret !== null) {
            $last = (int) (Credentials::row()['totp_last_counter'] ?? 0);
            $counter = Totp::verify($secret, $code, $last);
            if ($counter !== null) {
                Credentials::save(['totp_last_counter' => $counter]);
                $ok = true;
            }
        }
        if (!$ok && preg_match('/^[0-9a-f]{5}-[0-9a-f]{5}$/i', trim($code)) && Credentials::useRecoveryCode($code)) {
            $ok = true;
        }
        if ($ok) {
            $user = (string) $_SESSION['pending_2fa']['user'];
            unset($_SESSION['pending_2fa']);
            self::complete($request, $user);
            return true;
        }
        self::recordFailure($request);
        return false;
    }

    private static function complete(Request $request, string $user): void
    {
        try {
            Database::run('DELETE FROM login_attempts WHERE ip = ?', [$request->ip()]);
        } catch (\Throwable) {
        }
        session_regenerate_id(true);
        $_SESSION['auth_user'] = $user;
        $_SESSION['last_activity'] = time();
        $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    }

    public static function recordFailure(Request $request): void
    {
        try {
            Database::insert('login_attempts', ['ip' => $request->ip(), 'attempted_at' => Database::now()]);
            Database::run('DELETE FROM login_attempts WHERE attempted_at < ?', [gmdate('Y-m-d H:i:s', time() - 86400)]);
        } catch (\Throwable) {
        }
    }

    public static function logout(): void
    {
        Session::destroy();
    }
}
