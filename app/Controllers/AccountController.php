<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Security\{Auth, Credentials, Secrets, Session, Totp};
use DomainScope\Support\{Config, Request, Response};

/** Passwortwechsel und Zwei-Faktor-Authentifizierung (TOTP). */
final class AccountController extends Controller
{
    public function index(Request $r): Response
    {
        $secret = Session::get('totp_setup_secret');
        $user = (string) Config::get('app.auth.username', 'admin');
        $codes = Session::get('new_recovery_codes');
        Session::forget('new_recovery_codes');
        return $this->page('account', [
            'title' => 'Konto & Sicherheit', 'section' => 'account', 'breadcrumbs' => [['Konto & Sicherheit']],
            'totp' => Credentials::totpEnabled(), 'codesLeft' => Credentials::recoveryCodesLeft(),
            'setupSecret' => is_string($secret) ? $secret : null,
            'setupUri' => is_string($secret) ? Totp::uri($secret, $user) : null,
            'newCodes' => is_array($codes) ? $codes : null, 'user' => $user,
            'keyOk' => strlen((string) Config::get('app.key', '')) >= 32,
        ]);
    }

    /** Passwort aktuell prüfen; Fehlversuche zählen zur Sperre. */
    private function passwordOk(Request $r): bool
    {
        if (Auth::isLockedOut($r->ip())) {
            $this->flash('error', 'Zu viele Fehlversuche – bitte später erneut versuchen.');
            return false;
        }
        $hash = Credentials::passwordHash();
        if ($hash !== '' && password_verify((string) ($r->post['current_password'] ?? ''), $hash)) {
            return true;
        }
        Auth::recordFailure($r);
        $this->flash('error', 'Das aktuelle Passwort ist falsch.');
        return false;
    }

    public function password(Request $r): Response
    {
        if (!$this->passwordOk($r)) {
            return $this->redirect('/account');
        }
        $new = (string) ($r->post['new_password'] ?? '');
        if (mb_strlen($new) < 12) {
            $this->flash('error', 'Das neue Passwort muss mindestens 12 Zeichen lang sein.');
        } elseif ($new !== (string) ($r->post['new_password2'] ?? '')) {
            $this->flash('error', 'Die Passwort-Wiederholung stimmt nicht überein.');
        } elseif (password_verify($new, Credentials::passwordHash())) {
            $this->flash('error', 'Das neue Passwort muss sich vom aktuellen unterscheiden.');
        } else {
            Credentials::setPassword($new);
            session_regenerate_id(true);
            $_SESSION['_csrf'] = bin2hex(random_bytes(32));
            $this->flash('success', 'Passwort geändert.');
        }
        return $this->redirect('/account');
    }

    public function start2fa(Request $r): Response
    {
        if (strlen((string) Config::get('app.key', '')) < 32) {
            $this->flash('error', 'APP_KEY fehlt – bitte zuerst php bin/setup.php ausführen.');
        } elseif (Credentials::totpEnabled()) {
            $this->flash('warn', 'Zwei-Faktor ist bereits aktiv.');
        } else {
            Session::set('totp_setup_secret', Totp::generateSecret());
        }
        return $this->redirect('/account');
    }

    public function enable2fa(Request $r): Response
    {
        $secret = Session::get('totp_setup_secret');
        if (!is_string($secret)) {
            return $this->redirect('/account');
        }
        if (Totp::verify($secret, (string) ($r->post['code'] ?? '')) === null) {
            $this->flash('error', 'Der Code ist ungültig. Uhrzeit des Geräts prüfen und erneut versuchen.');
            return $this->redirect('/account');
        }
        Credentials::save(['totp_secret' => Secrets::encrypt($secret), 'totp_enabled' => 1, 'totp_last_counter' => intdiv(time(), 30)]);
        Session::set('new_recovery_codes', Credentials::newRecoveryCodes());
        Session::forget('totp_setup_secret');
        $this->flash('success', 'Zwei-Faktor-Authentifizierung ist aktiv. Bitte die Wiederherstellungscodes sicher aufbewahren.');
        return $this->redirect('/account');
    }

    public function disable2fa(Request $r): Response
    {
        if (!$this->passwordOk($r)) {
            return $this->redirect('/account');
        }
        $secret = Credentials::decryptSecret();
        $code = (string) ($r->post['code'] ?? '');
        $ok = $secret !== null && Totp::verify($secret, $code, (int) (Credentials::row()['totp_last_counter'] ?? 0)) !== null;
        if (!$ok && preg_match('/^[0-9a-f]{5}-[0-9a-f]{5}$/i', trim($code))) {
            $ok = Credentials::useRecoveryCode($code);
        }
        if (!$ok) {
            Auth::recordFailure($r);
            $this->flash('error', 'Der Code ist ungültig.');
            return $this->redirect('/account');
        }
        Credentials::save(['totp_enabled' => 0, 'totp_secret' => null, 'recovery_codes' => null]);
        $this->flash('success', 'Zwei-Faktor-Authentifizierung deaktiviert.');
        return $this->redirect('/account');
    }

    public function recovery(Request $r): Response
    {
        if (!Credentials::totpEnabled()) {
            return $this->redirect('/account');
        }
        if ($this->passwordOk($r)) {
            Session::set('new_recovery_codes', Credentials::newRecoveryCodes());
            $this->flash('success', 'Neue Wiederherstellungscodes erzeugt; die alten sind ungültig.');
        }
        return $this->redirect('/account');
    }
}
