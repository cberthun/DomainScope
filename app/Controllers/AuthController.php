<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Security\{Auth, Session};
use DomainScope\Support\{Request, Response, View};

final class AuthController extends Controller
{
    public function form(Request $r): Response
    {
        if (Auth::check()) {
            return $this->redirect('/');
        }
        if (Auth::pending2fa()) {
            return $this->redirect('/login/2fa');
        }
        return Response::html(View::partial('layouts/bare', [
            'title' => 'Anmelden',
            'content' => View::partial('pages/login', ['error' => Session::get('login_error'), 'locked' => Auth::isLockedOut($r->ip())]),
        ]));
    }

    public function login(Request $r): Response
    {
        if (Auth::isLockedOut($r->ip())) {
            Session::set('login_error', 'Zu viele fehlgeschlagene Versuche. Bitte später erneut versuchen.');
            return $this->redirect('/login');
        }
        if (Auth::attempt($r, $r->str('username'), (string) ($r->post['password'] ?? ''))) {
            return $this->afterLogin();
        }
        if (Auth::pending2fa()) {
            Session::forget('login_error');
            return $this->redirect('/login/2fa');
        }
        usleep(random_int(200_000, 500_000));
        Session::set('login_error', 'Benutzername oder Passwort ist falsch.');
        return $this->redirect('/login');
    }

    public function form2fa(Request $r): Response
    {
        if (!Auth::pending2fa()) {
            return $this->redirect('/login');
        }
        return Response::html(View::partial('layouts/bare', [
            'title' => 'Zwei-Faktor-Code',
            'content' => View::partial('pages/login_2fa', ['error' => Session::get('login_error'), 'locked' => Auth::isLockedOut($r->ip())]),
        ]));
    }

    public function verify2fa(Request $r): Response
    {
        if (!Auth::pending2fa()) {
            return $this->redirect('/login');
        }
        if (Auth::isLockedOut($r->ip())) {
            Session::set('login_error', 'Zu viele fehlgeschlagene Versuche. Bitte später erneut versuchen.');
            return $this->redirect('/login/2fa');
        }
        if (Auth::verifySecondFactor($r, (string) ($r->post['code'] ?? ''))) {
            return $this->afterLogin();
        }
        usleep(random_int(200_000, 500_000));
        Session::set('login_error', 'Der Code ist ungültig oder bereits verwendet.');
        return $this->redirect('/login/2fa');
    }

    private function afterLogin(): Response
    {
        Session::forget('login_error');
        $to = (string) Session::get('intended', '/');
        Session::forget('intended');
        return $this->redirect($to !== '' ? $to : '/');
    }

    public function logout(Request $r): Response
    {
        Auth::logout();
        return $this->redirect('/login');
    }
}
