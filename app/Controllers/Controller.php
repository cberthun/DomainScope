<?php
declare(strict_types=1);

namespace DomainScope\Controllers;

use DomainScope\Repositories\DomainRepository;
use DomainScope\Security\Session;
use DomainScope\Support\{Request, Response, View};
use DomainScope\Validation\Target;

abstract class Controller
{
    public function __construct(protected readonly Request $request)
    {
    }

    /** @param array<string,mixed> $data */
    protected function page(string $template, array $data = []): Response
    {
        $data += [
            'title' => 'DomainScope', 'breadcrumbs' => [], 'section' => '', 'scripts' => [], 'actions' => '',
            'flash' => Session::pullFlash(), 'path' => $this->request->path,
        ];
        return Response::html(View::page($template, $data));
    }

    protected function partial(string $template, array $data = []): Response
    {
        return Response::html(View::partial($template, $data));
    }

    protected function json(mixed $data, int $status = 200): Response
    {
        return Response::json($data, $status);
    }

    protected function redirect(string $to): Response
    {
        return Response::redirect($to);
    }

    protected function flash(string $type, string $message): void
    {
        Session::flash($type, $message);
    }

    /** Lädt die Domain aus dem Routenparameter oder liefert null (→ 404-Antwort durch Aufrufer). @return array<string,mixed>|null */
    protected function domainFromRoute(string $param = 'domain'): ?array
    {
        $t = Target::parse((string) ($this->request->params[$param] ?? ''));
        if (!$t->isDomain() || $t->registrable === null) {
            return null;
        }
        return DomainRepository::find($t->registrable);
    }

    protected function notFound(string $what = 'Seite'): Response
    {
        return Response::html(View::page('not_found', ['title' => 'Nicht gefunden', 'breadcrumbs' => [], 'section' => '', 'scripts' => [], 'actions' => '', 'flash' => [], 'path' => $this->request->path, 'what' => $what]), 404);
    }

    /** @return string[] */
    protected function listInput(string $key): array
    {
        $v = $this->request->input($key, []);
        if (is_string($v)) {
            $v = explode(',', $v);
        }
        return array_values(array_filter(array_map(static fn($x) => trim((string) $x), (array) $v), static fn($x) => $x !== ''));
    }
}
