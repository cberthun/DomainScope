<?php
declare(strict_types=1);

namespace DomainScope\Support;

final class Response
{
    /** @param array<string,string> $headers */
    public function __construct(
        public string $body = '',
        public int $status = 200,
        public array $headers = [],
    ) {
    }

    public static function html(string $body, int $status = 200): self
    {
        return new self($body, $status, ['Content-Type' => 'text/html; charset=utf-8']);
    }

    public static function json(mixed $data, int $status = 200): self
    {
        return new self(json_out($data), $status, ['Content-Type' => 'application/json; charset=utf-8']);
    }

    public static function redirect(string $location, int $status = 302): self
    {
        // Nur relative Pfade erlauben (kein Open Redirect)
        if (!str_starts_with($location, '/') || str_starts_with($location, '//') || str_contains($location, "\n")) {
            $location = '/';
        }
        return new self('', $status, ['Location' => $location]);
    }

    /** Download mit sicherem Dateinamen. */
    public static function download(string $body, string $filename, string $contentType): self
    {
        $safe = preg_replace('/[^A-Za-z0-9._-]+/', '_', $filename) ?? 'export';
        $safe = ltrim((string) preg_replace('/\.{2,}/', '.', $safe), '.') ?: 'export';
        return new self($body, 200, [
            'Content-Type' => $contentType,
            'Content-Disposition' => 'attachment; filename="' . $safe . '"',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    public function send(bool $headOnly = false): void
    {
        if (!headers_sent()) {
            header_remove('X-Powered-By');
            http_response_code($this->status);
            foreach ($this->headers as $k => $v) {
                header($k . ': ' . $v);
            }
        }
        if (!$headOnly) {
            echo $this->body;
        }
    }
}
