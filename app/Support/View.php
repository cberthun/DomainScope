<?php
declare(strict_types=1);

namespace DomainScope\Support;

final class View
{
    private static string $base = '';

    private static function base(): string
    {
        return self::$base ?: (self::$base = dirname(__DIR__) . '/Views');
    }

    /** Rendert ein Template ohne Layout (Partial/Komponente). */
    public static function partial(string $template, array $data = []): string
    {
        $file = self::resolve($template);
        extract($data, EXTR_SKIP);
        ob_start();
        try {
            require $file;
        } catch (\Throwable $e) {
            ob_end_clean();
            throw $e;
        }
        return (string) ob_get_clean();
    }

    /** Rendert eine Seite innerhalb des Layouts. */
    public static function page(string $template, array $data = [], string $layout = 'layouts/app'): string
    {
        $content = self::partial('pages/' . $template, $data);
        return self::partial($layout, $data + ['content' => $content]);
    }

    private static function resolve(string $template): string
    {
        if (!preg_match('#^[a-z0-9_/-]+$#i', $template)) {
            throw new \InvalidArgumentException('Ungültiger Template-Name');
        }
        $file = self::base() . '/' . $template . '.php';
        if (!is_file($file)) {
            throw new \RuntimeException('Template nicht gefunden: ' . $template);
        }
        return $file;
    }
}
