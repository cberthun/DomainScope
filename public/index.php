<?php
declare(strict_types=1);

/**
 * Front Controller. Einziger öffentlich erreichbarer PHP-Einstiegspunkt.
 * Aufrufe interner Dateien außerhalb von public/ sind über den Webserver-Root ausgeschlossen.
 */
require dirname(__DIR__) . '/app/bootstrap.php';

(new DomainScope\Support\App())->run();
