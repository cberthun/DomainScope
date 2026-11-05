<?php
declare(strict_types=1);

namespace DomainScope\Services\TLS;

use DomainScope\Services\Http\{CurlSupport, HostResolver};
use DomainScope\Support\DataSources;

/**
 * STARTTLS-Test eines Mailservers (SMTP Port 25): EHLO → STARTTLS → TLS-Handshake mit Zertifikatsauswertung.
 * Es wird keine Mail eingeliefert (Abbruch mit QUIT). Verbindungen gehen nur zu öffentlichen Adressen.
 * Viele Provider blockieren ausgehenden Port 25 – das Ergebnis ist dann "nicht erreichbar", kein Befund.
 */
final class SmtpTlsInspector
{
    /** @var callable|null fn(string $host): array (Tests) */
    public static $override = null;

    /** @return array<string,mixed> */
    public function inspect(string $host, int $port = 25, int $timeout = 8): array
    {
        if (self::$override !== null) {
            return (self::$override)($host);
        }
        $base = [
            'host' => $host, 'port' => $port, 'ip' => null, 'status' => 'unreachable', 'error' => null, 'banner' => null,
            'starttls' => null, 'protocol' => null, 'cipher' => null, 'certificate' => null, 'hostname_match' => null,
            'chain_trusted' => null, 'trust_error' => null, 'days_left' => null, 'expired' => null, 'checked_at' => gmdate('Y-m-d H:i:s'),
        ];
        $safe = HostResolver::resolveSafe($host);
        if (!$safe['ok']) {
            return ['error' => $safe['reason']] + $base;
        }
        $base['ip'] = $safe['ip'];
        $first = $this->session((string) $safe['ip'], $host, $timeout, false);
        $base['banner'] = $first['banner'];
        if ($first['error'] !== null && !$first['certs']) {
            DataSources::fail('smtp-starttls', 'SMTP-STARTTLS-Test (Port 25)', $first['error']);
            return ['error' => $first['error'], 'starttls' => $first['starttls']] + $base;
        }
        DataSources::ok('smtp-starttls', 'SMTP-STARTTLS-Test (Port 25)', 0);
        $base['starttls'] = $first['starttls'];
        if (!$first['starttls']) {
            return ['status' => 'no_starttls', 'error' => 'Der Server bietet STARTTLS nicht an (Nachrichten würden unverschlüsselt übertragen).'] + $base;
        }
        if (!$first['certs']) {
            return ['status' => 'tls_failed', 'error' => $first['error'] ?? 'TLS-Handshake nach STARTTLS fehlgeschlagen.'] + $base;
        }
        $tls = new TlsInspector();
        $leaf = $tls->parseCertificate($first['certs'][0]);
        if ($leaf === null) {
            return ['status' => 'tls_failed', 'error' => 'Kein auswertbares Zertifikat.'] + $base;
        }
        $base['certificate'] = $leaf;
        $base['protocol'] = $first['protocol'];
        $base['cipher'] = $first['cipher'];
        $base['hostname_match'] = TlsInspector::hostnameMatches($host, $leaf['sans'], $leaf['common_name']);
        $base['expired'] = $leaf['not_after_ts'] !== null && $leaf['not_after_ts'] < time();
        $base['days_left'] = $leaf['not_after_ts'] !== null ? (int) floor(($leaf['not_after_ts'] - time()) / 86400) : null;
        $verify = $this->session((string) $safe['ip'], $host, $timeout, true);
        $base['chain_trusted'] = $verify['error'] === null && $verify['certs'] !== [];
        $base['trust_error'] = $base['chain_trusted'] ? null : ($base['expired'] ? 'Zertifikat abgelaufen.' : ($leaf['self_signed'] ? 'Selbstsigniertes Zertifikat.' : 'Kette nicht vertrauenswürdig oder unvollständig.'));
        $base['status'] = ($base['expired'] || $base['hostname_match'] === false || !$base['chain_trusted']) ? 'invalid' : 'ok';
        return $base;
    }

    /** @return array{error:?string,banner:?string,starttls:?bool,certs:string[],protocol:?string,cipher:?string} */
    private function session(string $ip, string $host, int $timeout, bool $verify): array
    {
        $out = ['error' => null, 'banner' => null, 'starttls' => null, 'certs' => [], 'protocol' => null, 'cipher' => null];
        $ssl = ['peer_name' => $host, 'SNI_enabled' => true, 'SNI_server_name' => $host, 'verify_peer' => $verify, 'verify_peer_name' => false,
            'capture_peer_cert' => true, 'capture_peer_cert_chain' => true, 'allow_self_signed' => false];
        if (($ca = CurlSupport::caFile()) !== null) {
            $ssl['cafile'] = $ca;
        }
        $ctx = stream_context_create(['ssl' => $ssl]);
        $errno = 0;
        $errstr = '';
        try {
            $fp = @stream_socket_client('tcp://' . (str_contains($ip, ':') ? "[$ip]" : $ip) . ':25', $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
        } catch (\Throwable $e) {
            $fp = false;
            $errstr = $e->getMessage();
        }
        if (!$fp) {
            $out['error'] = 'Verbindung zu Port 25 fehlgeschlagen: ' . ($errstr ?: 'Timeout') . ' (ausgehender Port 25 wird oft vom Provider blockiert).';
            return $out;
        }
        stream_set_timeout($fp, $timeout);
        $greet = $this->readReply($fp);
        $out['banner'] = $greet !== null ? mb_substr($greet[0], 0, 160) : null;
        if ($greet === null || !str_starts_with($greet[0], '220')) {
            $out['error'] = 'Unerwartete SMTP-Begrüßung.';
            fclose($fp);
            return $out;
        }
        fwrite($fp, "EHLO domainscope.invalid\r\n");
        $ehlo = $this->readReply($fp);
        $caps = $ehlo ? strtoupper(implode("\n", $ehlo)) : '';
        $out['starttls'] = str_contains($caps, 'STARTTLS');
        if (!$out['starttls']) {
            @fwrite($fp, "QUIT\r\n");
            fclose($fp);
            return $out;
        }
        fwrite($fp, "STARTTLS\r\n");
        $rep = $this->readReply($fp);
        if ($rep === null || !str_starts_with($rep[0], '220')) {
            $out['error'] = 'STARTTLS wurde abgelehnt: ' . ($rep[0] ?? 'keine Antwort');
            fclose($fp);
            return $out;
        }
        try {
            $ok = stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        } catch (\Throwable $e) {
            $ok = false;
            $out['error'] = mb_substr($e->getMessage(), 0, 300);
        }
        $opts = stream_context_get_params($fp)['options']['ssl'] ?? [];
        if (!empty($opts['peer_certificate'])) {
            $pem = '';
            if (@openssl_x509_export($opts['peer_certificate'], $pem)) {
                $out['certs'][] = $pem;
            }
        }
        if ($ok === true) {
            $meta = stream_get_meta_data($fp);
            $out['protocol'] = $meta['crypto']['protocol'] ?? null;
            $out['cipher'] = $meta['crypto']['cipher_name'] ?? null;
            $out['error'] = null;
        } else {
            $out['error'] ??= 'TLS-Handshake nach STARTTLS fehlgeschlagen.';
        }
        @fclose($fp);
        return $out;
    }

    /** @param resource $fp @return string[]|null Zeilen einer (mehrzeiligen) SMTP-Antwort */
    private function readReply($fp): ?array
    {
        $lines = [];
        for ($i = 0; $i < 40; $i++) {
            $line = fgets($fp, 1024);
            if ($line === false) {
                break;
            }
            $line = rtrim($line);
            $lines[] = $line;
            if (strlen($line) < 4 || $line[3] !== '-') {
                return $lines;
            }
        }
        return $lines ?: null;
    }
}
