<?php
declare(strict_types=1);

namespace DomainScope\Services\TLS;

use DomainScope\Services\Http\CurlSupport;
use DomainScope\Services\Http\HostResolver;
use DomainScope\Support\DataSources;
use DomainScope\Validation\IpClassifier;

/**
 * Tatsächliche TLS-Prüfung per PHP/OpenSSL: Handshake mit SNI, Zertifikatskette, Hostnamenprüfung und
 * Vertrauensprüfung gegen das CA-Bundle. Ziele werden gegen SSRF geprüft und auf die geprüfte IP gepinnt.
 */
final class TlsInspector
{
    /** @var callable|null fn(string $host,int $port): array (Tests) */
    public static $override = null;

    /** @return array<string,mixed> */
    public function inspect(string $host, int $port = 443, ?string $ip = null, int $timeout = 8): array
    {
        if (self::$override !== null) {
            return (self::$override)($host, $port);
        }
        $started = microtime(true);
        $base = [
            'host' => $host, 'port' => $port, 'ip' => null, 'status' => 'unreachable', 'reachable' => false, 'error' => null,
            'error_stage' => null, 'protocol' => null, 'cipher' => null, 'cipher_bits' => null, 'chain_trusted' => null,
            'trust_error' => null, 'hostname_match' => null, 'certificate' => null, 'chain' => [], 'days_left' => null,
            'expired' => null, 'checked_at' => gmdate('Y-m-d H:i:s'), 'ms' => 0,
        ];
        if (!in_array($port, [443, 465, 636, 853, 993, 995, 8443], true)) {
            return ['error' => "Port $port ist für TLS-Prüfungen nicht freigegeben.", 'error_stage' => 'blocked'] + $base;
        }
        if ($ip === null) {
            $safe = HostResolver::resolveSafe($host);
            if (!$safe['ok']) {
                $stage = $safe['ips'] === [] ? 'dns' : 'blocked';
                return ['error' => $safe['reason'], 'error_stage' => $stage, 'ms' => $this->ms($started)] + $base;
            }
            $ip = $safe['ip'];
        } elseif (!IpClassifier::isPublic($ip)) {
            return ['error' => "Verbindung zu $ip blockiert (nicht öffentlich).", 'error_stage' => 'blocked', 'ip' => $ip] + $base;
        }
        $base['ip'] = $ip;

        $handshake = $this->connect($host, $port, $ip, $timeout, false);
        if ($handshake['error'] !== null && $handshake['certs'] === []) {
            DataSources::fail('tls', 'TLS-Handshakes (PHP/OpenSSL)', $handshake['error'], $this->ms($started));
            return ['error' => $handshake['error'], 'error_stage' => $handshake['stage'], 'ms' => $this->ms($started)] + $base;
        }
        DataSources::ok('tls', 'TLS-Handshakes (PHP/OpenSSL)', $this->ms($started));
        $base['reachable'] = true;
        $base['protocol'] = $handshake['protocol'];
        $base['cipher'] = $handshake['cipher'];
        $base['cipher_bits'] = $handshake['cipher_bits'];

        $chain = [];
        foreach ($handshake['certs'] as $i => $pem) {
            $parsed = $this->parseCertificate($pem);
            if ($parsed !== null) {
                $parsed['position'] = $i;
                $chain[] = $parsed;
            }
        }
        if ($chain === []) {
            return ['error' => 'Der Server hat kein auswertbares Zertifikat geliefert.', 'error_stage' => 'handshake', 'ms' => $this->ms($started)] + $base;
        }
        $leaf = $chain[0];
        $base['certificate'] = $leaf;
        $base['chain'] = $chain;
        $base['hostname_match'] = self::hostnameMatches($host, $leaf['sans'], $leaf['common_name']);
        $now = time();
        $base['expired'] = $leaf['not_after_ts'] !== null && $leaf['not_after_ts'] < $now;
        $base['days_left'] = $leaf['not_after_ts'] !== null ? (int) floor(($leaf['not_after_ts'] - $now) / 86400) : null;

        // Vertrauensprüfung mit eigener Verbindung (verify_peer=true, Hostname separat geprüft)
        $verify = $this->connect($host, $port, $ip, $timeout, true);
        $base['chain_trusted'] = $verify['error'] === null;
        $base['trust_error'] = $verify['error'] === null ? null : self::explainVerifyError($verify['error']);
        if ($verify['error'] !== null && str_contains(strtolower($verify['error']), 'certificate verify failed')) {
            // PHP liefert keinen konkreten OpenSSL-Verifikationscode; Ursache aus dem Zertifikat ableiten
            $base['trust_error'] = match (true) {
                $base['expired'] === true => 'Das Zertifikat ist abgelaufen (Ablaufdatum ' . $leaf['not_after'] . ' UTC).',
                ($leaf['not_before_ts'] ?? 0) > time() => 'Das Zertifikat ist noch nicht gültig (gültig ab ' . $leaf['not_before'] . ' UTC).',
                $leaf['self_signed'] => 'Selbstsigniertes Zertifikat – keine vertrauenswürdige CA.',
                count($chain) <= 1 => 'Aussteller nicht verifizierbar: Der Server liefert keine Zwischenzertifikate, oder die ausstellende CA ist nicht im CA-Bundle (unvollständige Kette).',
                default => 'Die Kette führt zu keiner vertrauenswürdigen Root-CA (unbekannter/nicht vertrauter Aussteller: ' . ($chain[count($chain) - 1]['issuer_cn'] ?? '?') . ').',
            };
        }
        if ($verify['error'] !== null && $verify['stage'] === 'connect') {
            // Verbindung beim 2. Versuch gescheitert – Vertrauen nicht beurteilbar
            $base['chain_trusted'] = null;
            $base['trust_error'] = 'Vertrauensprüfung nicht möglich: ' . $verify['error'];
        }

        $invalid = $base['expired'] || $base['hostname_match'] === false || $base['chain_trusted'] === false;
        $base['status'] = $invalid ? 'invalid' : 'ok';
        $base['ms'] = $this->ms($started);
        return $base;
    }

    /**
     * @return array{error:?string,stage:?string,certs:string[],protocol:?string,cipher:?string,cipher_bits:?int}
     */
    private function connect(string $host, int $port, string $ip, int $timeout, bool $verify): array
    {
        $out = ['error' => null, 'stage' => null, 'certs' => [], 'protocol' => null, 'cipher' => null, 'cipher_bits' => null];
        $ssl = [
            'peer_name' => $host, 'SNI_enabled' => true, 'SNI_server_name' => $host,
            'verify_peer' => $verify, 'verify_peer_name' => false, 'allow_self_signed' => false,
            'capture_peer_cert' => true, 'capture_peer_cert_chain' => true,
            'disable_compression' => true,
        ];
        $ca = CurlSupport::caFile();
        if ($ca !== null) {
            $ssl['cafile'] = $ca;
        }
        $ctx = stream_context_create(['ssl' => $ssl]);
        $addr = 'tcp://' . (str_contains($ip, ':') ? "[$ip]" : $ip) . ':' . $port;
        $errno = 0;
        $errstr = '';
        $fp = null;
        try {
            $fp = @stream_socket_client($addr, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
        } catch (\Throwable $e) {
            $errstr = $e->getMessage();
        }
        if (!$fp) {
            return ['error' => 'TCP-Verbindung fehlgeschlagen: ' . ($errstr ?: 'unbekannt') . ($errno ? " ($errno)" : ''), 'stage' => 'connect'] + $out;
        }
        stream_set_timeout($fp, $timeout);
        stream_set_blocking($fp, true);
        $ok = false;
        $err = null;
        try {
            $ok = stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        } catch (\Throwable $e) {
            $err = $e->getMessage();
        }
        $params = stream_context_get_params($fp);
        $opts = $params['options']['ssl'] ?? [];
        if (!empty($opts['peer_certificate'])) {
            $pem = '';
            if (@openssl_x509_export($opts['peer_certificate'], $pem)) {
                $out['certs'][] = $pem;
            }
            foreach ((array) ($opts['peer_certificate_chain'] ?? []) as $i => $c) {
                if ($i === 0) {
                    continue; // Blatt ist bereits enthalten
                }
                $p = '';
                if (@openssl_x509_export($c, $p)) {
                    $out['certs'][] = $p;
                }
            }
        }
        if ($ok === true) {
            $meta = stream_get_meta_data($fp);
            $out['protocol'] = $meta['crypto']['protocol'] ?? null;
            $out['cipher'] = $meta['crypto']['cipher_name'] ?? null;
            $out['cipher_bits'] = isset($meta['crypto']['cipher_bits']) ? (int) $meta['crypto']['cipher_bits'] : null;
        } else {
            $out['error'] = $err !== null ? self::cleanError($err) : 'TLS-Handshake fehlgeschlagen.';
            $out['stage'] = 'handshake';
        }
        @fclose($fp);
        return $out;
    }

    private static function cleanError(string $e): string
    {
        $e = preg_replace('/^stream_socket_enable_crypto\(\):\s*/', '', $e) ?? $e;
        return mb_substr(trim($e), 0, 400);
    }

    public static function explainVerifyError(string $e): string
    {
        $l = strtolower($e);
        return match (true) {
            str_contains($l, 'certificate has expired') => 'Das Zertifikat (oder ein Zertifikat der Kette) ist abgelaufen.',
            str_contains($l, 'self-signed') || str_contains($l, 'self signed') => 'Selbstsigniertes Zertifikat – nicht von einer vertrauenswürdigen CA ausgestellt.',
            str_contains($l, 'unable to get local issuer') || str_contains($l, 'unable to get issuer') => 'Der Aussteller ist unbekannt: Kette unvollständig (fehlendes Intermediate-Zertifikat) oder Root-CA nicht vertrauenswürdig.',
            str_contains($l, 'not yet valid') => 'Das Zertifikat ist noch nicht gültig (notBefore liegt in der Zukunft).',
            str_contains($l, 'revoked') => 'Das Zertifikat wurde widerrufen.',
            str_contains($l, 'certificate verify failed') => 'Die Zertifikatsprüfung ist fehlgeschlagen (' . self::cleanError($e) . ').',
            default => self::cleanError($e),
        };
    }

    /** @return array<string,mixed>|null */
    public function parseCertificate(string $pem): ?array
    {
        $x = @openssl_x509_parse($pem, true);
        if (!is_array($x)) {
            return null;
        }
        $sans = [];
        $ips = [];
        foreach (explode(',', (string) ($x['extensions']['subjectAltName'] ?? '')) as $entry) {
            $entry = trim($entry);
            if (stripos($entry, 'DNS:') === 0) {
                $sans[] = strtolower(trim(substr($entry, 4)));
            } elseif (stripos($entry, 'IP Address:') === 0) {
                $ips[] = trim(substr($entry, 11));
            }
        }
        $fp = (string) openssl_x509_fingerprint($pem, 'sha256');
        $subject = (array) ($x['subject'] ?? []);
        $issuer = (array) ($x['issuer'] ?? []);
        $pub = @openssl_pkey_get_public($pem);
        $key = $pub ? (openssl_pkey_get_details($pub) ?: []) : [];
        $keyType = match ($key['type'] ?? null) {
            OPENSSL_KEYTYPE_RSA => 'RSA', OPENSSL_KEYTYPE_EC => 'EC', OPENSSL_KEYTYPE_DSA => 'DSA',
            default => isset($key['type']) ? 'Sonstige' : null,
        };
        if ($keyType === null && isset($key['bits'])) {
            $keyType = 'Ed25519';
        }
        $curve = $key['ec']['curve_name'] ?? null;
        $bc = (string) ($x['extensions']['basicConstraints'] ?? '');
        $subjectStr = self::dnToString($subject);
        $issuerStr = self::dnToString($issuer);
        return [
            'subject' => $subjectStr, 'common_name' => $subject['CN'] ?? null,
            'issuer' => $issuerStr, 'issuer_cn' => $issuer['CN'] ?? null, 'issuer_org' => $issuer['O'] ?? null,
            'serial' => strtolower((string) ($x['serialNumberHex'] ?? '')),
            'fingerprint_sha256' => strtolower($fp),
            'fingerprint_sha1' => strtolower((string) openssl_x509_fingerprint($pem, 'sha1')),
            'sans' => array_values(array_unique($sans)), 'ip_sans' => $ips,
            'not_before' => isset($x['validFrom_time_t']) ? gmdate('Y-m-d H:i:s', (int) $x['validFrom_time_t']) : null,
            'not_after' => isset($x['validTo_time_t']) ? gmdate('Y-m-d H:i:s', (int) $x['validTo_time_t']) : null,
            'not_before_ts' => $x['validFrom_time_t'] ?? null, 'not_after_ts' => $x['validTo_time_t'] ?? null,
            'signature_algorithm' => $x['signatureTypeLN'] ?? ($x['signatureTypeSN'] ?? null),
            'key_type' => $keyType, 'key_bits' => $key['bits'] ?? null, 'key_curve' => $curve,
            'is_ca' => str_contains($bc, 'CA:TRUE'), 'self_signed' => $subjectStr === $issuerStr,
            'pem' => $pem,
        ];
    }

    /** @param array<string,mixed> $dn */
    public static function dnToString(array $dn): string
    {
        $parts = [];
        foreach ($dn as $k => $v) {
            foreach ((array) $v as $vv) {
                $parts[] = $k . '=' . $vv;
            }
        }
        return mb_substr(implode(', ', $parts), 0, 480);
    }

    /** RFC 6125-Hostnamenprüfung (Wildcard nur als vollständiges linkes Label). */
    public static function hostnameMatches(string $host, array $sans, ?string $cn): bool
    {
        $host = strtolower(rtrim($host, '.'));
        if (IpClassifier::isValid($host)) {
            return false;
        }
        $names = $sans !== [] ? $sans : ($cn !== null ? [strtolower($cn)] : []);
        foreach ($names as $n) {
            $n = strtolower(rtrim($n, '.'));
            if ($n === $host) {
                return true;
            }
            if (str_starts_with($n, '*.') && substr_count($n, '.') >= 2) {
                $suffix = substr($n, 1); // ".example.com"
                if (str_ends_with($host, $suffix)) {
                    $prefix = substr($host, 0, -strlen($suffix));
                    if ($prefix !== '' && !str_contains($prefix, '.')) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function ms(float $started): int
    {
        return (int) round((microtime(true) - $started) * 1000);
    }
}
