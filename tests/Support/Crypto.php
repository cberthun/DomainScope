<?php
declare(strict_types=1);

namespace DomainScope\Tests\Support;

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\SkippedWithMessageException;

/** Hilfen zum Erzeugen von Testschlüsseln/-zertifikaten (OpenSSL-Konfiguration plattformübergreifend finden). */
final class Crypto
{
    /** @return array{config?:string} */
    public static function opts(): array
    {
        $candidates = [getenv('OPENSSL_CONF') ?: '', dirname(PHP_BINARY) . '/extras/ssl/openssl.cnf', '/etc/ssl/openssl.cnf', '/usr/lib/ssl/openssl.cnf'];
        foreach ($candidates as $c) {
            if ($c !== '' && is_file($c)) {
                return ['config' => $c];
            }
        }
        return [];
    }

    public static function rsaKey(int $bits): \OpenSSLAsymmetricKey
    {
        $key = @openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + self::opts());
        if ($key === false) {
            throw new SkippedWithMessageException('OpenSSL kann in dieser Umgebung keine Testschlüssel erzeugen (openssl.cnf fehlt).');
        }
        return $key;
    }

    /**
     * Erzeugt ein Zertifikat als PEM.
     *
     * @param array{sans?:string[],days?:int,start_offset_days?:int,key_bits?:int,self_signed?:bool,cn?:string,digest?:string} $o
     */
    public static function certificate(array $o = []): string
    {
        $cn = $o['cn'] ?? 'example.test';
        $key = self::rsaKey($o['key_bits'] ?? 2048);
        $cfg = self::opts();
        $sans = $o['sans'] ?? [$cn];
        $san = implode(',', array_map(static fn($s) => 'DNS:' . $s, $sans));
        $tmp = tempnam(sys_get_temp_dir(), 'cnf');
        $base = isset($cfg['config']) ? (string) file_get_contents($cfg['config']) : "[req]\ndistinguished_name=req_dn\n[req_dn]\n";
        file_put_contents($tmp, $base . "\n[ v3_test ]\nsubjectAltName=$san\nbasicConstraints=CA:FALSE\n");
        $csr = openssl_csr_new(['commonName' => $cn, 'organizationName' => 'DomainScope Test'], $key, ['config' => $tmp, 'digest_alg' => $o['digest'] ?? 'sha256']);
        $x509 = openssl_csr_sign($csr, null, $key, (int) ($o['days'] ?? 90), ['config' => $tmp, 'x509_extensions' => 'v3_test', 'digest_alg' => $o['digest'] ?? 'sha256'], random_int(1000, 999999));
        unlink($tmp);
        Assert::assertNotFalse($x509, 'Zertifikat konnte nicht erzeugt werden');
        openssl_x509_export($x509, $pem);
        return $pem;
    }
}
