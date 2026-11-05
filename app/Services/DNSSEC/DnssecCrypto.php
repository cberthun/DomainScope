<?php
declare(strict_types=1);

namespace DomainScope\Services\DNSSEC;

use DomainScope\Services\DNS\RawDnsClient;

/**
 * Kryptografische DNSSEC-Bausteine: Key-Tag, DS-Digest, RRSIG-Prüfung (RSA und ECDSA P-256/P-384).
 */
final class DnssecCrypto
{
    public const ALGORITHMS = [
        1 => ['RSAMD5', 'insecure'], 3 => ['DSA', 'insecure'], 5 => ['RSASHA1', 'deprecated'],
        6 => ['DSA-NSEC3-SHA1', 'insecure'], 7 => ['RSASHA1-NSEC3-SHA1', 'deprecated'],
        8 => ['RSASHA256', 'ok'], 10 => ['RSASHA512', 'ok'], 12 => ['ECC-GOST', 'deprecated'],
        13 => ['ECDSAP256SHA256', 'ok'], 14 => ['ECDSAP384SHA384', 'ok'], 15 => ['ED25519', 'ok'], 16 => ['ED448', 'ok'],
    ];

    public static function algorithmName(int $alg): string
    {
        return (self::ALGORITHMS[$alg][0] ?? 'ALG' . $alg) . " ($alg)";
    }

    /** 'ok' | 'deprecated' | 'insecure' | 'unknown' */
    public static function algorithmStrength(int $alg): string
    {
        return self::ALGORITHMS[$alg][1] ?? 'unknown';
    }

    /** RDATA eines DNSKEY im Wire-Format. */
    public static function dnskeyRdata(int $flags, int $protocol, int $algorithm, string $keyBase64): ?string
    {
        $key = base64_decode($keyBase64, true);
        return $key === false ? null : pack('nCC', $flags, $protocol, $algorithm) . $key;
    }

    /** Key-Tag nach RFC 4034 Anhang B. */
    public static function keyTag(string $rdata): int
    {
        $ac = 0;
        $len = strlen($rdata);
        for ($i = 0; $i < $len; $i++) {
            $ac += ($i & 1) ? ord($rdata[$i]) : ord($rdata[$i]) << 8;
        }
        $ac += ($ac >> 16) & 0xFFFF;
        return $ac & 0xFFFF;
    }

    /** DS-Digest: hash(owner-wire | dnskey-rdata). Typen 1=SHA-1, 2=SHA-256, 4=SHA-384. */
    public static function dsDigest(string $owner, string $dnskeyRdata, int $digestType): ?string
    {
        $algo = match ($digestType) {
            1 => 'sha1', 2 => 'sha256', 4 => 'sha384', default => null,
        };
        return $algo === null ? null : hash($algo, RawDnsClient::nameToWire($owner) . $dnskeyRdata);
    }

    /**
     * Prüft die RRSIG über ein DNSKEY-RRset.
     *
     * @param array<int,array{flags:int,protocol:int,algorithm:int,key:string}> $dnskeys alle DNSKEYs des RRsets
     * @param array<string,mixed> $rrsig Ergebnis von RecordFormatter::parseRrsig (inkl. Rohdaten)
     * @return array{valid:?bool,reason:string}
     */
    public static function verifyDnskeyRrset(string $owner, array $dnskeys, array $rrsig, array $signerKey): array
    {
        $alg = (int) $rrsig['algorithm'];
        $sig = base64_decode((string) $rrsig['signature'], true);
        if ($sig === false) {
            return ['valid' => null, 'reason' => 'Signatur ist kein gültiges Base64'];
        }
        $rdatas = [];
        foreach ($dnskeys as $k) {
            $rd = self::dnskeyRdata($k['flags'], $k['protocol'], $k['algorithm'], $k['key']);
            if ($rd === null) {
                return ['valid' => null, 'reason' => 'DNSKEY mit ungültigem Base64'];
            }
            $rdatas[] = $rd;
        }
        sort($rdatas, SORT_STRING); // kanonische Reihenfolge (RFC 4034 §6.3)
        $ownerWire = RawDnsClient::nameToWire($owner);
        $header = pack('nCCNNNn', 48, $alg, (int) $rrsig['labels'], (int) $rrsig['original_ttl'], (int) $rrsig['expiration'], (int) $rrsig['inception'], (int) $rrsig['keytag'])
            . RawDnsClient::nameToWire((string) $rrsig['signer']);
        $data = $header;
        foreach ($rdatas as $rd) {
            $data .= $ownerWire . pack('nnNn', 48, 1, (int) $rrsig['original_ttl'], strlen($rd)) . $rd;
        }
        $pem = self::publicKeyPem($signerKey);
        if ($pem === null) {
            return ['valid' => null, 'reason' => 'Algorithmus ' . self::algorithmName($alg) . ' wird für die lokale Signaturprüfung nicht unterstützt'];
        }
        [$pem, $hash] = $pem;
        $signature = $sig;
        if (in_array($alg, [13, 14], true)) {
            $signature = self::ecdsaToDer($sig);
        }
        $r = @openssl_verify($data, $signature, $pem, $hash);
        return match ($r) {
            1 => ['valid' => true, 'reason' => 'Signatur kryptografisch gültig'],
            0 => ['valid' => false, 'reason' => 'Signaturprüfung fehlgeschlagen'],
            default => ['valid' => null, 'reason' => 'OpenSSL-Fehler bei der Signaturprüfung'],
        };
    }

    /** @return array{0:string,1:int|string}|null [PEM, OpenSSL-Hash] */
    private static function publicKeyPem(array $key): ?array
    {
        $alg = (int) $key['algorithm'];
        $raw = base64_decode((string) $key['key'], true);
        if ($raw === false || $raw === '') {
            return null;
        }
        switch ($alg) {
            case 5:
            case 7:
            case 8:
            case 10:
                $explen = ord($raw[0]);
                $off = 1;
                if ($explen === 0) {
                    $explen = unpack('n', substr($raw, 1, 2))[1];
                    $off = 3;
                }
                $exp = substr($raw, $off, $explen);
                $mod = substr($raw, $off + $explen);
                $rsaPub = self::derSeq(self::derInt($mod) . self::derInt($exp));
                $spki = self::derSeq(self::derSeq("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00") . "\x03" . self::derLen(strlen($rsaPub) + 1) . "\x00" . $rsaPub);
                $hash = match ($alg) {
                    8 => OPENSSL_ALGO_SHA256, 10 => OPENSSL_ALGO_SHA512, default => OPENSSL_ALGO_SHA1,
                };
                return [self::pem($spki), $hash];
            case 13:
                if (strlen($raw) !== 64) {
                    return null;
                }
                $prefix = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');
                return [self::pem($prefix . "\x04" . $raw), OPENSSL_ALGO_SHA256];
            case 14:
                if (strlen($raw) !== 96) {
                    return null;
                }
                $prefix = hex2bin('3076301006072a8648ce3d020106052b81040022036200');
                return [self::pem($prefix . "\x04" . $raw), OPENSSL_ALGO_SHA384];
            default:
                return null;
        }
    }

    private static function ecdsaToDer(string $sig): string
    {
        $half = intdiv(strlen($sig), 2);
        return self::derSeq(self::derInt(substr($sig, 0, $half)) . self::derInt(substr($sig, $half)));
    }

    private static function derLen(int $len): string
    {
        if ($len < 128) {
            return chr($len);
        }
        $bytes = ltrim(pack('N', $len), "\x00");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function derInt(string $bin): string
    {
        $bin = ltrim($bin, "\x00");
        if ($bin === '' || (ord($bin[0]) & 0x80)) {
            $bin = "\x00" . $bin;
        }
        return "\x02" . self::derLen(strlen($bin)) . $bin;
    }

    private static function derSeq(string $content): string
    {
        return "\x30" . self::derLen(strlen($content)) . $content;
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
}
