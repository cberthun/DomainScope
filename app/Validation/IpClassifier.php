<?php
declare(strict_types=1);

namespace DomainScope\Validation;

/** Klassifikation von IP-Adressen (öffentlich, privat, reserviert, speziell). */
final class IpClassifier
{
    /** @var array<int,array{0:string,1:string,2:bool}> [CIDR, Bezeichnung, global_erreichbar] */
    private const V4 = [
        ['0.0.0.0/8', 'Dieses Netzwerk (RFC 1122)', false],
        ['10.0.0.0/8', 'Privat (RFC 1918)', false],
        ['100.64.0.0/10', 'Carrier-grade NAT (RFC 6598)', false],
        ['127.0.0.0/8', 'Loopback', false],
        ['169.254.0.0/16', 'Link-Local', false],
        ['172.16.0.0/12', 'Privat (RFC 1918)', false],
        ['192.0.0.0/24', 'IETF-Protokollzuweisungen', false],
        ['192.0.2.0/24', 'Dokumentation (TEST-NET-1)', false],
        ['192.88.99.0/24', '6to4-Relay (veraltet)', false],
        ['192.168.0.0/16', 'Privat (RFC 1918)', false],
        ['198.18.0.0/15', 'Benchmark-Tests', false],
        ['198.51.100.0/24', 'Dokumentation (TEST-NET-2)', false],
        ['203.0.113.0/24', 'Dokumentation (TEST-NET-3)', false],
        ['224.0.0.0/4', 'Multicast', false],
        ['240.0.0.0/4', 'Reserviert (Klasse E)', false],
        ['255.255.255.255/32', 'Broadcast', false],
    ];

    private const V6 = [
        ['::/128', 'Unspezifiziert', false],
        ['::1/128', 'Loopback', false],
        ['::ffff:0:0/96', 'IPv4-mapped', false],
        ['64:ff9b::/96', 'NAT64 (RFC 6052)', false],
        ['64:ff9b:1::/48', 'NAT64 lokal', false],
        ['100::/64', 'Discard-Only', false],
        ['2001::/32', 'Teredo', false],
        ['2001:2::/48', 'Benchmark-Tests', false],
        ['2001:db8::/32', 'Dokumentation', false],
        ['2002::/16', '6to4', false],
        ['fc00::/7', 'Unique Local (privat)', false],
        ['fe80::/10', 'Link-Local', false],
        ['fec0::/10', 'Site-Local (veraltet)', false],
        ['ff00::/8', 'Multicast', false],
    ];

    public static function isValid(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    public static function version(string $ip): ?int
    {
        if (!self::isValid($ip)) {
            return null;
        }
        return str_contains($ip, ':') ? 6 : 4;
    }

    /** Normalisierte Textform (kompaktes IPv6 in Kleinbuchstaben). */
    public static function normalize(string $ip): ?string
    {
        $bin = @inet_pton($ip);
        return $bin === false ? null : inet_ntop($bin);
    }

    /**
     * @return array{public:bool,label:string,category:string}
     */
    public static function classify(string $ip): array
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return ['public' => false, 'label' => 'Ungültig', 'category' => 'invalid'];
        }
        if (strlen($bin) === 16) {
            // IPv4-mapped (::ffff:a.b.c.d) → als IPv4 bewerten
            if (str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
                $res = self::classify(inet_ntop(substr($bin, 12)));
                $res['label'] = 'IPv4-mapped: ' . $res['label'];
                $res['category'] = $res['public'] ? 'ipv4-mapped' : $res['category'];
                $res['public'] = false;
                return $res;
            }
            foreach (self::V6 as [$cidr, $label]) {
                if (self::inCidr($bin, $cidr)) {
                    return ['public' => false, 'label' => $label, 'category' => self::category($label)];
                }
            }
            return ['public' => true, 'label' => 'Öffentlich (global routbar)', 'category' => 'public'];
        }
        foreach (self::V4 as [$cidr, $label]) {
            if (self::inCidr($bin, $cidr)) {
                return ['public' => false, 'label' => $label, 'category' => self::category($label)];
            }
        }
        return ['public' => true, 'label' => 'Öffentlich (global routbar)', 'category' => 'public'];
    }

    public static function isPublic(string $ip): bool
    {
        return self::classify($ip)['public'];
    }

    private static function category(string $label): string
    {
        return match (true) {
            str_contains($label, 'Privat'), str_contains($label, 'Unique Local'), str_contains($label, 'Carrier') => 'private',
            str_contains($label, 'Loopback') => 'loopback',
            str_contains($label, 'Link-Local') => 'link-local',
            str_contains($label, 'Multicast') => 'multicast',
            str_contains($label, 'Dokumentation') => 'documentation',
            default => 'reserved',
        };
    }

    public static function inCidr(string $binIp, string $cidr): bool
    {
        [$net, $bits] = explode('/', $cidr);
        $netBin = inet_pton($net);
        if ($netBin === false || strlen($netBin) !== strlen($binIp)) {
            return false;
        }
        $bits = (int) $bits;
        $bytes = intdiv($bits, 8);
        if ($bytes > 0 && substr($binIp, 0, $bytes) !== substr($netBin, 0, $bytes)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        return (ord($binIp[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
    }

    public static function reverseName(string $ip): ?string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 4) {
            return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        }
        $hex = bin2hex($bin);
        return implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
    }
}
