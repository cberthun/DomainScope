<?php
declare(strict_types=1);

namespace DomainScope\Tests\Unit;

use DomainScope\Validation\{DomainName, IpClassifier, PublicSuffix, Punycode, Target};
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ValidationTest extends TestCase
{
    // ---- Domain-Normalisierung -------------------------------------------------------------------------

    #[DataProvider('validDomains')]
    public function testNormalizesValidDomains(string $input, string $expected): void
    {
        self::assertSame($expected, DomainName::normalize($input));
    }

    public static function validDomains(): array
    {
        return [
            'Großbuchstaben' => ['ExAmPle.COM', 'example.com'],
            'abschließender Punkt' => ['example.com.', 'example.com'],
            'Subdomain' => ['www.Example.co.uk', 'www.example.co.uk'],
            'Bindestrich' => ['my-site.org', 'my-site.org'],
            'ideographischer Punkt' => ["example\u{3002}com", 'example.com'],
            'IDN Umlaut' => ['bücher.de', 'xn--bcher-kva.de'],
            'IDN Großschreibung' => ['BÜCHER.DE', 'xn--bcher-kva.de'],
            'IDN Kyrillisch' => ['пример.рф', 'xn--e1afmkfd.xn--p1ai'],
            'bereits Punycode' => ['xn--bcher-kva.de', 'xn--bcher-kva.de'],
        ];
    }

    #[DataProvider('invalidDomains')]
    public function testRejectsInvalidDomains(string $input): void
    {
        self::assertNull(DomainName::normalize($input));
    }

    public static function invalidDomains(): array
    {
        return [
            'leer' => [''], 'nur Punkt' => ['.'], 'doppelter Punkt' => ['a..b.com'], 'führender Bindestrich' => ['-a.com'],
            'abschließender Bindestrich' => ['a-.com'], 'Leerzeichen' => ['a b.com'], 'Unterstrich' => ['a_b.com'],
            'Pfad' => ['a.com/x'], 'Port' => ['a.com:80'], 'numerischer TLD' => ['example.123'],
            'Label zu lang' => [str_repeat('a', 64) . '.com'], 'Gesamtlänge' => [str_repeat('abcdefghi.', 26) . 'com'],
            'ungültiges Punycode' => ['xn--.com'], 'Steuerzeichen' => ["a\x00.com"],
        ];
    }

    public function testUnderscoreLabelsOnlyWhenAllowed(): void
    {
        self::assertNull(DomainName::normalize('_dmarc.example.com'));
        self::assertSame('_dmarc.example.com', DomainName::normalize('_dmarc.example.com', true));
    }

    // ---- Punycode ------------------------------------------------------------------------------------

    #[DataProvider('punycodeVectors')]
    public function testPunycodeRoundTrip(string $unicode, string $ascii): void
    {
        self::assertSame($ascii, Punycode::toAscii($unicode));
        self::assertSame($unicode, Punycode::toUnicode($ascii));
    }

    public static function punycodeVectors(): array
    {
        // Referenzwerte aus RFC 3492 / IDNA-Praxis
        return [
            ['bücher.de', 'xn--bcher-kva.de'], ['münchen.de', 'xn--mnchen-3ya.de'], ['日本語.jp', 'xn--wgv71a119e.jp'],
            ['пример.рф', 'xn--e1afmkfd.xn--p1ai'], ['ドメイン名例.jp', 'xn--eckwd4c7cu47r2wf.jp'], ['faß.de', 'xn--fa-hia.de'],
        ];
    }

    public function testPunycodeEncodeDecodeLabel(): void
    {
        self::assertSame('tda', Punycode::encode('ü'));
        self::assertSame('ü', Punycode::decode('tda'));
    }

    // ---- Eingabeklassifikation ------------------------------------------------------------------------

    public function testTargetDistinguishesDomainUrlAndIp(): void
    {
        $d = Target::parse('www.Example.co.uk');
        self::assertSame('domain', $d->type);
        self::assertSame('example.co.uk', $d->registrable);
        self::assertSame('co.uk', $d->suffix);
        self::assertTrue($d->isSubdomain);

        $u = Target::parse('https://user@Sub.Example.com:8443/pfad?q=1#frag');
        self::assertSame('domain', $u->type);
        self::assertTrue($u->fromUrl);
        self::assertSame('sub.example.com', $u->host);
        self::assertSame('example.com', $u->registrable);
        self::assertSame(8443, $u->port);

        $ip4 = Target::parse('203.0.113.7');
        self::assertSame('ip', $ip4->type);
        self::assertSame('203.0.113.7', $ip4->host);

        $ip6 = Target::parse('[2001:DB8::1]:443');
        self::assertSame('ip', $ip6->type);
        self::assertSame('2001:db8::1', $ip6->host);

        $url6 = Target::parse('http://[::1]/');
        self::assertSame('ip', $url6->type);
    }

    public function testTargetRejectsAmbiguousAndForeignInput(): void
    {
        self::assertSame('invalid', Target::parse('2130706433')->type, 'Dezimal-IP-Trick');
        self::assertSame('invalid', Target::parse('0x7f.1')->type, 'Hex-IP-Trick');
        self::assertSame('invalid', Target::parse('127.1')->type);
        self::assertSame('invalid', Target::parse('ftp://example.com')->type);
        self::assertSame('invalid', Target::parse('javascript:alert(1)')->type);
        self::assertSame('invalid', Target::parse('')->type);
        self::assertSame('invalid', Target::parse(str_repeat('a', 3000))->type);
    }

    public function testTargetPublicSuffixHasNoRegistrableDomain(): void
    {
        $t = Target::parse('co.uk');
        self::assertSame('domain', $t->type);
        self::assertNull($t->registrable);
        self::assertNotNull($t->error);
    }

    public function testIdnTargetUsesPunycodeAndKeepsUnicode(): void
    {
        $t = Target::parse('https://Bücher.de/katalog');
        self::assertSame('xn--bcher-kva.de', $t->registrable);
        self::assertSame('bücher.de', $t->unicode);
    }

    // ---- Public Suffix -------------------------------------------------------------------------------

    public function testPublicSuffixRules(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'psl');
        file_put_contents($file, "// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\n*.kobe.jp\n!city.kobe.jp\njp\nde\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n");
        PublicSuffix::useFile($file);
        try {
            self::assertSame('co.uk', PublicSuffix::suffix('www.example.co.uk'));
            self::assertSame('example.co.uk', PublicSuffix::registrable('www.example.co.uk'));
            self::assertSame('example.com', PublicSuffix::registrable('a.b.example.com'));
            self::assertNull(PublicSuffix::registrable('co.uk'), 'Suffix selbst ist nicht registrierbar');
            // Wildcard- und Ausnahmeregel
            self::assertSame('x.kobe.jp', PublicSuffix::suffix('x.kobe.jp'));
            self::assertSame('a.x.kobe.jp', PublicSuffix::registrable('a.x.kobe.jp'));
            self::assertSame('kobe.jp', PublicSuffix::suffix('city.kobe.jp'));
            self::assertSame('city.kobe.jp', PublicSuffix::registrable('www.city.kobe.jp'));
            // unbekannte TLD → Standardregel "*"
            self::assertSame('zzz', PublicSuffix::suffix('example.zzz'));
            // Private Domains (github.io) sind nicht Teil der ICANN-Auswertung
            self::assertSame('github.io', PublicSuffix::registrable('user.github.io'));
        } finally {
            PublicSuffix::useFile(null);
            unlink($file);
        }
    }

    // ---- IP-Validierung ------------------------------------------------------------------------------

    #[DataProvider('ipClasses')]
    public function testIpClassification(string $ip, bool $public, string $category): void
    {
        $c = IpClassifier::classify($ip);
        self::assertSame($public, $c['public'], $ip);
        self::assertSame($category, $c['category'], $ip);
    }

    public static function ipClasses(): array
    {
        return [
            ['8.8.8.8', true, 'public'], ['1.1.1.1', true, 'public'], ['2606:4700:4700::1111', true, 'public'],
            ['10.1.2.3', false, 'private'], ['172.16.0.1', false, 'private'], ['172.32.0.1', true, 'public'], ['192.168.1.1', false, 'private'],
            ['100.64.0.1', false, 'private'], ['127.0.0.1', false, 'loopback'], ['::1', false, 'loopback'],
            ['169.254.169.254', false, 'link-local'], ['fe80::1', false, 'link-local'], ['fd00::1', false, 'private'],
            ['224.0.0.1', false, 'multicast'], ['ff02::1', false, 'multicast'], ['0.0.0.0', false, 'reserved'],
            ['192.0.2.10', false, 'documentation'], ['2001:db8::1', false, 'documentation'], ['255.255.255.255', false, 'reserved'],
            ['::ffff:127.0.0.1', false, 'loopback'], ['::ffff:8.8.8.8', false, 'ipv4-mapped'],
        ];
    }

    public function testIpValidationAndNormalization(): void
    {
        self::assertTrue(IpClassifier::isValid('192.0.2.1'));
        self::assertTrue(IpClassifier::isValid('2001:DB8:0:0:0:0:0:1'));
        self::assertFalse(IpClassifier::isValid('256.1.1.1'));
        self::assertFalse(IpClassifier::isValid('1.2.3'));
        self::assertFalse(IpClassifier::isValid('01.2.3.4'), 'führende Nullen sind mehrdeutig (oktal)');
        self::assertSame('2001:db8::1', IpClassifier::normalize('2001:DB8:0:0:0:0:0:1'));
        self::assertSame(4, IpClassifier::version('192.0.2.1'));
        self::assertSame(6, IpClassifier::version('::1'));
        self::assertNull(IpClassifier::version('nope'));
        self::assertSame('4.3.2.1.in-addr.arpa', IpClassifier::reverseName('1.2.3.4'));
        self::assertStringEndsWith('.ip6.arpa', (string) IpClassifier::reverseName('2001:db8::1'));
    }
}
