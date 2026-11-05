<?php
declare(strict_types=1);

namespace DomainScope\Services\Subdomains;

use DomainScope\Services\DNS\DohClient;
use DomainScope\Services\Http\SafeHttp;

/**
 * Erkennt Hinweise auf Subdomain-Takeover: CNAME zeigt auf einen Drittanbieter, bei dem die Ressource nicht
 * (mehr) existiert. Grundlage sind (1) Nichtexistenz des CNAME-Ziels (NXDOMAIN) oder (2) die typische
 * Fehlerseite des Anbieters. Es handelt sich um Indizien, nicht um einen Ausnutzbarkeitsnachweis.
 */
final class TakeoverChecker
{
    /**
     * name => [CNAME-Regex, Regex für die Fehlerseite (null = nur NXDOMAIN des Ziels aussagekräftig), NXDOMAIN-Ziel = übernehmbar]
     */
    public const PROVIDERS = [
        'GitHub Pages' => ['/\.github\.io$/', '/There isn\'t a GitHub Pages site here/i', false],
        'Heroku' => ['/\.herokuapp\.com$|\.herokudns\.com$/', '/no such app|herokucdn\.com\/error-pages\/no-such-app/i', true],
        'AWS S3' => ['/\.s3[.-][a-z0-9.-]*amazonaws\.com$|\.s3\.amazonaws\.com$/', '/NoSuchBucket|The specified bucket does not exist/i', false],
        'AWS Elastic Beanstalk' => ['/\.elasticbeanstalk\.com$/', null, true],
        'Azure App Service' => ['/\.azurewebsites\.net$/', '/Web App - Pending|404 Web Site not found/i', true],
        'Azure (Cloud Services/Traffic Manager/Blob)' => ['/\.cloudapp\.(azure\.com|net)$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$|\.azureedge\.net$/', null, true],
        'Netlify' => ['/\.netlify\.(app|com)$/', '/Not Found - Request ID/i', false],
        'Vercel' => ['/\.vercel\.app$|cname\.vercel-dns\.com$/', '/DEPLOYMENT_NOT_FOUND|The deployment could not be found/i', false],
        'Shopify' => ['/\.myshopify\.com$|shops\.myshopify\.com$/', '/Sorry, this shop is currently unavailable|Only one step left/i', false],
        'Fastly' => ['/\.fastly\.net$/', '/Fastly error: unknown domain/i', false],
        'Surge.sh' => ['/\.surge\.sh$/', '/project not found/i', false],
        'Ghost' => ['/\.ghost\.io$/', '/The thing you were looking for is no longer here/i', false],
        'Tumblr' => ['/domains\.tumblr\.com$/', '/Whatever you were looking for doesn\'t currently exist at this address/i', false],
        'Pantheon' => ['/\.pantheonsite\.io$/', '/404 error unknown site|The gods are wise/i', false],
        'Bitbucket' => ['/\.bitbucket\.io$/', '/Repository not found/i', false],
        'Zendesk' => ['/\.zendesk\.com$/', '/Help Center Closed|this help center no longer exists/i', false],
        'Unbounce' => ['/unbouncepages\.com$/', '/The requested URL was not found on this server/i', false],
        'WordPress.com' => ['/\.wordpress\.com$/', '/Do you want to register/i', false],
        'Amazon CloudFront' => ['/\.cloudfront\.net$/', '/The request could not be satisfied.*(Bad request|Not Found)/is', false],
    ];

    public function __construct(private readonly DohClient $doh)
    {
    }

    /** @return array{provider:?string,provider_pattern:bool}|null */
    public static function match(string $cname): ?array
    {
        $cname = strtolower(rtrim($cname, '.'));
        foreach (self::PROVIDERS as $name => [$re]) {
            if (preg_match($re, $cname)) {
                return ['provider' => $name, 'provider_pattern' => true];
            }
        }
        return null;
    }

    /**
     * @return array{status:string,provider:?string,cname:string,evidence:string,checked_at:string}
     *         status: vulnerable | dangling | provider | none
     */
    public function check(string $host, string $cname, bool $httpProbe = true): array
    {
        $cname = strtolower(rtrim($cname, '.'));
        $m = self::match($cname);
        $provider = $m['provider'] ?? null;
        $base = ['provider' => $provider, 'cname' => $cname, 'checked_at' => gmdate('Y-m-d H:i:s')];

        $a = $this->doh->query('cloudflare', $cname, 'A');
        $aaaa = $this->doh->query('cloudflare', $cname, 'AAAA');
        $unknownDns = in_array($a['status'], ['timeout', 'error', 'servfail'], true) && in_array($aaaa['status'], ['timeout', 'error', 'servfail'], true);
        if ($unknownDns) {
            return ['status' => 'none', 'evidence' => 'DNS-Auflösung des Ziels nicht möglich (' . ($a['error'] ?? $a['status']) . ') – keine Aussage.'] + $base;
        }
        if ($a['status'] === 'nxdomain') {
            if ($provider !== null && self::PROVIDERS[$provider][2]) {
                return ['status' => 'vulnerable', 'evidence' => "Das CNAME-Ziel $cname existiert nicht (NXDOMAIN) und gehört zu $provider, wo sich solche Namen neu registrieren lassen."] + $base;
            }
            return ['status' => 'dangling', 'evidence' => "Das CNAME-Ziel $cname existiert nicht (NXDOMAIN)."] + $base;
        }
        if ($provider === null) {
            return ['status' => 'none', 'evidence' => 'Kein bekannter Takeover-Anbieter.'] + $base;
        }
        $re = self::PROVIDERS[$provider][1];
        if ($httpProbe && $re !== null) {
            foreach (['https', 'http'] as $scheme) {
                $r = SafeHttp::request("$scheme://$host/", ['max_bytes' => 65536, 'timeout' => 8, 'source' => 'takeover-probe', 'label' => 'Takeover-Prüfung (HTTP)']);
                if ($r['status'] > 0 && preg_match($re, $r['body'])) {
                    return ['status' => 'vulnerable', 'evidence' => "Die Antwort von $scheme://$host zeigt die typische „Ressource nicht vorhanden“-Seite von $provider (HTTP {$r['status']})."] + $base;
                }
            }
        }
        return ['status' => 'provider', 'evidence' => "CNAME zeigt auf $provider; keine Anzeichen für eine freie Ressource."] + $base;
    }
}
