<?php
declare(strict_types=1);

namespace DomainScope\Services\DNS;

use DomainScope\Support\DataSources;
use DomainScope\Validation\IpClassifier;

/**
 * Minimaler DNS-Wire-Client (UDP mit TCP-Fallback) zur direkten Abfrage autoritativer Nameserver.
 * Dient der Delegations- und Konsistenzprüfung (Parent-/Child-Zone, SOA-Serials, Lame Delegation).
 * Nur öffentliche Zieladressen sind erlaubt.
 */
final class RawDnsClient
{
    /** @var callable|null fn(string $ip, string $packet, bool $tcp): ?string (Tests) */
    public static $transport = null;

    /**
     * @param array{rd?:bool,do?:bool,timeout?:int} $opts
     * @return array<string,mixed>
     */
    public function query(string $serverIp, string $name, string $type, array $opts = []): array
    {
        $fail = static fn(string $err) => [
            'ok' => false, 'error' => $err, 'rcode' => null, 'rcode_name' => null, 'flags' => [], 'answer' => [],
            'authority' => [], 'additional' => [], 'ms' => 0, 'via' => null, 'server' => $serverIp,
        ];
        if (!IpClassifier::isPublic($serverIp)) {
            return $fail("Server $serverIp ist keine öffentliche Adresse (blockiert).");
        }
        $code = DnsTypes::code($type);
        if ($code === null) {
            return $fail("Unbekannter Typ $type");
        }
        $id = random_int(0, 65535);
        $packet = $this->buildQuery($id, $name, $code, $opts);
        $started = microtime(true);
        $timeout = $opts['timeout'] ?? 3;

        $resp = $this->send($serverIp, $packet, false, $timeout);
        $via = 'udp';
        if ($resp === null) {
            DataSources::fail('authns', 'Autoritative Nameserver (direkt, Port 53)', 'keine UDP-Antwort', (int) ((microtime(true) - $started) * 1000));
            return $fail('Keine Antwort (Timeout oder Port 53/UDP blockiert).') + ['ms' => (int) ((microtime(true) - $started) * 1000)];
        }
        $parsed = $this->parse($resp, $id);
        if ($parsed === null) {
            return $fail('Ungültige DNS-Antwort.');
        }
        if ($parsed['flags']['tc']) {
            $tcp = $this->send($serverIp, $packet, true, $timeout);
            if ($tcp !== null && ($p2 = $this->parse($tcp, $id)) !== null) {
                $parsed = $p2;
                $via = 'tcp';
            }
        }
        $ms = (int) round((microtime(true) - $started) * 1000);
        DataSources::ok('authns', 'Autoritative Nameserver (direkt, Port 53)', $ms);
        return $parsed + ['ok' => true, 'error' => null, 'ms' => $ms, 'via' => $via, 'server' => $serverIp];
    }

    /** @param array{rd?:bool,do?:bool} $opts */
    public function buildQuery(int $id, string $name, int $type, array $opts = []): string
    {
        $flags = !empty($opts['rd']) ? 0x0100 : 0;
        $pkt = pack('nnnnnn', $id, $flags, 1, 0, 0, 1);
        $pkt .= self::nameToWire($name) . pack('nn', $type, 1);
        // EDNS0 OPT: Name root, TYPE 41, UDP-Größe 1232, ext-rcode/version 0, DO-Bit optional
        $pkt .= "\x00" . pack('nnNn', 41, 1232, !empty($opts['do']) ? 0x8000 : 0, 0);
        return $pkt;
    }

    public static function nameToWire(string $name): string
    {
        $name = rtrim(strtolower($name), '.');
        if ($name === '') {
            return "\x00";
        }
        $out = '';
        foreach (explode('.', $name) as $label) {
            $out .= chr(strlen($label)) . $label;
        }
        return $out . "\x00";
    }

    private function send(string $ip, string $packet, bool $tcp, int $timeout): ?string
    {
        if (self::$transport !== null) {
            return (self::$transport)($ip, $packet, $tcp);
        }
        $host = str_contains($ip, ':') ? "[$ip]" : $ip;
        $errno = 0;
        $errstr = '';
        try {
            $fp = @stream_socket_client(($tcp ? 'tcp' : 'udp') . "://$host:53", $errno, $errstr, $timeout);
        } catch (\Throwable) {
            return null;
        }
        if (!$fp) {
            return null;
        }
        stream_set_timeout($fp, $timeout);
        if ($tcp) {
            fwrite($fp, pack('n', strlen($packet)) . $packet);
            $len = fread($fp, 2);
            if ($len === false || strlen($len) < 2) {
                fclose($fp);
                return null;
            }
            $need = unpack('n', $len)[1];
            $data = '';
            while (strlen($data) < $need && !feof($fp)) {
                $chunk = fread($fp, $need - strlen($data));
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $data .= $chunk;
            }
            fclose($fp);
            return strlen($data) === $need ? $data : null;
        }
        fwrite($fp, $packet);
        $data = fread($fp, 4096);
        fclose($fp);
        return ($data === false || $data === '') ? null : $data;
    }

    /** @return array<string,mixed>|null */
    public function parse(string $msg, int $expectId): ?array
    {
        if (strlen($msg) < 12) {
            return null;
        }
        $h = unpack('nid/nflags/nqd/nan/nns/nar', $msg);
        if ($h['id'] !== $expectId) {
            return null;
        }
        $pos = 12;
        for ($i = 0; $i < $h['qd']; $i++) {
            $this->readName($msg, $pos);
            $pos += 4;
        }
        $sections = [];
        foreach (['an' => 'answer', 'ns' => 'authority', 'ar' => 'additional'] as $k => $label) {
            $recs = [];
            for ($i = 0; $i < $h[$k]; $i++) {
                $rec = $this->readRecord($msg, $pos);
                if ($rec === null) {
                    return null;
                }
                if ($rec['type'] !== 'OPT') {
                    $recs[] = $rec;
                }
            }
            $sections[$label] = $recs;
        }
        $rcode = $h['flags'] & 0xF;
        return [
            'rcode' => $rcode, 'rcode_name' => DnsTypes::rcodeName($rcode),
            'flags' => [
                'aa' => (bool) ($h['flags'] & 0x0400), 'tc' => (bool) ($h['flags'] & 0x0200),
                'rd' => (bool) ($h['flags'] & 0x0100), 'ra' => (bool) ($h['flags'] & 0x0080),
                'ad' => (bool) ($h['flags'] & 0x0020), 'cd' => (bool) ($h['flags'] & 0x0010),
            ],
        ] + $sections;
    }

    /** @return array{name:string,type:string,ttl:int,data:string}|null */
    private function readRecord(string $msg, int &$pos): ?array
    {
        $name = $this->readName($msg, $pos);
        if ($name === null || $pos + 10 > strlen($msg)) {
            return null;
        }
        $f = unpack('ntype/nclass/Nttl/nlen', substr($msg, $pos, 10));
        $pos += 10;
        $rdStart = $pos;
        if ($rdStart + $f['len'] > strlen($msg)) {
            return null;
        }
        $type = DnsTypes::name($f['type']);
        $data = $this->decodeRdata($msg, $rdStart, $f['len'], $f['type']);
        $pos = $rdStart + $f['len'];
        return ['name' => $name, 'type' => $type, 'ttl' => $f['ttl'], 'data' => $data];
    }

    private function decodeRdata(string $msg, int $start, int $len, int $type): string
    {
        $raw = substr($msg, $start, $len);
        switch ($type) {
            case 1:
                return $len === 4 ? (string) inet_ntop($raw) : bin2hex($raw);
            case 28:
                return $len === 16 ? (string) inet_ntop($raw) : bin2hex($raw);
            case 2:
            case 5:
            case 12:
            case 39:
                $p = $start;
                return (string) $this->readName($msg, $p);
            case 15:
                $p = $start + 2;
                return unpack('n', $raw)[1] . ' ' . $this->readName($msg, $p);
            case 6:
                $p = $start;
                $m = $this->readName($msg, $p);
                $r = $this->readName($msg, $p);
                $n = unpack('Nserial/Nrefresh/Nretry/Nexpire/Nmin', substr($msg, $p, 20));
                return "$m $r {$n['serial']} {$n['refresh']} {$n['retry']} {$n['expire']} {$n['min']}";
            case 43:
                $d = unpack('ntag/calg/cdt', substr($raw, 0, 4));
                return $d['tag'] . ' ' . ($d['alg'] & 0xFF) . ' ' . ($d['dt'] & 0xFF) . ' ' . bin2hex(substr($raw, 4));
            case 48:
                $d = unpack('nflags/cproto/calg', substr($raw, 0, 4));
                return $d['flags'] . ' ' . ($d['proto'] & 0xFF) . ' ' . ($d['alg'] & 0xFF) . ' ' . base64_encode(substr($raw, 4));
            case 16:
                $out = '';
                $o = 0;
                while ($o < $len) {
                    $l = ord($raw[$o]);
                    $out .= substr($raw, $o + 1, $l);
                    $o += $l + 1;
                }
                return $out;
            default:
                return bin2hex($raw);
        }
    }

    private function readName(string $msg, int &$pos): ?string
    {
        $labels = [];
        $p = $pos;
        $jumped = false;
        $hops = 0;
        while (true) {
            if ($p >= strlen($msg) || $hops++ > 64) {
                return null;
            }
            $len = ord($msg[$p]);
            if ($len === 0) {
                $p++;
                break;
            }
            if (($len & 0xC0) === 0xC0) {
                if ($p + 1 >= strlen($msg)) {
                    return null;
                }
                $ptr = (($len & 0x3F) << 8) | ord($msg[$p + 1]);
                if (!$jumped) {
                    $pos = $p + 2;
                    $jumped = true;
                }
                $p = $ptr;
                continue;
            }
            $labels[] = strtolower(substr($msg, $p + 1, $len));
            $p += $len + 1;
        }
        if (!$jumped) {
            $pos = $p;
        }
        return implode('.', $labels);
    }
}
