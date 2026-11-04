<?php

declare(strict_types=1);

require_once __DIR__ . '/loki_client.php';

// Only real bans ("[jail] Ban <ip>"), not Unban, Restore Ban or Found lines.
const FAIL2BAN_BAN_SELECTOR = '{job="fail2ban"} |~ `\] Ban [0-9a-fA-F]`';

/**
 * LogQL selector for SSH attempts rejected by the real sshd.
 *
 * The real SSH only accepts the admin's public key, so an attempt by anyone else
 * shows up as "Invalid user X from IP port N" (unknown account) or
 * "User X from IP not allowed because not listed in AllowUsers" (existing account).
 * "Failed password" is kept for servers that still allow passwords.
 * Requiring the "sshd[PID]:" / "sshd-session[PID]:" prefix (OpenSSH 9.8+ logs from
 * sshd-session) leaves out sudo audit lines that quote these words in a command.
 */
const SSH_REJECTION_SELECTOR = '{job="auth"} |~ `sshd(-session)?\[[0-9]+\]: (Invalid user .* from .* port [0-9]+|User .* from .* not allowed because|Failed password for )`';

function fetchSecurityMetrics(PDO $pdo): array
{
    $client = new LokiClient(getenv('LOKI_URL') ?: 'http://loki:3100');

    try {
        $fail2ban = fetchFail2BanMetrics($client, $pdo);
        $ssh      = fetchSshMetrics($client, $pdo);
        $cowrie   = fetchCowrieMetrics($client, $pdo);

        // Merge events + topIps for wider map coverage, deduplicated by IP.
        // Events take priority (they carry a timestamp); topIps act as a fallback
        // for IPs that have coordinates but whose events were cut by the limit of 25.
        $geoSources = array_merge(
            $fail2ban['events'] ?? [],
            $ssh['events']     ?? [],
            $cowrie['events']  ?? [],
            array_map(static fn($r) => $r + ['type' => 'fail2ban'], $fail2ban['topIps'] ?? []),
            array_map(static fn($r) => $r + ['type' => 'ssh'],      $ssh['topIps']      ?? []),
            array_map(static fn($r) => $r + ['type' => 'cowrie'],   $cowrie['topIps']   ?? []),
        );
        $ipSeen    = [];
        $geoPoints = [];
        foreach ($geoSources as $row) {
            if (!isset($row['lat'], $row['lon'])) {
                continue;
            }
            $ip = $row['ip'] ?? '';
            if ($ip !== '' && isset($ipSeen[$ip])) {
                continue;
            }
            if ($ip !== '') {
                $ipSeen[$ip] = true;
            }
            $geoPoints[] = $row;
        }
        $geoPoints = array_values($geoPoints);

        return [
            'generatedAt' => time(),
            'fail2ban'    => $fail2ban,
            'ssh'         => $ssh,
            'cowrie'      => $cowrie,
            'geo'         => array_slice($geoPoints, 0, 100),
        ];
    } catch (Throwable $exception) {
        // Details go to the PHP error log, not to the browser
        error_log('fetchSecurityMetrics: ' . $exception->getMessage());

        return [
            'error' => 'metrics_unavailable',
        ];
    }
}

function fetchFail2BanMetrics(LokiClient $client, PDO $pdo): array
{
    // The selector's regex matches only "Ban" (not Unban, Restore Ban, etc.)
    // The "] Ban" pattern catches the usual format: "fail2ban.actions ... [sshd] Ban IP"
    $totals = [
        'last1h' => $client->queryScalar('sum(count_over_time(' . FAIL2BAN_BAN_SELECTOR . ' [1h]))'),
        'last24h' => $client->queryScalar('sum(count_over_time(' . FAIL2BAN_BAN_SELECTOR . ' [24h]))'),
        'last7d' => $client->queryScalar('sum(count_over_time(' . FAIL2BAN_BAN_SELECTOR . ' [7d]))'),
    ];

    // Query last 7 days of logs for better historical view
    $logs = $client->queryRangeRaw(
        FAIL2BAN_BAN_SELECTOR,
        time() - (7 * 86400),
        time(),
        '5m',
        1500
    );

    $ipCounts      = [];
    $events        = [];

    foreach ($logs as $entry) {
        $parsed = parseFail2BanEvent($entry['line']);
        if (!$parsed || $parsed['action'] !== 'Ban') {
            continue;
        }

        $ip = $parsed['ip'];
        $jail = $parsed['jail'];

        $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;

        $geo = lookupGeoForIp($pdo, $ip);

        $events[] = [
            'timestamp' => $entry['timestamp'],
            'ip' => $ip,
            'country' => $geo['country_name'],
            'country_code' => $geo['country_code'],
            'lat' => $geo['lat'],
            'lon' => $geo['lon'],
            'jail' => $jail,
            'type' => 'fail2ban',
        ];
    }

    // Sort newest first so the most recent events (e.g. a newly enabled Cowrie jail)
    // are not cut from the slice when there are many older SSH events.
    usort($events, static fn($a, $b) => $b['timestamp'] <=> $a['timestamp']);

    return [
        'totals'     => $totals,
        'topIps'     => formatIpCountList($pdo, $ipCounts),
        'events'     => array_slice($events, 0, 500),
    ];
}

function fetchSshMetrics(LokiClient $client, PDO $pdo): array
{
    $totals = [
        'last5m' => $client->queryScalar('sum(count_over_time(' . SSH_REJECTION_SELECTOR . ' [5m]))'),
        'last1h' => $client->queryScalar('sum(count_over_time(' . SSH_REJECTION_SELECTOR . ' [1h]))'),
        'last24h' => $client->queryScalar('sum(count_over_time(' . SSH_REJECTION_SELECTOR . ' [24h]))'),
    ];

    // Query last 24 hours for better historical view
    $logs = $client->queryRangeRaw(
        SSH_REJECTION_SELECTOR,
        time() - 86400,
        time(),
        '60s',
        1200
    );

    $userCounts = [];
    $ipCounts = [];
    $events = [];

    foreach ($logs as $entry) {
        $parsed = parseSshFailure($entry['line']);
        if (!$parsed) {
            continue;
        }

        $username = $parsed['username'];
        $ip = $parsed['ip'];

        $userCounts[$username] = ($userCounts[$username] ?? 0) + 1;
        $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;

        $geo = lookupGeoForIp($pdo, $ip);

        $events[] = [
            'timestamp' => $entry['timestamp'],
            'username' => $username,
            'ip' => $ip,
            'country' => $geo['country_name'],
            'country_code' => $geo['country_code'],
            'lat' => $geo['lat'],
            'lon' => $geo['lon'],
            'result' => $parsed['result'],
            'type' => 'ssh',
        ];
    }

    return [
        'totals' => $totals,
        'topUsers' => array_slice(normalizeCounts($userCounts), 0, 5),
        'topIps' => formatIpCountList($pdo, $ipCounts),
        'events' => array_slice($events, 0, 25),
    ];
}

// =============================================================================
// COWRIE HONEYPOT METRICS
// =============================================================================

/**
 * Fetches Cowrie honeypot metrics from Loki.
 *
 * Totals are read from the text log (job=cowrie) because its counts are accurate.
 * Detailed events are read from cowrie_json (job=cowrie_json), which carries
 * src_ip as a structured field; in the text log the IP does not appear
 * on the "login attempt" lines.
 *
 * @return array{totals:array,topIps:list<array>,topUsers:list<array>,topCommands:list<array>,events:list<array>,commands:list<array>}
 */
function fetchCowrieMetrics(LokiClient $client, PDO $pdo): array
{
    // Totals from the text log: counting "login attempt" lines is accurate there.
    $totals = [
        'last1h'       => $client->queryScalar('sum(count_over_time({job="cowrie"} |= "login attempt" [1h]))'),
        'last24h'      => $client->queryScalar('sum(count_over_time({job="cowrie"} |= "login attempt" [24h]))'),
        'last7d'       => $client->queryScalar('sum(count_over_time({job="cowrie"} |= "login attempt" [7d]))'),
        'sessions_24h' => $client->queryScalar('sum(count_over_time({job="cowrie"} |= "New connection" [24h]))'),
    ];

    // Detailed events from cowrie_json: src_ip, username and password are structured fields.
    // One query filters login.success + login.failed; they are split by eventid afterwards.
    $jsonLogs = $client->queryRangeRaw(
        '{job="cowrie_json"} |= "cowrie.login."',
        time() - (7 * 86400),
        time(),
        '5m',
        2000
    );

    $ipCounts   = [];
    $userCounts = [];
    $events     = [];

    foreach ($jsonLogs as $entry) {
        $data = json_decode($entry['line'], true);
        if (!is_array($data)) {
            continue;
        }
        $eventid = $data['eventid'] ?? '';
        if ($eventid !== 'cowrie.login.success' && $eventid !== 'cowrie.login.failed') {
            continue;
        }

        $ip       = (string) ($data['src_ip'] ?? 'unknown');
        $username = (string) ($data['username'] ?? '');
        $password = (string) ($data['password'] ?? '');
        $result   = $eventid === 'cowrie.login.success' ? 'Logged into honeypot' : 'Rejected';

        if ($ip !== 'unknown') {
            $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
        }
        if ($username !== '') {
            $userCounts[$username] = ($userCounts[$username] ?? 0) + 1;
        }

        $geo = lookupGeoForIp($pdo, $ip);

        $events[] = [
            'timestamp'    => $entry['timestamp'],
            'ip'           => $ip,
            'username'     => $username,
            'password'     => $password,
            'result'       => $result,
            'country'      => $geo['country_name'],
            'country_code' => $geo['country_code'],
            'lat'          => $geo['lat'],
            'lon'          => $geo['lon'],
            'type'         => 'cowrie',
        ];
    }

    // Commands run inside the honeypot (eventid=cowrie.command.input).
    $cmdLogs = $client->queryRangeRaw(
        '{job="cowrie_json"} |= "cowrie.command.input"',
        time() - (7 * 86400),
        time(),
        '5m',
        600
    );

    $commandCounts = [];
    $commands      = [];
    foreach ($cmdLogs as $entry) {
        $data = json_decode($entry['line'], true);
        if (!is_array($data) || ($data['eventid'] ?? '') !== 'cowrie.command.input') {
            continue;
        }
        $cmd = trim((string) ($data['input'] ?? ''));
        if ($cmd === '') {
            continue;
        }
        $commandCounts[$cmd] = ($commandCounts[$cmd] ?? 0) + 1;
        $commands[] = [
            'timestamp' => $entry['timestamp'],
            'ip'        => $data['src_ip'] ?? 'unknown',
            'command'   => $cmd,
            'session'   => substr((string) ($data['session'] ?? ''), 0, 8),
        ];
    }

    return [
        'totals'      => $totals,
        'topIps'      => formatIpCountList($pdo, $ipCounts, 10),
        'topUsers'    => array_slice(normalizeCounts($userCounts), 0, 10),
        'topCommands' => array_slice(normalizeCounts($commandCounts), 0, 15),
        'events'      => array_slice($events, 0, 200),
        'commands'    => array_slice($commands, 0, 200),
    ];
}

function parseFail2BanEvent(string $line): ?array
{
    // Fail2Ban format: "2025-01-31 23:45:12,345 fail2ban.actions [12345]: NOTICE  [sshd] Ban 1.2.3.4"
    if (!preg_match('/NOTICE\s+\[(?<jail>[^\]]+)\]\s+(?<action>Ban|Unban)\s+(?<ip>[0-9A-Fa-f:.]+)/', $line, $matches)) {
        return null;
    }

    return [
        'jail' => $matches['jail'],
        'action' => $matches['action'],
        'ip' => $matches['ip'],
    ];
}

/**
 * Parses one rejected SSH attempt (see SSH_REJECTION_SELECTOR).
 *
 * The IP is taken from the last "from <ip> port <n>" of the line, so a crafted
 * username such as "x from 8.8.8.8" cannot spoof the source address.
 *
 * @return array{username:string,ip:string,result:string}|null
 */
function parseSshFailure(string $line): ?array
{
    $patterns = [
        '/sshd(?:-session)?\[\d+\]: Invalid user (?<user>.*) from (?<ip>[0-9A-Fa-f:.]+) port \d+/' => 'Invalid user',
        '/sshd(?:-session)?\[\d+\]: User (?<user>\S+) from (?<ip>[0-9A-Fa-f:.]+) not allowed because/' => 'User not allowed',
        '/sshd(?:-session)?\[\d+\]: Failed password for (?<invalid>invalid user )?(?<user>.*) from (?<ip>[0-9A-Fa-f:.]+) port \d+/' => null,
    ];

    foreach ($patterns as $regex => $result) {
        if (!preg_match($regex, $line, $match)) {
            continue;
        }
        if (filter_var($match['ip'], FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $result ??= ($match['invalid'] ?? '') !== '' ? 'Invalid user' : 'Existing user';

        return [
            'username' => $match['user'] === '' ? '(empty)' : $match['user'],
            'ip' => $match['ip'],
            'result' => $result,
        ];
    }

    return null;
}

function formatIpCountList(PDO $pdo, array $counts, int $limit = 5): array
{
    arsort($counts);
    $formatted = [];
    foreach ($counts as $ip => $count) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            continue;
        }
        $geo = lookupGeoForIp($pdo, $ip);
        $formatted[] = [
            'ip' => $ip,
            'count' => (int) round((float) $count),
            'country' => $geo['country_name'],
            'country_code' => $geo['country_code'],
            'lat' => $geo['lat'],
            'lon' => $geo['lon'],
        ];
        if (count($formatted) >= $limit) {
            break;
        }
    }

    return $formatted;
}

/**
 * @param array<string, int|float> $counts
 * @return array<int, array{label:string,count:int}>
 */
function normalizeCounts(array $counts): array
{
    arsort($counts);
    $normalized = [];
    foreach ($counts as $label => $count) {
        $normalized[] = [
            'label' => (string) $label,
            'count' => (int) round((float) $count),
        ];
    }

    return $normalized;
}

/**
 * IP geolocation lookup with a local MySQL cache.
 */
function lookupGeoForIp(PDO $pdo, string $ip): array
{
    static $memo = [];
    $default = [
        'country_code' => '??',
        'country_name' => 'Unknown',
        'lat' => null,
        'lon' => null,
    ];

    $countryFallback = static function (string $code) use ($default): array {
        $centroids = [
            'US' => [38.0, -97.0],
            'GB' => [54.0, -2.0],
            'NL' => [52.1, 5.3],
            'FR' => [46.2, 2.2],
            'DE' => [51.2, 10.4],
            'ES' => [40.4, -3.7],
            'IT' => [42.8, 12.5],
            'PT' => [39.4, -8.2],
            'RU' => [60.0, 90.0],
            'CN' => [35.8, 104.1],
            'JP' => [36.2, 138.3],
            'IN' => [21.7, 78.9],
            'SG' => [1.35, 103.82],
            'HK' => [22.3, 114.2],
            'ZA' => [-29.0, 24.0],
            'BR' => [-10.8, -52.9],
            'CA' => [61.1, -113.7],
            'AU' => [-25.3, 133.8],
        ];
        $cc = strtoupper($code);
        if (isset($centroids[$cc])) {
            return [
                'country_code' => $cc,
                'country_name' => $default['country_name'],
                'lat' => $centroids[$cc][0],
                'lon' => $centroids[$cc][1],
            ];
        }
        return $default;
    };

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return $default;
    }

    if (isset($memo[$ip])) {
        return $memo[$ip];
    }

    $stmt = $pdo->prepare('SELECT country_code, country_name, lat, lon, updated_at FROM ip_geo_cache WHERE ip = :ip');
    $stmt->execute(['ip' => $ip]);
    $row = $stmt->fetch();

    if ($row && isset($row['updated_at'])) {
        $freshThreshold = time() - (7 * 24 * 60 * 60);
        $stale = strtotime((string) $row['updated_at']) <= $freshThreshold;
        $hasCoords = $row['lat'] !== null && $row['lon'] !== null;
        if (!$stale && $hasCoords) {
            return $memo[$ip] = [
                'country_code' => $row['country_code'] ?? '??',
                'country_name' => $row['country_name'] ?? 'Unknown',
                'lat' => (float) $row['lat'],
                'lon' => (float) $row['lon'],
            ];
        }
    }

    $fallback = $default;
    if ($row && isset($row['country_code'])) {
        $fallback = $countryFallback((string) $row['country_code']);
        $fallback['country_name'] = $row['country_name'] ?? $fallback['country_name'];
    }

    $geo = lookupGeoFromMmdb($ip, $fallback);

    $stmt = $pdo->prepare('REPLACE INTO ip_geo_cache (ip, country_code, country_name, lat, lon) VALUES (:ip, :code, :name, :lat, :lon)');
    $stmt->execute([
        'ip' => $ip,
        'code' => $geo['country_code'],
        'name' => $geo['country_name'],
        'lat' => $geo['lat'],
        'lon' => $geo['lon'],
    ]);

    return $memo[$ip] = $geo;
}

function lookupGeoFromMmdb(string $ip, array $fallback): array
{
    $path = getenv('GEOIP_MMDB_PATH') ?: '/usr/share/GeoIP/GeoLite2-City.mmdb';
    if (!is_readable($path)) {
        return $fallback;
    }

    $record = null;

    if (function_exists('maxminddb_fetch_assoc')) {
        $record = @maxminddb_fetch_assoc($path, $ip);
    }

    // Fall back to the mmdblookup CLI tool if the PHP module exposes no functions.
    // The full output is parsed because some builds do not support deep lookup paths.
    if (!is_array($record) && is_executable('/usr/bin/mmdblookup')) {
        $cmd = sprintf(
            '/usr/bin/mmdblookup --file %s --ip %s 2>/dev/null',
            escapeshellarg($path),
            escapeshellarg($ip)
        );
        $output = shell_exec($cmd);
        if (is_string($output) && $output !== '') {
            $code = null;
            $name = null;
            $lat = null;
            $lon = null;

            if (preg_match('/iso_code"?\s*:\s*"?([A-Z]{2})"?/i', $output, $m)) {
                $code = strtoupper($m[1]);
            }
            if (preg_match('/names.*?"en"\s*:\s*"([^"]+)"/is', $output, $m)) {
                $name = $m[1];
            }
            if (preg_match('/latitude"?\s*:\s*([+-]?[0-9]+\.[0-9]+)/i', $output, $m)) {
                $lat = (float) $m[1];
            }
            if (preg_match('/longitude"?\s*:\s*([+-]?[0-9]+\.[0-9]+)/i', $output, $m)) {
                $lon = (float) $m[1];
            }

            if ($code || $name || $lat !== null || $lon !== null) {
                $record = [
                    'country' => [
                        'iso_code' => $code,
                        'names' => ['en' => $name],
                    ],
                    'location' => [
                        'latitude' => $lat,
                        'longitude' => $lon,
                    ],
                ];
            }
        }
    }

    if (!is_array($record)) {
        return $fallback;
    }

    $code = strtoupper((string) ($record['country']['iso_code'] ?? $fallback['country_code'] ?? '??'));
    $name = (string) ($record['country']['names']['en'] ?? $fallback['country_name'] ?? 'Unknown');
    $lat = $record['location']['latitude'] ?? null;
    $lon = $record['location']['longitude'] ?? null;

    return [
        'country_code' => $code ?: ($fallback['country_code'] ?? '??'),
        'country_name' => $name ?: ($fallback['country_name'] ?? 'Unknown'),
        'lat' => $lat !== null ? (float) $lat : ($fallback['lat'] ?? null),
        'lon' => $lon !== null ? (float) $lon : ($fallback['lon'] ?? null),
    ];
}
