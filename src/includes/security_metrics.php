<?php

declare(strict_types=1);

require_once __DIR__ . '/loki_client.php';

function fetchSecurityMetrics(PDO $pdo, string $mode = 'full'): array
{
    $client = new LokiClient(getenv('LOKI_URL') ?: 'http://loki:3100');

    try {
        $fail2ban = fetchFail2BanMetrics($client, $pdo);
        $ssh = fetchSshMetrics($client, $pdo);

        $geoPoints = array_values(array_filter(array_merge(
            $fail2ban['events'] ?? [],
            $ssh['events'] ?? []
        ), static function (array $row): bool {
            return isset($row['lat'], $row['lon']);
        }));

        if ($mode === 'lite') {
            $fail2ban['events'] = [];
            $ssh['events'] = [];
        }

        return [
            'generatedAt' => time(),
            'fail2ban' => $fail2ban,
            'ssh' => $ssh,
            'geo' => array_slice($geoPoints, 0, 100),
        ];
    } catch (Throwable $exception) {
        return [
            'error' => $exception->getMessage(),
        ];
    }
}

function fetchFail2BanMetrics(LokiClient $client, PDO $pdo): array
{
    $totals = [
        'last1h' => $client->queryScalar('sum(count_over_time({job="fail2ban"} |= "Ban" [1h]))'),
        'last24h' => $client->queryScalar('sum(count_over_time({job="fail2ban"} |= "Ban" [24h]))'),
    ];

    $logs = $client->queryRangeRaw(
        '{job="fail2ban"}',
        time() - 86400,
        time(),
        '60s',
        800
    );

    $ipCounts = [];
    $jailCounts = [];
    $events = [];

    foreach ($logs as $entry) {
        $parsed = parseFail2BanEvent($entry['line']);
        if (!$parsed || $parsed['action'] !== 'Ban') {
            continue;
        }

        $ip = $parsed['ip'];
        $jail = $parsed['jail'];

        $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
        $jailCounts[$jail] = ($jailCounts[$jail] ?? 0) + 1;

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

    return [
        'totals' => $totals,
        'topIps' => formatIpCountList($pdo, $ipCounts),
        'topJails' => array_slice(normalizeCounts($jailCounts), 0, 5),
        'events' => array_slice($events, 0, 25),
    ];
}

function fetchSshMetrics(LokiClient $client, PDO $pdo): array
{
    $totals = [
        'last5m' => $client->queryScalar('sum(count_over_time({job="auth"} |= "Failed password" [5m]))'),
        'last1h' => $client->queryScalar('sum(count_over_time({job="auth"} |= "Failed password" [1h]))'),
    ];

    $logs = $client->queryRangeRaw(
        '{job="auth"} |= "Failed password"',
        time() - 3600,
        time(),
        '30s',
        600
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

function parseFail2BanEvent(string $line): ?array
{
    if (!preg_match('/\[(?<jail>[^\]]+)\]\s+(?<action>Ban|Unban)\s+(?<ip>[0-9A-Fa-f:.]+)/', $line, $matches)) {
        return null;
    }

    return [
        'jail' => $matches['jail'],
        'action' => $matches['action'],
        'ip' => $matches['ip'],
    ];
}

function parseSshFailure(string $line): ?array
{
    if (!str_contains($line, 'Failed password')) {
        return null;
    }

    if (!preg_match('/Failed password for (invalid user )?(?<user>[\w.@-]+)/', $line, $userMatch)) {
        return null;
    }

    if (!preg_match('/from (?<ip>[0-9A-Fa-f:.]+)/', $line, $ipMatch)) {
        return null;
    }

    $result = str_contains($userMatch[0], 'invalid user') ? 'Usuario inválido' : 'Usuario existente';

    return [
        'username' => $userMatch['user'],
        'ip' => $ipMatch['ip'],
        'result' => $result,
    ];
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
 * Resolución geográfica de IP con caché local en MySQL.
 */
function lookupGeoForIp(PDO $pdo, string $ip): array
{
    static $memo = [];
    $default = [
        'country_code' => '??',
        'country_name' => 'Desconocido',
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

    static $tableEnsured = false;
    if (!$tableEnsured) {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS ip_geo_cache (
                ip VARCHAR(45) PRIMARY KEY,
                country_code CHAR(2) DEFAULT '??',
                country_name VARCHAR(100) DEFAULT 'Desconocido',
                lat DECIMAL(10,6) NULL,
                lon DECIMAL(10,6) NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB"
        );
        try {
            $pdo->exec("ALTER TABLE ip_geo_cache ADD COLUMN lat DECIMAL(10,6) NULL");
        } catch (Throwable $ignored) {
        }
        try {
            $pdo->exec("ALTER TABLE ip_geo_cache ADD COLUMN lon DECIMAL(10,6) NULL");
        } catch (Throwable $ignored) {
        }
        $tableEnsured = true;
    }

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
                'country_name' => $row['country_name'] ?? 'Desconocido',
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

    // Fallback a la herramienta CLI mmdblookup si el módulo PHP no expone funciones
    // Usamos la salida completa y la parseamos porque algunas builds no soportan rutas profundas.
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
    $name = (string) ($record['country']['names']['en'] ?? $fallback['country_name'] ?? 'Desconocido');
    $lat = $record['location']['latitude'] ?? null;
    $lon = $record['location']['longitude'] ?? null;

    return [
        'country_code' => $code ?: ($fallback['country_code'] ?? '??'),
        'country_name' => $name ?: ($fallback['country_name'] ?? 'Desconocido'),
        'lat' => $lat !== null ? (float) $lat : ($fallback['lat'] ?? null),
        'lon' => $lon !== null ? (float) $lon : ($fallback['lon'] ?? null),
    ];
}
