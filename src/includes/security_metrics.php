<?php

declare(strict_types=1);

require_once __DIR__ . '/loki_client.php';

function fetchSecurityMetrics(PDO $pdo): array
{
    $client = new LokiClient(getenv('LOKI_URL') ?: 'http://loki:3100');

    try {
        $fail2ban = fetchFail2BanMetrics($client, $pdo);
        $ssh = fetchSshMetrics($client, $pdo);

        return [
            'generatedAt' => time(),
            'fail2ban' => $fail2ban,
            'ssh' => $ssh,
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
            'jail' => $jail,
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
            'result' => $parsed['result'],
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
function lookupGeoForIp(PDO $pdo, string $ip): array
{
    $default = [
        'country_code' => '??',
        'country_name' => 'Desconocido',
    ];

    static $tableEnsured = false;
    if (!$tableEnsured) {
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS ip_geo_cache (
                ip VARCHAR(45) PRIMARY KEY,
                country_code CHAR(2) DEFAULT '??',
                country_name VARCHAR(100) DEFAULT 'Desconocido',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB"
        );
        $tableEnsured = true;
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return $default;
    }

    $stmt = $pdo->prepare('SELECT country_code, country_name, updated_at FROM ip_geo_cache WHERE ip = :ip');
    $stmt->execute(['ip' => $ip]);
    $row = $stmt->fetch();

    if ($row && isset($row['updated_at'])) {
        $freshThreshold = time() - (7 * 24 * 60 * 60);
        if (strtotime((string) $row['updated_at']) > $freshThreshold) {
            return [
                'country_code' => $row['country_code'] ?? '??',
                'country_name' => $row['country_name'] ?? 'Desconocido',
            ];
        }
    }

    $geo = fetchGeoFromApi($ip) ?: $default;

    $stmt = $pdo->prepare('REPLACE INTO ip_geo_cache (ip, country_code, country_name) VALUES (:ip, :code, :name)');
    $stmt->execute([
        'ip' => $ip,
        'code' => $geo['country_code'],
        'name' => $geo['country_name'],
    ]);

    return $geo;
}

function fetchGeoFromApi(string $ip): ?array
{
    $url = sprintf('https://ipapi.co/%s/json/', urlencode($ip));
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 3,
        CURLOPT_USERAGENT => 'asir-vps-defense-panel/1.0',
    ]);

    $response = curl_exec($ch);
    if ($response === false) {
        curl_close($ch);
        return null;
    }

    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($status >= 400) {
        return null;
    }

    $data = json_decode($response, true);
    if (!is_array($data)) {
        return null;
    }

    $code = strtoupper((string) ($data['country_code'] ?? '??'));
    $name = (string) ($data['country_name'] ?? ($data['country'] ?? 'Desconocido'));

    return [
        'country_code' => $code ?: '??',
        'country_name' => $name ?: 'Desconocido',
    ];
}
