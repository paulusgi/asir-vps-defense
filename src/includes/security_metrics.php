<?php

declare(strict_types=1);

require_once __DIR__ . '/loki_client.php';

function fetchSecurityMetrics(PDO $pdo): array
{
    $client = new LokiClient(getenv('LOKI_URL') ?: 'http://loki:3100');

    try {
        $totals = [
            'last5m' => $client->queryScalar('sum(count_over_time({job="nginx_waf",status="403"}[5m]))'),
            'last1h' => $client->queryScalar('sum(count_over_time({job="nginx_waf",status="403"}[1h]))'),
            'last24h' => $client->queryScalar('sum(count_over_time({job="nginx_waf",status="403"}[24h]))'),
        ];

        $trend = $client->queryRangeSeries(
            'sum(count_over_time({job="nginx_waf",status="403"}[1m]))',
            60,
            '60s'
        );

        $topIps = formatTopIps($pdo, $client->queryVector(
            'topk(5, sum by (client_ip) (count_over_time({job="nginx_waf",status="403"}[1h])))'
        ));

        $recentLogs = $client->queryRangeRaw(
            '{job="nginx_waf",status="403"}',
            time() - 3600,
            time(),
            '30s',
            500
        );

        $recentEvents = [];
        $attackTypeCounts = [];
        $surfaceCounts = [];
        $countryCounts = [];
        $geoCache = [];

        foreach ($recentLogs as $entry) {
            $payload = json_decode($entry['line'], true);
            if (!is_array($payload)) {
                continue;
            }

            $ip = $payload['remote_addr'] ?? ($payload['client_ip'] ?? ($entry['labels']['client_ip'] ?? null));
            if (!$ip) {
                continue;
            }

            if (!isset($geoCache[$ip])) {
                $geoCache[$ip] = lookupGeoForIp($pdo, $ip);
            }
            $geo = $geoCache[$ip];

            $attackType = classifyAttackType((string) ($payload['request'] ?? ''));
            $surface = determineSurface((string) ($payload['uri'] ?? '/'));

            $attackTypeCounts[$attackType] = ($attackTypeCounts[$attackType] ?? 0) + 1;
            $surfaceCounts[$surface] = ($surfaceCounts[$surface] ?? 0) + 1;

            if (!isset($countryCounts[$geo['country_code']])) {
                $countryCounts[$geo['country_code']] = [
                    'label' => $geo['country_name'],
                    'count' => 0,
                ];
            }
            $countryCounts[$geo['country_code']]['count']++;

            $recentEvents[] = [
                'timestamp' => $entry['timestamp'],
                'ip' => $ip,
                'request' => $payload['request'] ?? 'N/A',
                'country' => $geo['country_name'],
                'country_code' => $geo['country_code'],
                'attack_type' => $attackType,
                'surface' => $surface,
                'user_agent' => $payload['user_agent'] ?? ($payload['http_user_agent'] ?? 'N/A'),
            ];
        }

        return [
            'generatedAt' => time(),
            'totals' => normalizeTotals($totals),
            'trend' => $trend,
            'attackTypes' => normalizeCounts($attackTypeCounts),
            'surfaces' => normalizeCounts($surfaceCounts),
            'countries' => normalizeCountryCounts($countryCounts),
            'topIps' => $topIps,
            'events' => array_slice($recentEvents, 0, 25),
        ];
    } catch (Throwable $exception) {
        return [
            'error' => $exception->getMessage(),
        ];
    }
}

/**
 * @param array<int, array<string, mixed>> $results
 * @return array<int, array<string, mixed>>
 */
function formatTopIps(PDO $pdo, array $results): array
{
    $topIps = [];
    foreach ($results as $row) {
        $ip = $row['metric']['client_ip'] ?? null;
        if (!$ip) {
            continue;
        }

        $geo = lookupGeoForIp($pdo, $ip);
        $value = $row['value'][1] ?? 0;
        $topIps[] = [
            'ip' => $ip,
            'count' => (int) round((float) $value),
            'country' => $geo['country_name'],
            'country_code' => $geo['country_code'],
        ];
    }

    return $topIps;
}

function classifyAttackType(string $request): string
{
    $needle = strtolower($request);

    $rules = [
        'SQL Injection' => ['union select', 'sleep(', 'benchmark(', "' or '1'='1", 'or 1=1', 'information_schema'],
        'Cross-Site Scripting' => ['<script', 'onerror=', 'svg/onload', 'alert('],
        'Command Injection' => [';cat /etc/passwd', ';ls', '|nc', '| bash', '`whoami`'],
        'Remote File Inclusion' => ['http://', 'https://', 'php://', 'file://'],
        'Path Traversal' => ['../', '..\\', '%2e%2e/'],
        'Insecure Deserialization' => ['phpggc', 'O:'],
    ];

    foreach ($rules as $label => $patterns) {
        foreach ($patterns as $pattern) {
            if (str_contains($needle, strtolower($pattern))) {
                return $label;
            }
        }
    }

    return 'Exploit Desconocido';
}

function determineSurface(string $uri): string
{
    $uri = strtolower($uri);

    if (str_contains($uri, 'login')) {
        return 'Portal de Autenticacion';
    }

    if (str_contains($uri, 'admin')) {
        return 'Gateway Administrativo';
    }

    if (str_contains($uri, 'api')) {
        return 'API Interna';
    }

    if (str_contains($uri, 'php')) {
        return 'Aplicacion PHP';
    }

    return 'Sitio Publico';
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
 * @param array<string, array{label:string,count:int|float}> $counts
 * @return array<int, array{code:string,label:string,count:int}>
 */
function normalizeCountryCounts(array $counts): array
{
    uasort($counts, static fn($a, $b) => ($b['count'] ?? 0) <=> ($a['count'] ?? 0));
    $normalized = [];

    foreach ($counts as $code => $data) {
        $normalized[] = [
            'code' => (string) $code,
            'label' => (string) ($data['label'] ?? $code),
            'count' => (int) round((float) ($data['count'] ?? 0)),
        ];
    }

    return $normalized;
}

function normalizeTotals(array $totals): array
{
    return [
        'last5m' => (int) ($totals['last5m'] ?? 0),
        'last1h' => (int) ($totals['last1h'] ?? 0),
        'last24h' => (int) ($totals['last24h'] ?? 0),
    ];
}

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
