<?php

declare(strict_types=1);

/**
 * Minimal Loki HTTP client (query + query_range helpers).
 */
final class LokiClient
{
    private string $baseUrl;

    public function __construct(?string $baseUrl = null)
    {
        $this->baseUrl = rtrim($baseUrl ?: 'http://loki:3100', '/');
    }

    public function queryScalar(string $logql): int
    {
        $payload = $this->request('/loki/api/v1/query', [
            'query' => $logql,
            'time' => $this->toNanoseconds(time()),
        ]);

        $data = $payload['data'] ?? [];
        $resultType = $data['resultType'] ?? '';

        if ($resultType === 'scalar') {
            return (int) round((float) ($data['result'][1] ?? 0));
        }

        if ($resultType === 'vector') {
            $first = $data['result'][0]['value'][1] ?? 0;
            return (int) round((float) $first);
        }

        return 0;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function queryVector(string $logql): array
    {
        $payload = $this->request('/loki/api/v1/query', [
            'query' => $logql,
            'time' => $this->toNanoseconds(time()),
        ]);

        $data = $payload['data'] ?? [];
        return $data['result'] ?? [];
    }

    /**
     * Returns timeline entries as [ ['ts' => ms, 'value' => int], ... ]
     *
     * @return array<int, array{ts:int,value:int}>
     */
    public function queryRangeSeries(string $logql, int $minutes, string $step = '60s'): array
    {
        $end = time();
        $start = $end - ($minutes * 60);

        $payload = $this->request('/loki/api/v1/query_range', [
            'query' => $logql,
            'start' => $this->toNanoseconds($start),
            'end' => $this->toNanoseconds($end),
            'step' => $step,
        ]);

        $data = $payload['data'] ?? [];
        $result = $data['result'] ?? [];
        $timeline = [];

        foreach ($result as $series) {
            foreach ($series['values'] ?? [] as $point) {
                $tsMs = (int) round(((int) ($point[0] ?? 0)) / 1_000_000);
                $value = (float) ($point[1] ?? 0);
                $timeline[$tsMs] = ($timeline[$tsMs] ?? 0) + $value;
            }
        }

        ksort($timeline);

        $formatted = [];
        foreach ($timeline as $ts => $value) {
            $formatted[] = [
                'ts' => (int) $ts,
                'value' => (int) round($value),
            ];
        }

        return $formatted;
    }

    /**
     * Flattens raw log entries for downstream classification.
     *
     * @return array<int, array{timestamp:int,line:string,labels:array<string,string>}>
     */
    public function queryRangeRaw(
        string $logql,
        int $startTs,
        int $endTs,
        string $step = '60s',
        int $limit = 500
    ): array {
        $payload = $this->request('/loki/api/v1/query_range', [
            'query' => $logql,
            'start' => $this->toNanoseconds($startTs),
            'end' => $this->toNanoseconds($endTs),
            'limit' => $limit,
            'step' => $step,
            'direction' => 'BACKWARD',
        ]);

        $entries = [];
        foreach (($payload['data']['result'] ?? []) as $stream) {
            $labels = $stream['stream'] ?? [];
            foreach ($stream['values'] ?? [] as $pair) {
                $timestampSeconds = (int) floor(((int) ($pair[0] ?? 0)) / 1_000_000_000);
                $entries[] = [
                    'timestamp' => $timestampSeconds,
                    'line' => (string) ($pair[1] ?? ''),
                    'labels' => $labels,
                ];
            }
        }

        usort($entries, static fn(array $a, array $b) => $b['timestamp'] <=> $a['timestamp']);

        return $entries;
    }

    private function request(string $path, array $params): array
    {
        $url = $this->baseUrl . $path;
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
        ]);

        $response = curl_exec($ch);
        if ($response === false) {
            $message = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('Loki request failed: ' . $message);
        }

        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($statusCode >= 400) {
            error_log(sprintf(
                'ASIR VPS Defense - Loki error: HTTP %d for %s (response: %s)',
                $statusCode,
                $url,
                substr((string) $response, 0, 500)
            ));
            throw new RuntimeException(sprintf('Loki responded with HTTP %d', $statusCode));
        }

        $decoded = json_decode($response, true);
        if (!is_array($decoded)) {
            error_log(sprintf(
                'ASIR VPS Defense - Loki invalid JSON from %s: %s',
                $url,
                substr((string) $response, 0, 500)
            ));
            throw new RuntimeException('Unexpected Loki response payload');
        }

        return $decoded;
    }

    private function toNanoseconds(int $seconds): string
    {
        return sprintf('%d', $seconds * 1_000_000_000);
    }
}
