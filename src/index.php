<?php
// Hardened session cookies; secure flag active when served over HTTPS
$cookieSecure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $cookieSecure,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

require_once __DIR__ . '/includes/security_metrics.php';

function readSystemMetrics(): array
{
    try {
        $cpu1 = file('/proc/stat', FILE_IGNORE_NEW_LINES)[0] ?? '';
        usleep(200000);
        $cpu2 = file('/proc/stat', FILE_IGNORE_NEW_LINES)[0] ?? '';

        $parseCpu = static function (string $line): array {
            $parts = preg_split('/\s+/', trim($line));
            array_shift($parts);
            $values = array_map('intval', $parts);
            $total = array_sum($values);
            $idle = $values[3] ?? 0;
            return [$total, $idle];
        };

        [$total1, $idle1] = $parseCpu($cpu1);
        [$total2, $idle2] = $parseCpu($cpu2);
        $totalDelta = max(1, $total2 - $total1);
        $idleDelta = max(0, $idle2 - $idle1);
        $cpuUsage = max(0, min(100, round(100 * (1 - ($idleDelta / $totalDelta)), 1)));

        $memInfo = @file('/proc/meminfo', FILE_IGNORE_NEW_LINES) ?: [];
        $mem = [];
        foreach ($memInfo as $line) {
            if (preg_match('/^(\w+):\s+(\d+)/', $line, $m)) {
                $mem[$m[1]] = (int) $m[2];
            }
        }
        $memTotalKb = $mem['MemTotal'] ?? 0;
        $memAvailKb = $mem['MemAvailable'] ?? 0;
        $memUsed = max(0, $memTotalKb - $memAvailKb);
        $memUsage = $memTotalKb > 0 ? round(($memUsed / $memTotalKb) * 100, 1) : 0;

        $diskTotal = @disk_total_space('/') ?: 0;
        $diskFree = @disk_free_space('/') ?: 0;
        $diskUsed = max(0, $diskTotal - $diskFree);
        $diskUsage = $diskTotal > 0 ? round(($diskUsed / $diskTotal) * 100, 1) : 0;

        $netLines = @file('/proc/net/dev', FILE_IGNORE_NEW_LINES) ?: [];
        $rx = 0;
        $tx = 0;
        foreach ($netLines as $line) {
            if (!str_contains($line, ':')) {
                continue;
            }
            [$iface, $rest] = array_map('trim', explode(':', $line, 2));
            if ($iface === 'lo') {
                continue;
            }
            $fields = preg_split('/\s+/', $rest);
            $rx += (int) ($fields[0] ?? 0);
            $tx += (int) ($fields[8] ?? 0);
        }

        return [
            'ts' => time(),
            'cpu' => $cpuUsage,
            'mem' => [
                'usedPct' => $memUsage,
                'usedMb' => round($memUsed / 1024, 1),
                'totalMb' => round($memTotalKb / 1024, 1),
            ],
            'disk' => [
                'usedPct' => $diskUsage,
                'usedGb' => round($diskUsed / 1024 / 1024 / 1024, 2),
                'totalGb' => round($diskTotal / 1024 / 1024 / 1024, 2),
            ],
            'net' => [
                'rx' => $rx,
                'tx' => $tx,
            ],
        ];
    } catch (Throwable $e) {
        return ['error' => $e->getMessage()];
    }
}

$host = getenv('MYSQL_HOST');
$db   = getenv('MYSQL_DATABASE');
$user = getenv('MYSQL_USER');

// Leer password de Docker Secret (más seguro que variable de entorno)
$secretFile = '/run/secrets/mysql_app_password';
if (file_exists($secretFile)) {
    $pass = trim(file_get_contents($secretFile));
} else {
    // Fallback a variable de entorno para desarrollo local
    $pass = getenv('MYSQL_PASSWORD');
}

$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    error_log('ASIR VPS Defense - DB connection failed: ' . $e->getMessage());
    http_response_code(503);
    echo '<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Servicio no disponible</h1><p>Error interno del servidor. Contacta al administrador.</p></body></html>';
    exit;
}

if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        echo json_encode(['error' => 'No autorizado']);
        exit;
    }

    if ($_GET['action'] === 'metrics') {
        $mode = $_GET['mode'] ?? 'full';
        echo json_encode(fetchSecurityMetrics($pdo, $mode));
        exit;
    }

    if ($_GET['action'] === 'system') {
        echo json_encode(readSystemMetrics());
        exit;
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// Handle login
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    // Validar token CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
        $error = 'Token de seguridad inválido. Recarga la página.';
    } else {
    $stmt = $pdo->prepare('SELECT id, username, password_hash, role FROM users WHERE username = :username');
    $stmt->execute(['username' => $_POST['username']]);
    $userRow = $stmt->fetch();

    if ($userRow && password_verify($_POST['password'], $userRow['password_hash'])) {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userRow['id'];
        $_SESSION['username'] = $userRow['username'];
        $_SESSION['role'] = $userRow['role'];

        $stmt = $pdo->prepare('INSERT INTO audit_log (user_id, action, ip_address) VALUES (:uid, "LOGIN_SUCCESS", :ip)');
        $stmt->execute(['uid' => $userRow['id'], 'ip' => $_SERVER['REMOTE_ADDR']]);

        header('Location: index.php');
        exit;
    }

    $error = 'Credenciales inválidas.';
    $stmt = $pdo->prepare('INSERT INTO audit_log (user_id, action, ip_address) VALUES (NULL, "LOGIN_FAILED", :ip)');
    $stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
    } // Cierre del else CSRF
}

if (!isset($_SESSION['user_id'])) {
    // Generar token CSRF si no existe
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    ?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Login - ASIR Defense</title>
    <style>
        body { font-family: sans-serif; background: #0b1220; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; color: #e8eef9; }
        .login-box { background: #0f172a; padding: 28px; border-radius: 10px; box-shadow: 0 12px 40px rgba(0,0,0,0.35); width: 320px; border: 1px solid rgba(255,255,255,0.05); }
        h2 { text-align: center; color: #e8eef9; margin-top: 0; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #1f2937; border-radius: 6px; background: #111827; color: #e8eef9; }
        button { width: 100%; padding: 12px; background: #10b981; color: #0b1220; border: none; border-radius: 6px; cursor: pointer; font-weight: 700; }
        button:hover { background: #0ea371; }
        .error { color: #f87171; text-align: center; margin-bottom: 10px; }
        small { display: block; text-align: center; color: #94a3b8; padding-top: 1rem; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>ASIR VPS Defense</h2>
        <?php if (!empty($error)): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <input type="text" name="username" placeholder="Usuario" required autofocus>
            <input type="password" name="password" placeholder="Contraseña" required>
            <button type="submit">Entrar</button>
        </form>
        <small>Panel accesible solo vía túnel SSH</small>
    </div>
</body>
</html>
<?php
    exit;
}

// Logged-in dashboard
$logsStmt = $pdo->query('SELECT audit_log.id, users.username, audit_log.action, audit_log.ip_address, audit_log.created_at FROM audit_log LEFT JOIN users ON audit_log.user_id = users.id ORDER BY audit_log.created_at DESC LIMIT 50');
$logs = $logsStmt->fetchAll();

function h($value) {
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>ASIR VPS Defense</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css">
    <style>
        :root {
            --bg: #0b1220;
            --panel: #0f172a;
            --panel-border: rgba(255,255,255,0.12);
            --text: #e8eef9;
            --text-muted: #94a3b8;
            --accent: #10b981;
            --accent-warm: #f59e0b;
            --danger: #f87171;
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background: radial-gradient(circle at 15% 20%, rgba(16,185,129,0.12), transparent 32%), radial-gradient(circle at 80% 0%, rgba(59,130,246,0.12), transparent 30%), var(--bg); color: var(--text); padding: 24px; }
        a { color: var(--accent); }
        .dashboard { max-width: 1200px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
        .hero { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }
        .hero .meta { display: flex; flex-direction: column; gap: 6px; }
        .user-panel { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; text-align: right; }
        .user-row { display: inline-flex; align-items: center; gap: 8px; padding: 8px 10px; background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.3); border-radius: 999px; }
        .logout-link { display: inline-flex; align-items: center; gap: 6px; color: var(--accent); text-decoration: none; font-size: 0.95rem; padding: 6px 10px; border: 1px solid rgba(16,185,129,0.35); border-radius: 999px; background: rgba(16,185,129,0.12); }
        .logout-link:hover { background: rgba(16,185,129,0.18); text-decoration: none; }
        .badge { padding: 6px 12px; border-radius: 999px; background: rgba(16,185,129,0.15); border: 1px solid rgba(16,185,129,0.35); color: var(--accent); font-size: 0.9rem; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
        .card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 14px; padding: 16px; display: flex; flex-direction: column; gap: 6px; }
        .card .label { color: var(--text-muted); font-size: 0.95rem; }
        .card strong { font-size: 2rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; }
        .panel { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 14px; padding: 16px; }
        .panel h3 { margin: 0 0 10px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.06); text-align: left; }
        th { color: var(--text-muted); font-weight: 500; }
        .table-scroll { overflow-x: auto; }
        .alert { display: none; margin: 0 0 8px; padding: 10px; border-radius: 10px; background: rgba(248,113,113,0.1); border: 1px solid rgba(248,113,113,0.35); color: #fca5a5; }
        .alert.show { display: block; }
        .status-pill { display: inline-flex; align-items: center; gap: 6px; background: rgba(16,185,129,0.15); color: var(--accent); border: 1px solid rgba(16,185,129,0.35); padding: 8px 12px; border-radius: 999px; font-size: 0.95rem; }
        .controls { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; color: var(--text-muted); }
        .controls select, .controls button { background: #111827; color: var(--text); border: 1px solid var(--panel-border); border-radius: 8px; padding: 8px 10px; cursor: pointer; }
        .badge-result { padding: 3px 8px; border-radius: 10px; font-size: 0.8rem; white-space: nowrap; display: inline-block; }
        .badge-result.ok { background: rgba(16,185,129,0.18); color: var(--accent); border: 1px solid rgba(16,185,129,0.35); }
        .badge-result.warn { background: rgba(245,158,11,0.18); color: var(--accent-warm); border: 1px solid rgba(245,158,11,0.35); }
        .badge-result.honeypot-ok { background: rgba(139,92,246,0.18); color: #a78bfa; border: 1px solid rgba(139,92,246,0.35); }
        .seg-control { display: flex; gap: 0; margin-bottom: 10px; border: 1px solid var(--panel-border); border-radius: 8px; overflow: hidden; width: fit-content; }
        .seg-btn { background: transparent; border: none; color: var(--text-muted); padding: 5px 14px; font-size: 0.8rem; cursor: pointer; transition: background 0.15s, color 0.15s; }
        .seg-btn:not(:last-child) { border-right: 1px solid var(--panel-border); }
        .seg-btn.active { background: var(--accent); color: #000; font-weight: 600; }
        #geoMap { height: 380px; width: 100%; border-radius: 14px; border: 1px solid var(--panel-border); overflow: hidden; }
        #geoSkeleton { height: 380px; width: 100%; }
        .system-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; width: 100%; }
        .sys-card { background: #0d1627; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 12px; display: flex; flex-direction: column; gap: 6px; position: relative; overflow: hidden; }
        .sys-card .label { color: var(--text-muted); font-size: 0.9rem; display: flex; align-items: center; gap: 6px; }
        .sys-card .value { font-size: 1.8rem; font-weight: 700; }
        .donut { width: 96px; aspect-ratio: 1; border-radius: 50%; display: grid; place-items: center; background: conic-gradient(var(--accent) 0deg, rgba(255,255,255,0.08) 0deg); position: relative; }
        .donut::after { content: ""; position: absolute; inset: 18px; background: #0d1627; border-radius: 50%; }
        .donut span { position: relative; font-weight: 700; font-size: 1.1rem; }
        .chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 999px; background: rgba(59,130,246,0.12); color: #93c5fd; border: 1px solid rgba(59,130,246,0.25); font-size: 0.9rem; }
        .tab-bar { display: flex; gap: 4px; flex-wrap: wrap; margin-bottom: 8px; border-bottom: 2px solid rgba(255,255,255,0.08); }
        .tab-button { background: transparent; color: var(--text-muted); border: none; border-bottom: 3px solid transparent; padding: 12px 20px; cursor: pointer; transition: all 0.25s ease; font-weight: 500; font-size: 0.95rem; position: relative; }
        .tab-button:hover { color: var(--text); border-bottom-color: rgba(16,185,129,0.4); background: rgba(255,255,255,0.03); }
        .tab-button.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; background: rgba(16,185,129,0.06); }
        .tab-button.active::before { content: ""; position: absolute; bottom: -2px; left: 0; right: 0; height: 2px; background: var(--accent); box-shadow: 0 0 8px rgba(16,185,129,0.5); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .load-more { background: #111827; color: var(--text); border: 1px solid var(--panel-border); border-radius: 10px; padding: 8px 12px; cursor: pointer; }
        .skeleton { position: relative; overflow: hidden; background: linear-gradient(90deg, rgba(255,255,255,0.04) 25%, rgba(255,255,255,0.08) 37%, rgba(255,255,255,0.04) 63%); background-size: 400% 100%; animation: shimmer 1.2s ease-in-out infinite; }
        @keyframes shimmer { 0% { background-position: 100% 0; } 100% { background-position: -100% 0; } }
        .toast { position: fixed; top: 16px; right: 16px; background: #1f2937; color: var(--text); padding: 10px 14px; border-radius: 10px; border: 1px solid rgba(248,113,113,0.35); display: none; gap: 8px; align-items: center; box-shadow: 0 10px 30px rgba(0,0,0,0.35); }
        .toast.show { display: inline-flex; }
        .map-skeleton { height: 340px; border-radius: 14px; border: 1px solid var(--panel-border); background: linear-gradient(90deg, rgba(255,255,255,0.03) 25%, rgba(255,255,255,0.08) 37%, rgba(255,255,255,0.03) 63%); background-size: 400% 100%; animation: shimmer 1.2s ease-in-out infinite; }
        .flag { display: inline-block; width: 1.5em; text-align: center; }
        @media (max-width: 720px) { .hero { flex-direction: column; align-items: flex-start; } body { padding: 18px 12px; } }

        /* Indicador de severidad global */
        .severity-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-weight: 600;
            font-size: 0.85rem;
            transition: all 0.3s ease;
        }
        .severity-low { background: rgba(34, 197, 94, 0.15); color: #22c55e; border: 1px solid rgba(34, 197, 94, 0.3); }
        .severity-medium { background: rgba(251, 191, 36, 0.15); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.3); }
        .severity-high { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
        .severity-critical { background: rgba(239, 68, 68, 0.25); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.5); animation: pulse-critical 2s infinite; }
        @keyframes pulse-critical { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        .severity-indicator svg { width: 16px; height: 16px; }

        /* Badges de tendencia */
        .trend-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            margin-left: 0.5rem;
        }
        .trend-up { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
        .trend-down { background: rgba(34, 197, 94, 0.15); color: #22c55e; }
        .trend-stable { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }

        /* Estados vacíos contextuales */
        .empty-state {
            text-align: center;
            padding: 2rem 1rem;
            color: var(--text-muted);
        }
        .empty-state svg {
            width: 48px;
            height: 48px;
            margin-bottom: 0.75rem;
            opacity: 0.5;
        }
        .empty-state-title {
            font-weight: 600;
            color: var(--text);
            margin-bottom: 0.25rem;
        }
        .empty-state-desc {
            font-size: 0.85rem;
        }
        .empty-state-positive svg { color: #22c55e; }
        .empty-state-neutral svg { color: #60a5fa; }

        /* Highlight usuarios críticos */
        .user-critical { color: #ef4444; font-weight: 600; }
        .user-warning { color: #fbbf24; }
        .user-root { background: rgba(239, 68, 68, 0.1); }

        /* Timestamps relativos */
        .timestamp-relative {
            font-size: 0.75rem;
            color: var(--text-muted);
            display: block;
        }
        .timestamp-recent { color: #fbbf24; }

        /* Leyenda del mapa */
        .map-legend {
            display: flex;
            gap: 1.5rem;
            padding: 0.75rem 1rem;
            background: var(--panel);
            border-radius: 6px;
            margin-top: 0.75rem;
            font-size: 0.8rem;
            border: 1px solid var(--panel-border);
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }
        .legend-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        .legend-dot.fail2ban { background: #10b981; }
        .legend-dot.ssh { background: #f59e0b; }
        .legend-dot.cowrie { background: #8b5cf6; }
        .pager {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 4px;
            padding: 10px 0 2px;
            border-top: 1px solid var(--panel-border);
            margin-top: 6px;
        }
        .pager-btn {
            background: transparent;
            border: 1px solid var(--panel-border);
            color: var(--text-muted);
            border-radius: 6px;
            padding: 3px 9px;
            font-size: 0.78rem;
            cursor: pointer;
            transition: background 0.15s, color 0.15s;
            line-height: 1.5;
        }
        .pager-btn:hover:not(:disabled) { background: var(--panel-border); color: var(--text-primary); }
        .pager-btn.active { background: var(--accent); border-color: var(--accent); color: #000; font-weight: 700; }
        .pager-btn:disabled { opacity: 0.35; cursor: default; }
        .pager-info {
            margin-left: auto;
            font-size: 0.75rem;
            color: var(--text-muted);
            white-space: nowrap;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <header class="hero">
            <div class="meta">
                <h1 style="margin:0;">🛡️ ASIR VPS Defense</h1>
                <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
                    <div class="status-pill" aria-live="polite">● Operativo · Solo túnel SSH</div>
                    <div id="severityIndicator" class="severity-indicator severity-low">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        <span id="severityText">Sistema Normal</span>
                    </div>
                </div>
                <small style="color:var(--text-muted);">Última sincronización: <span id="lastRefresh">--</span></small>
            </div>
            <div class="user-panel">
                <div class="user-row">
                    <span>Hola, <strong><?= h($_SESSION['username']) ?></strong></span>
                    <a class="logout-link" href="?logout=1">Cerrar sesión</a>
                    <?php if (($_SESSION['role'] ?? '') !== ($_SESSION['username'] ?? '')): ?>
                        <span class="badge"><?= h($_SESSION['role']) ?></span>
                    <?php endif; ?>
                </div>
            </div>
        </header>

        <div class="controls">
            <span>Auto-refresco:</span>
            <select id="refreshSelect" aria-label="Frecuencia de refresco">
                <option value="5000" selected>5s</option>
                <option value="15000">15s</option>
                <option value="60000">1m</option>
            </select>
            <button id="toggleRefresh" aria-pressed="false">Pausar</button>
            <span id="netChip" class="chip" aria-live="polite">↕ Red: -- / --</span>
        </div>

        <section class="system-cards" aria-label="Recursos del sistema">
            <div class="sys-card" id="cardCpu">
                <span class="label">CPU</span>
                <div class="value" id="cpuValue">--</div>
                <svg id="cpuSpark" viewBox="0 0 100 30" height="30" role="presentation"></svg>
            </div>
            <div class="sys-card" id="cardMem">
                <span class="label">RAM</span>
                <div class="donut" id="memDonut"><span id="memDonutLabel">--</span></div>
                <small id="memDetail" style="color:var(--text-muted);">-- / -- GB</small>
            </div>
            <div class="sys-card" id="cardDisk">
                <span class="label">Disco</span>
                <div class="donut" id="diskDonut"><span id="diskDonutLabel">--</span></div>
                <small id="diskDetail" style="color:var(--text-muted);">-- / -- GB</small>
            </div>
            <div class="sys-card" id="cardNet">
                <span class="label">Red (60s)</span>
                <div class="value" id="netValue">--</div>
                <small id="netDetail" style="color:var(--text-muted);">↑ -- / ↓ --</small>
                <svg id="netSpark" viewBox="0 0 100 30" height="30" role="presentation"></svg>
            </div>
        </section>

        <div class="cards">
            <div class="card">
                <span class="label">Baneos Fail2Ban (24h)</span>
                <strong id="fail2ban24h">--</strong>
                <small>Última hora: <span id="fail2ban1h">--</span> | 7 días: <span id="fail2ban7d">--</span></small>
            </div>
            <div class="card">
                <span class="label">Intentos SSH fallidos (24h)</span>
                <strong id="ssh24h">--</strong>
                <small>Última hora: <span id="ssh1h">--</span> | 5 min: <span id="ssh5m">--</span></small>
            </div>
            <div class="card">
                <span class="label">Honeypot Cowrie (24h)</span>
                <strong id="cowrie24h">--</strong>
                <small>1h: <span id="cowrie1h">--</span> | 7d: <span id="cowrie7d">--</span> | Sesiones: <span id="cowrieSessions">--</span></small>
            </div>
        </div>

        <div class="tab-bar" role="tablist">
            <button class="tab-button active" data-tab="ban" aria-selected="true">Baneos</button>
            <button class="tab-button" data-tab="ssh" aria-selected="false">SSH</button>
            <button class="tab-button" data-tab="honeypot" aria-selected="false">Honeypot</button>
            <button class="tab-button" data-tab="map" aria-selected="false">Mapa</button>
            <button class="tab-button" data-tab="audit" aria-selected="false">Auditoría</button>
        </div>

        <div id="metricsError" class="alert" role="alert">No se pudo actualizar la telemetría.</div>

        <div class="tab-content active" data-tab="ban">
            <section class="grid">
                <div class="panel table-scroll">
                    <h3>Top IP baneadas (Fail2Ban)</h3>
                    <table>
                        <thead><tr><th>IP</th><th>País</th><th>Eventos</th></tr></thead>
                        <tbody id="banIpsBody"></tbody>
                    </table>
                </div>
                <div class="panel">
                    <h3>Baneos SSH recientes</h3>
                    <div class="table-scroll"><table>
                        <thead><tr><th>Fecha</th><th>Jail</th><th>Origen</th></tr></thead>
                        <tbody id="banEventsBody"></tbody>
                    </table></div>
                    <div class="pager" id="banEventsPager"></div>
                </div>
            </section>
            <section class="panel">
                <h3>Baneos Cowrie <span class="legend-dot cowrie" style="margin-left:6px;vertical-align:middle;width:10px;height:10px;display:inline-block;border-radius:50%;"></span></h3>
                <div class="table-scroll"><table>
                    <thead><tr><th>Fecha</th><th>Pa&iacute;s</th><th>IP</th></tr></thead>
                    <tbody id="cowrieBanBody"></tbody>
                </table></div>
                <div class="pager" id="cowrieBanPager"></div>
            </section>
        </div>

        <div class="tab-content" data-tab="ssh">
            <section class="grid">
                <div class="panel table-scroll">
                    <h3>Top IP ofensivas (SSH)</h3>
                    <table>
                        <thead><tr><th>IP</th><th>País</th><th>Intentos</th></tr></thead>
                        <tbody id="sshIpsBody"></tbody>
                    </table>
                </div>
                <div class="panel table-scroll">
                    <h3>Usuarios más atacados (SSH)</h3>
                    <table>
                        <thead><tr><th>Usuario</th><th>Intentos</th></tr></thead>
                        <tbody id="sshUsersBody"></tbody>
                    </table>
                </div>
            </section>
            <section class="panel table-scroll">
                <h3>Intentos SSH recientes</h3>
                <table>
                    <thead><tr><th>Fecha</th><th>Usuario</th><th>Origen</th><th>Resultado</th></tr></thead>
                    <tbody id="sshEventsBody"></tbody>
                </table>
                <button type="button" class="load-more" id="sshLoadMore" aria-label="Cargar más eventos SSH">Cargar más</button>
            </section>
        </div>

        <div class="tab-content" data-tab="map">
            <section class="panel">
                <h3>Mapa de actividad (últimos eventos)</h3>
                <div id="geoSkeleton" class="map-skeleton"></div>
                <div id="geoMap" style="display:none;"></div>
                <div class="map-legend">
                    <div class="legend-item"><span class="legend-dot fail2ban"></span> Fail2Ban (IPs baneadas)</div>
                    <div class="legend-item"><span class="legend-dot ssh"></span> SSH (intentos fallidos)</div>
                    <div class="legend-item"><span class="legend-dot cowrie"></span> Honeypot (Cowrie)</div>
                    <span style="margin-left:auto;color:var(--text-muted)" id="mapStats">0 ubicaciones</span>
                </div>
            </section>
        </div>

        <div class="tab-content" data-tab="honeypot">
            <section class="grid">
                <div class="panel">
                    <h3>Top IP atacantes (Honeypot)</h3>
                    <div class="table-scroll"><table>
                        <thead><tr><th>IP</th><th>País</th><th>Intentos</th></tr></thead>
                        <tbody id="cowrieIpsBody"></tbody>
                    </table></div>
                    <div class="pager" id="cowrieIpsPager"></div>
                </div>
                <div class="panel">
                    <h3>Credenciales más probadas</h3>
                    <div class="table-scroll"><table>
                        <thead><tr><th>Usuario</th><th>Intentos</th></tr></thead>
                        <tbody id="cowrieUsersBody"></tbody>
                    </table></div>
                    <div class="pager" id="cowrieUsersPager"></div>
                </div>
            </section>
            <section class="grid">
                <div class="panel">
                    <h3>Intentos recientes en honeypot</h3>
                    <div class="table-scroll"><table>
                        <thead><tr><th>Fecha</th><th>IP</th><th>Usuario</th><th>Contraseña</th><th>Resultado</th></tr></thead>
                        <tbody id="cowrieEventsBody"></tbody>
                    </table></div>
                    <div class="pager" id="cowrieEventsPager"></div>
                </div>
                <div class="panel">
                    <h3>Comandos ejecutados en honeypot</h3>
                    <div class="seg-control">
                        <button type="button" class="seg-btn active" id="cmdsModeRecent">Recientes</button>
                        <button type="button" class="seg-btn" id="cmdsModeTop">Más ejecutados</button>
                    </div>
                    <div class="table-scroll"><table id="cowrieCmdsTable">
                        <thead id="cowrieCmdsHead"><tr><th>Fecha</th><th>IP</th><th>Comando</th></tr></thead>
                        <tbody id="cowrieCmdsBody"></tbody>
                    </table></div>
                    <div class="pager" id="cowrieCmdsPager"></div>
                </div>
            </section>
        </div>

        <div class="tab-content" data-tab="audit">
            <section class="panel table-scroll">
                <h3>Registro de Auditoría Interna</h3>
                <table>
                    <thead><tr><th>ID</th><th>Usuario</th><th>Acción</th><th>IP Origen</th><th>Fecha</th></tr></thead>
                    <tbody>
                        <?php foreach ($logs as $log): ?>
                            <tr>
                                <td><?= h($log['id']) ?></td>
                                <td><?= h($log['username'] ?: 'Anónimo') ?></td>
                                <td><?= h($log['action']) ?></td>
                                <td><?= h($log['ip_address']) ?></td>
                                <td><?= h($log['created_at']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </section>
        </div>
    </div>

    <div id="toast" class="toast" role="status">No se pudo actualizar la telemetría.</div>

    <script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        };

        const formatTs = (ts) => {
            if (!ts) return '';
            const d = new Date(ts * 1000);
            const now = Date.now();
            const diff = now - d.getTime();
            const mins = Math.floor(diff / 60000);
            const hours = Math.floor(diff / 3600000);
            const days = Math.floor(diff / 86400000);
            let relative = '';
            let recentClass = '';
            if (mins < 1) { relative = 'ahora mismo'; recentClass = 'timestamp-recent'; }
            else if (mins < 60) { relative = `hace ${mins}m`; recentClass = mins < 10 ? 'timestamp-recent' : ''; }
            else if (hours < 24) { relative = `hace ${hours}h`; }
            else if (days < 7) { relative = `hace ${days}d`; }
            else { relative = d.toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit' }); }
            const absolute = d.toLocaleString('es-ES', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
            return `${absolute}<span class="timestamp-relative ${recentClass}">${relative}</span>`;
        };
        const formatBytes = (bytes) => {
            if (bytes <= 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const idx = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
            const value = bytes / Math.pow(1024, idx);
            return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[idx]}`;
        };

        const CRITICAL_USERS = ['root', 'admin', 'administrator', 'ubuntu', 'pi', 'postgres', 'mysql', 'oracle'];
        const EMPTY_STATES = {
            banIpsBody: { icon: 'shield', title: '¡Sin IPs baneadas!', desc: 'El sistema no ha detectado amenazas recientes', positive: true },
            banEventsBody: { icon: 'shield', title: 'Sin baneos SSH', desc: 'Fail2Ban no ha registrado baneos SSH en este período', positive: true },
            cowrieBanBody: { icon: 'shield', title: 'Sin baneos Cowrie', desc: 'Ninguna IP baneada por actividad en el honeypot', positive: true },
            sshIpsBody: { icon: 'lock', title: 'Sin ataques SSH', desc: 'No hay intentos de acceso no autorizados', positive: true },
            sshUsersBody: { icon: 'users', title: 'Sin usuarios atacados', desc: 'No se detectaron intentos de login sospechosos', positive: true },
            sshEventsBody: { icon: 'activity', title: 'Sin actividad SSH', desc: 'No hay eventos de autenticación en este período', neutral: true },
            cowrieIpsBody: { icon: 'lock', title: 'Sin atacantes en honeypot', desc: 'No hay IPs registradas atacando el honeypot', positive: true },
            cowrieUsersBody: { icon: 'users', title: 'Sin credenciales probadas', desc: 'No se han registrado intentos de login en el honeypot', positive: true },
            cowrieEventsBody: { icon: 'activity', title: 'Sin intentos en honeypot', desc: 'No hay eventos recientes en el honeypot', neutral: true },
            cowrieCmdsBody: { icon: 'activity', title: 'Sin comandos ejecutados', desc: 'Ningún atacante ha ejecutado comandos', positive: true },
        };
        const emptyIcon = (type) => {
            const icons = {
                shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>',
                lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>',
                users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>',
                activity: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>',
            };
            return icons[type] || icons.activity;
        };
        const highlightUser = (username) => {
            const u = (username || '').toLowerCase();
            if (u === 'root') return `<span class="user-critical">⚠️ ${username}</span>`;
            if (CRITICAL_USERS.includes(u)) return `<span class="user-warning">${username}</span>`;
            return username;
        };
        const updateTable = (tbodyId, rows, columns = 3, htmlCols = [], userCol = -1) => {
            const tbody = document.getElementById(tbodyId);
            if (!tbody) return;
            tbody.innerHTML = '';
            if (!rows || !rows.length) {
                const es = EMPTY_STATES[tbodyId] || { icon: 'activity', title: 'Sin datos', desc: 'No hay información disponible' };
                const cls = es.positive ? 'empty-state-positive' : (es.neutral ? 'empty-state-neutral' : '');
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                td.colSpan = columns;
                td.innerHTML = `<div class="empty-state ${cls}">${emptyIcon(es.icon)}<div class="empty-state-title">${es.title}</div><div class="empty-state-desc">${es.desc}</div></div>`;
                tr.appendChild(td);
                tbody.appendChild(tr);
                return;
            }
            rows.forEach((cols) => {
                const tr = document.createElement('tr');
                // Highlight row if contains critical user
                if (userCol >= 0 && cols[userCol]) {
                    const uname = (cols[userCol]+'').toLowerCase().replace(/[^a-z]/g,'');
                    if (CRITICAL_USERS.includes(uname)) tr.className = 'user-root';
                }
                cols.forEach((value, idx) => {
                    const td = document.createElement('td');
                    let content = value;
                    if (userCol === idx) content = highlightUser(value);
                    if (htmlCols.includes(idx) || userCol === idx) {
                        td.innerHTML = content;
                    } else {
                        td.textContent = content;
                    }
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });
        };

        const setSkeleton = (tbodyId, rows = 3, cols = 3) => {
            const tbody = document.getElementById(tbodyId);
            if (!tbody) return;
            tbody.innerHTML = '';
            for (let i = 0; i < rows; i++) {
                const tr = document.createElement('tr');
                for (let c = 0; c < cols; c++) {
                    const td = document.createElement('td');
                    td.className = 'skeleton';
                    td.innerHTML = '&nbsp;';
                    tr.appendChild(td);
                }
                tbody.appendChild(tr);
            }
        };

        const flagFromCode = (code) => {
            if (!code || code === '??') return '🏳️';
            const cc = code.toUpperCase();
            if (cc.length !== 2) return '🏳️';
            return String.fromCodePoint(...[...cc].map(c => 127397 + c.charCodeAt(0)));
        };

        const badgeResult = (result) => {
            const span = document.createElement('span');
            span.className = 'badge-result ' + (result === 'Usuario existente' ? 'ok' : 'warn');
            span.textContent = result;
            return span.outerHTML;
        };

        // Sistema de severidad global
        const updateSeverity = (fail2ban1h, ssh5m) => {
            const el = document.getElementById('severityIndicator');
            const txt = document.getElementById('severityText');
            if (!el || !txt) return;
            el.classList.remove('severity-low', 'severity-medium', 'severity-high', 'severity-critical');
            let level, icon, text;
            if (fail2ban1h >= 20 || ssh5m >= 50) {
                level = 'severity-critical'; icon = 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z';
                text = '⚠️ Ataque Activo';
            } else if (fail2ban1h >= 10 || ssh5m >= 20) {
                level = 'severity-high'; icon = 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
                text = 'Alerta Alta';
            } else if (fail2ban1h >= 5 || ssh5m >= 10) {
                level = 'severity-medium'; icon = 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
                text = 'Actividad Elevada';
            } else {
                level = 'severity-low'; icon = 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z';
                text = 'Sistema Normal';
            }
            el.classList.add(level);
            el.querySelector('svg').innerHTML = `<path d="${icon}"/>`;
            txt.textContent = text;
        };

        // Badges de tendencia
        const trendBadge = (current, previous, invert = false) => {
            if (previous === 0 && current === 0) return '<span class="trend-badge trend-stable">→ 0%</span>';
            if (previous === 0) return `<span class="trend-badge ${invert ? 'trend-down' : 'trend-up'}">↑ nuevo</span>`;
            const pct = Math.round(((current - previous) / previous) * 100);
            if (Math.abs(pct) < 5) return '<span class="trend-badge trend-stable">→ estable</span>';
            const cls = pct > 0 ? (invert ? 'trend-down' : 'trend-up') : (invert ? 'trend-up' : 'trend-down');
            const arrow = pct > 0 ? '↑' : '↓';
            return `<span class="trend-badge ${cls}">${arrow} ${Math.abs(pct)}%</span>`;
        };
        let prevMetrics = { fail2ban24h: 0, ssh24h: 0 };

        const renderSpark = (id, series) => {
            const svg = document.getElementById(id);
            if (!svg) return;
            const values = series.slice(-20);
            if (!values.length) {
                svg.innerHTML = '';
                return;
            }
            const max = Math.max(...values, 1);
            const points = values.map((v, i) => {
                const x = (i / Math.max(1, values.length - 1)) * 100;
                const y = 30 - (v / max) * 28;
                return `${x},${y}`;
            }).join(' ');
            svg.innerHTML = `<polyline points="${points}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" />`;
        };

        const renderDonut = (id, pct, color = 'var(--accent)') => {
            const el = document.getElementById(id);
            if (!el) return;
            const clamped = Math.max(0, Math.min(100, pct));
            el.style.background = `conic-gradient(${color} ${clamped}%, rgba(255,255,255,0.08) 0)`;
        };

        let state = {
            banEvents: [],
            cowrieBanEvents: [],
            sshEvents: [],
            banIps: [],
            sshIps: [],
            sshUsers: [],
            cowrieEvents: [],
            cowrieIps: [],
            cowrieUsers: [],
            cowrieCmds: [],
            cowrieCmdsTop: [],
            geo: [],
            system: {
                cpu: [],
                mem: [],
                disk: [],
                net: [],
                ts: [],
            },
            netTotals: null,
        };

        let failureCount = 0;
        let refreshMs = 5000;
        let refreshTimer = null;
        let inFlight = false;
        let paused = false;
        let sshVisible = 20;

        const COWRIE_PAGE_SIZE = 10;
        const cowriePages = { ips: 0, users: 0, events: 0, cmds: 0 };
        const banPages = { events: 0, cowrie: 0 };
        let cowrieCmdsMode = 'recent'; // 'recent' | 'top'

        // Renderiza un paginador numérico compacto.
        // onPage(n) se llama con el número de página (0-indexed) al hacer clic.
        const renderPager = (containerId, currentPage, total, onPage) => {
            const el = document.getElementById(containerId);
            if (!el) return;
            el.innerHTML = '';
            if (total <= COWRIE_PAGE_SIZE) return;          // sin paginación si cabe en 1 página
            const pages = Math.ceil(total / COWRIE_PAGE_SIZE);
            const mkBtn = (label, page, active = false, disabled = false) => {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'pager-btn' + (active ? ' active' : '');
                b.textContent = label;
                b.disabled = disabled;
                if (!disabled && !active) b.addEventListener('click', () => onPage(page));
                return b;
            };
            el.appendChild(mkBtn('←', currentPage - 1, false, currentPage === 0));
            // Ventana de páginas: siempre primera, última y hasta 3 alrededor de la actual
            const show = new Set([0, pages - 1]);
            for (let i = Math.max(0, currentPage - 1); i <= Math.min(pages - 1, currentPage + 1); i++) show.add(i);
            let prev = -1;
            [...show].sort((a, b) => a - b).forEach((p) => {
                if (p - prev > 1) {
                    const dots = document.createElement('span');
                    dots.className = 'pager-btn';
                    dots.textContent = '…';
                    dots.style.cursor = 'default';
                    dots.style.border = 'none';
                    el.appendChild(dots);
                }
                el.appendChild(mkBtn(String(p + 1), p, p === currentPage));
                prev = p;
            });
            el.appendChild(mkBtn('→', currentPage + 1, false, currentPage >= pages - 1));
            const info = document.createElement('span');
            info.className = 'pager-info';
            info.textContent = `Pág. ${currentPage + 1} / ${pages} · ${total} registros`;
            el.appendChild(info);
        };

        const renderCowrieTables = () => {
            const slice = (arr, page) => arr.slice(page * COWRIE_PAGE_SIZE, (page + 1) * COWRIE_PAGE_SIZE);
            updateTable('cowrieIpsBody', slice(state.cowrieIps, cowriePages.ips), 3, [1], -1);
            renderPager('cowrieIpsPager', cowriePages.ips, state.cowrieIps.length, (p) => { cowriePages.ips = p; renderCowrieTables(); });
            updateTable('cowrieUsersBody', slice(state.cowrieUsers, cowriePages.users), 2, [], 0);
            renderPager('cowrieUsersPager', cowriePages.users, state.cowrieUsers.length, (p) => { cowriePages.users = p; renderCowrieTables(); });
            updateTable('cowrieEventsBody', slice(state.cowrieEvents, cowriePages.events), 5, [0, 1, 4], 2);
            renderPager('cowrieEventsPager', cowriePages.events, state.cowrieEvents.length, (p) => { cowriePages.events = p; renderCowrieTables(); });
            // Comandos: modo recientes (fecha+IP+cmd, 3 cols) o top (cmd+veces, 2 cols)
            const head = document.getElementById('cowrieCmdsHead');
            if (cowrieCmdsMode === 'recent') {
                if (head) head.innerHTML = '<tr><th>Fecha</th><th>IP</th><th>Comando</th></tr>';
                updateTable('cowrieCmdsBody', slice(state.cowrieCmds, cowriePages.cmds), 3, [0, 1], -1);
                renderPager('cowrieCmdsPager', cowriePages.cmds, state.cowrieCmds.length, (p) => { cowriePages.cmds = p; renderCowrieTables(); });
            } else {
                if (head) head.innerHTML = '<tr><th>Comando</th><th>Veces</th></tr>';
                updateTable('cowrieCmdsBody', slice(state.cowrieCmdsTop, cowriePages.cmds), 2, [], -1);
                renderPager('cowrieCmdsPager', cowriePages.cmds, state.cowrieCmdsTop.length, (p) => { cowriePages.cmds = p; renderCowrieTables(); });
            }
        };

        const showToast = (msg) => {
            const toast = document.getElementById('toast');
            if (!toast) return;
            toast.textContent = msg;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 3500);
        };

        const scheduleRefresh = (delay = refreshMs) => {
            if (refreshTimer) clearTimeout(refreshTimer);
            refreshTimer = setTimeout(refreshLoop, delay);
        };

        const renderMap = (points) => {
            geoLayer.clearLayers();
            const valid = points.filter(p => p.lat !== null && p.lon !== null);
            let f2bCount = 0, sshCount = 0, cowrieCount = 0;
            valid.forEach((p) => {
                const color = p.type === 'fail2ban' ? '#10b981' : p.type === 'cowrie' ? '#8b5cf6' : '#f59e0b';
                if (p.type === 'fail2ban') f2bCount++;
                else if (p.type === 'cowrie') cowrieCount++;
                else sshCount++;
                L.circleMarker([p.lat, p.lon], {
                    radius: 5,
                    color,
                    weight: 1,
                    fillColor: color,
                    fillOpacity: 0.7,
                }).addTo(geoLayer).bindTooltip(`${flagFromCode(p.code)} ${p.ip}<br><span style="color:${color}">${p.type}</span>`);
            });
            // Actualizar estadísticas del mapa
            const mapStats = document.getElementById('mapStats');
            if (mapStats) mapStats.textContent = `${valid.length} ubicaciones (${f2bCount} bans, ${sshCount} SSH, ${cowrieCount} honeypot)`;
            if (valid.length && typeof geoLayer.getBounds === 'function') {
                map.fitBounds(geoLayer.getBounds(), { padding: [20, 20], maxZoom: 4 });
            } else {
                map.setView([20, 0], 0.25);
            }
            const sk = document.getElementById('geoSkeleton');
            const gm = document.getElementById('geoMap');
            if (gm && sk) {
                sk.style.display = 'none';
                gm.style.display = 'block';
                // Leaflet necesita recalcular cuando el contenedor deja de estar oculto
                setTimeout(() => map.invalidateSize(), 50);
            }
        };

        const renderSystem = (sys) => {
            if (sys.error) return;
            state.system.ts.push(sys.ts);
            state.system.cpu.push(sys.cpu);
            state.system.mem.push(sys.mem.usedPct);
            state.system.disk.push(sys.disk.usedPct);
            const capSeries = (arr) => { if (arr.length > 40) arr.splice(0, arr.length - 40); };
            capSeries(state.system.ts);
            capSeries(state.system.cpu);
            capSeries(state.system.mem);
            capSeries(state.system.disk);
            const netTotal = sys.net;
            if (state.netTotals) {
                const deltaRx = Math.max(0, netTotal.rx - state.netTotals.rx);
                const deltaTx = Math.max(0, netTotal.tx - state.netTotals.tx);
                const elapsed = Math.max(1, sys.ts - (state.system.ts[state.system.ts.length - 2] || sys.ts));
                const rxRate = deltaRx / elapsed;
                const txRate = deltaTx / elapsed;
                state.system.net.push(rxRate + txRate);
                capSeries(state.system.net);
                setText('netDetail', `↑ ${formatBytes(txRate)}/s · ↓ ${formatBytes(rxRate)}/s`);
                setText('netValue', `${formatBytes(rxRate + txRate)}/s`);
                document.getElementById('netChip').textContent = `↕ Red: ↑ ${formatBytes(txRate)}/s · ↓ ${formatBytes(rxRate)}/s`;
                renderSpark('netSpark', state.system.net);
            }
            state.netTotals = netTotal;

            setText('cpuValue', `${sys.cpu}%`);
            renderSpark('cpuSpark', state.system.cpu);

            setText('memDonutLabel', `${sys.mem.usedPct}%`);
            setText('memDetail', `${(sys.mem.usedMb/1024).toFixed(2)} / ${(sys.mem.totalMb/1024).toFixed(2)} GB`);
            renderDonut('memDonut', sys.mem.usedPct);

            setText('diskDonutLabel', `${sys.disk.usedPct}%`);
            setText('diskDetail', `${sys.disk.usedGb} / ${sys.disk.totalGb} GB`);
            renderDonut('diskDonut', sys.disk.usedPct, '#60a5fa');
        };

        const PAGE_SIZE_BAN = 15;
        const sliceBan = (arr, page) => arr.slice(page * PAGE_SIZE_BAN, (page + 1) * PAGE_SIZE_BAN);
        const renderPagerBan = (containerId, currentPage, total, pages, key) => {
            const el = document.getElementById(containerId);
            if (!el) return;
            el.innerHTML = '';
            if (total <= PAGE_SIZE_BAN) return;
            const numPages = Math.ceil(total / PAGE_SIZE_BAN);
            const mkBtn = (label, page, active = false, disabled = false) => {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'pager-btn' + (active ? ' active' : '');
                b.textContent = label;
                b.disabled = disabled;
                if (!disabled && !active) b.addEventListener('click', () => { pages[key] = page; renderTables(); });
                return b;
            };
            el.appendChild(mkBtn('←', currentPage - 1, false, currentPage === 0));
            const show = new Set([0, numPages - 1]);
            for (let i = Math.max(0, currentPage - 1); i <= Math.min(numPages - 1, currentPage + 1); i++) show.add(i);
            let prev = -1;
            [...show].sort((a, b) => a - b).forEach((p) => {
                if (p - prev > 1) { const d = document.createElement('span'); d.className = 'pager-btn'; d.textContent = '…'; d.style.cssText = 'cursor:default;border:none'; el.appendChild(d); }
                el.appendChild(mkBtn(String(p + 1), p, p === currentPage));
                prev = p;
            });
            el.appendChild(mkBtn('→', currentPage + 1, false, currentPage >= numPages - 1));
            const info = document.createElement('span');
            info.className = 'pager-info';
            info.textContent = `Pág. ${currentPage + 1} / ${numPages} · ${total} registros`;
            el.appendChild(info);
        };

        const renderTables = () => {
            updateTable('banIpsBody', state.banIps, 3, [1], -1);
            updateTable('banEventsBody', sliceBan(state.banEvents, banPages.events), 3, [0, 2], -1);
            renderPagerBan('banEventsPager', banPages.events, state.banEvents.length, banPages, 'events');
            updateTable('cowrieBanBody', sliceBan(state.cowrieBanEvents, banPages.cowrie), 3, [0, 2], -1);
            renderPagerBan('cowrieBanPager', banPages.cowrie, state.cowrieBanEvents.length, banPages, 'cowrie');

            updateTable('sshIpsBody', state.sshIps, 3, [1], -1);
            updateTable('sshUsersBody', state.sshUsers, 2, [], 0);
            updateTable('sshEventsBody', state.sshEvents.slice(0, sshVisible), 4, [0, 2, 3], 1);
            const sshBtn = document.getElementById('sshLoadMore');
            if (sshBtn) sshBtn.disabled = sshVisible >= state.sshEvents.length;

            renderCowrieTables();
        };

        const refreshLoop = async () => {
            if (paused || inFlight) return;
            inFlight = true;
            let hadError = false;
            try {
                const [metricsRes, systemRes] = await Promise.allSettled([
                    fetch('?action=metrics'),
                    fetch('?action=system'),
                ]);

                const systemOk = (systemRes.status === 'fulfilled' && systemRes.value.ok);
                const metricsOk = (metricsRes.status === 'fulfilled' && metricsRes.value.ok);

                if (systemOk) {
                    const system = await systemRes.value.json();
                    if (!system.error) {
                        renderSystem(system);
                    }
                }

                if (metricsOk) {
                    const data = await metricsRes.value.json();
                    if (!data.error) {
                        const fail2banTotals = (data.fail2ban && data.fail2ban.totals) || {};
                        const f24h = fail2banTotals.last24h ?? 0;
                        const f1h = fail2banTotals.last1h ?? 0;
                        const f7d = fail2banTotals.last7d ?? 0;
                        setText('fail2ban24h', f24h);
                        setText('fail2ban1h', f1h);
                        setText('fail2ban7d', f7d);
                        // Añadir tendencia comparando con valor previo
                        const f24hEl = document.getElementById('fail2ban24h');
                        if (f24hEl && prevMetrics.fail2ban24h > 0) {
                            const badge = f24hEl.parentElement.querySelector('.trend-badge');
                            if (!badge) f24hEl.insertAdjacentHTML('afterend', trendBadge(f24h, prevMetrics.fail2ban24h));
                        }

                        const sshTotals = (data.ssh && data.ssh.totals) || {};
                        const s24h = sshTotals.last24h ?? 0;
                        const s1h = sshTotals.last1h ?? 0;
                        const s5m = sshTotals.last5m ?? 0;
                        setText('ssh24h', s24h);
                        setText('ssh1h', s1h);
                        setText('ssh5m', s5m);

                        // Actualizar severidad global
                        updateSeverity(f1h, s5m);
                        prevMetrics = { fail2ban24h: f24h, ssh24h: s24h };

                        const generatedAt = (data.generatedAt ?? Date.now() / 1000) * 1000;
                        setText('lastRefresh', new Date(generatedAt).toLocaleTimeString('es-ES'));

                        const flagLabel = (cc, name = '') => `<span class="flag">${flagFromCode(cc)}</span> ${name || cc || ''}`.trim();
                        state.banIps = ((data.fail2ban && data.fail2ban.topIps) || []).map((r) => [r.ip, flagLabel(r.country_code, r.country), r.count]);
                        const allBanEvents = ((data.fail2ban && data.fail2ban.events) || []);
                        state.banEvents      = allBanEvents.filter(r => r.jail !== 'cowrie').map((r) => [formatTs(r.timestamp), r.jail, flagLabel(r.country_code, r.ip)]);
                        state.cowrieBanEvents = allBanEvents.filter(r => r.jail === 'cowrie').map((r) => [formatTs(r.timestamp), flagLabel(r.country_code, r.country), r.ip]);
                        banPages.events = 0;
                        banPages.cowrie = 0;
                        state.sshIps = ((data.ssh && data.ssh.topIps) || []).map((r) => [r.ip, flagLabel(r.country_code, r.country), r.count]);
                        state.sshUsers = ((data.ssh && data.ssh.topUsers) || []).map((r) => [r.label, r.count]);
                        state.sshEvents = ((data.ssh && data.ssh.events) || []).map((r) => [formatTs(r.timestamp), r.username, flagLabel(r.country_code, r.ip), badgeResult(r.result)]);

                        const cowrieTotals = (data.cowrie && data.cowrie.totals) || {};
                        setText('cowrie24h', cowrieTotals.last24h ?? 0);
                        setText('cowrie1h', cowrieTotals.last1h ?? 0);
                        setText('cowrie7d', cowrieTotals.last7d ?? 0);
                        setText('cowrieSessions', cowrieTotals.sessions_24h ?? 0);
                        state.cowrieIps    = ((data.cowrie && data.cowrie.topIps) || []).map((r) => [r.ip, flagLabel(r.country_code, r.country), r.count]);
                        state.cowrieUsers  = ((data.cowrie && data.cowrie.topUsers) || []).map((r) => [r.label, r.count]);
                        const badgeCowrie  = (result) => `<span class="badge-result ${result === 'ingresó al honeypot' ? 'honeypot-ok' : 'warn'}">${result === 'ingresó al honeypot' ? '🍯 Honeypot' : 'Rechazado'}</span>`;
                        state.cowrieEvents = ((data.cowrie && data.cowrie.events) || []).map((r) => [formatTs(r.timestamp), flagLabel(r.country_code, r.ip), r.username, r.password, badgeCowrie(r.result)]);
                        state.cowrieCmds      = ((data.cowrie && data.cowrie.commands) || [])
                            .sort((a, b) => b.timestamp - a.timestamp)
                            .map((r) => [formatTs(r.timestamp), flagLabel('', r.ip), r.command]);
                        state.cowrieCmdsTop   = ((data.cowrie && data.cowrie.topCommands) || [])
                            .map((r) => [r.label, r.count]);
                        // Resetear páginas al actualizar datos para que no queden en páginas inexistentes
                        Object.keys(cowriePages).forEach(k => { cowriePages[k] = 0; });
                        state.geo = (data.geo || []).map((p) => ({ lat: p.lat, lon: p.lon, ip: p.ip, country: p.country, code: p.country_code, type: p.type }));

                        renderTables();
                        renderMap(state.geo);
                        failureCount = 0;
                        document.getElementById('metricsError').classList.remove('show');
                    } else {
                        hadError = true;
                    }
                }

                if (!systemOk || !metricsOk) {
                    hadError = true;
                }
            } catch (e) {
                hadError = true;
            }

            if (hadError) {
                failureCount++;
                document.getElementById('metricsError').classList.add('show');
                if (failureCount % 2 === 0) showToast('No se pudo actualizar la telemetría.');
            } else {
                failureCount = 0;
                document.getElementById('metricsError').classList.remove('show');
            }

            const penalty = hadError ? Math.min(30000, failureCount * 2000) : 0;
            inFlight = false;
            scheduleRefresh(refreshMs + penalty);
        };

        // Leaflet map
        const map = L.map('geoMap', { worldCopyJump: true, zoomControl: false, zoomSnap: 0.25, minZoom: 0 });
        const tiles = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap, © Carto',
            maxZoom: 6,
            minZoom: 0,
        }).addTo(map);
        const geoLayer = L.featureGroup().addTo(map);
        map.setView([20, 0], 0.25);

        document.getElementById('refreshSelect').addEventListener('change', (e) => {
            refreshMs = Number(e.target.value) || 15000;
            scheduleRefresh(refreshMs);
        });

        document.getElementById('toggleRefresh').addEventListener('click', (e) => {
            paused = !paused;
            e.target.textContent = paused ? 'Reanudar' : 'Pausar';
            e.target.setAttribute('aria-pressed', paused ? 'true' : 'false');
            if (paused) {
                if (refreshTimer) clearTimeout(refreshTimer);
            } else {
                scheduleRefresh(0);
            }
        });

        document.querySelectorAll('.tab-button').forEach((btn) => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                const tab = btn.dataset.tab;
                const content = document.querySelector(`.tab-content[data-tab="${tab}"]`);
                if (content) content.classList.add('active');
                if (tab === 'map') {
                    // Asegura que Leaflet recalcule tras mostrar el tab
                    setTimeout(() => map.invalidateSize(), 50);
                    renderMap(state.geo);
                }
            });
        });

        document.getElementById('sshLoadMore').addEventListener('click', () => {
            sshVisible += 15;
            renderTables();
        });

        document.getElementById('cmdsModeRecent').addEventListener('click', () => {
            cowrieCmdsMode = 'recent';
            cowriePages.cmds = 0;
            document.getElementById('cmdsModeRecent').classList.add('active');
            document.getElementById('cmdsModeTop').classList.remove('active');
            renderCowrieTables();
        });
        document.getElementById('cmdsModeTop').addEventListener('click', () => {
            cowrieCmdsMode = 'top';
            cowriePages.cmds = 0;
            document.getElementById('cmdsModeTop').classList.add('active');
            document.getElementById('cmdsModeRecent').classList.remove('active');
            renderCowrieTables();
        });

        // Initial skeletons
        setSkeleton('banIpsBody', 3, 3);
        setSkeleton('banEventsBody', 4, 3);
        setSkeleton('cowrieBanBody', 3, 3);
        setSkeleton('sshIpsBody', 3, 3);
        setSkeleton('sshUsersBody', 3, 2);
        setSkeleton('sshEventsBody', 5, 4);
        setSkeleton('cowrieIpsBody', 3, 3);
        setSkeleton('cowrieUsersBody', 3, 2);
        setSkeleton('cowrieEventsBody', 5, 5);
        setSkeleton('cowrieCmdsBody', 5, 3);

        scheduleRefresh(0);
    </script>
</body>
</html>
