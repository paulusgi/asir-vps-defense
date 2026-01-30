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
$pass = getenv('MYSQL_PASSWORD');
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
    die('Error de conexión: ' . $e->getMessage());
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
}

if (!isset($_SESSION['user_id'])) {
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
            <input type="text" name="username" placeholder="Usuario" required autofocus>
            <input type="password" name="password" placeholder="Contraseña" required>
            <button type="submit">Entrar</button>
        </form>
        <small>Panel accesible solo vía túnel SSH</small>
        <small style="color:#9ca3af;">Máx 5 req/min por IP (rate-limit)</small>
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
        .badge-result { padding: 4px 8px; border-radius: 10px; font-size: 0.85rem; }
        .badge-result.ok { background: rgba(16,185,129,0.18); color: var(--accent); border: 1px solid rgba(16,185,129,0.35); }
        .badge-result.warn { background: rgba(245,158,11,0.18); color: var(--accent-warm); border: 1px solid rgba(245,158,11,0.35); }
        #geoMap { height: 340px; border-radius: 14px; border: 1px solid var(--panel-border); overflow: hidden; }
        .system-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; width: 100%; }
        .sys-card { background: #0d1627; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 12px; display: flex; flex-direction: column; gap: 6px; position: relative; overflow: hidden; }
        .sys-card .label { color: var(--text-muted); font-size: 0.9rem; display: flex; align-items: center; gap: 6px; }
        .sys-card .value { font-size: 1.8rem; font-weight: 700; }
        .donut { width: 96px; aspect-ratio: 1; border-radius: 50%; display: grid; place-items: center; background: conic-gradient(var(--accent) 0deg, rgba(255,255,255,0.08) 0deg); position: relative; }
        .donut::after { content: ""; position: absolute; inset: 18px; background: #0d1627; border-radius: 50%; }
        .donut span { position: relative; font-weight: 700; font-size: 1.1rem; }
        .chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 999px; background: rgba(59,130,246,0.12); color: #93c5fd; border: 1px solid rgba(59,130,246,0.25); font-size: 0.9rem; }
        .tab-bar { display: flex; gap: 8px; flex-wrap: wrap; }
        .tab-button { background: #111827; color: var(--text); border: 1px solid var(--panel-border); border-radius: 10px; padding: 8px 12px; cursor: pointer; transition: background 0.15s, border-color 0.15s; }
        .tab-button.active { background: rgba(16,185,129,0.14); border-color: rgba(16,185,129,0.5); color: var(--accent); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .load-more { background: #111827; color: var(--text); border: 1px solid var(--panel-border); border-radius: 10px; padding: 8px 12px; cursor: pointer; }
        .skeleton { position: relative; overflow: hidden; background: linear-gradient(90deg, rgba(255,255,255,0.04) 25%, rgba(255,255,255,0.08) 37%, rgba(255,255,255,0.04) 63%); background-size: 400% 100%; animation: shimmer 1.2s ease-in-out infinite; }
        @keyframes shimmer { 0% { background-position: 100% 0; } 100% { background-position: -100% 0; } }
        .toast { position: fixed; top: 16px; right: 16px; background: #1f2937; color: var(--text); padding: 10px 14px; border-radius: 10px; border: 1px solid rgba(248,113,113,0.35); display: none; gap: 8px; align-items: center; box-shadow: 0 10px 30px rgba(0,0,0,0.35); }
        .toast.show { display: inline-flex; }
        .map-skeleton { height: 340px; border-radius: 14px; border: 1px solid var(--panel-border); background: linear-gradient(90deg, rgba(255,255,255,0.03) 25%, rgba(255,255,255,0.08) 37%, rgba(255,255,255,0.03) 63%); background-size: 400% 100%; animation: shimmer 1.2s ease-in-out infinite; }
        @media (max-width: 720px) { .hero { flex-direction: column; align-items: flex-start; } body { padding: 18px 12px; } }
    </style>
</head>
<body>
    <div class="dashboard">
        <header class="hero">
            <div class="meta">
                <h1 style="margin:0;">🛡️ ASIR VPS Defense</h1>
                <div class="status-pill" aria-live="polite">● Operativo · Solo túnel SSH</div>
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
                <option value="5000">5s</option>
                <option value="15000" selected>15s</option>
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
                <small>Última hora: <span id="fail2ban1h">--</span></small>
            </div>
            <div class="card">
                <span class="label">Intentos SSH fallidos (1h)</span>
                <strong id="ssh1h">--</strong>
                <small>Últimos 5 min: <span id="ssh5m">--</span></small>
            </div>
        </div>

        <div class="tab-bar" role="tablist">
            <button class="tab-button active" data-tab="ban" aria-selected="true">Baneos</button>
            <button class="tab-button" data-tab="ssh" aria-selected="false">SSH</button>
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
                <div class="panel table-scroll">
                    <h3>Baneos recientes (Fail2Ban)</h3>
                    <table>
                        <thead><tr><th>Fecha</th><th>Jail</th><th>Origen</th></tr></thead>
                        <tbody id="banEventsBody"></tbody>
                    </table>
                    <button type="button" class="load-more" id="banLoadMore" aria-label="Cargar más baneos">Cargar más</button>
                </div>
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

        const formatTs = (ts) => new Date(ts * 1000).toLocaleString('es-ES');
        const formatBytes = (bytes) => {
            if (bytes <= 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const idx = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
            const value = bytes / Math.pow(1024, idx);
            return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[idx]}`;
        };

        const updateTable = (tbodyId, rows, columns = 3, htmlCols = []) => {
            const tbody = document.getElementById(tbodyId);
            if (!tbody) return;
            tbody.innerHTML = '';
            if (!rows || !rows.length) {
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                td.colSpan = columns;
                td.textContent = 'Sin registros';
                tr.appendChild(td);
                tbody.appendChild(tr);
                return;
            }
            rows.forEach((cols) => {
                const tr = document.createElement('tr');
                cols.forEach((value, idx) => {
                    const td = document.createElement('td');
                    if (htmlCols.includes(idx)) {
                        td.innerHTML = value;
                    } else {
                        td.textContent = value;
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
            sshEvents: [],
            banIps: [],
            sshIps: [],
            sshUsers: [],
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
        let refreshMs = 15000;
        let refreshTimer = null;
        let inFlight = false;
        let paused = false;
        let banVisible = 15;
        let sshVisible = 20;

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
            valid.forEach((p) => {
                const color = p.type === 'fail2ban' ? '#10b981' : '#f59e0b';
                L.circleMarker([p.lat, p.lon], {
                    radius: 5,
                    color,
                    weight: 1,
                    fillColor: color,
                    fillOpacity: 0.7,
                }).addTo(geoLayer).bindTooltip(`${flagFromCode(p.code)} ${p.ip}`);
            });
            if (valid.length) {
                map.fitBounds(geoLayer.getBounds(), { padding: [20, 20], maxZoom: 4 });
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

        const renderTables = () => {
            updateTable('banIpsBody', state.banIps, 3);
            updateTable('banEventsBody', state.banEvents.slice(0, banVisible), 3);
            const banBtn = document.getElementById('banLoadMore');
            if (banBtn) banBtn.disabled = banVisible >= state.banEvents.length;

            updateTable('sshIpsBody', state.sshIps, 3);
            updateTable('sshUsersBody', state.sshUsers, 2);
            updateTable('sshEventsBody', state.sshEvents.slice(0, sshVisible), 4, [3]);
            const sshBtn = document.getElementById('sshLoadMore');
            if (sshBtn) sshBtn.disabled = sshVisible >= state.sshEvents.length;
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
                        setText('fail2ban24h', fail2banTotals.last24h ?? 0);
                        setText('fail2ban1h', fail2banTotals.last1h ?? 0);

                        const sshTotals = (data.ssh && data.ssh.totals) || {};
                        setText('ssh1h', sshTotals.last1h ?? 0);
                        setText('ssh5m', sshTotals.last5m ?? 0);

                        const generatedAt = (data.generatedAt ?? Date.now() / 1000) * 1000;
                        setText('lastRefresh', new Date(generatedAt).toLocaleTimeString('es-ES'));

                        state.banIps = ((data.fail2ban && data.fail2ban.topIps) || []).map((r) => [r.ip, `${flagFromCode(r.country_code)} ${r.country}`, r.count]);
                        state.banEvents = ((data.fail2ban && data.fail2ban.events) || []).map((r) => [formatTs(r.timestamp), r.jail, `${flagFromCode(r.country_code)} ${r.ip}`]);
                        state.sshIps = ((data.ssh && data.ssh.topIps) || []).map((r) => [r.ip, `${flagFromCode(r.country_code)} ${r.country}`, r.count]);
                        state.sshUsers = ((data.ssh && data.ssh.topUsers) || []).map((r) => [r.label, r.count]);
                        state.sshEvents = ((data.ssh && data.ssh.events) || []).map((r) => [formatTs(r.timestamp), r.username, `${flagFromCode(r.country_code)} ${r.ip}`, badgeResult(r.result)]);
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
        const map = L.map('geoMap', { worldCopyJump: true, zoomControl: false });
        const tiles = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap, © Carto',
            maxZoom: 6,
            minZoom: 1,
        }).addTo(map);
        const geoLayer = L.layerGroup().addTo(map);
        map.setView([20, 0], 2);

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

        document.getElementById('banLoadMore').addEventListener('click', () => {
            banVisible += 15;
            renderTables();
        });

        document.getElementById('sshLoadMore').addEventListener('click', () => {
            sshVisible += 15;
            renderTables();
        });

        // Initial skeletons
        setSkeleton('banIpsBody', 3, 3);
        setSkeleton('banEventsBody', 4, 3);
        setSkeleton('sshIpsBody', 3, 3);
        setSkeleton('sshUsersBody', 3, 2);
        setSkeleton('sshEventsBody', 5, 4);

        scheduleRefresh(0);
    </script>
</body>
</html>
