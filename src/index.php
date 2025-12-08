<?php
session_start();
require_once __DIR__ . '/includes/security_metrics.php';

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
} catch (\PDOException $e) {
    die("Error de conexión: " . $e->getMessage());
}

if (isset($_GET['action']) && $_GET['action'] === 'metrics') {
    header('Content-Type: application/json');
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        echo json_encode(['error' => 'No autorizado']);
        exit;
    }

    echo json_encode(fetchSecurityMetrics($pdo));
    exit;
}

// Handle Logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit;
}

// Handle Login
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $stmt = $pdo->prepare("SELECT id, username, password_hash, role FROM users WHERE username = :username");
    $stmt->execute(['username' => $_POST['username']]);
    $user = $stmt->fetch();

    if ($user && password_verify($_POST['password'], $user['password_hash'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        
        // Log Login Success
        $stmt = $pdo->prepare("INSERT INTO audit_log (user_id, action, ip_address) VALUES (:uid, 'LOGIN_SUCCESS', :ip)");
        $stmt->execute(['uid' => $user['id'], 'ip' => $_SERVER['REMOTE_ADDR']]);
        
        header("Location: index.php");
        exit;
    } else {
        $error = "Credenciales inválidas.";
        // Log Login Failure
        $stmt = $pdo->prepare("INSERT INTO audit_log (user_id, action, ip_address) VALUES (NULL, 'LOGIN_FAILED', :ip)");
        $stmt->execute(['ip' => $_SERVER['REMOTE_ADDR']]);
    }
}

// Require Login
if (!isset($_SESSION['user_id'])) {
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Login - ASIR Defense</title>
    <style>
        body { font-family: sans-serif; background: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 0 15px rgba(0,0,0,0.1); width: 300px; }
        h2 { text-align: center; color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #2e7d32; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #1b5e20; }
        .error { color: red; text-align: center; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔒 Acceso Seguro</h2>
        <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="POST">
            <input type="text" name="username" placeholder="Usuario" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <button type="submit">Entrar</button>
        </form>
    </div>
</body>
</html>
<?php
    exit;
}

// --- AUTHENTICATED AREA ---

// Log Page View
$stmt = $pdo->prepare("INSERT INTO audit_log (user_id, action, ip_address) VALUES (:uid, 'PAGE_VIEW', :ip)");
$stmt->execute(['uid' => $_SESSION['user_id'], 'ip' => $_SERVER['REMOTE_ADDR']]);

// Fetch Audit Logs
$logs = $pdo->query("SELECT * FROM view_audit_summary LIMIT 20")->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASIR Defense Panel</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #04060d;
            --panel: rgba(12, 14, 25, 0.85);
            --panel-border: rgba(255, 255, 255, 0.08);
            --accent: #2de0c5;
            --accent-2: #ff7b72;
            --text-muted: rgba(255, 255, 255, 0.65);
        }

        * { box-sizing: border-box; }

        body {
            font-family: 'Space Grotesk', sans-serif;
            margin: 0;
            min-height: 100vh;
            background: radial-gradient(circle at 10% 20%, #082032 0%, #04060d 55%) fixed;
            color: #f5f7ff;
            padding: 30px 15px;
        }

        .dashboard {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        .hero {
            background: var(--panel);
            border: 1px solid var(--panel-border);
            border-radius: 18px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            backdrop-filter: blur(12px);
            box-shadow: 0 25px 70px rgba(0, 0, 0, 0.4);
        }

        .hero header {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
        }

        .hero h1 {
            margin: 0;
            font-size: 2rem;
        }

        .badge {
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            background: rgba(255, 255, 255, 0.1);
        }

        .badge-admin { background: rgba(45, 224, 197, 0.2); }
        .badge-viewer { background: rgba(255, 123, 114, 0.25); }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 0.85rem;
            color: #0d332d;
            background: rgba(45, 224, 197, 0.25);
        }

        .cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }

        .card {
            background: var(--panel);
            border: 1px solid var(--panel-border);
            border-radius: 16px;
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            min-height: 120px;
            box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.02);
        }

        .card span.label { color: var(--text-muted); font-size: 0.9rem; }
        .card strong { font-size: 2rem; }
        .card small { color: var(--text-muted); font-size: 0.8rem; }

        .panels-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 18px;
        }

        .panel {
            background: var(--panel);
            border: 1px solid var(--panel-border);
            border-radius: 18px;
            padding: 20px;
            min-height: 280px;
        }

        .panel h3 {
            margin-top: 0;
            margin-bottom: 12px;
            font-size: 1.1rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }

        th, td {
            padding: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }

        th { text-align: left; color: var(--text-muted); font-weight: 500; }

        tbody tr:last-child td { border-bottom: none; }

        .surface-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
        }

        .surface-tile {
            border: 1px solid var(--panel-border);
            border-radius: 14px;
            padding: 16px;
            background: rgba(255, 255, 255, 0.02);
        }

        .surface-tile small { color: var(--text-muted); display: block; margin-bottom: 6px; }

        .alert {
            padding: 12px;
            border-radius: 10px;
            background: rgba(255, 123, 114, 0.1);
            border: 1px solid rgba(255, 123, 114, 0.35);
            color: #ffb4ac;
            display: none;
        }

        .alert.show { display: block; }

        .table-scroll { overflow-x: auto; }

        @media (max-width: 640px) {
            body { padding: 18px 12px; }
            .hero header { flex-direction: column; align-items: flex-start; }
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <section class="hero">
            <header>
                <div>
                    <h1>🛡️ ASIR VPS Defense</h1>
                    <p style="margin:0;color:var(--text-muted);">Centro de mando reforzado para el WAF + Gateway</p>
                </div>
                <div style="text-align:right;">
                    <div>Hola, <strong><?= htmlspecialchars($_SESSION['username']) ?></strong></div>
                    <span class="badge badge-<?= htmlspecialchars($_SESSION['role']) ?>"><?= htmlspecialchars($_SESSION['role']) ?></span><br>
                    <a href="?logout=1" style="color: var(--accent); text-decoration: none; font-size: 0.9rem;">Cerrar sesión</a>
                </div>
            </header>
            <div>
                <span class="status-pill">● Operativo · Modo Fortaleza</span>
            </div>
            <small style="color:var(--text-muted);">Última sincronización: <span id="lastRefresh">--</span></small>
        </section>

        <div id="metricsError" class="alert">No se pudo actualizar la telemetría.</div>

        <section class="cards-grid">
            <div class="card">
                <span class="label">Ataques (últimos 5 min)</span>
                <strong id="total5m">--</strong>
            </div>
            <div class="card">
                <span class="label">Ataques (última hora)</span>
                <strong id="total1h">--</strong>
            </div>
            <div class="card">
                <span class="label">Ataques (24 horas)</span>
                <strong id="total24h">--</strong>
            </div>
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
        </section>

        <section class="panels-grid">
            <div class="panel">
                <h3>Intensidad por minuto</h3>
                <canvas id="trendChart" height="260"></canvas>
            </div>
            <div class="panel">
                <h3>Tipos de ataque detectados</h3>
                <canvas id="attackTypesChart" height="260"></canvas>
            </div>
        </section>

        <section class="panels-grid">
            <div class="panel">
                <h3>Origen geográfico (Top países)</h3>
                <canvas id="countryChart" height="260"></canvas>
            </div>
            <div class="panel">
                <h3>Superficies más presionadas</h3>
                <div id="surfaceGrid" class="surface-grid"></div>
            </div>
        </section>

        <section class="panels-grid">
            <div class="panel table-scroll">
                <h3>Top IP agresoras (última hora)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>País</th>
                            <th>Intentos</th>
                        </tr>
                    </thead>
                    <tbody id="topIpsBody"></tbody>
                </table>
            </div>
            <div class="panel table-scroll">
                <h3>Últimos bloqueos del WAF</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Fecha</th>
                            <th>IP</th>
                            <th>Tipo</th>
                            <th>Recurso</th>
                        </tr>
                    </thead>
                    <tbody id="eventsBody"></tbody>
                </table>
            </div>
        </section>

        <section class="panels-grid">
            <div class="panel table-scroll">
                <h3>Top IP baneadas (Fail2Ban)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>País</th>
                            <th>Eventos</th>
                        </tr>
                    </thead>
                    <tbody id="banIpsBody"></tbody>
                </table>
            </div>
            <div class="panel table-scroll">
                <h3>Baneos recientes (Fail2Ban)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Fecha</th>
                            <th>Jail</th>
                            <th>Origen</th>
                        </tr>
                    </thead>
                    <tbody id="banEventsBody"></tbody>
                </table>
            </div>
        </section>

        <section class="panels-grid">
            <div class="panel">
                <h3>Jails más activas</h3>
                <div id="jailGrid" class="surface-grid"></div>
            </div>
            <div class="panel table-scroll">
                <h3>Usuarios más atacados (SSH)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Usuario</th>
                            <th>Intentos</th>
                        </tr>
                    </thead>
                    <tbody id="sshUsersBody"></tbody>
                </table>
            </div>
        </section>

        <section class="panels-grid">
            <div class="panel table-scroll">
                <h3>Top IP ofensivas (SSH)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>País</th>
                            <th>Intentos</th>
                        </tr>
                    </thead>
                    <tbody id="sshIpsBody"></tbody>
                </table>
            </div>
            <div class="panel table-scroll">
                <h3>Intentos SSH recientes</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Fecha</th>
                            <th>Usuario</th>
                            <th>Origen</th>
                            <th>Resultado</th>
                        </tr>
                    </thead>
                    <tbody id="sshEventsBody"></tbody>
                </table>
            </div>
        </section>

        <section class="panel table-scroll">
            <h3>Registro de Auditoría Interna</h3>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Usuario</th>
                        <th>Acción</th>
                        <th>IP Origen</th>
                        <th>Fecha</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs as $log): ?>
                        <tr>
                            <td><?= htmlspecialchars($log['id']) ?></td>
                            <td><?= htmlspecialchars($log['username'] ?? 'Anónimo') ?></td>
                            <td><?= htmlspecialchars($log['action']) ?></td>
                            <td><?= htmlspecialchars($log['ip_address']) ?></td>
                            <td><?= htmlspecialchars($log['created_at']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </section>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const charts = {};

        const palette = ['#2de0c5', '#ff7b72', '#ffd166', '#5a6cea', '#9c6bff', '#4ad3ff'];

        const initCharts = () => {
            const trendCtx = document.getElementById('trendChart').getContext('2d');
            charts.trend = new Chart(trendCtx, {
                type: 'line',
                data: { labels: [], datasets: [{ label: 'Bloqueos/min', data: [], borderColor: '#2de0c5', backgroundColor: 'rgba(45,224,197,0.2)', tension: 0.35, fill: true }] },
                options: { plugins: { legend: { display: false } }, scales: { x: { ticks: { color: 'rgba(255,255,255,0.6)' } }, y: { ticks: { color: 'rgba(255,255,255,0.6)' }, beginAtZero: true } } }
            });

            charts.attackTypes = new Chart(document.getElementById('attackTypesChart'), {
                type: 'doughnut',
                data: { labels: [], datasets: [{ data: [], backgroundColor: palette }] },
                options: { plugins: { legend: { position: 'bottom', labels: { color: 'rgba(255,255,255,0.8)' } } } }
            });

            charts.countries = new Chart(document.getElementById('countryChart'), {
                type: 'polarArea',
                data: { labels: [], datasets: [{ data: [], backgroundColor: palette }] },
                options: { scales: { r: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { display: false } } }, plugins: { legend: { position: 'bottom', labels: { color: 'rgba(255,255,255,0.8)' } } } }
            });
        };

        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) { el.textContent = value; }
        };

        const formatTs = (ts) => new Date(ts * 1000).toLocaleString('es-ES');

        const updateTiles = (containerId, items) => {
            const grid = document.getElementById(containerId);
            if (!grid) return;
            grid.innerHTML = '';
            if (!items || !items.length) {
                grid.innerHTML = '<div class="surface-tile"><small>Sin datos</small><strong>0</strong></div>';
                return;
            }
            items.forEach((item) => {
                const tile = document.createElement('div');
                tile.className = 'surface-tile';
                tile.innerHTML = `<small>${item.label}</small><strong>${item.count}</strong>`;
                grid.appendChild(tile);
            });
        };

        const updateTable = (tbodyId, rows, columns = 4) => {
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
                cols.forEach((value) => {
                    const td = document.createElement('td');
                    td.textContent = value;
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });
        };

        const refreshMetrics = async () => {
            try {
                const res = await fetch('?action=metrics');
                const data = await res.json();
                if (!res.ok || data.error) {
                    document.getElementById('metricsError').classList.add('show');
                    return;
                }

                document.getElementById('metricsError').classList.remove('show');

                setText('total5m', data.totals.last5m ?? 0);
                setText('total1h', data.totals.last1h ?? 0);
                setText('total24h', data.totals.last24h ?? 0);

                const fail2banTotals = (data.fail2ban && data.fail2ban.totals) || {};
                setText('fail2ban24h', fail2banTotals.last24h ?? 0);
                setText('fail2ban1h', fail2banTotals.last1h ?? 0);

                const sshTotals = (data.ssh && data.ssh.totals) || {};
                setText('ssh1h', sshTotals.last1h ?? 0);
                setText('ssh5m', sshTotals.last5m ?? 0);

                setText('lastRefresh', new Date((data.generatedAt ?? Date.now()/1000) * 1000).toLocaleTimeString('es-ES'));

                charts.trend.data.labels = data.trend.map((entry) => new Date(entry.ts).toLocaleTimeString('es-ES', { minute: '2-digit', second: '2-digit' }));
                charts.trend.data.datasets[0].data = data.trend.map((entry) => entry.value);
                charts.trend.update('none');

                charts.attackTypes.data.labels = data.attackTypes.map((item) => item.label);
                charts.attackTypes.data.datasets[0].data = data.attackTypes.map((item) => item.count);
                charts.attackTypes.update('none');

                charts.countries.data.labels = data.countries.map((item) => `${item.label} (${item.count})`);
                charts.countries.data.datasets[0].data = data.countries.map((item) => item.count);
                charts.countries.update('none');

                updateTiles('surfaceGrid', data.surfaces);
                updateTiles('jailGrid', (data.fail2ban && data.fail2ban.topJails) || []);

                updateTable('topIpsBody', (data.topIps || []).map((row) => [row.ip, `${row.country} (${row.country_code})`, row.count]), 3);

                updateTable('eventsBody', (data.events || []).map((row) => [formatTs(row.timestamp), `${row.ip} · ${row.country_code}`, row.attack_type, row.surface]), 4);

                updateTable('banIpsBody', ((data.fail2ban && data.fail2ban.topIps) || []).map((row) => [row.ip, `${row.country} (${row.country_code})`, row.count]), 3);

                updateTable('banEventsBody', ((data.fail2ban && data.fail2ban.events) || []).map((row) => [formatTs(row.timestamp), row.jail, `${row.ip} · ${row.country_code}`]), 3);

                updateTable('sshUsersBody', ((data.ssh && data.ssh.topUsers) || []).map((row) => [row.label, row.count]), 2);

                updateTable('sshIpsBody', ((data.ssh && data.ssh.topIps) || []).map((row) => [row.ip, `${row.country} (${row.country_code})`, row.count]), 3);

                updateTable('sshEventsBody', ((data.ssh && data.ssh.events) || []).map((row) => [formatTs(row.timestamp), row.username, `${row.ip} · ${row.country_code}`, row.result]), 4);
            } catch (error) {
                document.getElementById('metricsError').classList.add('show');
            }
        };

        initCharts();
        refreshMetrics();
        setInterval(refreshMetrics, 5000);
    </script>
</body>
</html>
