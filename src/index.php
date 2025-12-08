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
        small { display: block; text-align: center; color: #94a3b8; }
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
            --panel-border: rgba(255,255,255,0.07);
            --text: #e8eef9;
            --text-muted: #94a3b8;
            --accent: #10b981;
            --accent-warm: #f59e0b;
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background: radial-gradient(circle at 15% 20%, rgba(16,185,129,0.12), transparent 32%), radial-gradient(circle at 80% 0%, rgba(59,130,246,0.12), transparent 30%), var(--bg); color: var(--text); padding: 24px; }
        a { color: var(--accent); }
        .dashboard { max-width: 1200px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
        header { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
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
        .pager { display: flex; gap: 8px; align-items: center; margin-top: 8px; color: var(--text-muted); font-size: 0.9rem; }
        .pager button { background: #111827; color: var(--text); border: 1px solid var(--panel-border); border-radius: 8px; padding: 6px 10px; cursor: pointer; }
        .badge-result { padding: 4px 8px; border-radius: 10px; font-size: 0.85rem; }
        .badge-result.ok { background: rgba(16,185,129,0.18); color: var(--accent); border: 1px solid rgba(16,185,129,0.35); }
        .badge-result.warn { background: rgba(245,158,11,0.18); color: var(--accent-warm); border: 1px solid rgba(245,158,11,0.35); }
        #geoMap { height: 340px; border-radius: 14px; border: 1px solid var(--panel-border); overflow: hidden; }
        @media (max-width: 720px) { header { flex-direction: column; align-items: flex-start; } body { padding: 18px 12px; } }
    </style>
</head>
<body>
    <div class="dashboard">
        <header>
            <div>
                <h1 style="margin:0;">🛡️ ASIR VPS Defense</h1>
                <div style="color:var(--text-muted);">Panel seguro · SSH + Fail2Ban</div>
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

        <div class="status-pill">● Operativo · Solo túnel SSH</div>
        <small style="color:var(--text-muted);">Última sincronización: <span id="lastRefresh">--</span></small>

        <div class="controls">
            <span>Auto-refresco:</span>
            <select id="refreshSelect">
                <option value="5000" selected>5s</option>
                <option value="15000">15s</option>
                <option value="60000">1m</option>
            </select>
            <button id="toggleRefresh">Pausar</button>
        </div>

        <div id="metricsError" class="alert">No se pudo actualizar la telemetría.</div>

        <section class="cards">
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
                <div class="pager" id="banPager"></div>
            </div>
        </section>

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
            <div class="pager" id="sshPager"></div>
        </section>

        <section class="panel">
            <h3>Mapa de actividad (últimos eventos)</h3>
            <div id="geoMap"></div>
        </section>

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

    <script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        };

        const formatTs = (ts) => new Date(ts * 1000).toLocaleString('es-ES');

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

        const paginate = (rows, page, size) => {
            const start = page * size;
            return rows.slice(start, start + size);
        };

        const renderPager = (pagerId, total, page, size, onChange) => {
            const pager = document.getElementById(pagerId);
            if (!pager) return;
            const pages = Math.max(1, Math.ceil(total / size));
            pager.innerHTML = '';
            const info = document.createElement('span');
            info.textContent = `Página ${page + 1}/${pages}`;
            const prev = document.createElement('button');
            prev.textContent = '◀';
            prev.disabled = page === 0;
            prev.onclick = () => onChange(Math.max(0, page - 1));
            const next = document.createElement('button');
            next.textContent = '▶';
            next.disabled = page >= pages - 1;
            next.onclick = () => onChange(Math.min(pages - 1, page + 1));
            pager.append(prev, info, next);
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

        let state = {
            banEvents: [],
            sshEvents: [],
            banIps: [],
            sshIps: [],
            sshUsers: [],
            geo: [],
        };

        let failureCount = 0; // track consecutive failures to avoid flashing the alert

        let pages = { ban: 0, ssh: 0 };
        const PAGE_SIZE = 10;

        let refreshMs = 5000;
        let refreshTimer = null;
        const startRefresh = () => {
            if (refreshTimer) clearInterval(refreshTimer);
            refreshTimer = setInterval(refreshMetrics, refreshMs);
        };

        const refreshMetrics = async () => {
            try {
                const res = await fetch('?action=metrics');
                const data = await res.json();
                if (!res.ok || data.error) {
                    failureCount++;
                    if (failureCount >= 2) {
                        document.getElementById('metricsError').classList.add('show');
                    }
                    return;
                }

                failureCount = 0;
                document.getElementById('metricsError').classList.remove('show');

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
                state.geo = (data.geo || []).map((p) => ({
                    lat: p.lat,
                    lon: p.lon,
                    ip: p.ip,
                    country: p.country,
                    code: p.country_code,
                    type: p.type,
                }));

                updateTable('banIpsBody', state.banIps, 3);
                const banPageRows = paginate(state.banEvents, pages.ban, PAGE_SIZE);
                updateTable('banEventsBody', banPageRows, 3);
                renderPager('banPager', state.banEvents.length, pages.ban, PAGE_SIZE, (p) => {
                    pages.ban = p;
                    updateTable('banEventsBody', paginate(state.banEvents, pages.ban, PAGE_SIZE), 3);
                    renderPager('banPager', state.banEvents.length, pages.ban, PAGE_SIZE, () => {});
                });

                updateTable('sshIpsBody', state.sshIps, 3);
                updateTable('sshUsersBody', state.sshUsers, 2);
                const sshPageRows = paginate(state.sshEvents, pages.ssh, PAGE_SIZE);
                updateTable('sshEventsBody', sshPageRows, 4, [3]);
                renderPager('sshPager', state.sshEvents.length, pages.ssh, PAGE_SIZE, (p) => {
                    pages.ssh = p;
                    updateTable('sshEventsBody', paginate(state.sshEvents, pages.ssh, PAGE_SIZE), 4, [3]);
                    renderPager('sshPager', state.sshEvents.length, pages.ssh, PAGE_SIZE, () => {});
                });

                renderMap(state.geo);
            } catch (e) {
                failureCount++;
                if (failureCount >= 2) {
                    document.getElementById('metricsError').classList.add('show');
                }
            }
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
        };

        document.getElementById('refreshSelect').addEventListener('change', (e) => {
            refreshMs = Number(e.target.value) || 5000;
            startRefresh();
        });

        document.getElementById('toggleRefresh').addEventListener('click', (e) => {
            if (refreshTimer) {
                clearInterval(refreshTimer);
                refreshTimer = null;
                e.target.textContent = 'Reanudar';
            } else {
                e.target.textContent = 'Pausar';
                startRefresh();
            }
        });

        refreshMetrics();
        startRefresh();
    </script>
</body>
</html>
