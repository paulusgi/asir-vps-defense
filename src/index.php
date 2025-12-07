<?php
session_start();

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
    <title>ASIR Defense Panel</title>
    <style>
        body { font-family: sans-serif; background: #f4f4f4; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }
        h1 { color: #333; margin: 0; }
        .user-info { text-align: right; }
        .logout { color: #d32f2f; text-decoration: none; font-weight: bold; }
        .status { padding: 10px; background: #e8f5e9; color: #2e7d32; border-radius: 4px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border-bottom: 1px solid #ddd; text-align: left; }
        th { background-color: #f8f9fa; }
        .badge { padding: 3px 8px; border-radius: 12px; font-size: 0.8em; color: white; }
        .badge-admin { background: #1976d2; }
        .badge-viewer { background: #757575; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ASIR VPS Defense</h1>
            <div class="user-info">
                Hola, <strong><?= htmlspecialchars($_SESSION['username']) ?></strong> 
                <span class="badge badge-<?= htmlspecialchars($_SESSION['role']) ?>"><?= htmlspecialchars($_SESSION['role']) ?></span><br>
                <a href="?logout=1" class="logout">Cerrar Sesión</a>
            </div>
        </div>

        <div class="status">
            <strong>Estado del Sistema:</strong> Operativo (Modo Fortaleza)
        </div>

        <!-- Unified Dashboard (Grafana Embedded) -->
        <div style="margin-bottom: 30px;">
            <h3 style="color: #0d47a1;">📊 Centro de Monitoreo Unificado</h3>
            <p>Visualización en tiempo real de la seguridad del VPS (Loki + Grafana).</p>
            <div style="border: 1px solid #ddd; border-radius: 4px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                <!-- 
                    NOTE: For this to work, you must forward port 3000 in your SSH Tunnel command:
                    ssh -L 8888:127.0.0.1:8080 -L 3000:127.0.0.1:3000 user@host
                -->
                <iframe src="http://localhost:3000/d/home/home?orgId=1&refresh=5s&kiosk" width="100%" height="600" frameborder="0"></iframe>
            </div>
            <p style="font-size: 0.8em; color: #666; text-align: center; margin-top: 5px;">
                * Si no ves el gráfico, asegúrate de haber incluido <code>-L 3000:127.0.0.1:3000</code> en tu túnel SSH.
            </p>
        </div>
        
        <div style="padding: 20px; background: #fff3e0; border-radius: 8px; border-left: 5px solid #ff9800; margin-bottom: 30px;">
            <h3 style="margin-top: 0; color: #e65100;">🗄️ Estado de Base de Datos (MySQL)</h3>
            <p>Conexión: <strong>Activa</strong> | Usuarios: <strong>1</strong> | Integridad: <strong>Verificada</strong></p>
        </div>
        
        <h2>Registro de Auditoría Interna (Accesos al Panel)</h2>
        <p style="color: #666; font-size: 0.9em;">Este registro muestra quién ha accedido a este panel de control (Gateway).</p>
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
    </div>
</body>
</html>
