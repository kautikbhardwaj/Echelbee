<?php
// ─────────────────────────────────────────────────────────────────
//  ECHELBEE — Admin API v2
//  Token storage moved to MySQL (temp dir was not writable on cPanel)
// ─────────────────────────────────────────────────────────────────

define('ADMIN_USERNAME', 'echelbee');
define('ADMIN_PASSWORD', 'Echelbee@2026');
define('SUPPORT_EMAIL',  'support@echelbee.in');
define('FROM_EMAIL',     'noreply@echelbee.in');

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Admin-Token');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

function resp(int $code, array $data): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function body(): array {
    return json_decode(file_get_contents('php://input'), true) ?? [];
}

// ── DB connection + table bootstrap ──────────────────────────────
function getDB(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    try {
        $pdo = new PDO(
            "mysql:host=localhost;dbname=echela83_fms;charset=utf8mb4",
            'echela83_kb_admin', 'Online2025',
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
        );
    } catch (PDOException $e) {
        resp(500, ['error' => 'DB connection failed: ' . $e->getMessage()]);
    }

    // Admin sessions table — DB-backed, no temp file needed
    $pdo->exec("CREATE TABLE IF NOT EXISTS admin_sessions (
        token      VARCHAR(64)  PRIMARY KEY,
        expires_at DATETIME     NOT NULL,
        created_at DATETIME     DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Visitor logs table
    $pdo->exec("CREATE TABLE IF NOT EXISTS visitor_logs (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        ip           VARCHAR(45)  NOT NULL,
        country      VARCHAR(100) DEFAULT '',
        country_code VARCHAR(5)   DEFAULT '',
        region       VARCHAR(100) DEFAULT '',
        city         VARCHAR(100) DEFAULT '',
        isp          VARCHAR(250) DEFAULT '',
        lat          DECIMAL(9,6) DEFAULT NULL,
        lon          DECIMAL(9,6) DEFAULT NULL,
        device       VARCHAR(50)  DEFAULT 'Unknown',
        browser      VARCHAR(100) DEFAULT 'Unknown',
        os           VARCHAR(100) DEFAULT 'Unknown',
        user_agent   TEXT,
        page         VARCHAR(500) DEFAULT '/',
        referrer     VARCHAR(500) DEFAULT '',
        visited_at   DATETIME     DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_ip   (ip),
        INDEX idx_time (visited_at),
        INDEX idx_cc   (country_code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    return $pdo;
}

// ── Token helpers ─────────────────────────────────────────────────
function createToken(): string {
    $token = bin2hex(random_bytes(32));
    $exp   = date('Y-m-d H:i:s', strtotime('+12 hours'));
    $db    = getDB();
    $db->exec("DELETE FROM admin_sessions WHERE expires_at < NOW()");
    $db->prepare("INSERT INTO admin_sessions (token, expires_at) VALUES (?,?)")->execute([$token, $exp]);
    return $token;
}
function validateToken(string $token): bool {
    if (!$token) return false;
    $s = getDB()->prepare("SELECT token FROM admin_sessions WHERE token=? AND expires_at > NOW()");
    $s->execute([$token]);
    return (bool)$s->fetch();
}
function deleteToken(string $token): void {
    getDB()->prepare("DELETE FROM admin_sessions WHERE token=?")->execute([$token]);
}
function requireAuth(): void {
    $token = $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? ($_GET['token'] ?? '');
    if (!validateToken($token)) resp(401, ['error' => 'Invalid or expired session']);
}

$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

// ── LOGIN ─────────────────────────────────────────────────────────
if ($action === 'login' && $method === 'POST') {
    $b    = body();
    $user = trim($b['username'] ?? '');
    $pass = trim($b['password'] ?? '');
    if (strtolower($user) !== ADMIN_USERNAME || $pass !== ADMIN_PASSWORD) {
        usleep(400000);
        resp(401, ['error' => 'Invalid username or password']);
    }
    try {
        resp(200, ['token' => createToken(), 'expires_in' => 43200]);
    } catch (Exception $e) {
        resp(500, ['error' => 'Session error: ' . $e->getMessage()]);
    }
}

// ── FORGOT PASSWORD ───────────────────────────────────────────────
if ($action === 'forgot' && $method === 'POST') {
    $subject = 'Echelbee Admin — Login Credentials';
    $html = "<html><body style='font-family:Arial,sans-serif;background:#f5f7fa;padding:20px'>
      <div style='max-width:480px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden'>
        <div style='background:#0066FF;padding:24px;text-align:center'>
          <h2 style='color:#fff;margin:0'>Ech El Bee — Admin Panel</h2>
        </div>
        <div style='padding:28px'>
          <p style='color:#333'>Your admin credentials:</p>
          <div style='background:#f0f6ff;border-left:4px solid #0066FF;padding:14px 18px;margin:16px 0;border-radius:0 6px 6px 0'>
            <b style='color:#0066FF'>Username:</b> Echelbee<br><br>
            <b style='color:#0066FF'>Password:</b> Echelbee@2026
          </div>
          <p style='color:#666;font-size:13px'>Admin URL: <a href='https://www.echelbee.in/admin.html'>www.echelbee.in/admin.html</a></p>
        </div>
        <div style='background:#0A1929;padding:12px;text-align:center;font-size:11px;color:#aaa'>
          Ech El Bee · Durgapura, Jaipur
        </div>
      </div>
    </body></html>";

    $headers  = "MIME-Version: 1.0\r\nContent-type: text/html; charset=UTF-8\r\n";
    $headers .= "From: Ech El Bee <" . FROM_EMAIL . ">\r\nX-Mailer: PHP/" . phpversion();
    $sent = @mail(SUPPORT_EMAIL, $subject, $html, $headers);
    resp($sent ? 200 : 500, ['ok' => $sent, 'message' => $sent ? 'Credentials sent to ' . SUPPORT_EMAIL : 'Mail failed']);
}

// ── LOGOUT ────────────────────────────────────────────────────────
if ($action === 'logout' && $method === 'POST') {
    $token = $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? '';
    if ($token) deleteToken($token);
    resp(200, ['ok' => true]);
}

// ── Protected routes ──────────────────────────────────────────────
requireAuth();

// ── DATA ──────────────────────────────────────────────────────────
if ($action === 'data' && $method === 'GET') {
    $db     = getDB();
    $limit  = min((int)($_GET['limit']  ?? 100), 500);
    $offset = (int)($_GET['offset'] ?? 0);
    $from   = $_GET['from']   ?? null;
    $to     = $_GET['to']     ?? null;
    $search = $_GET['search'] ?? '';

    $stats = $db->query("SELECT
        COUNT(*) AS total_visits, COUNT(DISTINCT ip) AS unique_ips,
        COUNT(DISTINCT country_code) AS countries,
        SUM(DATE(visited_at)=CURDATE()) AS today,
        SUM(DATE(visited_at)>=DATE_SUB(CURDATE(),INTERVAL 7 DAY)) AS last_7d,
        SUM(DATE(visited_at)>=DATE_SUB(CURDATE(),INTERVAL 30 DAY)) AS last_30d
        FROM visitor_logs")->fetch();

    $top_countries = $db->query("SELECT country, country_code, COUNT(*) AS visits
        FROM visitor_logs WHERE country!='' AND country!='Unknown'
        GROUP BY country,country_code ORDER BY visits DESC LIMIT 10")->fetchAll();

    $top_pages = $db->query("SELECT page, COUNT(*) AS visits FROM visitor_logs
        GROUP BY page ORDER BY visits DESC LIMIT 10")->fetchAll();

    $devices = $db->query("SELECT device, COUNT(*) AS count FROM visitor_logs
        GROUP BY device ORDER BY count DESC")->fetchAll();

    $daily = $db->query("SELECT DATE(visited_at) AS date, COUNT(*) AS visits
        FROM visitor_logs WHERE visited_at>=DATE_SUB(NOW(),INTERVAL 30 DAY)
        GROUP BY DATE(visited_at) ORDER BY date ASC")->fetchAll();

    $hourly = $db->query("SELECT HOUR(visited_at) AS hour, COUNT(*) AS visits
        FROM visitor_logs WHERE DATE(visited_at)=CURDATE()
        GROUP BY HOUR(visited_at) ORDER BY hour ASC")->fetchAll();

    $where = []; $params = [];
    if ($from)   { $where[] = "visited_at >= ?"; $params[] = $from.' 00:00:00'; }
    if ($to)     { $where[] = "visited_at <= ?"; $params[] = $to.' 23:59:59'; }
    if ($search) {
        $like = "%$search%";
        $where[] = "(ip LIKE ? OR country LIKE ? OR city LIKE ? OR browser LIKE ? OR page LIKE ? OR os LIKE ? OR isp LIKE ?)";
        array_push($params, $like, $like, $like, $like, $like, $like, $like);
    }
    $wq = $where ? 'WHERE '.implode(' AND ',$where) : '';

    $c = $db->prepare("SELECT COUNT(*) FROM visitor_logs $wq"); $c->execute($params);
    $total_rows = (int)$c->fetchColumn();

    $q = $db->prepare("SELECT id,ip,country,country_code,region,city,isp,device,browser,os,page,referrer,visited_at
        FROM visitor_logs $wq ORDER BY visited_at DESC LIMIT $limit OFFSET $offset");
    $q->execute($params);

    resp(200, ['stats'=>$stats,'top_countries'=>$top_countries,'top_pages'=>$top_pages,
        'devices'=>$devices,'daily'=>$daily,'hourly'=>$hourly,'logs'=>$q->fetchAll(),'total_rows'=>$total_rows]);
}

// ── PURGE ─────────────────────────────────────────────────────────
if ($action === 'purge' && $method === 'POST') {
    getDB()->exec("TRUNCATE TABLE visitor_logs");
    resp(200, ['ok' => true]);
}

// ── DELETE single ─────────────────────────────────────────────────
if ($action === 'delete' && $method === 'POST') {
    $id = (int)(body()['id'] ?? 0);
    if (!$id) resp(400, ['error' => 'ID required']);
    getDB()->prepare("DELETE FROM visitor_logs WHERE id=?")->execute([$id]);
    resp(200, ['ok' => true]);
}

resp(404, ['error' => 'Unknown action: '.$action]);
