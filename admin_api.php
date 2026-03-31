<?php
// ─────────────────────────────────────────────────────────────────
//  ECHELBEE — Admin API (standalone, no DB auth needed)
//  Hardcoded credentials, session-based token, visitor analytics
// ─────────────────────────────────────────────────────────────────

// ── Credentials ──────────────────────────────────────────────────
define('ADMIN_USERNAME', 'echelbee');        // case-insensitive match
define('ADMIN_PASSWORD', 'Echelbee@2026');
define('SUPPORT_EMAIL',  'support@echelbee.in');
define('FROM_EMAIL',     'noreply@echelbee.in');

// ── Headers ──────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Admin-Token');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

// ── Helpers ──────────────────────────────────────────────────────
function resp(int $code, array $data): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function body(): array {
    return json_decode(file_get_contents('php://input'), true) ?? [];
}

// ── Token storage (file-based, no DB needed) ─────────────────────
$TOKEN_FILE = sys_get_temp_dir() . '/eb_admin_sessions.json';

function loadTokens(string $file): array {
    if (!file_exists($file)) return [];
    $data = @json_decode(file_get_contents($file), true);
    if (!is_array($data)) return [];
    // prune expired
    $now = time();
    return array_filter($data, fn($t) => $t['exp'] > $now);
}
function saveTokens(string $file, array $tokens): void {
    file_put_contents($file, json_encode(array_values($tokens)));
}
function generateToken(): string {
    return bin2hex(random_bytes(32));
}

// ── DB ───────────────────────────────────────────────────────────
function getDB(): PDO {
    static $pdo = null;
    if ($pdo) return $pdo;
    $pdo = new PDO(
        "mysql:host=localhost;dbname=echela83_fms;charset=utf8mb4",
        'echela83_kb_admin', 'Online2025',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
    // Ensure visitor_logs table exists
    $pdo->exec("CREATE TABLE IF NOT EXISTS visitor_logs (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        ip           VARCHAR(45)      NOT NULL,
        country      VARCHAR(100)     DEFAULT '',
        country_code VARCHAR(5)       DEFAULT '',
        region       VARCHAR(100)     DEFAULT '',
        city         VARCHAR(100)     DEFAULT '',
        isp          VARCHAR(250)     DEFAULT '',
        lat          DECIMAL(9,6)     DEFAULT NULL,
        lon          DECIMAL(9,6)     DEFAULT NULL,
        device       VARCHAR(50)      DEFAULT 'Unknown',
        browser      VARCHAR(100)     DEFAULT 'Unknown',
        os           VARCHAR(100)     DEFAULT 'Unknown',
        user_agent   TEXT,
        page         VARCHAR(500)     DEFAULT '/',
        referrer     VARCHAR(500)     DEFAULT '',
        visited_at   DATETIME         DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_ip   (ip),
        INDEX idx_time (visited_at),
        INDEX idx_cc   (country_code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    return $pdo;
}

// ── Auth middleware ───────────────────────────────────────────────
function requireToken(string $tokenFile): void {
    $token = $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? ($_GET['token'] ?? '');
    if (!$token) resp(401, ['error' => 'No token']);
    $tokens = loadTokens($tokenFile);
    $valid = array_filter($tokens, fn($t) => $t['token'] === $token);
    if (empty($valid)) resp(401, ['error' => 'Invalid or expired session']);
}

// ── Route ────────────────────────────────────────────────────────
$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

// ── LOGIN ────────────────────────────────────────────────────────
if ($action === 'login' && $method === 'POST') {
    $b    = body();
    $user = trim($b['username'] ?? '');
    $pass = trim($b['password'] ?? '');

    if (strtolower($user) !== ADMIN_USERNAME) {
        resp(401, ['error' => 'Invalid username or password']);
    }
    if ($pass !== ADMIN_PASSWORD) {
        resp(401, ['error' => 'Invalid username or password']);
    }

    $token   = generateToken();
    $exp     = time() + (12 * 3600); // 12 hours
    $tokens  = loadTokens($TOKEN_FILE);
    $tokens[] = ['token' => $token, 'exp' => $exp];
    saveTokens($TOKEN_FILE, $tokens);

    resp(200, ['token' => $token, 'expires_in' => 43200]);
}

// ── FORGOT PASSWORD ──────────────────────────────────────────────
if ($action === 'forgot' && $method === 'POST') {
    $subject = 'Echelbee Admin — Password Reset Request';
    $message = "
    <html><body style='font-family:Arial,sans-serif;color:#333;'>
      <div style='max-width:500px;margin:0 auto;padding:30px;'>
        <div style='background:#0066FF;padding:20px;border-radius:8px 8px 0 0;text-align:center;'>
          <h2 style='color:#fff;margin:0;'>Ech El Bee — Admin Access</h2>
        </div>
        <div style='background:#f5f7fa;padding:24px;border-radius:0 0 8px 8px;'>
          <p>A password reset was requested for the admin panel.</p>
          <p>Your admin credentials are:</p>
          <div style='background:#fff;border-left:4px solid #0066FF;padding:12px 16px;margin:16px 0;'>
            <strong>Username:</strong> Echelbee<br>
            <strong>Password:</strong> Echelbee@2026
          </div>
          <p style='color:#999;font-size:12px;'>If you did not request this, please ignore this email.<br>
          Admin panel URL: www.echelbee.in/admin.html</p>
        </div>
        <p style='text-align:center;font-size:11px;color:#aaa;margin-top:16px;'>
          Ech El Bee · 299 Basement, Mandir Marg, Jaipur
        </p>
      </div>
    </body></html>";

    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-type: text/html; charset=UTF-8\r\n";
    $headers .= "From: Ech El Bee <" . FROM_EMAIL . ">\r\n";
    $headers .= "X-Mailer: PHP/" . phpversion();

    $sent = mail(SUPPORT_EMAIL, $subject, $message, $headers);
    resp($sent ? 200 : 500, ['ok' => $sent, 'message' => $sent
        ? 'Reset details sent to ' . SUPPORT_EMAIL
        : 'Mail sending failed — please contact hosting support'
    ]);
}

// ── LOGOUT ───────────────────────────────────────────────────────
if ($action === 'logout' && $method === 'POST') {
    $token  = $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? '';
    $tokens = loadTokens($TOKEN_FILE);
    $tokens = array_filter($tokens, fn($t) => $t['token'] !== $token);
    saveTokens($TOKEN_FILE, $tokens);
    resp(200, ['ok' => true]);
}

// ── All below require valid token ────────────────────────────────
requireToken($TOKEN_FILE);

// ── STATS + LOGS ─────────────────────────────────────────────────
if ($action === 'data' && $method === 'GET') {
    $pdo     = getDB();
    $limit   = min((int)($_GET['limit']  ?? 100), 500);
    $offset  = (int)($_GET['offset'] ?? 0);
    $from    = $_GET['from']    ?? null;
    $to      = $_GET['to']      ?? null;
    $search  = $_GET['search']  ?? '';

    // ── Summary stats ─────────────────────────────────────────
    $stats = $pdo->query("
        SELECT
            COUNT(*)                                                        AS total_visits,
            COUNT(DISTINCT ip)                                              AS unique_ips,
            COUNT(DISTINCT country_code)                                    AS countries,
            SUM(DATE(visited_at) = CURDATE())                               AS today,
            SUM(DATE(visited_at) >= DATE_SUB(CURDATE(), INTERVAL 7 DAY))   AS last_7d,
            SUM(DATE(visited_at) >= DATE_SUB(CURDATE(), INTERVAL 30 DAY))  AS last_30d
        FROM visitor_logs
    ")->fetch();

    // ── Top countries ─────────────────────────────────────────
    $top_countries = $pdo->query("
        SELECT country, country_code, COUNT(*) AS visits
        FROM visitor_logs
        WHERE country != '' AND country != 'Unknown'
        GROUP BY country, country_code ORDER BY visits DESC LIMIT 10
    ")->fetchAll();

    // ── Top pages ─────────────────────────────────────────────
    $top_pages = $pdo->query("
        SELECT page, COUNT(*) AS visits
        FROM visitor_logs GROUP BY page ORDER BY visits DESC LIMIT 10
    ")->fetchAll();

    // ── Devices ───────────────────────────────────────────────
    $devices = $pdo->query("
        SELECT device, COUNT(*) AS count FROM visitor_logs GROUP BY device
    ")->fetchAll();

    // ── Daily last 30 days ────────────────────────────────────
    $daily = $pdo->query("
        SELECT DATE(visited_at) AS date, COUNT(*) AS visits
        FROM visitor_logs
        WHERE visited_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY DATE(visited_at) ORDER BY date ASC
    ")->fetchAll();

    // ── Hourly today ──────────────────────────────────────────
    $hourly = $pdo->query("
        SELECT HOUR(visited_at) AS hour, COUNT(*) AS visits
        FROM visitor_logs WHERE DATE(visited_at) = CURDATE()
        GROUP BY HOUR(visited_at) ORDER BY hour ASC
    ")->fetchAll();

    // ── Filtered logs ─────────────────────────────────────────
    $where = []; $params = [];
    if ($from)   { $where[] = "visited_at >= ?"; $params[] = $from.' 00:00:00'; }
    if ($to)     { $where[] = "visited_at <= ?"; $params[] = $to.' 23:59:59'; }
    if ($search) {
        $like = "%$search%";
        $where[] = "(ip LIKE ? OR country LIKE ? OR city LIKE ? OR browser LIKE ? OR page LIKE ? OR os LIKE ?)";
        array_push($params, $like, $like, $like, $like, $like, $like);
    }
    $wq = $where ? 'WHERE '.implode(' AND ', $where) : '';

    $total_q = $pdo->prepare("SELECT COUNT(*) FROM visitor_logs $wq");
    $total_q->execute($params);
    $total_rows = (int)$total_q->fetchColumn();

    $rows_q = $pdo->prepare("
        SELECT id, ip, country, country_code, region, city, isp,
               device, browser, os, page, referrer, visited_at
        FROM visitor_logs $wq
        ORDER BY visited_at DESC LIMIT $limit OFFSET $offset
    ");
    $rows_q->execute($params);
    $logs = $rows_q->fetchAll();

    resp(200, [
        'stats'         => $stats,
        'top_countries' => $top_countries,
        'top_pages'     => $top_pages,
        'devices'       => $devices,
        'daily'         => $daily,
        'hourly'        => $hourly,
        'logs'          => $logs,
        'total_rows'    => $total_rows,
    ]);
}

// ── DELETE log ───────────────────────────────────────────────────
if ($action === 'delete' && $method === 'POST') {
    $b  = body();
    $id = (int)($b['id'] ?? 0);
    if (!$id) resp(400, ['error' => 'ID required']);
    getDB()->prepare("DELETE FROM visitor_logs WHERE id=?")->execute([$id]);
    resp(200, ['ok' => true]);
}

// ── PURGE all logs ───────────────────────────────────────────────
if ($action === 'purge' && $method === 'POST') {
    getDB()->exec("TRUNCATE TABLE visitor_logs");
    resp(200, ['ok' => true]);
}

resp(404, ['error' => 'Unknown action']);
