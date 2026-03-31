<?php
// ─────────────────────────────────────────────
//  ECHELBEE — Visitor Tracker
//  Called silently from index.html on every page load
// ─────────────────────────────────────────────

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST')    { http_response_code(405); exit; }

// ── DB ────────────────────────────────────────
try {
    $pdo = new PDO("mysql:host=localhost;dbname=echela83_fms;charset=utf8mb4",
        'echela83_kb_admin', 'Online2025',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    http_response_code(500); echo json_encode(['error' => 'db']); exit;
}

// ── Create table if missing ───────────────────
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

// ── Get real IP ───────────────────────────────
$ip = '';
foreach (['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'] as $k) {
    if (!empty($_SERVER[$k])) { $ip = trim(explode(',', $_SERVER[$k])[0]); break; }
}
if (!$ip) { echo json_encode(['ok' => false]); exit; }

// ── Parse body ───────────────────────────────
$body     = json_decode(file_get_contents('php://input'), true) ?? [];
$page     = substr($body['page']     ?? '/', 0, 500);
$referrer = substr($body['referrer'] ?? '',  0, 500);
$ua       = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500);

// ── Geo lookup via ip-api.com (free, 45 req/min) ──
$geo = [];
// Skip private/loopback IPs
if (!preg_match('/^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/', $ip)) {
    $ctx = stream_context_create(['http' => ['timeout' => 3, 'ignore_errors' => true]]);
    $raw = @file_get_contents("http://ip-api.com/json/{$ip}?fields=status,country,countryCode,regionName,city,isp,lat,lon", false, $ctx);
    if ($raw) { $g = json_decode($raw, true); if (($g['status']??'') === 'success') $geo = $g; }
}

// ── Detect device / browser / OS ─────────────
function detectDevice(string $ua): string {
    if (preg_match('/iPad/i', $ua))            return 'Tablet';
    if (preg_match('/Tablet/i', $ua))          return 'Tablet';
    if (preg_match('/Mobile|Android|iPhone|iPod/i', $ua)) return 'Mobile';
    return 'Desktop';
}
function detectBrowser(string $ua): string {
    if (preg_match('/Edg\/(\d+)/i',     $ua, $m)) return 'Edge '.$m[1];
    if (preg_match('/OPR\/(\d+)/i',     $ua, $m)) return 'Opera '.$m[1];
    if (preg_match('/Chrome\/(\d+)/i',  $ua, $m)) return 'Chrome '.$m[1];
    if (preg_match('/Firefox\/(\d+)/i', $ua, $m)) return 'Firefox '.$m[1];
    if (preg_match('/Safari\/(\d+)/i',  $ua, $m)) return 'Safari';
    if (preg_match('/MSIE (\d+)/i',     $ua, $m)) return 'IE '.$m[1];
    return 'Other';
}
function detectOS(string $ua): string {
    if (preg_match('/Windows NT 10/i', $ua)) return 'Windows 10/11';
    if (preg_match('/Windows NT/i',    $ua)) return 'Windows';
    if (preg_match('/iPhone|iPad/i',   $ua)) return 'iOS';
    if (preg_match('/Android/i',       $ua)) return 'Android';
    if (preg_match('/Mac OS X/i',      $ua)) return 'macOS';
    if (preg_match('/Linux/i',         $ua)) return 'Linux';
    return 'Unknown';
}

// ── Insert ────────────────────────────────────
$stmt = $pdo->prepare("INSERT INTO visitor_logs
    (ip, country, country_code, region, city, isp, lat, lon, device, browser, os, user_agent, page, referrer)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");

$stmt->execute([
    $ip,
    $geo['country']     ?? 'Unknown',
    $geo['countryCode'] ?? '',
    $geo['regionName']  ?? '',
    $geo['city']        ?? '',
    $geo['isp']         ?? '',
    isset($geo['lat'])  ? (float)$geo['lat'] : null,
    isset($geo['lon'])  ? (float)$geo['lon'] : null,
    detectDevice($ua),
    detectBrowser($ua),
    detectOS($ua),
    $ua,
    $page,
    $referrer,
]);

echo json_encode(['ok' => true, 'id' => $pdo->lastInsertId()]);
