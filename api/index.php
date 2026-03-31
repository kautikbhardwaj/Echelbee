<?php
// ECH EL BEE FSM — REST API
// Credentials already set — just upload and go

define('DB_HOST', 'localhost');
define('DB_NAME', 'echela83_fms');
define('DB_USER', 'echela83_kb_admin');
define('DB_PASS', 'Online2025');
// ── ANTHROPIC KEY (for AI document scan) ─────────────────────
// Get your key from: https://console.anthropic.com/
define('ANTHROPIC_KEY', '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');

// CORS - allow web browsers, Android Capacitor app, and dev
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed = ['https://echelbee.in','https://www.echelbee.in','http://localhost:3000','capacitor://localhost','ionic://localhost'];
if ($origin && in_array($origin, $allowed)) {
    // Known origin — send with credentials allowed
    header("Access-Control-Allow-Origin: $origin");
    header('Access-Control-Allow-Credentials: true');
} else {
    // Unknown / no origin (Android app, Postman, etc) — use wildcard, no credentials header
    header('Access-Control-Allow-Origin: *');
}
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

// DB
try {
    $pdo = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=utf8mb4", DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    resp(500, ['error' => 'DB error: '.$e->getMessage()]);
}

// Helpers
function resp(int $code, array $data): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function body(): array {
    return json_decode(file_get_contents('php://input'), true) ?? [];
}
function uid(): string {
    return substr(bin2hex(random_bytes(6)), 0, 12);
}
function require_auth(PDO $pdo): array {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $token  = trim(str_replace('Bearer', '', $header));
    if (!$token) resp(401, ['error' => 'No token provided']);
    $stmt = $pdo->prepare("SELECT u.id,u.name,u.email,u.role FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=? AND s.expires_at>NOW() AND u.active=1");
    $stmt->execute([$token]);
    $user = $stmt->fetch();
    if (!$user) resp(401, ['error' => 'Invalid or expired session']);
    return $user;
}
function require_role(array $user, array $roles): void {
    if (!in_array($user['role'], $roles)) resp(403, ['error' => 'Permission denied']);
}

// Router — parse URL robustly
$method = $_SERVER['REQUEST_METHOD'];
$uri    = $_SERVER['REQUEST_URI'];

// Remove query string
$uri = strtok($uri, '?');

// Remove everything up to and including /api/
$uri = preg_replace('#^.*/api/?#', '', $uri);
$uri = trim($uri, '/');

$parts    = $uri ? explode('/', $uri) : [];
$resource = $parts[0] ?? '';
$seg2     = $parts[1] ?? '';
$id       = ($resource !== 'auth') ? $seg2 : null;

// ── AUTH ──────────────────────────────────────────────────────

if ($resource === 'auth' && $seg2 === 'login' && $method === 'POST') {
    $b        = body();
    $email    = trim($b['email']    ?? '');
    $password = trim($b['password'] ?? '');
    if (!$email || !$password) resp(400, ['error' => 'Email and password required']);

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email=? AND active=1");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    $ok = false;
    if ($user) {
        $stored = $user['password'];
        if (strpos($stored, 'PLAINTEXT:') === 0) {
            if ($password === substr($stored, 10)) {
                $ok = true;
                $pdo->prepare("UPDATE users SET password=? WHERE id=?")
                    ->execute([password_hash($password, PASSWORD_BCRYPT), $user['id']]);
            }
        } else {
            $ok = password_verify($password, $stored);
        }
    }
    if (!$ok) resp(401, ['error' => 'Invalid email or password']);

    $token   = bin2hex(random_bytes(32));
    $expires = date('Y-m-d H:i:s', strtotime('+30 days'));
    $pdo->prepare("INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)")->execute([$token, $user['id'], $expires]);
    $pdo->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$user['id']]);
    resp(200, ['token' => $token, 'user' => ['id'=>$user['id'],'name'=>$user['name'],'email'=>$user['email'],'role'=>$user['role']]]);
}

if ($resource === 'auth' && $seg2 === 'logout' && $method === 'POST') {
    $token = trim(str_replace('Bearer', '', $_SERVER['HTTP_AUTHORIZATION'] ?? ''));
    if ($token) $pdo->prepare("DELETE FROM sessions WHERE token=?")->execute([$token]);
    resp(200, ['message' => 'Logged out']);
}

if ($resource === 'auth' && $seg2 === 'me' && $method === 'GET') {
    resp(200, ['user' => require_auth($pdo)]);
}

// All routes below need auth
$user = require_auth($pdo);

// ── USERS ─────────────────────────────────────────────────────

if ($resource === 'users') {
    require_role($user, ['admin']);
    if ($method === 'GET' && !$id) {
        resp(200, $pdo->query("SELECT id,name,email,role,active,created_at,last_login FROM users ORDER BY name")->fetchAll());
    }
    if ($method === 'POST') {
        $b = body();
        if (!($b['name']??'') || !($b['email']??'') || !($b['password']??'')) resp(400, ['error' => 'name, email, password required']);
        $newId = 'usr_'.uid();
        $pdo->prepare("INSERT INTO users (id,name,email,password,role) VALUES (?,?,?,?,?)")
            ->execute([$newId, $b['name'], $b['email'], password_hash($b['password'], PASSWORD_BCRYPT), $b['role']??'engineer']);
        resp(201, ['id' => $newId]);
    }
    if ($method === 'PUT' && $id) {
        $b = body(); $fields = []; $vals = [];
        foreach (['name','email','role','active'] as $f) { if (isset($b[$f])) { $fields[] = "$f=?"; $vals[] = $b[$f]; } }
        if (!empty($b['password'])) { $fields[] = "password=?"; $vals[] = password_hash($b['password'], PASSWORD_BCRYPT); }
        if (!$fields) resp(400, ['error' => 'Nothing to update']);
        $vals[] = $id;
        $pdo->prepare("UPDATE users SET ".implode(',', $fields)." WHERE id=?")->execute($vals);
        resp(200, ['message' => 'Updated']);
    }
    if ($method === 'DELETE' && $id) {
        if ($id === $user['id']) resp(400, ['error' => 'Cannot delete yourself']);
        $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$id]);
        resp(200, ['message' => 'Deleted']);
    }
}

// ── MODELS ────────────────────────────────────────────────────

if ($resource === 'models') {
    if ($method === 'GET') {
        resp(200, $pdo->query("SELECT id,name FROM models ORDER BY name")->fetchAll());
    }
    if ($method === 'POST') {
        require_role($user, ['admin','engineer']);
        $b = body();
        if (!($b['name']??'')) resp(400, ['error' => 'name required']);
        try {
            $pdo->prepare("INSERT INTO models (name,created_by) VALUES (?,?)")->execute([trim($b['name']), $user['id']]);
            resp(201, ['id' => $pdo->lastInsertId(), 'name' => trim($b['name'])]);
        } catch (PDOException $e) { resp(409, ['error' => 'Model already exists']); }
    }
    if ($method === 'DELETE' && $id) {
        require_role($user, ['admin']);
        $pdo->prepare("DELETE FROM models WHERE id=?")->execute([$id]);
        resp(200, ['message' => 'Deleted']);
    }
}

// ── CUSTOMERS ─────────────────────────────────────────────────

if ($resource === 'customers') {
    if ($method === 'GET' && !$id) {
        $q = $_GET['q'] ?? '';
        if ($q) {
            $like = "%$q%";
            $stmt = $pdo->prepare("SELECT * FROM customers WHERE name LIKE ? OR tel LIKE ? OR email LIKE ? ORDER BY name");
            $stmt->execute([$like, $like, $like]);
        } else {
            $stmt = $pdo->query("SELECT * FROM customers ORDER BY name");
        }
        resp(200, $stmt->fetchAll());
    }
    if ($method === 'GET' && $id) {
        $stmt = $pdo->prepare("SELECT * FROM customers WHERE id=?");
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        if (!$row) resp(404, ['error' => 'Not found']);
        resp(200, $row);
    }
    if ($method === 'POST') {
        require_role($user, ['admin','engineer']);
        $b = body();
        if (!($b['name']??'')) resp(400, ['error' => 'name required']);
        $dup = $pdo->prepare("SELECT id FROM customers WHERE LOWER(name)=LOWER(?)");
        $dup->execute([trim($b['name'])]);
        if ($existing = $dup->fetch()) resp(200, ['id' => $existing['id'], 'existing' => true]);
        $newId = 'cus_'.uid();
        $pdo->prepare("INSERT INTO customers (id,name,address,tel,email,contact_person,key_operator,office_hours,weekly_off,created_by) VALUES (?,?,?,?,?,?,?,?,?,?)")
            ->execute([$newId,$b['name'],$b['address']??'',$b['tel']??'',$b['email']??'',$b['contactPerson']??'',$b['keyOperator']??'',$b['officeHours']??'',$b['weeklyOff']??'',$user['id']]);
        resp(201, ['id' => $newId]);
    }
    if ($method === 'PUT' && $id) {
        require_role($user, ['admin','engineer']);
        $b = body();
        $fields = "name=?,address=?,tel=?,email=?,contact_person=?,key_operator=?,office_hours=?,weekly_off=?";
        $vals   = [$b['name']??'',$b['address']??'',$b['tel']??'',$b['email']??'',$b['contactPerson']??'',$b['keyOperator']??'',$b['officeHours']??'',$b['weeklyOff']??''];
        // Admin can upload/update stamp image
        if (isset($b['stampImage'])) {
            $fields .= ",stamp_image=?";
            $vals[]  = $b['stampImage'] ?: null;
        }
        $vals[] = $id;
        $pdo->prepare("UPDATE customers SET $fields WHERE id=?")->execute($vals);
        resp(200, ['message' => 'Updated']);
    }
    if ($method === 'DELETE' && $id) {
        require_role($user, ['admin']);
        $pdo->prepare("DELETE FROM customers WHERE id=?")->execute([$id]);
        resp(200, ['message' => 'Deleted']);
    }
}

// ── MACHINES ──────────────────────────────────────────────────

if ($resource === 'machines') {
    if ($method === 'GET' && !$id) {
        $sql = "SELECT m.*,c.name as customer_name FROM machines m LEFT JOIN customers c ON m.customer_id=c.id WHERE 1=1";
        $params = [];
        if (!empty($_GET['status']))      { $sql .= " AND m.status=?";      $params[] = $_GET['status']; }
        if (!empty($_GET['customer_id'])) { $sql .= " AND m.customer_id=?"; $params[] = $_GET['customer_id']; }
        if (!empty($_GET['q']))           { $like="%{$_GET['q']}%"; $sql .= " AND (m.model LIKE ? OR m.mc_sl_no LIKE ? OR c.name LIKE ?)"; $params = array_merge($params,[$like,$like,$like]); }
        $sql .= " ORDER BY m.created_at DESC";
        $stmt = $pdo->prepare($sql); $stmt->execute($params);
        resp(200, $stmt->fetchAll());
    }
    if ($method === 'GET' && $id) {
        $stmt = $pdo->prepare("SELECT m.*,c.name as customer_name FROM machines m LEFT JOIN customers c ON m.customer_id=c.id WHERE m.id=?");
        $stmt->execute([$id]); $row = $stmt->fetch();
        if (!$row) resp(404, ['error' => 'Not found']);
        resp(200, $row);
    }
    if ($method === 'POST') {
        require_role($user, ['admin','engineer']);
        $b = body();
        if (!($b['customerId']??'')) resp(400, ['error' => 'customerId required']);
        if (!($b['model']??''))      resp(400, ['error' => 'model required']);
        $newId = 'mac_'.uid();
        // Handle photos array — store as JSON string
        $photosJson = null;
        if (!empty($b['photos']) && is_array($b['photos'])) {
            $photosJson = json_encode($b['photos']);
        }
        $pdo->prepare("INSERT INTO machines (id,customer_id,model,status,invoice_no,date,delivered_on,installed_on,warranty_expiry,warranty_copies,mc_sl_no,option_sl_no,mc_ip,mc_password,os,cvt,earthing,acc1,acc1_sl,acc2,acc2_sl,acc3,acc3_sl,acc4,acc4_sl,sol1,sol2,sol3,sol4,trained_name,trained_date,eng_name,eng_no,notes,created_by,gps_lat,gps_lng,signature,photos) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            ->execute([$newId,$b['customerId'],$b['model'],$b['status']??'installed',$b['invoiceNo']??'',$b['date']??null,$b['deliveredOn']??null,$b['installedOn']??null,$b['warrantyExpiry']??null,$b['warrantyCopies']??'',$b['mcSlNo']??'',$b['optionSlNo']??'',$b['mcIp']??'',$b['mcPassword']??'',$b['os']??'',$b['cvt']??'N',$b['earthing']??'N',$b['acc1']??'',$b['acc1sl']??'',$b['acc2']??'',$b['acc2sl']??'',$b['acc3']??'',$b['acc3sl']??'',$b['acc4']??'',$b['acc4sl']??'',$b['sol1']??'',$b['sol2']??'',$b['sol3']??'',$b['sol4']??'',$b['trainedName']??'',$b['trainedDate']??null,$b['engName']??'',$b['engNo']??'',$b['notes']??'',$user['id'],$b['gpsLat']??null,$b['gpsLng']??null,$b['signature']??null,$photosJson]);
        resp(201, ['id' => $newId]);
    }
    if ($method === 'PUT' && $id) {
        require_role($user, ['admin','engineer']);
        $b = body();
        $pdo->prepare("UPDATE machines SET status=?,mc_ip=?,mc_password=?,notes=?,return_date=? WHERE id=?")
            ->execute([$b['status']??'installed',$b['mcIp']??'',$b['mcPassword']??'',$b['notes']??'',$b['returnDate']??null,$id]);
        resp(200, ['message' => 'Updated']);
    }
    if ($method === 'DELETE' && $id) {
        require_role($user, ['admin']);
        $pdo->prepare("DELETE FROM machines WHERE id=?")->execute([$id]);
        resp(200, ['message' => 'Deleted']);
    }
}

// ── SERVICE CALLS ─────────────────────────────────────────────

if ($resource === 'service-calls') {
    if ($method === 'GET' && !$id) {
        $sql = "SELECT sc.*,c.name as customer_name,m.model as machine_model,m.mc_sl_no FROM service_calls sc LEFT JOIN customers c ON sc.customer_id=c.id LEFT JOIN machines m ON sc.machine_id=m.id WHERE 1=1";
        $params = [];
        if (!empty($_GET['customer_id'])) { $sql .= " AND sc.customer_id=?"; $params[] = $_GET['customer_id']; }
        if (!empty($_GET['machine_id']))  { $sql .= " AND sc.machine_id=?";  $params[] = $_GET['machine_id']; }
        if (!empty($_GET['q']))           { $like="%{$_GET['q']}%"; $sql .= " AND (c.name LIKE ? OR m.model LIKE ? OR sc.symptom LIKE ?)"; $params=array_merge($params,[$like,$like,$like]); }
        $sql .= " ORDER BY sc.created_at DESC";
        $stmt = $pdo->prepare($sql); $stmt->execute($params);
        $calls = $stmt->fetchAll();
        foreach ($calls as &$call) {
            $sp = $pdo->prepare("SELECT * FROM spare_parts WHERE service_call_id=?");
            $sp->execute([$call['id']]);
            $call['spareParts'] = $sp->fetchAll();
        }
        resp(200, $calls);
    }
    if ($method === 'GET' && $id) {
        $stmt = $pdo->prepare("SELECT sc.*,c.name as customer_name,m.model as machine_model FROM service_calls sc LEFT JOIN customers c ON sc.customer_id=c.id LEFT JOIN machines m ON sc.machine_id=m.id WHERE sc.id=?");
        $stmt->execute([$id]); $call = $stmt->fetch();
        if (!$call) resp(404, ['error' => 'Not found']);
        $sp = $pdo->prepare("SELECT * FROM spare_parts WHERE service_call_id=?");
        $sp->execute([$id]); $call['spareParts'] = $sp->fetchAll();
        resp(200, $call);
    }
    if ($method === 'POST') {
        require_role($user, ['admin','engineer']);
        $b = body();
        if (!($b['customerId']??'')) resp(400, ['error' => 'customerId required']);
        if (!($b['machineId']??''))  resp(400, ['error' => 'machineId required']);
        $newId = 'sc_'.uid();
        // Handle photos array — store as JSON string
        $photosJson = null;
        if (!empty($b['photos']) && is_array($b['photos'])) {
            $photosJson = json_encode($b['photos']);
        }
        $pdo->prepare("INSERT INTO service_calls (id,customer_id,machine_id,date,call_time,so_id,document_no,territory_code,contract_type,call_reason,inc_code,time_despatched,time_arrived,call_completed,sca_code,eng_tech_no,eng_name,symptom,cause,action,meter_total,mfp_cpr,mfp_fax,mfp_prp,mfp_cl_cpr,mfp_cl_fax,mfp_cl_prp,master_copies,billable,call_charges,tax_services,grand_total,notes,created_by,gps_lat,gps_lng,signature,photos) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            ->execute([$newId,$b['customerId'],$b['machineId'],$b['date']??null,$b['callTime']??null,$b['soId']??'',$b['documentNo']??'',$b['territoryCode']??'',$b['contractType']??'',$b['callReason']??'',$b['incCode']??'',$b['timeDespatched']??null,$b['timeArrived']??null,$b['callCompleted']??null,$b['scaCode']??'',$b['engTechNo']??'',$b['engName']??'',$b['symptom']??'',$b['cause']??'',$b['action']??'',$b['meterTotal']??'',$b['mfpCpr']??'',$b['mfpFax']??'',$b['mfpPrp']??'',$b['mfpClCpr']??'',$b['mfpClFax']??'',$b['mfpClPrp']??'',$b['masterCopies']??'',$b['billable']??0,$b['callCharges']??'',$b['taxServices']??'',$b['grandTotal']??'',$b['notes']??'',$user['id'],$b['gpsLat']??null,$b['gpsLng']??null,$b['signature']??null,$photosJson]);
        if (!empty($b['spareParts'])) {
            $sp = $pdo->prepare("INSERT INTO spare_parts (service_call_id,part_no,description,seo_no,qty_reqd,qty_used,unit_price) VALUES (?,?,?,?,?,?,?)");
            foreach ($b['spareParts'] as $p) {
                if (!($p['partNo']??'') && !($p['description']??'')) continue;
                $sp->execute([$newId,$p['partNo']??'',$p['description']??'',$p['seoNo']??'',$p['qtyReqd']??'',$p['qtyUsed']??'',$p['unitPrice']??'']);
            }
        }
        resp(201, ['id' => $newId]);
    }
    if ($method === 'DELETE' && $id) {
        require_role($user, ['admin']);
        $pdo->prepare("DELETE FROM service_calls WHERE id=?")->execute([$id]);
        resp(200, ['message' => 'Deleted']);
    }
}

// ── RETURNS ───────────────────────────────────────────────────

if ($resource === 'returns') {
    if ($method === 'GET') {
        $stmt = $pdo->query("SELECT r.*,c.name as customer_name,m.model as machine_model,m.mc_sl_no FROM returns r LEFT JOIN customers c ON r.customer_id=c.id LEFT JOIN machines m ON r.machine_id=m.id ORDER BY r.created_at DESC");
        resp(200, $stmt->fetchAll());
    }
    if ($method === 'POST') {
        require_role($user, ['admin','engineer']);
        $b = body();
        if (!($b['machineId']??'')) resp(400, ['error' => 'machineId required']);
        $newId = 'ret_'.uid();
        $pdo->prepare("INSERT INTO returns (id,customer_id,machine_id,return_date,reason,`condition`,collected_by,notes,created_by) VALUES (?,?,?,?,?,?,?,?,?)")
            ->execute([$newId,$b['customerId']??'',$b['machineId'],$b['returnDate']??null,$b['reason']??'',$b['condition']??'Good',$b['collectedBy']??'',$b['notes']??'',$user['id']]);
        $pdo->prepare("UPDATE machines SET status='returned',return_date=? WHERE id=?")->execute([$b['returnDate']??null,$b['machineId']]);
        resp(201, ['id' => $newId]);
    }
    if ($method === 'DELETE' && $id) {
        require_role($user, ['admin']);
        $pdo->prepare("DELETE FROM returns WHERE id=?")->execute([$id]);
        resp(200, ['message' => 'Deleted']);
    }
}

// ── STATS ─────────────────────────────────────────────────────

if ($resource === 'stats' && $method === 'GET') {
    $month = date('Y-m');
    resp(200, [
        'machines'    => $pdo->query("SELECT COUNT(*) FROM machines")->fetchColumn(),
        'installed'   => $pdo->query("SELECT COUNT(*) FROM machines WHERE status='installed'")->fetchColumn(),
        'returned'    => $pdo->query("SELECT COUNT(*) FROM machines WHERE status='returned'")->fetchColumn(),
        'on_amc'      => $pdo->query("SELECT COUNT(*) FROM machines WHERE status='on_amc'")->fetchColumn(),
        'customers'   => $pdo->query("SELECT COUNT(*) FROM customers")->fetchColumn(),
        'total_calls' => $pdo->query("SELECT COUNT(*) FROM service_calls")->fetchColumn(),
        'month_calls' => $pdo->query("SELECT COUNT(*) FROM service_calls WHERE DATE_FORMAT(date,'%Y-%m')='$month'")->fetchColumn(),
    ]);
}

// ── AI DOCUMENT SCAN PROXY ───────────────────────────────────
// Routes Claude API call through server so API key stays safe
// and no CORS issues on mobile

if ($resource === 'ai-scan' && $method === 'POST') {
    require_role($user, ['admin','engineer']);
    $b = body();
    if (empty($b['image']))    resp(400, ['error' => 'image required']);
    if (empty($b['formType'])) resp(400, ['error' => 'formType required']);

    $ANTHROPIC_KEY = ANTHROPIC_KEY;

    $prompts = [
        'installation' => 'This is a photo of a machine installation report / delivery challan for a photocopier/printer.
Extract ALL visible information and return ONLY a JSON object with these exact fields (empty string if not visible):
{"customerName":"","address":"","tel":"","contactPerson":"","invoiceNo":"","date":"YYYY-MM-DD","installedOn":"YYYY-MM-DD","deliveredOn":"YYYY-MM-DD","warrantyExpiry":"YYYY-MM-DD","warrantyCopies":"","model":"","mcSlNo":"","optionSlNo":"","mcIp":"","mcPassword":"","os":"","cvt":"Y or N","earthing":"Y or N","acc1":"","acc1sl":"","acc2":"","acc2sl":"","sol1":"","sol2":"","trainedName":"","engName":"","engNo":"","notes":""}
Return ONLY valid JSON, no explanation, no markdown.',

        'service' => 'This is a photo of a service call report / job sheet for a photocopier/printer repair.
Extract ALL visible information and return ONLY a JSON object with these exact fields (empty string if not visible):
{"customerName":"","date":"YYYY-MM-DD","callTime":"HH:MM","timeArrived":"HH:MM","callCompleted":"HH:MM","soId":"","documentNo":"","contractType":"","callReason":"","engName":"","engTechNo":"","symptom":"","cause":"","action":"","meterTotal":"","mfpCpr":"","mcSlNo":"","model":"","billable":"true or false","callCharges":"","grandTotal":"","notes":"","spareParts":[{"partNo":"","description":"","qtyUsed":"","unitPrice":""}]}
Return ONLY valid JSON, no explanation, no markdown.',

        'return' => 'This is a photo of a machine return / pickup document for a photocopier/printer.
Extract ALL visible information and return ONLY a JSON object with these exact fields (empty string if not visible):
{"customerName":"","returnDate":"YYYY-MM-DD","model":"","mcSlNo":"","reason":"","condition":"Good or Fair or Damaged or Needs Service","collectedBy":"","notes":""}
Return ONLY valid JSON, no explanation, no markdown.',
    ];

    $formType = $b['formType'];
    if (!isset($prompts[$formType])) resp(400, ['error' => 'Invalid formType']);

    // Strip data URL prefix if present
    $imageData = preg_replace('/^data:image\/\w+;base64,/', '', $b['image']);

    $payload = json_encode([
        'model'      => 'claude-opus-4-6',
        'max_tokens' => 1500,
        'messages'   => [[
            'role'    => 'user',
            'content' => [
                ['type' => 'image', 'source' => ['type' => 'base64', 'media_type' => 'image/jpeg', 'data' => $imageData]],
                ['type' => 'text',  'text'   => $prompts[$formType]],
            ],
        ]],
    ]);

    $ch = curl_init('https://api.anthropic.com/v1/messages');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'x-api-key: ' . $ANTHROPIC_KEY,
            'anthropic-version: 2023-06-01',
        ],
        CURLOPT_TIMEOUT => 30,
    ]);
    $result = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (!$result) resp(500, ['error' => 'AI service unreachable']);

    $aiResp = json_decode($result, true);
    if ($httpCode !== 200) resp(500, ['error' => $aiResp['error']['message'] ?? 'AI error']);

    $text = $aiResp['content'][0]['text'] ?? '';
    // Strip any markdown fences just in case
    $text = preg_replace('/^```json\s*/m', '', $text);
    $text = preg_replace('/^```\s*/m',     '', $text);
    $text = trim($text);

    $parsed = json_decode($text, true);
    if (!$parsed) resp(500, ['error' => 'AI returned unreadable data. Try a clearer photo.']);

    resp(200, ['extracted' => $parsed]);
}

// ── PHOTO UPLOAD ──────────────────────────────────────────────
// Stores base64 photos and returns a URL path

if ($resource === 'upload-photo' && $method === 'POST') {
    require_role($user, ['admin','engineer']);
    $b = body();
    if (empty($b['image'])) resp(400, ['error' => 'image required']);

    // Save to uploads folder
    $uploadsDir = __DIR__ . '/uploads/';
    if (!is_dir($uploadsDir)) mkdir($uploadsDir, 0755, true);

    // Create .htaccess to protect uploads if it doesn't exist
    $htaccess = $uploadsDir . '.htaccess';
    if (!file_exists($htaccess)) {
        file_put_contents($htaccess, "Options -Indexes
");
    }

    $imageData = preg_replace('/^data:image\/\w+;base64,/', '', $b['image']);
    $imageData = base64_decode($imageData);
    if (!$imageData) resp(400, ['error' => 'Invalid image data']);

    $filename  = date('Ymd_His') . '_' . uid() . '.jpg';
    $filepath  = $uploadsDir . $filename;
    file_put_contents($filepath, $imageData);

    // Return the accessible URL
    $baseUrl = (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
    resp(201, ['url' => $baseUrl . '/api/uploads/' . $filename, 'filename' => $filename]);
}

// ── SERVE UPLOADS ─────────────────────────────────────────────

if ($resource === 'uploads' && $method === 'GET' && $id) {
    require_role($user, ['admin','engineer','viewer']);
    $file = __DIR__ . '/uploads/' . basename($id);
    if (!file_exists($file)) { http_response_code(404); exit; }
    $mime = mime_content_type($file) ?: 'image/jpeg';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

resp(404, ['error' => "Not found: $method /$uri"]);
