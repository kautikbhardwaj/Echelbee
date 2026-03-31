<?php
// ECHELBEE DEBUG — visit this URL once to diagnose, then DELETE it
// Access: www.echelbee.in/eb_debug.php
header('Content-Type: text/html; charset=utf-8');
?><!DOCTYPE html>
<html><head><title>Echelbee Debug</title>
<style>
body{font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:24px;font-size:13px}
h2{color:#00d4ff;margin:20px 0 8px}
.ok{color:#00e5a0} .fail{color:#ff4444} .warn{color:#ffaa00}
pre{background:#111;padding:12px;border-radius:6px;border:1px solid #222;overflow-x:auto}
</style></head><body>
<h1 style="color:#fff">🔍 Echelbee Server Debug</h1>
<p style="color:#888">Run once to diagnose — delete after use.</p>

<h2>1. PHP Version</h2>
<pre><?= phpversion() ?></pre>

<h2>2. MySQL Connection</h2>
<?php
try {
    $pdo = new PDO("mysql:host=localhost;dbname=echela83_fms;charset=utf8mb4",
        'echela83_kb_admin','Online2025',
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    echo '<p class="ok">✓ Connected to echela83_fms</p>';
} catch(Exception $e) {
    echo '<p class="fail">✕ DB FAILED: '.$e->getMessage().'</p>';
    die();
}
?>

<h2>3. Create Tables</h2>
<?php
try {
    $pdo->exec("CREATE TABLE IF NOT EXISTS visitor_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(45), country VARCHAR(100) DEFAULT '',
        country_code VARCHAR(5) DEFAULT '', region VARCHAR(100) DEFAULT '',
        city VARCHAR(100) DEFAULT '', isp VARCHAR(250) DEFAULT '',
        device VARCHAR(50) DEFAULT 'Unknown', browser VARCHAR(100) DEFAULT 'Unknown',
        os VARCHAR(100) DEFAULT 'Unknown', user_agent TEXT,
        page VARCHAR(500) DEFAULT '/', referrer VARCHAR(500) DEFAULT '',
        visited_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_time(visited_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    echo '<p class="ok">✓ visitor_logs table ready</p>';

    $pdo->exec("CREATE TABLE IF NOT EXISTS admin_sessions (
        token VARCHAR(64) PRIMARY KEY,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    echo '<p class="ok">✓ admin_sessions table ready</p>';
} catch(Exception $e) {
    echo '<p class="fail">✕ Table creation FAILED: '.$e->getMessage().'</p>';
}
?>

<h2>4. Test Insert into visitor_logs</h2>
<?php
try {
    $pdo->prepare("INSERT INTO visitor_logs (ip,country,country_code,city,isp,device,browser,os,user_agent,page,referrer)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    ->execute(['1.2.3.4','Test Country','TC','Test City','Test ISP','Desktop','Chrome 120','Windows 10','DebugAgent','/','' ]);
    $id = $pdo->lastInsertId();
    echo '<p class="ok">✓ Test row inserted — ID: '.$id.'</p>';
} catch(Exception $e) {
    echo '<p class="fail">✕ Insert FAILED: '.$e->getMessage().'</p>';
}
?>

<h2>5. Row Count in visitor_logs</h2>
<?php
$cnt = $pdo->query("SELECT COUNT(*) FROM visitor_logs")->fetchColumn();
echo '<p class="'.($cnt>0?'ok':'warn').'">Rows in visitor_logs: <b>'.$cnt.'</b></p>';
?>

<h2>6. cURL (for geo lookup)</h2>
<?php
if (function_exists('curl_init')) {
    $ch = curl_init('http://ip-api.com/json/8.8.8.8?fields=status,country,city');
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>5,CURLOPT_SSL_VERIFYPEER=>false]);
    $r = curl_exec($ch); $err = curl_error($ch); curl_close($ch);
    if ($r && !$err) {
        $j = json_decode($r, true);
        echo '<p class="ok">✓ cURL works — ip-api.com responded: '.htmlspecialchars(json_encode($j)).'</p>';
    } else {
        echo '<p class="warn">⚠ cURL available but ip-api.com unreachable: '.$err.'<br>(Geo will be blank, but tracking still works)</p>';
    }
} else {
    echo '<p class="warn">⚠ cURL not available — will try file_get_contents</p>';
}
?>

<h2>7. allow_url_fopen</h2>
<?php
echo '<p class="'.(ini_get('allow_url_fopen')?'ok':'warn').'">allow_url_fopen: '.(ini_get('allow_url_fopen')?'ON':'OFF').'</p>';
?>

<h2>8. Outbound IP (your server's IP)</h2>
<?php
$myip = '';
if (function_exists('curl_init')) {
    $ch = curl_init('https://api.ipify.org'); 
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>4,CURLOPT_SSL_VERIFYPEER=>false]);
    $myip = curl_exec($ch); curl_close($ch);
}
echo '<pre>Server IP: '.htmlspecialchars($myip ?: 'Could not fetch').'</pre>';
?>

<h2>9. track.php reachability test</h2>
<?php
$trackUrl = (isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']==='on'?'https':'http').'://'.$_SERVER['HTTP_HOST'].'/track.php';
echo '<pre>Expected URL: '.$trackUrl.'</pre>';
if (file_exists(__DIR__.'/track.php')) {
    echo '<p class="ok">✓ track.php EXISTS on disk</p>';
} else {
    echo '<p class="fail">✕ track.php NOT FOUND on disk — file not deployed!</p>';
}
if (file_exists(__DIR__.'/admin_api.php')) {
    echo '<p class="ok">✓ admin_api.php EXISTS on disk</p>';
} else {
    echo '<p class="fail">✕ admin_api.php NOT FOUND — file not deployed!</p>';
}
?>

<h2>10. Recent visitor_logs entries</h2>
<?php
$rows = $pdo->query("SELECT id,ip,country,city,device,browser,page,visited_at FROM visitor_logs ORDER BY visited_at DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);
if ($rows) {
    echo '<pre>'.htmlspecialchars(json_encode($rows, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)).'</pre>';
} else {
    echo '<p class="warn">⚠ No rows yet in visitor_logs</p>';
}
?>

<hr style="border-color:#222;margin:24px 0">
<p style="color:#555">⚠ DELETE this file after debugging: <code>eb_debug.php</code></p>
</body></html>
