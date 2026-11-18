<?php
session_start();
require_once __DIR__ . '/config.php';

/*
 * WeChat + phone binding FAS for openNDS fas_secure_enabled=3.
 * config.php must define $faskey, $mac_file, $user_db, $wechat_appid,
 * $wechat_secret, $public_domain and $base_path.
 */

function smsCodeFile($phone) {
    $dir = __DIR__ . '/sms_codes';
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('Cannot create SMS code directory');
    }
    return $dir . '/' . md5($phone) . '.txt';
}

function getUserData($file) {
    if (!is_file($file)) return [];
    $data = json_decode((string)file_get_contents($file), true);
    return is_array($data) ? $data : [];
}

function saveUserData($file, $data) {
    $dir = dirname($file);
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('Cannot create user database directory');
    }
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    if ($json === false || file_put_contents($file, $json, LOCK_EX) === false) {
        throw new RuntimeException('Cannot save user database');
    }
}

function do_authenticate($mac, $hid, $gatewayhash, $faskey) {
    global $mac_file;

    if (!preg_match('/^[0-9a-f]{64}$/i', (string)$gatewayhash) || $hid === '' || $faskey === '') {
        throw new InvalidArgumentException('Invalid openNDS authentication parameters');
    }
    if (!preg_match('/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i', (string)$mac)) {
        throw new InvalidArgumentException('Invalid client MAC address');
    }

    if (!empty($mac_file)) {
        $current = is_file($mac_file) ? (string)file_get_contents($mac_file) : '';
        if (!preg_match('/^' . preg_quote($mac, '/') . '$/im', $current)) {
            @file_put_contents($mac_file, strtolower($mac) . "\n", FILE_APPEND | LOCK_EX);
        }
    }

    $rhid = hash('sha256', trim($hid) . trim($faskey));
    $gwDir = __DIR__ . '/queue/' . $gatewayhash;
    if (!is_dir($gwDir) && !mkdir($gwDir, 0700, true) && !is_dir($gwDir)) {
        throw new RuntimeException('Cannot create openNDS auth queue');
    }

    // openNDS authmon queue format: rhid sessionlength uploadrate downloadrate uploadquota downloadquota custom
    $line = $rhid . " 0 0 0 0 0 " . base64_encode('') . " \n";
    if (file_put_contents($gwDir . '/' . $rhid, $line, LOCK_EX) === false) {
        throw new RuntimeException('Cannot write openNDS auth queue entry');
    }
}

function authmon_request() {
    global $faskey;

    // Current openNDS wget authmon sends these values in the query string (GET).
    // Accept POST too for deployments using the alternate remote request helper.
    $request = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
    if (!isset($request['auth_get'])) return false;

    $action = (string)$request['auth_get'];
    $gatewayhash = (string)($request['gatewayhash'] ?? '');
    $payload = (string)($request['payload'] ?? '');
    $authmac = (string)($request['authmac'] ?? '');

    if (!preg_match('/^[0-9a-f]{64}$/', $gatewayhash) ||
        !in_array($action, ['clear', 'view', 'list', 'deauthed', 'custom'], true)) {
        http_response_code(400);
        exit;
    }

    // libopennds signs the action, gateway hash and *encoded* payload.
    $expected = hash_hmac('sha256', $action . "\n" . $gatewayhash . "\n" . $payload, (string)$faskey);
    if ($faskey === '' || !preg_match('/^[0-9a-f]{64}$/', $authmac) || !hash_equals($expected, $authmac)) {
        http_response_code(403);
        exit;
    }

    $gwDir = __DIR__ . '/queue/' . $gatewayhash;
    if ($action === 'clear') {
        if (is_dir($gwDir)) {
            foreach (scandir($gwDir) ?: [] as $name) {
                if (preg_match('/^[0-9a-f]{64}$/', $name)) @unlink($gwDir . '/' . $name);
            }
        }
        exit;
    }

    if ($action === 'deauthed' || $action === 'custom') {
        echo 'ack';
        exit;
    }

    $decoded = base64_decode($payload, true);
    if ($decoded === false) {
        http_response_code(400);
        exit;
    }

    if ($action === 'view' && $decoded !== 'none') {
        // Authmon sends "* <rhid> ..." as the ack list. Delete only acknowledged entries.
        foreach (preg_split('/\s+/', trim($decoded)) as $rhid) {
            if (preg_match('/^[0-9a-f]{64}$/', $rhid) && is_file($gwDir . '/' . $rhid)) {
                @unlink($gwDir . '/' . $rhid);
            }
        }
        echo 'ack';
        exit;
    }

    // "none" is base64-encoded by openNDS to bm9uZQ==. Return queued RHIDs in authmon format.
    $authList = '*';
    if (is_dir($gwDir)) {
        foreach (scandir($gwDir) ?: [] as $name) {
            if (!preg_match('/^[0-9a-f]{64}$/', $name)) continue;
            $lines = @file($gwDir . '/' . $name, FILE_IGNORE_NEW_LINES);
            if (!empty($lines[0])) $authList .= ' ' . rawurlencode(trim($lines[0]));
            if ($action === 'list') @unlink($gwDir . '/' . $name);
        }
    }
    echo trim($authList);
    exit;
}

function show_success_page() {
    unset($_SESSION['wx_openid'], $_SESSION['wx_nickname'], $_SESSION['clientmac'], $_SESSION['hid'], $_SESSION['gw_hash']);
    echo "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>认证成功</title><style>body{font-family:-apple-system,sans-serif;padding:20px;background:#f4f4f9;text-align:center}.card{background:white;padding:40px 20px;border-radius:12px;box-shadow:0 4px 12px #0001;max-width:400px;margin:40px auto}h2{color:#07c160}p{color:#666;font-size:14px}</style></head>
    <body><div class='card'><h2>🎉 认证成功</h2><p>您的设备已成功连接网络！</p><p style='font-size:12px;color:#999;margin-top:20px'>页面将在 5 秒后跳转...</p></div>
    <script>setTimeout(function(){location.href='https://www.baidu.com'},5000)</script></body></html>";
    exit;
}

function curl_get($url) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result === false ? '' : $result;
}

function render_bind_form($openid, $nickname, $clientmac, $params, $gatewayhash) {
    $h = static function ($value) { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
    ?>
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>绑定手机号</title>
    <style>body{font-family:-apple-system,sans-serif;padding:20px;background:#f4f4f9}.card{background:white;padding:20px;border-radius:12px;box-shadow:0 4px 12px #0001;max-width:400px;margin:40px auto;text-align:center}.btn{display:block;padding:12px;background:#07c160;color:white;border:0;border-radius:8px;font-weight:bold;margin-top:20px;width:100%;font-size:16px}.input-group{display:flex;gap:10px;margin:15px 0}input[type=text]{min-width:0;flex:1;box-sizing:border-box;padding:12px;border:1px solid #ddd;border-radius:8px;font-size:16px;text-align:center}.btn-sms{width:120px;background:#07c160;color:white;border:0;border-radius:8px}.btn-sms:disabled{background:#ccc}</style></head><body>
    <div class="card"><h2>欢迎您，<?= $h($nickname) ?></h2><p style="color:#666;font-size:14px">请验证手机号完成上网</p>
    <form method="post"><input type="hidden" name="action" value="bind_phone"><input type="hidden" name="openid" value="<?= $h($openid) ?>"><input type="hidden" name="mac" value="<?= $h($clientmac) ?>"><input type="hidden" name="hid" value="<?= $h($params['hid'] ?? '') ?>"><input type="hidden" name="gw_hash" value="<?= $h($gatewayhash) ?>">
    <input type="text" name="phone" id="phoneInput" placeholder="请输入 11 位手机号" maxlength="11" required style="width:100%;margin:15px 0">
    <div class="input-group"><input type="text" name="sms_code" placeholder="输入验证码" maxlength="6" required><button type="button" class="btn-sms" id="sendSmsBtn">获取验证码</button></div><button type="submit" class="btn">验证并上网</button></form></div>
    <script>
    document.getElementById('sendSmsBtn').onclick=function(){const phone=document.getElementById('phoneInput').value,btn=this;if(!/^1[3-9]\d{9}$/.test(phone)){alert('请输入正确的手机号格式');return}btn.disabled=true;btn.textContent='发送中...';const body=new URLSearchParams({action:'send_sms',phone});fetch(window.location.pathname,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}).then(r=>r.json()).then(d=>{if(d.status!=='success')throw new Error(d.msg);alert(d.msg);let n=60;const timer=setInterval(()=>{btn.textContent=n+' 秒后重发';if(--n<0){clearInterval(timer);btn.disabled=false;btn.textContent='获取验证码'}},1000)}).catch(e=>{alert(e.message||'网络错误');btn.disabled=false;btn.textContent='获取验证码'})};
    </script></body></html>
    <?php
}

// Authmon requests must be handled before the browser-facing FAS flow.
if (authmon_request()) exit;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'send_sms') {
    header('Content-Type: application/json; charset=utf-8');
    $phone = (string)($_POST['phone'] ?? '');
    if (!preg_match('/^1[3-9]\d{9}$/', $phone)) {
        echo json_encode(['status' => 'error', 'msg' => '手机号格式错误'], JSON_UNESCAPED_UNICODE);
    } else {
        // Test/demo behavior: the code is returned in the response. Replace with an SMS provider in production.
        $code = (string)random_int(100000, 999999);
        file_put_contents(smsCodeFile($phone), $code, LOCK_EX);
        echo json_encode(['status' => 'success', 'msg' => "【测试环境】验证码为: {$code}"], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'bind_phone') {
    $phone = (string)($_POST['phone'] ?? '');
    $smsCode = (string)($_POST['sms_code'] ?? '');
    $openid = (string)($_POST['openid'] ?? '');
    $mac = (string)($_POST['mac'] ?? '');
    $hid = (string)($_POST['hid'] ?? '');
    $gatewayhash = (string)($_POST['gw_hash'] ?? '');
    $codeFile = smsCodeFile($phone);
    $savedCode = is_file($codeFile) ? trim((string)file_get_contents($codeFile)) : '';

    if ($openid === '' || $mac === '' || $hid === '' || $gatewayhash === '') {
        http_response_code(400);
        exit('<h2 style="text-align:center;margin-top:50px">参数丢失，请重新扫码。</h2>');
    }
    if (!preg_match('/^1[3-9]\d{9}$/', $phone) || $savedCode === '' || !hash_equals($savedCode, $smsCode)) {
        http_response_code(400);
        exit('<h2 style="text-align:center;margin-top:50px">手机号或验证码错误，请返回重试。</h2>');
    }

    try {
        $db = getUserData($user_db);
        $db[$openid] = ['phone' => $phone, 'nickname' => '微信用户', 'bind_time' => date('Y-m-d H:i:s')];
        saveUserData($user_db, $db);
        do_authenticate($mac, $hid, $gatewayhash, $faskey);
        @unlink($codeFile);
        $_SESSION['wx_openid'] = $openid;
        $_SESSION['wx_bound'] = true;
        header('Location: ?done=1');
        exit;
    } catch (Throwable $e) {
        error_log('FAS bind/authentication failed: ' . $e->getMessage());
        http_response_code(500);
        exit('认证处理失败，请稍后重试。');
    }
}

// Parse FAS parameters from either a short-lived QR token or openNDS AES query.
$params = [];
$isTest = isset($_GET['_test']) && $_GET['_test'] === '1';
$currentMac = (string)($_GET['mac'] ?? '');
$currentHid = (string)($_GET['hid'] ?? '');
$currentIp = (string)($_GET['ip'] ?? '');
$currentGwHash = (string)($_GET['gw_hash'] ?? '');
$clientmac = '';
$gatewayhash = '';

if (!empty($_GET['token'])) {
    $token = basename((string)$_GET['token']);
    if (!preg_match('/^[a-f0-9]{8}$/i', $token)) exit('无效的认证链接，请重新扫码。');
    $tokenFile = __DIR__ . '/tokens/' . $token . '.json';
    if (is_file($tokenFile)) {
        $tokenData = json_decode((string)file_get_contents($tokenFile), true) ?: [];
        $clientmac = (string)($tokenData['mac'] ?? '');
        $params['hid'] = (string)($tokenData['hid'] ?? '');
        $params['clientip'] = (string)($tokenData['ip'] ?? '');
        $gatewayhash = (string)($tokenData['gw_hash'] ?? '');
    }
} elseif ($isTest || $currentMac !== '') {
    $clientmac = $currentMac ?: '08:00:27:11:d6:8f';
    $params['hid'] = $currentHid ?: 'test_hid_' . time();
    $params['clientip'] = $currentIp ?: '192.168.56.101';
    $gatewayhash = $currentGwHash ?: 'ac8c4c8b3dde1cb59f314c559132130941d8f0147486d13ab2d252c8d9673011';
} else {
    $fas = (string)($_GET['fas'] ?? '');
    $iv = (string)($_GET['iv'] ?? '');
    if ($fas !== '' && $iv !== '') {
        $decrypted = openssl_decrypt(base64_decode($fas), 'AES-256-CBC', $faskey, 0, $iv);
        if ($decrypted !== false) {
            foreach (explode(', ', $decrypted) as $pair) {
                if (strpos($pair, '=') !== false) {
                    [$key, $value] = explode('=', $pair, 2);
                    $params[trim($key)] = trim($value);
                }
            }
            $clientmac = (string)($params['clientmac'] ?? '');
            $gatewayhash = hash('sha256', trim((string)($params['gatewayname'] ?? '')));
        }
    }
}

if (isset($_GET['done']) && $_GET['done'] === '1') show_success_page();

$userAgent = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
$isWechat = strpos($userAgent, 'MicroMessenger') !== false || strpos($userAgent, 'wechatdevtools') !== false;

if ($isWechat && !empty($_SESSION['wx_openid']) && !$isTest) {
    $openid = (string)$_SESSION['wx_openid'];
    $clientmac = (string)($_SESSION['clientmac'] ?? $clientmac);
    $params['hid'] = (string)($_SESSION['hid'] ?? ($params['hid'] ?? ''));
    $gatewayhash = (string)($_SESSION['gw_hash'] ?? $gatewayhash);
    $db = getUserData($user_db);
    if (isset($db[$openid]['phone'])) {
        try { do_authenticate($clientmac, $params['hid'], $gatewayhash, $faskey); }
        catch (Throwable $e) { error_log('FAS auth failed: ' . $e->getMessage()); exit('认证处理失败，请稍后重试。'); }
        show_success_page();
    }
    render_bind_form($openid, $_SESSION['wx_nickname'] ?? '微信用户', $clientmac, $params, $gatewayhash);
    exit;
}

if ($isWechat && isset($_GET['code']) && !$isTest) {
    $state = [];
    parse_str((string)($_GET['state'] ?? ''), $state);
    $token = basename((string)($state['token'] ?? ''));
    if (!preg_match('/^[a-f0-9]{8}$/i', $token)) exit('认证链接无效，请重新扫码。');
    $tokenFile = __DIR__ . '/tokens/' . $token . '.json';
    if (is_file($tokenFile)) {
        $tokenData = json_decode((string)file_get_contents($tokenFile), true) ?: [];
        $clientmac = (string)($tokenData['mac'] ?? '');
        $params['hid'] = (string)($tokenData['hid'] ?? '');
        $params['clientip'] = (string)($tokenData['ip'] ?? '');
        $gatewayhash = (string)($tokenData['gw_hash'] ?? '');
    } else {
        exit('认证链接已失效，请重新扫码。');
    }

    $code = (string)$_GET['code'];
    $usedDir = __DIR__ . '/used_codes';
    if (!is_dir($usedDir)) @mkdir($usedDir, 0700, true);
    $usedCodeFile = $usedDir . '/' . md5($code);
    if (is_file($usedCodeFile)) exit('该授权链接已失效，请重新扫描二维码。');

    $oauthUrl = 'https://api.weixin.qq.com/sns/oauth2/access_token?' . http_build_query([
        'appid' => $wechat_appid, 'secret' => $wechat_secret, 'code' => $code, 'grant_type' => 'authorization_code'
    ]);
    $oauth = json_decode(curl_get($oauthUrl), true);
    if (isset($oauth['openid'], $oauth['access_token'])) {
        $openid = (string)$oauth['openid'];
        $userUrl = 'https://api.weixin.qq.com/sns/userinfo?' . http_build_query([
            'access_token' => $oauth['access_token'], 'openid' => $openid, 'lang' => 'zh_CN'
        ]);
        $user = json_decode(curl_get($userUrl), true) ?: [];
        $nickname = (string)($user['nickname'] ?? '微信用户');
        file_put_contents($usedCodeFile, date('c'), LOCK_EX);
        $_SESSION['wx_openid'] = $openid;
        $_SESSION['wx_nickname'] = $nickname;
        $_SESSION['clientmac'] = $clientmac;
        $_SESSION['hid'] = $params['hid'];
        $_SESSION['gw_hash'] = $gatewayhash;
        $db = getUserData($user_db);
        if (isset($db[$openid]['phone'])) {
            try { do_authenticate($clientmac, $params['hid'], $gatewayhash, $faskey); }
            catch (Throwable $e) { error_log('FAS auth failed: ' . $e->getMessage()); exit('认证处理失败，请稍后重试。'); }
            show_success_page();
        }
        render_bind_form($openid, $nickname, $clientmac, $params, $gatewayhash);
        exit;
    }
    http_response_code(502);
    exit('微信授权失败，请重新扫码。');
}

// Desktop page: generate a QR code that carries the client parameters to WeChat.
if (!$isWechat) {
    $qrcodeMac = $clientmac ?: '08:00:27:11:d6:8f';
    $qrcodeHid = (string)($params['hid'] ?? 'test_hid');
    $qrcodeIp = (string)($params['clientip'] ?? '192.168.56.101');
    $qrData = $public_domain . $base_path . '/?mac=' . rawurlencode($qrcodeMac) . '&hid=' . rawurlencode($qrcodeHid) . '&ip=' . rawurlencode($qrcodeIp) . '&gw_hash=' . rawurlencode($gatewayhash);
    $qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . rawurlencode($qrData);
    echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WiFi 认证中心</title></head><body style="font-family:sans-serif;padding:20px;background:#f4f4f9;text-align:center"><div style="background:white;padding:20px;border-radius:12px;max-width:400px;margin:40px auto"><h2>WiFi 认证</h2><p>请使用微信扫一扫</p><img src="' . htmlspecialchars($qrUrl, ENT_QUOTES, 'UTF-8') . '" alt="微信扫码认证" width="200" height="200"></div></body></html>';
    exit;
}

// First WeChat visit: create a token for the OAuth callback and redirect to WeChat.
if ($isWechat && !isset($_GET['code']) && !$isTest) {
    $newToken = bin2hex(random_bytes(4));
    $tokenDir = __DIR__ . '/tokens';
    if (!is_dir($tokenDir)) @mkdir($tokenDir, 0700, true);
    $tokenData = ['mac' => $clientmac, 'hid' => $params['hid'] ?? '', 'ip' => $params['clientip'] ?? '', 'gw_hash' => $gatewayhash];
    if (file_put_contents($tokenDir . '/' . $newToken . '.json', json_encode($tokenData), LOCK_EX) === false) exit('认证初始化失败，请重试。');
    $redirectUri = $public_domain . $base_path . '/';
    $wechatUrl = 'https://open.weixin.qq.com/connect/oauth2/authorize?' . http_build_query([
        'appid' => $wechat_appid, 'redirect_uri' => $redirectUri, 'response_type' => 'code',
        'scope' => 'snsapi_userinfo', 'state' => 'token=' . $newToken
    ]) . '#wechat_redirect';
    header('Location: ' . $wechatUrl);
    exit;
}
?>
