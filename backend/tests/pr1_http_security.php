<?php
declare(strict_types=1);

/**
 * PR1 HTTP security integration checks.
 *
 * Run from the backend directory with the repository's portable PHP:
 *   php tests/pr1_http_security.php
 *
 * The application is served through a temporary public/index.php wrapper so
 * the real index.php?s= query parser and HTTP middleware pipeline are used.
 * Data and runtime files stay below backend/runtime/pr1-test-*.
 */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$root = dirname(__DIR__);
$runtime = $root . DIRECTORY_SEPARATOR . 'runtime' . DIRECTORY_SEPARATOR . 'pr1-test-' . getmypid() . '-' . bin2hex(random_bytes(4));
$database = $runtime . DIRECTORY_SEPARATOR . 'fixture.sqlite';
$failures = [];
$serverPort = 0;
$serverProcess = null;
$serverPid = 0;
$serverLog = $runtime . DIRECTORY_SEPARATOR . 'server.log';
$pdo = null;

$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$removeTree = static function (string $path) use (&$removeTree): void {
    if (!is_dir($path)) {
        return;
    }

    foreach (scandir($path) ?: [] as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $child = $path . DIRECTORY_SEPARATOR . $item;
        if (is_dir($child) && !is_link($child)) {
            $removeTree($child);
        } else {
            @unlink($child);
        }
    }
    @rmdir($path);
};

$request = static function (string $method, string $path, ?string $apiKey = null, array $post = [], ?string $input = null) use (&$serverPort): array {
    $url = 'http://127.0.0.1:' . $serverPort . '/index.php?s=' . rawurlencode('/' . ltrim($path, '/'));
    $headers = ['Accept: application/json'];
    if ($apiKey !== null) {
        $headers[] = 'Authorization: Bearer ' . $apiKey;
    }

    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('unable to initialize cURL');
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    if ($input !== null) {
        $headers[] = 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $input);
    } elseif (strtoupper($method) !== 'GET') {
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }

    $content = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($content === false) {
        throw new RuntimeException('HTTP request failed: ' . $error);
    }

    $decoded = json_decode($content, true);

    return [
        'status' => $status,
        'content' => (string)$content,
        'json' => is_array($decoded) ? $decoded : null,
    ];
};

$expectStatus = static function (array $response, int $status, string $label) use ($assert): void {
    $assert($response['status'] === $status, $label . ': expected HTTP ' . $status . ', got ' . $response['status'] . ' (' . $response['content'] . ')');
};

$expectPassed = static function (array $response, bool $passed, string $label) use ($assert): void {
    $actual = $response['json']['passed'] ?? null;
    $assert($actual === $passed, $label . ': expected passed=' . ($passed ? 'true' : 'false') . ', got ' . var_export($actual, true));
};

try {
    if (!extension_loaded('pdo_sqlite')) {
        throw new RuntimeException('pdo_sqlite extension is required');
    }

    if (!mkdir($runtime, 0777, true) && !is_dir($runtime)) {
        throw new RuntimeException('unable to create isolated runtime: ' . $runtime);
    }

    putenv('DB_DRIVER=sqlite');
    putenv('DB_PATH=' . $database);
    putenv('APP_DEBUG=0');
    putenv('GEETEST_ALLOWED_ORIGINS=https://gateway.example.test');

    $pdo = new PDO('sqlite:' . $database);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec(<<<'SQL'
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE GeetestTable (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_id INTEGER DEFAULT NULL,
    token TEXT NOT NULL UNIQUE,
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    code TEXT DEFAULT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0,
    ip TEXT DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    extra TEXT DEFAULT NULL,
    expire_at INTEGER NOT NULL,
    verified_at INTEGER DEFAULT NULL,
    used_at INTEGER DEFAULT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER DEFAULT NULL
);
CREATE INDEX idx_pr1_code_group ON GeetestTable (code, group_id);
CREATE INDEX idx_pr1_api_key_expire ON GeetestTable (api_key_id, expire_at);
SQL);

    $keys = [
        'default' => 'default-key-for-pr1-tests-0001',
        'bot-one' => 'ordinary-key-for-pr1-tests-0002',
        'bot-two' => 'ordinary-key-for-pr1-tests-0003',
    ];
    $now = time();
    $insertKey = $pdo->prepare('INSERT INTO api_keys (hash, created_at, updated_at) VALUES (?, ?, ?)');
    foreach ($keys as $value) {
        $insertKey->execute([hash('sha256', $value), $now, $now]);
    }

    $insertSetting = $pdo->prepare('INSERT INTO settings (name, value, created_at, updated_at) VALUES (?, ?, ?, ?)');
    foreach ([
        'GEETEST_CAPTCHA_ID' => 'pr1-captcha-id',
        'GEETEST_CAPTCHA_KEY' => 'pr1-captcha-key',
        'GEETEST_API_SERVER' => 'https://gcaptcha4.geetest.com',
        'GEETEST_CODE_EXPIRE' => '300',
        'SALT' => str_repeat('s', 32),
    ] as $name => $value) {
        $insertSetting->execute([$name, $value, $now, $now]);
    }

    $insertTicket = $pdo->prepare(<<<'SQL'
INSERT INTO GeetestTable
    (api_key_id, token, group_id, user_id, code, verified, used, expire_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?, ?)
SQL);
    $insertTicket->execute([2, 'ticket-cross-key', '10001', '20001', 'CROSS1', $now + 3600, $now, $now]);
    $insertTicket->execute([2, 'ticket-user-scope', '10001', '20002', 'USER1', $now + 3600, $now, $now]);
    $insertLegacyTicket = $pdo->prepare(<<<'SQL'
INSERT INTO GeetestTable
    (api_key_id, token, group_id, user_id, code, verified, used, expire_at, created_at, updated_at)
    VALUES (NULL, ?, ?, ?, ?, 1, 0, ?, ?, ?)
SQL);
    $insertLegacyTicket->execute(['ticket-legacy-owner', '10002', '20003', 'LEGACY1', $now + 3600, $now, $now]);

    $fixturePublic = $runtime . DIRECTORY_SEPARATOR . 'public';
    if (!mkdir($fixturePublic, 0777, true) && !is_dir($fixturePublic)) {
        throw new RuntimeException('unable to create temporary public root');
    }

    // Replace only the external vendor HTTP boundary; application routing,
    // signing, callback persistence and one-time consumption remain real.
    $vendorStub = <<<'PHP'
function curl(string $url, $data = [], int $timeout = 10, string $method = 'GET'): array {
    $valid = $url === 'https://gcaptcha4.geetest.com/validate?captcha_id=pr1-captcha-id'
        && $method === 'POST'
        && ($data['sign_token'] ?? '') === hash_hmac('sha256', 'fixture-lot', 'pr1-captcha-key')
        && ($data['pass_token'] ?? '') === 'fixture-pass';
    return ['http_code' => 200, 'error' => '', 'content' => json_encode(['result' => $valid ? 'success' : 'fail'])];
}
PHP;
    $entry = "<?php\n" . $vendorStub . "\n"
        . 'require_once ' . var_export($root . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php', true) . ";\n"
        . '$app = new \\think\\App(' . var_export($root, true) . ");\n"
        . '$app->setRuntimePath(' . var_export($runtime . DIRECTORY_SEPARATOR, true) . ");\n"
        . "\\think\\App::setInstance(\$app);\n"
        . "\$http = \$app->http;\n"
        . "\$response = \$http->run();\n"
        . "\$response->send();\n"
        . "\$http->end(\$response);\n";
    if (file_put_contents($fixturePublic . DIRECTORY_SEPARATOR . 'index.php', $entry, LOCK_EX) === false) {
        throw new RuntimeException('unable to create temporary HTTP entry point');
    }

    $serverPort = 19000 + random_int(0, 2000);
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $probe = @fsockopen('127.0.0.1', $serverPort, $errno, $errstr, 0.1);
        if (is_resource($probe)) {
            fclose($probe);
            $serverPort++;
            continue;
        }
        break;
    }

    $nullDevice = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
    $descriptors = [
        0 => ['file', $nullDevice, 'r'],
        1 => ['file', $serverLog, 'a'],
        2 => ['file', $serverLog, 'a'],
    ];
    $serverEnv = getenv();
    if (!is_array($serverEnv)) {
        $serverEnv = [];
    }
    $serverEnv['DB_DRIVER'] = 'sqlite';
    $serverEnv['DB_PATH'] = $database;
    $serverEnv['APP_DEBUG'] = '0';
    $serverEnv['GEETEST_ALLOWED_ORIGINS'] = 'https://gateway.example.test';
    $phpBinary = PHP_BINARY;
    $command = [$phpBinary, '-S', '127.0.0.1:' . $serverPort, '-t', $fixturePublic];
    $serverProcess = proc_open($command, $descriptors, $serverPipes, $root, $serverEnv, ['bypass_shell' => true]);
    if (!is_resource($serverProcess)) {
        throw new RuntimeException('unable to start PHP built-in server');
    }
    $serverStatus = proc_get_status($serverProcess);
    $serverPid = (int)($serverStatus['pid'] ?? 0);

    $ready = false;
    for ($attempt = 0; $attempt < 50; $attempt++) {
        $probe = @fsockopen('127.0.0.1', $serverPort, $errno, $errstr, 0.2);
        if (is_resource($probe)) {
            fclose($probe);
            $ready = true;
            break;
        }
        usleep(100000);
    }
    if (!$ready) {
        throw new RuntimeException('PHP built-in server did not become ready');
    }

    $noKey = $request('POST', 'verify/check', null, ['group_id' => '10001', 'user_id' => '20001', 'code' => 'CROSS1']);
    $expectStatus($noKey, 401, 'verify/check without API key');

    $directController = $request('POST', 'VerifyController/check', null, ['group_id' => '10001', 'user_id' => '20001', 'code' => 'CROSS1']);
    $expectStatus($directController, 404, 'undeclared direct controller path');

    $publicCallback = $request('POST', 'verify/callback', null, ['ticket' => '']);
    $expectStatus($publicCallback, 400, 'public callback remains reachable without API key');

    $publicStatus = $request('GET', 'verify/status/does-not-exist');
    $expectStatus($publicStatus, 404, 'public status remains reachable without API key');

    $publicPage = $request('GET', 'v/does-not-exist');
    $assert($publicPage['status'] !== 401, 'public verification page must not be protected by API auth');

    $crossKey = $request('POST', 'verify/check', $keys['bot-two'], ['group_id' => '10001', 'user_id' => '20001', 'code' => 'CROSS1']);
    $expectStatus($crossKey, 400, 'cross-key verification must fail');
    $usedAfterCrossKey = (int)$pdo->query("SELECT used FROM GeetestTable WHERE code = 'CROSS1'")->fetchColumn();
    $assert($usedAfterCrossKey === 0, 'cross-key failure must not consume another key\'s verification code');

    $legacyOwner = $request('POST', 'verify/check', $keys['bot-one'], ['group_id' => '10002', 'user_id' => '20003', 'code' => 'LEGACY1']);
    $expectStatus($legacyOwner, 400, 'legacy API-key-less verification record must not be accepted');
    $legacyUsed = (int)$pdo->query("SELECT used FROM GeetestTable WHERE code = 'LEGACY1'")->fetchColumn();
    $assert($legacyUsed === 0, 'legacy API-key-less verification record must not be consumed');

    $wrongUser = $request('POST', 'verify/check', $keys['bot-one'], ['group_id' => '10001', 'user_id' => '29999', 'code' => 'USER1']);
    $expectStatus($wrongUser, 400, 'wrong-user verification must fail');
    $usedAfterWrongUser = (int)$pdo->query("SELECT used FROM GeetestTable WHERE code = 'USER1'")->fetchColumn();
    $assert($usedAfterWrongUser === 0, 'wrong-user failure must not consume the code');

    $missingUser = $request('POST', 'verify/check', $keys['bot-one'], ['group_id' => '10001', 'code' => 'CROSS1']);
    $expectStatus($missingUser, 400, 'user_id is required for verification');

    $validCheck = $request('POST', 'verify/check', $keys['bot-one'], ['group_id' => '10001', 'user_id' => '20001', 'code' => 'CROSS1']);
    $expectStatus($validCheck, 200, 'matching API key, group and user verification');
    $expectPassed($validCheck, true, 'matching verification');
    $usedAfterSuccess = (int)$pdo->query("SELECT used FROM GeetestTable WHERE code = 'CROSS1'")->fetchColumn();
    $assert($usedAfterSuccess === 1, 'successful verification must consume its own code');

    $replay = $request('POST', 'verify/check', $keys['bot-one'], ['group_id' => '10001', 'user_id' => '20001', 'code' => 'CROSS1']);
    $expectStatus($replay, 400, 'already used verification code');

    $ordinaryAdmin = $request('GET', 'admin/settings', $keys['bot-one']);
    $expectStatus($ordinaryAdmin, 403, 'ordinary API key cannot access admin settings');

    $defaultAdmin = $request('GET', 'admin/settings', $keys['default']);
    $expectStatus($defaultAdmin, 200, 'default API key retains admin settings access');

    $noKeyAdmin = $request('GET', 'admin/settings');
    $expectStatus($noKeyAdmin, 401, 'admin settings without API key');

    $create = $request('POST', 'verify/create', $keys['bot-one'], ['group_id' => '10001', 'user_id' => '28888']);
    $expectStatus($create, 200, 'ordinary API key retains robot create access');
    $createdTicket = (string)($create['json']['data']['ticket'] ?? '');
    $createdOwner = $pdo->prepare('SELECT api_key_id FROM GeetestTable WHERE token = ?');
    $createdOwner->execute([$createdTicket]);
    $assert((int)$createdOwner->fetchColumn() === 2, 'new verification record must retain API key ownership');
    $createdOwner->closeCursor();

    $defaultBot = $request('POST', 'verify/create', $keys['default'], ['group_id' => '10001', 'user_id' => '29998']);
    $expectStatus($defaultBot, 200, 'default API key retains robot create access');
    $defaultTicket = (string)($defaultBot['json']['data']['ticket'] ?? '');
    $defaultOwner = $pdo->prepare('SELECT api_key_id FROM GeetestTable WHERE token = ?');
    $defaultOwner->execute([$defaultTicket]);
    $assert((int)$defaultOwner->fetchColumn() === 1, 'default robot request must retain default API key ownership');
    $defaultOwner->closeCursor();

    if ($createdTicket !== '') {
        $statusForTicket = $request('GET', 'verify/status/' . $createdTicket);
        $expectStatus($statusForTicket, 200, 'status remains public for a valid ticket');
    }

    if ($createdTicket !== '') {
        $callback = $request('POST', 'verify/callback', null, [
            'ticket' => $createdTicket, 'lot_number' => 'fixture-lot',
            'captcha_output' => 'fixture-output', 'pass_token' => 'fixture-pass', 'gen_time' => (string)$now,
        ]);
        $expectStatus($callback, 200, 'successful Geetest callback with vendor HTTP fixture');
        $callbackCode = (string)($callback['json']['data']['code'] ?? '');
        $assert(strlen($callbackCode) === 6, 'callback generates a six-character verification code');
        $callbackCheck = $request('POST', 'verify/check', $keys['bot-one'], [
            'group_id' => '10001', 'user_id' => '28888', 'code' => $callbackCode,
        ]);
        $expectStatus($callbackCheck, 200, 'callback code can be consumed by its owning bot');
        $expectPassed($callbackCheck, true, 'callback end-to-end check');
        $callbackReplay = $request('POST', 'verify/check', $keys['bot-one'], [
            'group_id' => '10001', 'user_id' => '28888', 'code' => $callbackCode,
        ]);
        $expectStatus($callbackReplay, 400, 'callback code cannot be reused');
    }

    foreach ([
        'http://gcaptcha4.geetest.com',
        'https://gcaptcha4.geetest.com.evil.example',
        'https://unlisted-gateway.example.test',
    ] as $unsafeEndpoint) {
        $unsafeUpdate = $request('PUT', 'admin/settings', $keys['default'], [], json_encode(['values' => ['GEETEST_API_SERVER' => $unsafeEndpoint]], JSON_THROW_ON_ERROR));
        $expectStatus($unsafeUpdate, 400, 'web settings reject unsafe Geetest endpoint ' . $unsafeEndpoint);
    }

    $safeUpdate = $request('PUT', 'admin/settings', $keys['default'], [], json_encode(['values' => ['GEETEST_API_SERVER' => 'https://gateway.example.test']], JSON_THROW_ON_ERROR));
    $expectStatus($safeUpdate, 200, 'web settings accept server-local allowlisted HTTPS gateway');
    $storedEndpoint = (string)$pdo->query("SELECT value FROM settings WHERE name = 'GEETEST_API_SERVER'")->fetchColumn();
    $assert($storedEndpoint === 'https://gateway.example.test', 'allowlisted endpoint should be stored after a valid admin update');

    // Simulate configuration drift outside the web UI. The model must fail
    // closed and avoid an outbound request to an unauthorized endpoint.
    $pdo->exec("UPDATE settings SET value = 'https://unlisted-gateway.example.test' WHERE name = 'GEETEST_API_SERVER'");
    $insertPendingTicket = $pdo->prepare(<<<'SQL'
INSERT INTO GeetestTable
    (api_key_id, token, group_id, user_id, code, verified, used, expire_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, NULL, 0, 0, ?, ?, ?)
SQL);
    $insertPendingTicket->execute([2, 'ticket-invalid-endpoint', '10001', '20003', $now + 3600, $now, $now]);
    $invalidEndpointCallback = $request('POST', 'verify/callback', null, [
        'ticket' => 'ticket-invalid-endpoint',
        'lot_number' => 'invalid-lot',
        'captcha_output' => 'invalid-output',
        'pass_token' => 'invalid-pass',
        'gen_time' => (string)$now,
    ]);
    $expectStatus($invalidEndpointCallback, 400, 'invalid stored Geetest endpoint must fail closed');
} catch (Throwable $e) {
    $failures[] = 'unexpected test exception: ' . $e::class . ': ' . $e->getMessage();
    if (is_file($serverLog)) {
        $log = trim((string)file_get_contents($serverLog));
        if ($log !== '') {
            $failures[] = 'temporary HTTP server log: ' . $log;
        }
    }
} finally {
    if (is_resource($serverProcess)) {
        if (PHP_OS_FAMILY === 'Windows' && $serverPid > 0) {
            $taskkillOutput = [];
            $taskkillCode = 0;
            @exec('taskkill /PID ' . $serverPid . ' /T /F', $taskkillOutput, $taskkillCode);
        }
        @proc_terminate($serverProcess);
        @proc_close($serverProcess);
    }
    $insertKey = null;
    $insertSetting = null;
    $insertTicket = null;
    $insertLegacyTicket = null;
    $insertPendingTicket = null;
    $createdOwner = null;
    $defaultOwner = null;
    $pdo = null;
    $removeTree($runtime);
}

if ($failures) {
    fwrite(STDERR, implode(PHP_EOL, array_map(static fn(string $failure): string => 'FAIL: ' . $failure, $failures)) . PHP_EOL);
    exit(1);
}

fwrite(STDOUT, "PR1 HTTP security integration checks passed\n");
