<?php
// Native SQLite + real controller tests; no test framework or production data required.
require dirname(__DIR__) . '/vendor/autoload.php';
require_once dirname(__DIR__) . '/vendor/topthink/framework/src/helper.php';

use app\controller\Index;
use app\support\SetupToken;
use think\App;

function check(bool $ok, string $label): void {
    if (!$ok) { throw new RuntimeException($label); }
    echo "PASS $label\n";
}
function fixture(): string {
    $root = dirname(__DIR__) . '/runtime/setup-test-' . bin2hex(random_bytes(6)) . '/';
    mkdir($root . 'database/migrations', 0775, true);
    mkdir($root . 'runtime');
    copy(dirname(__DIR__) . '/database/migrations/Geetest_Table.sql', $root . 'database/migrations/Geetest_Table.sql');
    return $root;
}
function callSetup(string $root, array $post = [], array $get = []) {
    $app = new App($root);
    // Load the server-owned policy while keeping state in the isolated fixture.
    foreach (glob(dirname(__DIR__) . '/config/*.php') ?: [] as $config) {
        if (basename($config) === 'database.php') { continue; }
        $app->config->set(include $config, pathinfo($config, PATHINFO_FILENAME));
    }
    $app->request->setMethod($post ? 'POST' : 'GET')->withPost($post)->withGet($get);
    return (new Index($app))->setup();
}
function values(string $token, string $filename = 'sqlite.db'): array {
    return ['setup_token' => $token, 'geetest_captcha_id' => 'test-id',
        'geetest_captcha_key' => 'test-secret', 'geetest_api_server' => 'https://gcaptcha4.geetest.com',
        'geetest_code_expire' => '300', 'api_key' => str_repeat('a', 32),
        'salt' => str_repeat('s', 64), 'app_debug' => 'false', 'db_sqlite_path' => $filename];
}
function status($result): int { return $result instanceof \think\Response ? $result->getCode() : 200; }
function issue(string $root): string {
    $tokens = new SetupToken($root); $lock = $tokens->lock();
    try { return $tokens->generate(); } finally { flock($lock, LOCK_UN); fclose($lock); }
}
function cleanup(string $root): void {
    $base = realpath(dirname(__DIR__) . '/runtime');
    $resolved = realpath($root);
    if ($resolved === false || !str_starts_with($resolved, $base . DIRECTORY_SEPARATOR . 'setup-test-')) {
        throw new RuntimeException('Refusing out-of-fixture cleanup');
    }
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) {
        if ($file->isDir() && !$file->isLink()) { rmdir($file->getPathname()); }
        else { unlink($file->getPathname()); }
    }
    rmdir($root);
}
if (($argv[1] ?? '') === '--install-worker') {
    $result = callSetup($argv[2], values($argv[3]));
    echo status($result) . ':' . (is_string($result) && str_contains($result, '初始化成功') ? 'success' : 'closed');
    exit;
}
$fixtures = [];
try {
    $cli = $fixtures[] = fixture();
    mkdir($cli . 'config');
    foreach (glob(dirname(__DIR__) . '/config/*.php') as $config) {
        copy($config, $cli . 'config/' . basename($config));
    }
    $cliApp = new App($cli);
    $output = $cliApp->console->call('setup:token')->fetch();
    preg_match_all('/^[a-f0-9]{64}$/m', $output, $matches);
    check(count($matches[0]) === 1 && (new SetupToken($cli))->matches($matches[0][0]), 'real setup:token command emits one usable credential');
    $oldCliToken = $matches[0][0];
    $output = $cliApp->console->call('setup:token')->fetch();
    check(!(new SetupToken($cli))->matches($oldCliToken), 'issuing another credential invalidates previous one');
    unset($output, $matches, $oldCliToken);
    $root = $fixtures[] = fixture();
    check(status(callSetup($root)) === 404, 'setup hidden without local token');
    $token = issue($root);
    check(strlen($token) === 64 && !str_contains(file_get_contents($root . '.setup-token.json'), $token), '32 random bytes, hash-only persistence');
    $form = callSetup($root);
    check(status($form) === 200, 'active token enables form');
    check(!preg_match('/name="(?:api_key|salt|geetest_captcha_key)" value="[^"]+"/', $form) && !str_contains($form, $root), 'GET does not disclose credentials or server paths');
    check(status(callSetup($root, ['setup_token' => 'wrong'])) === 403, 'incorrect credential refused');
    check(status(callSetup($root, ['db_sqlite_path' => 'sqlite.db'], ['setup_token' => $token])) === 403, 'URL credential cannot authorize POST');
    $state = json_decode(file_get_contents($root . '.setup-token.json'), true);
    $state['expires_at'] = time() - 1;
    file_put_contents($root . '.setup-token.json', json_encode($state));
    check(status(callSetup($root, values($token))) === 404, 'expired token closes installer');
    $token = issue($root);
    foreach (['../escape.db', '/tmp/escape.db', 'C:\\escape.db', 'nested/file.db', 'file.php', 'file.db.php', 'file.DB', '.hidden.db', 'file.db/'] as $name) {
        $result = callSetup($root, values($token, $name));
        check(is_string($result) && str_contains($result, '只能是安全文件名') && !file_exists($root . '.env'), 'reject path ' . $name);
    }
    file_put_contents($root . 'database/existing.db', 'existing data');
    $before = hash_file('sha256', $root . 'database/existing.db');
    callSetup($root, values($token, 'existing.db'));
    check(hash_file('sha256', $root . 'database/existing.db') === $before && (new SetupToken($root))->matches($token), 'existing database preserved and token reusable');
    // A failing migration cannot publish configuration or damage another database.
    $migration = file_get_contents($root . 'database/migrations/Geetest_Table.sql');
    file_put_contents($root . 'database/migrations/Geetest_Table.sql', 'THIS IS INVALID SQL;');
    callSetup($root, values($token));
    check(!file_exists($root . '.env') && !file_exists($root . 'database/sqlite.db') && (new SetupToken($root))->matches($token), 'initialization failure is retryable');
    check(hash_file('sha256', $root . 'database/existing.db') === $before, 'failed setup preserves existing data');
    file_put_contents($root . 'database/migrations/Geetest_Table.sql', $migration);
    $result = callSetup($root, values($token));
    check(is_string($result) && str_contains($result, '初始化成功'), 'retry completes SQLite initialization');
    check(str_contains(file_get_contents($root . '.env'), './database/sqlite.db'), 'atomic final configuration references contained database');
    $pdo = new PDO('sqlite:' . $root . 'database/sqlite.db');
    check((int)$pdo->query('SELECT COUNT(*) FROM settings')->fetchColumn() > 0 && (int)$pdo->query('SELECT COUNT(*) FROM api_keys')->fetchColumn() === 1, 'settings and hashed admin key persisted');
    $pdo = null;
    check(!(new SetupToken($root))->active() && status(callSetup($root, values($token))) === 404, 'success consumes token and replay is closed');
    unlink($root . '.env');
    check(status(callSetup($root)) === 404, 'deleted configuration does not permit reinitialization');
    $rejected = false;
    try { issue($root); } catch (RuntimeException $e) { $rejected = true; }
    check($rejected, 'installed deployment cannot issue another credential');

    $legacy = $fixtures[] = fixture();
    $legacyPdo = new PDO('sqlite:' . $legacy . 'geetest.db');
    $legacyPdo->exec("CREATE TABLE settings (name TEXT, value TEXT); INSERT INTO settings VALUES ('existing', 'keep')");
    $legacyPdo = null;
    check((new SetupToken($legacy))->installed(), 'legacy root geetest.db prevents reinstallation');

    foreach ([false, true] as $publishBeforeCrash) {
        $crash = $fixtures[] = fixture();
        $crashToken = issue($crash);
        $stagedDb = tempnam($crash . 'database', '.setup-');
        $stagedEnv = tempnam($crash, '.setup-');
        $crashPdo = new PDO('sqlite:' . $stagedDb);
        $crashPdo->exec("CREATE TABLE settings (name TEXT, value TEXT); INSERT INTO settings VALUES ('existing', 'keep')");
        $crashPdo = null;
        file_put_contents($stagedEnv, "DB_DRIVER = sqlite\nDB_PATH = ./database/sqlite.db\n");
        $crashTokens = new SetupToken($crash);
        $crashLock = $crashTokens->lock();
        $crashTokens->prepare($stagedDb, $stagedEnv, 'sqlite.db');
        if ($publishBeforeCrash) { link($stagedDb, $crash . 'database/sqlite.db'); }
        flock($crashLock, LOCK_UN); fclose($crashLock);
        // Equivalent durable disk state to SIGKILL at either publication boundary.
        check(status(callSetup($crash)) === 404
            && file_exists($crash . '.env') && file_exists($crash . 'database/sqlite.db')
            && !file_exists($crash . '.setup-progress.json')
            && !$crashTokens->active(), 'crash journal resumes authorized publication (' . ($publishBeforeCrash ? 'database published' : 'fully staged') . ')');
    }

    $conflict = $fixtures[] = fixture();
    $conflictToken = issue($conflict);
    $conflictDb = tempnam($conflict . 'database', '.setup-');
    $conflictEnv = tempnam($conflict, '.setup-');
    file_put_contents($conflictDb, 'staged-database');
    file_put_contents($conflictEnv, 'intended-configuration');
    $conflictTokens = new SetupToken($conflict);
    $conflictTokens->prepare($conflictDb, $conflictEnv, 'sqlite.db');
    file_put_contents($conflict . '.env', 'pre-existing-configuration');
    check(status(callSetup($conflict)) === 503
        && file_get_contents($conflict . '.env') === 'pre-existing-configuration'
        && is_file($conflict . '.setup-progress.json') && is_file($conflictDb)
        && $conflictTokens->matches($conflictToken)
        && !is_file($conflict . '.installed'), 'conflicting final configuration preserves recovery state and token');
    file_put_contents($conflict . '.env', 'intended-configuration');
    check(status(callSetup($conflict)) === 404
        && file_get_contents($conflict . 'database/sqlite.db') === 'staged-database'
        && !is_file($conflict . '.setup-progress.json'), 'matching final configuration still requires database recovery before consume');

    $parallel = $fixtures[] = fixture();
    $parallelToken = issue($parallel);
    $lock = (new SetupToken($parallel))->lock();
    $processes = [];
    for ($i = 0; $i < 2; $i++) {
        $pipes = [];
        $proc = proc_open([PHP_BINARY, __FILE__, '--install-worker', $parallel, $parallelToken], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) { throw new RuntimeException('Cannot start concurrency worker'); }
        fclose($pipes[0]); $processes[] = [$proc, $pipes];
    }
    usleep(200000);
    check(!file_exists($parallel . '.env'), 'workers cannot initialize while setup lock is held');
    flock($lock, LOCK_UN); fclose($lock);
    $outputs = [];
    foreach ($processes as [$proc, $pipes]) {
        $outputs[] = trim(stream_get_contents($pipes[1]));
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        if (proc_close($proc) !== 0 || $errors !== '') { throw new RuntimeException('Concurrent worker failed: ' . $errors); }
    }
    sort($outputs);
    check($outputs === ['200:success', '404:closed'], 'concurrent installation permits exactly one success');
    echo "Setup security checks passed.\n";
} catch (Throwable $e) {
    $failure = $e;
} finally {
    foreach ($fixtures as $root) { cleanup($root); }
}
if (isset($failure)) {
    fwrite(STDERR, "FAIL " . $failure->getMessage() . "\n");
    exit(1);
}
