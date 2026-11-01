<?php

namespace app\support;

/** Local-only setup capability. Plaintext credentials are never persisted. */
class SetupToken
{
    private string $root;

    public function __construct(string $root)
    {
        $this->root = rtrim($root, '/\\') . DIRECTORY_SEPARATOR;
    }

    public function lock()
    {
        $handle = fopen($this->root . '.setup.lock', 'c');
        if ($handle === false || !flock($handle, LOCK_EX)) {
            if (is_resource($handle)) { fclose($handle); }
            throw new \RuntimeException('无法锁定安装状态');
        }
        @chmod($this->root . '.setup.lock', 0600);
        return $handle;
    }

    public function installed(): bool
    {
        if (file_exists($this->root . '.env') || file_exists($this->root . '.installed')) {
            return true;
        }
        // Also refuse reinstallation if .env was removed from an existing deployment.
        $paths = glob($this->root . 'database/*.db') ?: [];
        $paths[] = $this->root . 'sqlite.db';
        $paths[] = $this->root . 'geetest.db';
        foreach ($paths as $path) {
            if (!is_file($path)) { continue; }
            try {
                $pdo = new \PDO('sqlite:' . $path);
                if ((int)$pdo->query('SELECT COUNT(*) FROM settings')->fetchColumn() > 0) {
                    return true;
                }
            } catch (\Throwable $e) {
                // Unrelated or empty SQLite files must never be overwritten by setup.
            }
        }
        return false;
    }

    /** Caller must hold lock() through generation/installation. */
    public function generate(): string
    {
        $this->recover();
        if ($this->installed()) {
            throw new \RuntimeException('系统已初始化，不能生成安装凭据');
        }
        $token = bin2hex(random_bytes(32));
        $this->atomicWrite($this->root . '.setup-token.json', json_encode([
            'hash' => hash('sha256', $token),
            'expires_at' => time() + 1800,
        ], JSON_THROW_ON_ERROR));
        return $token;
    }

    public function active(): bool
    {
        $state = $this->state();
        return $state !== null && $state['expires_at'] > time();
    }

    public function matches(string $token): bool
    {
        $state = $this->state();
        return preg_match('/\A[a-f0-9]{64}\z/D', $token) === 1
            && $state !== null && $state['expires_at'] > time()
            && hash_equals($state['hash'], hash('sha256', $token));
    }

    /** Prepare an authorized installation so a process crash can be resumed. */
    public function prepare(string $database, string $environment, string $filename): void
    {
        if (!preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\.db\z/D', $filename)) {
            throw new \RuntimeException('无效安装路径');
        }
        $this->atomicWrite($this->root . '.setup-progress.json', json_encode([
            'database' => basename($database), 'environment' => basename($environment),
            'filename' => $filename,
            'database_hash' => hash_file('sha256', $database),
            'environment_hash' => hash_file('sha256', $environment),
        ], JSON_THROW_ON_ERROR));
    }

    /** Caller holds lock(); only an already authorized, fully staged install is resumed. */
    public function recover(): void
    {
        $journal = $this->root . '.setup-progress.json';
        if (!is_file($journal)) { return; }
        $state = json_decode((string)file_get_contents($journal), true);
        foreach (['database', 'environment'] as $field) {
            if (!is_string($state[$field] ?? null)
                || preg_match('/\A(?:\.setup-[a-zA-Z0-9]+|\.se[a-fA-F0-9]+\.tmp)\z/D', $state[$field]) !== 1) {
                throw new \RuntimeException('安装恢复状态无效');
            }
        }
        if (!is_string($state['filename'] ?? null)
            || preg_match('/\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\.db\z/D', $state['filename']) !== 1) {
            throw new \RuntimeException('安装恢复路径无效');
        }
        $directory = realpath($this->root . 'database');
        if ($directory === false || dirname($directory) !== realpath($this->root)) {
            throw new \RuntimeException('安装恢复路径越界');
        }
        $database = $directory . DIRECTORY_SEPARATOR . $state['filename'];
        $stagedDatabase = $directory . DIRECTORY_SEPARATOR . $state['database'];
        $stagedEnvironment = $this->root . $state['environment'];
        $environment = $this->root . '.env';
        $environmentExists = file_exists($environment);
        $environmentSource = $environmentExists ? $environment : $stagedEnvironment;
        if (!is_file($environmentSource) || is_link($environmentSource)
            || !hash_equals((string)($state['environment_hash'] ?? ''), hash_file('sha256', $environmentSource))) {
            throw new \RuntimeException('安装恢复配置不完整或已有配置不属于此次安装');
        }
        if (is_link($database) || is_link($stagedDatabase)) {
            throw new \RuntimeException('安装恢复文件无效');
        }
        if (file_exists($database)) {
            if (!is_file($database) || !hash_equals((string)($state['database_hash'] ?? ''), hash_file('sha256', $database))) {
                throw new \RuntimeException('已有数据库不属于此次安装，拒绝覆盖');
            }
        } else {
            if (!is_file($stagedDatabase)
                || !hash_equals((string)($state['database_hash'] ?? ''), hash_file('sha256', $stagedDatabase))
                || !@link($stagedDatabase, $database)) {
                throw new \RuntimeException('无法恢复数据库发布');
            }
        }
        if (!$environmentExists && !@link($stagedEnvironment, $environment)) {
            throw new \RuntimeException('无法恢复配置发布');
        }
        $this->consume();
        @file_put_contents($this->root . '.installed', "installed\n", LOCK_EX);
        @unlink($stagedDatabase);
        @unlink($stagedEnvironment);
        $this->discardPending();
    }

    public function discardPending(): void
    {
        @unlink($this->root . '.setup-progress.json');
    }

    public function consume(): void
    {
        // .env independently closes the entry even if unlink fails.
        @unlink($this->root . '.setup-token.json');
    }

    private function state(): ?array
    {
        $raw = @file_get_contents($this->root . '.setup-token.json');
        if ($raw === false) { return null; }
        $state = json_decode($raw, true);
        if (!is_array($state) || !is_string($state['hash'] ?? null)
            || preg_match('/\A[a-f0-9]{64}\z/D', $state['hash']) !== 1
            || !is_int($state['expires_at'] ?? null)) {
            return null;
        }
        return $state;
    }

    private function atomicWrite(string $path, string $contents): void
    {
        $temp = tempnam($this->root, '.setup-');
        if ($temp === false) { throw new \RuntimeException('无法创建安装凭据文件'); }
        try {
            @chmod($temp, 0600);
            if (file_put_contents($temp, $contents) !== strlen($contents) || !rename($temp, $path)) {
                throw new \RuntimeException('无法保存安装凭据');
            }
        } finally {
            if (is_file($temp)) { @unlink($temp); }
        }
    }
}
