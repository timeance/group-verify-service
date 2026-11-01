<?php
namespace app\controller;

use app\BaseController;
use app\model\GeetestModel;
use app\support\GeetestEndpoint;
use app\traits\ApiKeyTrait;
use think\facade\Db;

class AdminSettingsController extends BaseController
{
    use ApiKeyTrait;

    /**
     * 管理控制器不能只依赖 route/app.php 的路由中间件。
     * 直接访问控制器动作时也必须使用默认 API Key。
     */
    protected $middleware = [
        \app\middleware\AdminApiKeyAuth::class,
    ];

    protected function getSettingWithFallback(string $key, string $default = ''): array
    {
        $v = $this->getSettingRaw($key);
        if ($v !== null) {
            return ['value' => $v, 'source' => 'DB'];
        }

        $envValue = env($key, null);
        if ($envValue !== null) {
            $sv = (string)$envValue;
            $this->upsertSetting($key, $sv);
            return ['value' => $sv, 'source' => 'ENV'];
        }

        return ['value' => $default, 'source' => 'DEFAULT'];
    }

    protected function maskSecretList(string $value): string
    {
        $keys = $this->parseApiKeys($value);
        if (!$keys) {
            return $this->maskSecret($value);
        }
        $masked = [];
        foreach ($keys as $k) {
            $masked[] = $this->maskSecret((string)$k);
        }
        return implode('，', $masked);
    }

    protected function readApiKeysFromTable(): array
    {
        $this->ensureApiKeysReady();
        try {
            $rows = Db::name('api_keys')->column('hash');
            $hashes = [];
            foreach ($rows ?: [] as $h) {
                $k = trim((string)$h);
                if ($k === '') {
                    continue;
                }
                $hashes[$k] = true;
            }
            return array_keys($hashes);
        } catch (\Throwable $e) {
            return [];
        }
    }

    protected function writeApiKeysToTable(array $keys, bool $replaceAll): int
    {
        $this->ensureApiKeysReady();
        $ts = time();
        $failed = 0;

        if ($replaceAll) {
            Db::startTrans();
            try {
                Db::name('api_keys')->delete(true);

                foreach ($keys as $v) {
                    $k = trim((string)$v);
                    if ($k === '') {
                        continue;
                    }
                    try {
                        Db::name('api_keys')->insert([
                            'hash' => hash('sha256', $k),
                            'created_at' => $ts,
                            'updated_at' => $ts,
                        ]);
                    } catch (\Throwable $e) {
                        $failed++;
                    }
                }

                if ($failed >= count($keys)) {
                    Db::rollback();
                    return -1;
                }

                Db::commit();
            } catch (\Throwable $e) {
                Db::rollback();
                return -1;
            }
        } else {
            foreach ($keys as $v) {
                $k = trim((string)$v);
                if ($k === '') {
                    continue;
                }
                try {
                    Db::name('api_keys')->insert([
                        'hash' => hash('sha256', $k),
                        'created_at' => $ts,
                        'updated_at' => $ts,
                    ]);
                } catch (\Throwable $e) {
                    $failed++;
                }
            }
        }

        return $failed;
    }

    protected function whitelist(): array
    {
        return [
            ['key' => 'GEETEST_CAPTCHA_ID', 'label' => 'GEETEST_CAPTCHA_ID', 'secret' => false, 'type' => 'string'],
            ['key' => 'GEETEST_CAPTCHA_KEY', 'label' => 'GEETEST_CAPTCHA_KEY', 'secret' => true, 'type' => 'string'],
            ['key' => 'GEETEST_API_SERVER', 'label' => 'GEETEST_API_SERVER', 'secret' => false, 'type' => 'url'],
            ['key' => 'GEETEST_CODE_EXPIRE', 'label' => 'GEETEST_CODE_EXPIRE', 'secret' => false, 'type' => 'int'],
            ['key' => 'API_KEY', 'label' => 'API_KEY', 'secret' => true, 'type' => 'string'],
            ['key' => 'SALT', 'label' => 'SALT', 'secret' => true, 'type' => 'string'],
        ];
    }

    public function get()
    {
        $this->ensureApiKeysMigrated();

        $items = [];
        foreach ($this->whitelist() as $def) {
            $key = (string)$def['key'];
            if ($key === 'API_KEY') {
                $hashes = $this->readApiKeysFromTable();
                $count = count($hashes);
                $items[] = [
                    'key' => $key,
                    'label' => (string)($def['label'] ?? $key),
                    'is_set' => $count > 0,
                    'value' => '',
                    'masked' => $count > 0 ? ($count . ' 个密钥已配置') : '',
                    'source' => 'API_KEYS',
                ];
                continue;
            }

            $fallback = $key === 'GEETEST_API_SERVER' ? 'https://gcaptcha4.geetest.com' : ($key === 'GEETEST_CODE_EXPIRE' ? '300' : '');
            $read = $this->getSettingWithFallback($key, $fallback);
            $value = (string)($read['value'] ?? '');
            $source = (string)($read['source'] ?? 'DEFAULT');
            $secret = (bool)($def['secret'] ?? false);

            $items[] = [
                'key' => $key,
                'label' => (string)($def['label'] ?? $key),
                'is_set' => $value !== '',
                'value' => $secret ? '' : $value,
                'masked' => $secret ? ($value !== '' ? $this->maskSecret($value) : '') : '',
                'source' => $source,
            ];
        }

        return json(['code' => 0, 'msg' => 'success', 'data' => ['items' => $items]]);
    }

    public function update()
    {
        $this->ensureApiKeysMigrated();

        $body = $this->getJsonBody();
        $values = $body['values'] ?? null;
        if (!is_array($values)) {
            $values = $this->request->post('values');
        }
        if (!is_array($values)) {
            return json(['code' => 400, 'msg' => '参数错误'], 400);
        }

        $defs = [];
        foreach ($this->whitelist() as $def) {
            $defs[(string)$def['key']] = $def;
        }

        // 统一预处理参数：过滤、转换
        $parsed = [];
        foreach ($values as $key => $value) {
            $k = (string)$key;
            if (!isset($defs[$k])) {
                continue;
            }
            $v = is_string($value) ? $value : (is_null($value) ? '' : json_encode($value, JSON_UNESCAPED_UNICODE));
            $v = trim((string)$v);
            if ($v === '') {
                continue;
            }
            $parsed[$k] = $v;
        }

        // 验证
        $errors = [];
        foreach ($parsed as $k => $v) {
            $type = (string)($defs[$k]['type'] ?? 'string');
            if ($type === 'int') {
                if (!ctype_digit($v)) {
                    $errors[] = $k . ' 必须是整数';
                    continue;
                }
                $n = (int)$v;
                if ($k === 'GEETEST_CODE_EXPIRE' && ($n < 30 || $n > 3600)) {
                    $errors[] = $k . ' 建议在 30~3600 之间';
                    continue;
                }
            }
            if ($type === 'url') {
                if (!filter_var($v, FILTER_VALIDATE_URL)) {
                    $errors[] = $k . ' 不是合法 URL';
                    continue;
                }

                if ($k === 'GEETEST_API_SERVER' && !GeetestEndpoint::isAllowed($v)) {
                    $errors[] = $k . ' 必须使用 HTTPS 官方端点，或使用服务器本地 allowlist 中的端点';
                    continue;
                }
            }
            if ($k === 'API_KEY') {
                $keys = $this->parseApiKeys($v);
                if (!$keys) {
                    $errors[] = $k . ' 不能为空';
                    continue;
                }
                foreach ($keys as $one) {
                    if (mb_strlen((string)$one) < 16) {
                        $errors[] = $k . ' 每个密钥建议至少 16 位';
                        continue 2;
                    }
                }
            }
            if ($k === 'SALT' && mb_strlen($v) < 32) {
                $errors[] = $k . ' 建议至少 32 位';
                continue;
            }
        }

        if ($errors) {
            return json(['code' => 400, 'msg' => implode('；', $errors)], 400);
        }

        // 写入（复用已解析的数据）
        foreach ($parsed as $k => $v) {
            if ($k === 'API_KEY') {
                $keys = $this->parseApiKeys($v);
                if ($keys) {
                    $failed = $this->writeApiKeysToTable($keys, true);
                    if ($failed < 0) {
                        $errors[] = 'API_KEY 替换失败：无法清除旧密钥';
                    } elseif ($failed > 0) {
                        $errors[] = 'API_KEY 写入部分失败（' . $failed . ' 个）';
                        $this->deleteSetting('API_KEY');
                    } else {
                        $this->deleteSetting('API_KEY');
                    }
                }
                continue;
            }
            $this->upsertSetting($k, $v);
        }

        if ($errors) {
            GeetestModel::reloadConfig();
            return json(['code' => 207, 'msg' => implode('；', $errors)], 207);
        }

        GeetestModel::reloadConfig();
        return $this->get();
    }

    protected function safeCount(string $table, array $where = []): int
    {
        try {
            $q = Db::name($table);
            foreach ($where as $w) {
                if (!is_array($w) || count($w) < 3) {
                    continue;
                }
                $q = $q->where($w[0], $w[1], $w[2]);
            }
            return (int)$q->count();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    public function dashboard()
    {
        $this->ensureApiKeysMigrated();
        ensure_api_call_logs_table();

        $now = time();
        $from24h = $now - 86400;

        $apiKeysTotal = $this->safeCount('api_keys');
        $ticketsTotal = $this->safeCount('GeetestTable');
        $ticketsVerified = $this->safeCount('GeetestTable', [['verified', '=', 1]]);
        $ticketsUsed = $this->safeCount('GeetestTable', [['used', '=', 1]]);
        $ticketsPending = $this->safeCount('GeetestTable', [['verified', '=', 0], ['expire_at', '>', $now]]);
        $ticketsExpired = $this->safeCount('GeetestTable', [['expire_at', '<=', $now]]);

        $calls24h = $this->safeCount('api_call_logs', [['created_at', '>=', $from24h]]);
        $calls24hErr = $this->safeCount('api_call_logs', [['created_at', '>=', $from24h], ['status_code', '>=', 400]]);

        $callsByEndpoint = [];
        try {
            $rows = Db::name('api_call_logs')
                ->field('endpoint, COUNT(1) AS cnt')
                ->where('created_at', '>=', $from24h)
                ->group('endpoint')
                ->order('cnt', 'desc')
                ->limit(10)
                ->select()
                ->toArray();
            foreach ($rows ?: [] as $r) {
                $callsByEndpoint[] = [
                    'endpoint' => (string)($r['endpoint'] ?? ''),
                    'count' => (int)($r['cnt'] ?? 0),
                ];
            }
        } catch (\Throwable $e) {
            $callsByEndpoint = [];
        }

        $topGroups = [];
        try {
            $rows = Db::name('api_call_logs')
                ->field('group_id, COUNT(1) AS cnt')
                ->where('created_at', '>=', $from24h)
                ->where('group_id', '<>', '')
                ->group('group_id')
                ->order('cnt', 'desc')
                ->limit(10)
                ->select()
                ->toArray();
            foreach ($rows ?: [] as $r) {
                $gid = (string)($r['group_id'] ?? '');
                if ($gid === '') {
                    continue;
                }
                $topGroups[] = [
                    'group_id' => $gid,
                    'count' => (int)($r['cnt'] ?? 0),
                ];
            }
        } catch (\Throwable $e) {
            $topGroups = [];
        }

        $recentCalls = [];
        try {
            $rows = Db::name('api_call_logs')->order('id', 'desc')->limit(20)->select()->toArray();
            foreach ($rows ?: [] as $r) {
                $recentCalls[] = [
                    'id' => (int)($r['id'] ?? 0),
                    'created_at' => (int)($r['created_at'] ?? 0),
                    'api_key_id' => (int)($r['api_key_id'] ?? 0),
                    'endpoint' => (string)($r['endpoint'] ?? ''),
                    'method' => (string)($r['method'] ?? ''),
                    'status_code' => (int)($r['status_code'] ?? 0),
                    'group_id' => (string)($r['group_id'] ?? ''),
                    'user_id' => (string)($r['user_id'] ?? ''),
                    'ticket' => (string)($r['ticket'] ?? ''),
                    'code' => (string)($r['code'] ?? ''),
                    'duration_ms' => (int)($r['duration_ms'] ?? 0),
                ];
            }
        } catch (\Throwable $e) {
            $recentCalls = [];
        }

        return json([
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'now' => $now,
                'api_keys_total' => $apiKeysTotal,
                'tickets_total' => $ticketsTotal,
                'tickets_verified_total' => $ticketsVerified,
                'tickets_used_total' => $ticketsUsed,
                'tickets_pending' => $ticketsPending,
                'tickets_expired_total' => $ticketsExpired,
                'calls_24h_total' => $calls24h,
                'calls_24h_error' => $calls24hErr,
                'calls_24h_by_endpoint' => $callsByEndpoint,
                'calls_24h_top_groups' => $topGroups,
                'recent_calls' => $recentCalls,
            ],
        ]);
    }

    public function apiCallLogs()
    {
        $this->ensureApiKeysMigrated();
        ensure_api_call_logs_table();

        $page = 1;
        $pageSize = 20;
        try {
            $page = (int)$this->request->get('page', 1);
            $pageSize = (int)$this->request->get('page_size', 20);
        } catch (\Throwable $e) {
            $page = 1;
            $pageSize = 20;
        }
        if ($page <= 0) {
            $page = 1;
        }
        if ($pageSize <= 0) {
            $pageSize = 20;
        }
        if ($pageSize > 200) {
            $pageSize = 200;
        }

        $from = 0;
        $to = 0;
        $apiKeyId = 0;
        $statusCode = 0;
        $endpoint = '';
        $groupId = '';
        $userId = '';
        try {
            $from = (int)$this->request->get('from', 0);
            $to = (int)$this->request->get('to', 0);
            $apiKeyId = (int)$this->request->get('api_key_id', 0);
            $statusCode = (int)$this->request->get('status_code', 0);
            $endpoint = trim((string)$this->request->get('endpoint', ''));
            $groupId = trim((string)$this->request->get('group_id', ''));
            $userId = trim((string)$this->request->get('user_id', ''));
        } catch (\Throwable $e) {
        }

        try {
            $q = Db::name('api_call_logs');
            if ($from > 0) {
                $q = $q->where('created_at', '>=', $from);
            }
            if ($to > 0) {
                $q = $q->where('created_at', '<=', $to);
            }
            if ($apiKeyId > 0) {
                $q = $q->where('api_key_id', $apiKeyId);
            }
            if ($statusCode > 0) {
                $q = $q->where('status_code', $statusCode);
            }
            if ($endpoint !== '') {
                $escaped = addcslashes($endpoint, '%_');
                $q = $q->where('endpoint', 'like', '%' . $escaped . '%');
            }
            if ($groupId !== '') {
                $q = $q->where('group_id', $groupId);
            }
            if ($userId !== '') {
                $q = $q->where('user_id', $userId);
            }

            $total = (int)$q->count();
            $rows = $q->order('id', 'desc')->page($page, $pageSize)->select()->toArray();

            $items = [];
            foreach ($rows ?: [] as $r) {
                $items[] = [
                    'id' => (int)($r['id'] ?? 0),
                    'created_at' => (int)($r['created_at'] ?? 0),
                    'api_key_id' => (int)($r['api_key_id'] ?? 0),
                    'endpoint' => (string)($r['endpoint'] ?? ''),
                    'method' => (string)($r['method'] ?? ''),
                    'status_code' => (int)($r['status_code'] ?? 0),
                    'group_id' => (string)($r['group_id'] ?? ''),
                    'user_id' => (string)($r['user_id'] ?? ''),
                    'ticket' => (string)($r['ticket'] ?? ''),
                    'code' => (string)($r['code'] ?? ''),
                    'ip' => (string)($r['ip'] ?? ''),
                    'user_agent' => (string)($r['user_agent'] ?? ''),
                    'duration_ms' => (int)($r['duration_ms'] ?? 0),
                ];
            }

            return json(['code' => 0, 'msg' => 'success', 'data' => ['items' => $items, 'total' => $total, 'page' => $page, 'page_size' => $pageSize]]);
        } catch (\Throwable $e) {
            return json(['code' => 500, 'msg' => '加载失败'], 500);
        }
    }
}
