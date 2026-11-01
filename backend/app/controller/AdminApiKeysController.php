<?php
namespace app\controller;

use app\BaseController;
use app\traits\ApiKeyTrait;
use think\facade\Db;

class AdminApiKeysController extends BaseController
{
    use ApiKeyTrait;

    /**
     * 管理控制器不能只依赖 route/app.php 的路由中间件。
     * 直接访问控制器动作时也必须使用默认 API Key。
     */
    protected $middleware = [
        \app\middleware\AdminApiKeyAuth::class,
    ];

    public function list()
    {
        $this->ensureApiKeysMigrated();
        $defaultId = $this->getDefaultApiKeyId();

        $sid = '';
        try {
            $sid = trim((string)$this->request->get('id', ''));
        } catch (\Throwable $e) {
            $sid = '';
        }
        $filterId = 0;
        if ($sid !== '') {
            if (!ctype_digit($sid)) {
                return json(['code' => 400, 'msg' => '参数错误'], 400);
            }
            $filterId = (int)$sid;
        }

        try {
            $query = Db::name('api_keys');
            if ($filterId > 0) {
                $query = $query->where('id', $filterId);
            }
            $rows = $query->order('id', 'desc')->select()->toArray();
        } catch (\Throwable $e) {
            $rows = [];
        }

        $items = [];
        foreach ($rows ?: [] as $r) {
            $id = (int)($r['id'] ?? 0);
            $h = (string)($r['hash'] ?? '');
            $items[] = [
                'id' => $id,
                'is_default' => $defaultId > 0 && $id === $defaultId,
                'masked' => $h !== '' ? ('Key#' . $id . ' (' . mb_substr($h, 0, 4) . '...' . mb_substr($h, -4) . ')') : '',
                'created_at' => (int)($r['created_at'] ?? 0),
                'updated_at' => (int)($r['updated_at'] ?? 0),
            ];
        }

        return json(['code' => 0, 'msg' => 'success', 'data' => ['items' => $items]]);
    }

    public function create()
    {
        $this->ensureApiKeysMigrated();
        $body = $this->getJsonBody();
        $value = trim((string)($body['value'] ?? ''));

        if ($value === '') {
            try {
                $value = bin2hex(random_bytes(32));
            } catch (\Throwable $e) {
                $value = hash('sha256', uniqid('api_key', true) . microtime(true));
            }
        }

        if (mb_strlen($value) < 16) {
            return json(['code' => 400, 'msg' => '密钥长度至少 16 位'], 400);
        }

        $keyHash = hash('sha256', $value);
        $ts = time();
        try {
            Db::name('api_keys')->insert([
                'hash' => $keyHash,
                'created_at' => $ts,
                'updated_at' => $ts,
            ]);
        } catch (\Throwable $e) {
            try {
                $exists = Db::name('api_keys')->where('hash', $keyHash)->value('id');
                if ($exists !== null) {
                    return json(['code' => 409, 'msg' => '密钥已存在'], 409);
                }
            } catch (\Throwable $e2) {
            }
            return json(['code' => 500, 'msg' => '创建失败'], 500);
        }

        $id = 0;
        try {
            $id = (int)Db::name('api_keys')->where('hash', $keyHash)->value('id');
        } catch (\Throwable $e) {
        }

        return json([
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'id' => $id,
                'value' => $value,
                'masked' => $this->maskSecret($value),
                'created_at' => $ts,
                'updated_at' => $ts,
            ],
        ])->header(['Cache-Control' => 'no-store']);
    }

    public function delete($id = '')
    {
        $this->ensureApiKeysMigrated();
        $sid = trim((string)$id);
        if ($sid === '' || !ctype_digit($sid)) {
            return json(['code' => 400, 'msg' => '参数错误'], 400);
        }

        $defaultId = $this->getDefaultApiKeyId();
        if ($defaultId > 0 && (int)$sid === $defaultId) {
            return json(['code' => 403, 'msg' => '当前使用的 API Key 不可删除'], 403);
        }

        $n = 0;
        try {
            $n = (int)Db::name('api_keys')->where('id', (int)$sid)->delete();
        } catch (\Throwable $e) {
            $n = 0;
        }

        if ($n <= 0) {
            return json(['code' => 404, 'msg' => '不存在'], 404);
        }

        return json(['code' => 0, 'msg' => 'success', 'data' => ['deleted' => $n]]);
    }

    public function reset($id = '')
    {
        $this->ensureApiKeysMigrated();
        $sid = trim((string)$id);
        if ($sid === '' || !ctype_digit($sid)) {
            return json(['code' => 400, 'msg' => '参数错误'], 400);
        }

        $targetId = (int)$sid;
        if ($targetId <= 0) {
            return json(['code' => 400, 'msg' => '参数错误'], 400);
        }

        $newValue = '';
        $updated = 0;
        $ts = time();
        for ($i = 0; $i < 3; $i++) {
            try {
                try {
                    $newValue = bin2hex(random_bytes(32));
                } catch (\Throwable $e) {
                    $newValue = hash('sha256', uniqid('api_key', true) . microtime(true) . $i);
                }

                $newHash = hash('sha256', $newValue);
                $updated = (int)Db::name('api_keys')->where('id', $targetId)->update([
                    'hash' => $newHash,
                    'updated_at' => $ts,
                ]);
                if ($updated > 0) {
                    break;
                }
            } catch (\Throwable $e) {
                $updated = 0;
            }
        }

        if ($updated <= 0 || $newValue === '') {
            return json(['code' => 500, 'msg' => '重置失败'], 500);
        }

        self::$traitCachedDefaultIdAt = 0;
        \app\middleware\ApiAuth::clearCache();

        return json([
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'id' => $targetId,
                'value' => $newValue,
                'masked' => $this->maskSecret($newValue),
                'updated_at' => $ts,
            ],
        ])->header(['Cache-Control' => 'no-store']);
    }
}
