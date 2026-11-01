<?php
namespace app\model;

use app\support\GeetestEndpoint;
use think\facade\Request;
use think\facade\Db;

class GeetestModel
{
    protected static string $captchaId;
    protected static string $captchaKey;
    protected static string $apiServer;
    protected static int $codeExpire;
    protected static string $salt;
    protected static bool $initialized = false;
    protected static int $initializedAt = 0;
    protected static int $configTtl = 10;
    protected static bool $ownershipReady = false;

    protected static function ensureSettingsReady(): void
    {
        ensure_settings_table();
    }

    /**
     * 探测 settings 表字段名（name 或 key），复用 common.php 中的 detect_settings_field()
     */
    protected static function detectSettingsField(): string
    {
        return detect_settings_field();
    }

    protected static function getSetting(string $key, $default = null)
    {
        self::ensureSettingsReady();
        $field = self::detectSettingsField();

        try {
            $value = Db::name('settings')->where($field, $key)->value('value');
            if ($value !== null) {
                return $value;
            }
        } catch (\Throwable $e) {
            \think\facade\Log::warning('GeetestModel::getSetting - 读取配置失败: ' . $key . ' - ' . $e->getMessage());
        }

        $envValue = env($key, null);
        if ($envValue === null) {
            return $default;
        }

        $ts = time();
        try {
            Db::name('settings')->insert([
                $field => $key,
                'value' => (string)$envValue,
                'created_at' => $ts,
                'updated_at' => $ts,
            ]);
        } catch (\Throwable $e) {
            \think\facade\Log::warning('GeetestModel::getSetting - 写入配置失败: ' . $key . ' - ' . $e->getMessage());
        }

        return $envValue;
    }

    protected static function initConfig()
    {
        $now = time();
        if (self::$initialized && ($now - self::$initializedAt) < self::$configTtl) {
            return;
        }

        self::$captchaId = (string)self::getSetting('GEETEST_CAPTCHA_ID', '');
        self::$captchaKey = (string)self::getSetting('GEETEST_CAPTCHA_KEY', '');
        $apiServer = trim((string)self::getSetting('GEETEST_API_SERVER', GeetestEndpoint::defaultEndpoint()));
        if (!GeetestEndpoint::isAllowed($apiServer)) {
            // 已存储的非法值不能静默回退后继续外呼，否则会掩盖配置漂移。
            // 前端展示/安装流程可以使用安全默认值，但服务端验证必须 fail-closed。
            \think\facade\Log::warning('GeetestModel::initConfig - GEETEST_API_SERVER 不在 HTTPS allowlist 中，已禁止服务端外呼');
            $apiServer = '';
        }
        self::$apiServer = rtrim($apiServer, '/');
        self::$codeExpire = (int)self::getSetting('GEETEST_CODE_EXPIRE', 300);
        self::$salt = (string)self::getSetting('SALT', '');

        self::$initialized = true;
        self::$initializedAt = $now;
    }

    public static function reloadConfig(): void
    {
        self::$initialized = false;
        self::$initializedAt = 0;
    }

    protected static function ensureOwnershipReady(): void
    {
        if (self::$ownershipReady) {
            return;
        }

        try {
            Db::query('SELECT api_key_id FROM `GeetestTable` LIMIT 1');
            self::$ownershipReady = true;
            return;
        } catch (\Throwable $e) {
        }

        try {
            try {
                Db::execute('ALTER TABLE `GeetestTable` ADD COLUMN `api_key_id` INTEGER DEFAULT NULL');
            } catch (\Throwable $e) {
                Db::execute('ALTER TABLE `GeetestTable` ADD COLUMN `api_key_id` INT UNSIGNED NULL');
            }
        } catch (\Throwable $e) {
            \think\facade\Log::warning('GeetestModel::ensureOwnershipReady - 添加 api_key_id 列失败: ' . $e->getMessage());
        }

        try {
            Db::execute('CREATE INDEX IF NOT EXISTS `idx_api_key_expire` ON `GeetestTable` (`api_key_id`, `expire_at`)');
        } catch (\Throwable $e) {
            try {
                Db::execute('CREATE INDEX `idx_api_key_expire` ON `GeetestTable` (`api_key_id`, `expire_at`)');
            } catch (\Throwable $e2) {
                \think\facade\Log::warning('GeetestModel::ensureOwnershipReady - 创建索引失败: ' . $e2->getMessage());
            }
        }

        self::$ownershipReady = true;
    }

    public static function generateToken(string $gid, string $uid)
    {
        self::initConfig();
        if (self::$salt === '') {
            \think\facade\Log::warning('GeetestModel::generateToken - SALT 未配置，token 安全性降低');
        }
        $timestamp = time();
        $random = bin2hex(random_bytes(16));
        return hash('sha256', $gid . $uid . $timestamp . $random . self::$salt);
    }

    public static function generateCode(string $groupId = '')
    {
        $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $maxAttempts = 10;

        for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
            $code = '';
            for ($i = 0; $i < 6; $i++) {
                $code .= $characters[random_int(0, strlen($characters) - 1)];
            }

            // 检查同 group 下是否存在未过期且未使用的相同验证码
            $query = GeetestTable::where('code', $code)
                ->where('verified', 1)
                ->where('used', 0)
                ->where('expire_at', '>', time());
            if ($groupId !== '') {
                $query = $query->where('group_id', $groupId);
            }
            if (!$query->find()) {
                return $code;
            }
        }

        throw new \RuntimeException('验证码生成失败：连续碰撞次数过多，请稍后重试');
    }

    public static function saveVerifyData(string $token, array $data)
    {
        self::initConfig();
        self::ensureOwnershipReady();

        $apiKeyId = (int)($data['api_key_id'] ?? 0);
        if ($apiKeyId <= 0) {
            // 新记录必须有明确的 API Key 归属；历史无归属记录只允许自然过期。
            return false;
        }

        $validate = new GeetestTable();
        $validate->token = $token;
        $validate->api_key_id = $apiKeyId;
        $validate->group_id = $data['group_id'];
        $validate->user_id = $data['user_id'];
        $validate->code = $data['code'] ?? null;
        $validate->verified = $data['verified'] ?? 0;
        $validate->used = 0;
        $validate->ip = Request::ip();
        $validate->user_agent = Request::header('user-agent');
        $validate->extra = $data['extra'] ?? null;
        $validate->expire_at = time() + self::$codeExpire;
        $validate->created_at = time();
        $validate->updated_at = time();

        return $validate->save();
    }

    public static function getVerifyData(string $token)
    {
        self::initConfig();

        $validate = GeetestTable::where('token', $token)->find();

        if (!$validate) {
            return null;
        }

        if ($validate->expire_at < time()) {
            return null;
        }

        return $validate->toArray();
    }

    public static function findByCode(string $code, string $gid, string $uid, int $apiKeyId)
    {
        self::initConfig();
        self::ensureOwnershipReady();

        if ($uid === '' || $apiKeyId <= 0) {
            return null;
        }

        $validate = GeetestTable::where('code', $code)
            ->where('group_id', $gid)
            ->where('user_id', $uid)
            ->where('api_key_id', $apiKeyId)
            ->where('verified', 1)
            ->where('used', 0)
            ->where('expire_at', '>', time())
            ->find();

        if ($validate) {
            return $validate->toArray();
        }

        return null;
    }

    public static function findCodeByAllStatus(string $code, string $gid, string $uid, int $apiKeyId)
    {
        self::initConfig();
        self::ensureOwnershipReady();

        if ($uid === '' || $apiKeyId <= 0) {
            return null;
        }

        $validate = GeetestTable::where('code', $code)
            ->where('group_id', $gid)
            ->where('user_id', $uid)
            ->where('api_key_id', $apiKeyId)
            ->where('verified', 1)
            ->find();

        if ($validate) {
            return $validate->toArray();
        }

        return null;
    }

    public static function updateVerifyData(string $token, array $newVerifyData)
    {
        self::initConfig();

        $validate = GeetestTable::where('token', $token)->find();

        if (!$validate) {
            return false;
        }

        $validate->code = $newVerifyData['code'] ?? $validate->code;
        $validate->verified = $newVerifyData['verified'] ?? $validate->verified;
        $validate->verified_at = $newVerifyData['verified_at'] ?? $validate->verified_at;
        $validate->updated_at = time();

        return $validate->save();
    }

    public static function deleteVerifyData(string $token)
    {
        self::initConfig();

        return GeetestTable::where('token', $token)->delete() > 0;
    }

    public static function deleteByCode(string $code, string $gid)
    {
        self::initConfig();

        return GeetestTable::where('code', $code)
            ->where('group_id', $gid)
            ->delete() > 0;
    }

    public static function verifyGeetest(array $params)
    {
        self::initConfig();

        $lotNumber = $params['lot_number'] ?? '';
        $captchaOutput = $params['captcha_output'] ?? '';
        $passToken = $params['pass_token'] ?? '';
        $genTime = $params['gen_time'] ?? '';

        if (empty($lotNumber) || empty($captchaOutput) || empty($passToken) || empty($genTime)) {
            return false;
        }

        $signToken = hash_hmac('sha256', $lotNumber, self::$captchaKey);

        $postData = [
            'lot_number' => $lotNumber,
            'captcha_output' => $captchaOutput,
            'pass_token' => $passToken,
            'gen_time' => $genTime,
            'sign_token' => $signToken,
            'captcha_id' => self::$captchaId,
        ];

        if (!GeetestEndpoint::isAllowed(self::$apiServer)) {
            return false;
        }

        $url = rtrim(self::$apiServer, '/') . '/validate?captcha_id=' . rawurlencode(self::$captchaId);

        $result = curl($url, $postData, 10, 'POST');

        if ($result['http_code'] !== 200 || !empty($result['error'])) {
            return false;
        }

        $response = json_decode($result['content'], true);

        return isset($response['result']) && $response['result'] === 'success';
    }

    public static function getCaptchaId()
    {
        self::initConfig();
        return self::$captchaId;
    }

    public static function getCodeExpire()
    {
        self::initConfig();
        return self::$codeExpire;
    }

    public static function cleanExpiredCodes(int $apiKeyId = 0, bool $isDefault = false)
    {
        self::initConfig();
        self::ensureOwnershipReady();

        $q = GeetestTable::where('expire_at', '<', time());
        if (!$isDefault && $apiKeyId > 0) {
            $q = $q->where('api_key_id', $apiKeyId);
        } elseif (!$isDefault) {
            $q = $q->where('api_key_id', -1);
        }

        return $q->delete();
    }

    public static function markCodeAsUsed(string $code, string $gid, string $uid, int $apiKeyId)
    {
        self::initConfig();

        if ($uid === '' || $apiKeyId <= 0) {
            return false;
        }

        $now = time();
        // 使用条件更新避免并发竞态：只有 used=0 的记录才会被更新
        $affected = GeetestTable::where('code', $code)
            ->where('group_id', $gid)
            ->where('user_id', $uid)
            ->where('api_key_id', $apiKeyId)
            ->where('verified', 1)
            ->where('used', 0)
            ->where('expire_at', '>', $now)
            ->update([
                'used' => 1,
                'used_at' => $now,
                'updated_at' => $now,
            ]);

        return $affected > 0;
    }
}
