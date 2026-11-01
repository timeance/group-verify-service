<?php
namespace app\controller;

use app\BaseController;
use app\model\GeetestModel;
use think\facade\Db;

class VerifyController extends BaseController
{
    /**
     * 机器人接口在控制器层再次鉴权，避免通过未声明的控制器入口绕过路由中间件。
     * page/status/callback/adminPage 保持公开，不加入此列表。
     */
    protected $middleware = [
        \app\middleware\ApiAuth::class => [
            'only' => ['create', 'check', 'clean', 'resetKey'],
        ],
    ];

    /**
     * @title 生成验证链接
     * @desc 生成验证链接
     * @author VanillaNahida
     * @url /verify/create
     * @method post
     * @return json
     */
    public function create()
    {   
        $apiKeyId = 0;
        try {
            $apiKeyId = (int)$this->request->middleware('api_key_id', 0);
        } catch (\Throwable $e) {
            $apiKeyId = 0;
        }

        if ($apiKeyId <= 0) {
            return json(['code' => 401, 'msg' => 'Unauthorized'], 401);
        }

        $ip = '';
        try {
            $ip = (string)$this->request->ip();
        } catch (\Throwable $e) {
            $ip = '';
        }
        $limitKey = $apiKeyId > 0 ? ('rl:verify_create:api:' . $apiKeyId) : ('rl:verify_create:ip:' . ($ip !== '' ? $ip : 'unknown'));
        $retryAfter = rate_limit_hit($limitKey, 120, 60);
        if ($retryAfter > 0) {
            return json(['code' => 429, 'msg' => '请求过于频繁，请稍后重试'], 429)->header(['Retry-After' => (string)$retryAfter]);
        }

        //赋值参数
        $groupId = $this->request->post('group_id', '');
        $userId = $this->request->post('user_id', '');

        //不存在返回400
        if (empty($groupId) || empty($userId)) {
            $Errorresult = ['code' => 400, 'msg' => '参数错误'];
            return json($Errorresult, 400);
        }

        //生成唯一Token
        if (!ctype_digit($groupId) || !ctype_digit($userId)) {
            $Errorresult = ['code' => 400, 'msg' => '参数错误：group_id 和 user_id 必须为数字'];
            return json($Errorresult, 400);
        }

        $token = GeetestModel::generateToken($groupId, $userId);
        
        //保存验证数据
        if (!GeetestModel::saveVerifyData($token, ['api_key_id' => $apiKeyId, 'group_id' => $groupId,'user_id' => $userId,'verified' => false,'code' => null])) {
            return json(['code' => 500, 'msg' => '验证记录保存失败'], 500);
        }
        
        // 生成验证链接
        $validate = $this->request->domain() . '/v/' . $token;
        $expire = GeetestModel::getCodeExpire();
        //构建json并返回
        $result = ['code' => 0,'msg' => 'success','data' => ['ticket' => $token,'url' => $validate,'expire' => $expire,]];
        return json($result);
    }

    /**
     * 时间 2026-01-03
     * @title 生成用户访问的验证页
     * @desc 生成用户访问的验证页
     * @author VanillaNahida
     * @url /verify/page?=
     * @method get
     * @return html
     */
    public function page()
    {
        $ticket = (string)$this->request->route('ticket', '');
        if ($ticket === '') {
            return response('无效的验证链接', 400);
        }

        $htmlFile = root_path() . 'public' . DIRECTORY_SEPARATOR . 'static' . DIRECTORY_SEPARATOR . 'verify' . DIRECTORY_SEPARATOR . 'index.html';
        if (!is_file($htmlFile)) {
            return response('验证页面资源缺失', 500);
        }

        $html = (string)file_get_contents($htmlFile);
        return response($html)->contentType('text/html');
    }

    public function adminPage()
    {
        $htmlFile = root_path() . 'public' . DIRECTORY_SEPARATOR . 'static' . DIRECTORY_SEPARATOR . 'verify' . DIRECTORY_SEPARATOR . 'index.html';
        if (!is_file($htmlFile)) {
            return response('验证页面资源缺失', 500);
        }

        $html = (string)file_get_contents($htmlFile);
        return response($html)->contentType('text/html');
    }

    public function status()
    {
        $ticket = (string)$this->request->route('ticket', '');
        if ($ticket === '') {
            return json(['code' => 400, 'msg' => '参数错误'], 400);
        }

        $codeExpire = GeetestModel::getCodeExpire();
        $expireMinutes = (int)ceil($codeExpire / 60);
        $data = GeetestModel::getVerifyData($ticket);

        if (!$data) {
            return json(['code' => 404, 'msg' => '验证链接已过期或不存在'], 404);
        }

        if (!empty($data['verified'])) {
            return json([
                'code' => 0,
                'msg' => 'success',
                'data' => [
                    'ticket' => $ticket,
                    'verified' => true,
                    'code_expire' => $codeExpire,
                    'expire_minutes' => $expireMinutes,
                ],
            ]);
        }

        $captchaId = GeetestModel::getCaptchaId();
        return json([
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'ticket' => $ticket,
                'verified' => false,
                'captcha_id' => $captchaId,
                'code_expire' => $codeExpire,
                'expire_minutes' => $expireMinutes,
            ],
        ]);
    }

    /**
     * 时间 2026-01-03
     * @title 处理极验验证结果
     * @desc 处理极验验证结果
     * @author VanillaNahida
     * @url /verify/callback
     * @method post
     * @return json
     */
    public function callback()
    {
        $ip = '';
        try {
            $ip = (string)$this->request->ip();
        } catch (\Throwable $e) {
            $ip = '';
        }
        $ticket = $this->request->post('ticket', '');
        $limitKeySuffix = !empty($ticket) ? ('ticket:' . $ticket) : ('ip:' . ($ip !== '' ? $ip : 'unknown'));
        $retryAfter = rate_limit_hit('rl:verify_callback:' . $limitKeySuffix, 30, 60);
        if ($retryAfter > 0) {
            return json(['code' => 429, 'msg' => '请求过于频繁，请稍后重试'], 429)->header(['Retry-After' => (string)$retryAfter]);
        }

        //从post请求里获取信息
        $lotNumber = $this->request->post('lot_number', '');
        $captchaOutput = $this->request->post('captcha_output', '');
        $passToken = $this->request->post('pass_token', '');
        $genTime = $this->request->post('gen_time', '');
        
        //ticket不存在的处理
        if (empty($ticket)) {
            return json(['code' => 400, 'msg' => '参数错误'], 400);
        }

        if (empty($lotNumber) || empty($captchaOutput) || empty($passToken) || empty($genTime)) {
            return json(['code' => 400, 'msg' => '参数错误：缺少验证必填参数'], 400);
        }
        
        $data = GeetestModel::getVerifyData($ticket);
        
        if (!$data) {
            return json(['code' => 404, 'msg' => '验证链接已过期或不存在'], 404);
        }
        
        if ($data['verified']) {
            // 已验证状态不再返回明文 code，防止重放攻击泄露验证码
            return json(['code' => 0, 'msg' => '已验证']);
        }
        
        //验证
        $param = ['lot_number' => $lotNumber,'captcha_output' => $captchaOutput,'pass_token' => $passToken,'gen_time' => $genTime,];
        $geetestResult = GeetestModel::verifyGeetest($param);
        
        if (!$geetestResult) {
            $result=['code' => 400, 'msg' => '验证失败，请重试'];
            return json($result, 400);
        }
        
        //生成6位验证码
        try {
            $code = GeetestModel::generateCode($data['group_id'] ?? '');
        } catch (\RuntimeException $e) {
            return json(['code' => 500, 'msg' => $e->getMessage()], 500);
        }
        
        // 更新验证数据
        $result = ['verified' => true, 'code' => $code, 'verified_at' => time()];
        GeetestModel::updateVerifyData($ticket, $result);

        $jsonResult = ['code' => 0, 'msg' => '验证成功', 'data' => ['code' => $code]];
        return json($jsonResult);
    }

    /**
     * 时间 2026-01-03
     * @title 验证验证码
     * @desc 验证验证码
     * @author VanillaNahida
     * @url /verify/check
     * @method post
     * @return json
     */
    public function check()
    {
        $ip = '';
        try {
            $ip = (string)$this->request->ip();
        } catch (\Throwable $e) {
            $ip = '';
        }
        $retryAfter = rate_limit_hit('rl:verify_check:' . ($ip !== '' ? $ip : 'unknown'), 60, 60);
        if ($retryAfter > 0) {
            return json(['code' => 429, 'msg' => '请求过于频繁，请稍后重试', 'passed' => false], 429)->header(['Retry-After' => (string)$retryAfter]);
        }

        $groupId = trim((string)$this->request->post('group_id', ''));
        $userId = trim((string)$this->request->post('user_id', ''));
        $code = trim((string)$this->request->post('code', ''));
        $apiKeyId = 0;
        try {
            $apiKeyId = (int)$this->request->middleware('api_key_id', 0);
        } catch (\Throwable $e) {
            $apiKeyId = 0;
        }
        
        if ($apiKeyId <= 0 || $groupId === '' || $userId === '' || $code === '') {
            return json(['code' => 400, 'msg' => '参数错误：缺少必填参数 group_id、user_id、code 或 API Key', 'passed' => false], 400);
        }

        // 按 group_id 维度限流，防止对同一群组暴力猜测验证码
        $retryAfterGroup = rate_limit_hit('rl:verify_check:group:' . $groupId, 30, 60);
        if ($retryAfterGroup > 0) {
            return json(['code' => 429, 'msg' => '请求过于频繁，请稍后重试', 'passed' => false], 429)->header(['Retry-After' => (string)$retryAfterGroup]);
        }
        
        // 查找匹配的验证码
        if (!ctype_digit($groupId)) {
            return json(['code' => 400, 'msg' => '参数错误：group_id 必须为数字', 'passed' => false], 400);
        }

        if (!ctype_digit($userId)) {
            return json(['code' => 400, 'msg' => '参数错误：user_id 必须为数字', 'passed' => false], 400);
        }
        
        // 验证码必须同时属于当前 API Key、群和用户；缺少归属的旧记录不会匹配。
        $data = GeetestModel::findByCode($code, $groupId, $userId, $apiKeyId);
        
        if (!$data) {
            $allStatusData = GeetestModel::findCodeByAllStatus($code, $groupId, $userId, $apiKeyId);
            
            if ($allStatusData) {
                if ($allStatusData['used'] == 1) {
                    return json(['code' => 400, 'msg' => '验证失败：验证码已使用', 'passed' => false], 400);
                } elseif ($allStatusData['expire_at'] < time()) {
                    return json(['code' => 400, 'msg' => '验证失败：验证码已过期', 'passed' => false], 400);
                } elseif ($allStatusData['verified'] != 1) {
                    return json(['code' => 400, 'msg' => '验证失败：验证码未完成验证', 'passed' => false], 400);
                } else {
                    return json(['code' => 400, 'msg' => '验证失败：验证码不存在或已失效', 'passed' => false], 400);
                }
            }
            
            return json(['code' => 400, 'msg' => '验证失败：验证码不存在或已失效', 'passed' => false], 400);
        }
        
        // 标记验证码为已使用（原子操作，防止并发重复使用）
        $marked = GeetestModel::markCodeAsUsed($code, $groupId, $userId, $apiKeyId);
        if (!$marked) {
            return json(['code' => 400, 'msg' => '验证失败：验证码已使用', 'passed' => false], 400);
        }
        
        //构建返回数据
        $result = ['code' => 0,'msg' => '验证通过','passed' => true,'data' => ['user_id' => $data['user_id'],'group_id' => $data['group_id'],]];
        return json($result);
    }

    /**
     * 时间 2026-01-03
     * @title 删除验证码
     * @desc 删除验证码
     * @author VanillaNahida
     * @url /verify/clean
     * @method post
     * @return json
     */
    public function clean()
    {
        $isDefaultKey = false;
        try {
            $isDefaultKey = (bool)$this->request->middleware('api_key_is_default', false);
        } catch (\Throwable $e) {
            $isDefaultKey = false;
        }
        if (!$isDefaultKey) {
            return json(['code' => 403, 'msg' => '权限不足：该接口仅允许默认 API Key 调用'], 403);
        }

        $apiKeyId = 0;
        try {
            $apiKeyId = (int)$this->request->middleware('api_key_id', 0);
        } catch (\Throwable $e) {
            $apiKeyId = 0;
        }

        //实例化模型类
        $cleaned = GeetestModel::cleanExpiredCodes($apiKeyId, $isDefaultKey);
        $result = ['code' => 0, 'msg' => "清理了 {$cleaned} 个过期验证码"];
        return json($result);
    }

    public function resetKey()
    {
        $apiKeyId = 0;
        try {
            $apiKeyId = (int)$this->request->middleware('api_key_id', 0);
        } catch (\Throwable $e) {
            $apiKeyId = 0;
        }
        if ($apiKeyId <= 0) {
            return json(['code' => 401, 'msg' => 'Unauthorized'], 401);
        }

        $isDefaultKey = false;
        try {
            $isDefaultKey = (bool)$this->request->middleware('api_key_is_default', false);
        } catch (\Throwable $e) {
            $isDefaultKey = false;
        }
        if (!$isDefaultKey) {
            return json(['code' => 403, 'msg' => '权限不足：该接口仅允许默认 API Key 调用'], 403);
        }

        $retryAfter = rate_limit_hit('rl:api_key_reset:' . $apiKeyId, 3, 60);
        if ($retryAfter > 0) {
            return json(['code' => 429, 'msg' => '请求过于频繁，请稍后重试'], 429)->header(['Retry-After' => (string)$retryAfter]);
        }

        ensure_api_keys_table();

        $newValue = '';
        $updated = 0;
        $ts = time();
        for ($i = 0; $i < 3; $i++) {
            try {
                try {
                    $newValue = bin2hex(random_bytes(32));
                } catch (\Throwable $e) {
                    $newValue = hash('sha256', uniqid('api_key_reset', true) . microtime(true) . $i);
                }

                $newHash = hash('sha256', $newValue);
                $updated = (int)Db::name('api_keys')->where('id', $apiKeyId)->update([
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

        \app\middleware\ApiAuth::clearCache();

        return json([
            'code' => 0,
            'msg' => 'success',
            'data' => [
                'id' => $apiKeyId,
                'value' => $newValue,
                'updated_at' => $ts,
            ],
        ])->header(['Cache-Control' => 'no-store']);
    }
}
