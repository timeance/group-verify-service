<?php

/**
 * Geetest 服务端端点安全配置。
 *
 * 官方端点固定随代码提供；自定义网关只能由服务器本地环境变量
 * GEETEST_ALLOWED_ORIGINS 加入，管理网页不会写入或扩大这个列表。
 */
$rawAllowedOrigins = function_exists('env')
    ? env('GEETEST_ALLOWED_ORIGINS', '')
    : getenv('GEETEST_ALLOWED_ORIGINS');

$allowedOrigins = [];
foreach (preg_split('/[\\s,]+/', trim((string)($rawAllowedOrigins ?: ''))) ?: [] as $origin) {
    $origin = trim((string)$origin);
    if ($origin !== '') {
        $allowedOrigins[] = $origin;
    }
}

return [
    // 兼容现有配置读取；动态配置仍由 GeetestModel 从 settings/ENV 读取。
    'captcha_id' => env('GEETEST_CAPTCHA_ID', ''),
    'captcha_key' => env('GEETEST_CAPTCHA_KEY', ''),
    'api_server' => env('GEETEST_API_SERVER', 'https://gcaptcha4.geetest.com'),
    'code_expire' => env('GEETEST_CODE_EXPIRE', 300),
    'storage_path' => env('GEETEST_STORAGE_PATH', 'runtime/Geetest/'),
    'salt' => env('SALT', ''),
    'default_endpoint' => 'https://gcaptcha4.geetest.com',
    'official_origins' => [
        'https://gcaptcha4.geetest.com',
    ],
    'allowed_origins' => $allowedOrigins,
];
