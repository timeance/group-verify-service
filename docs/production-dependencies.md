# 生产依赖与构建说明

本文档对应生产依赖升级分支。后端鉴权和一次性安装凭据由 PR1 提供；如果 PR1 尚未合并，请不要把本文档中的 `setup:token` 当作当前旧版本已经存在的命令。

## 运行版本

- PHP：8.4 系列，建议使用最新补丁版本；本次验证使用 PHP 8.4.27。
- PHP 扩展：`ctype`、`curl`、`fileinfo`、`json`、`mbstring`、`openssl`、`pdo_sqlite`、`sqlite3`、`zip`。
- Node.js：22.12.0 或更高的 22.x 版本；本次验证使用 Node 22.23.4。
- npm：随 Node.js 提供的 npm；本次验证使用 npm 11.6.2。

不要使用 Node 20 或 Node 24 代替生产构建基线。开发机可以安装其他版本，但构建和发布应显式调用 Node 22。

## 依赖安装与构建

在仓库根目录执行：

```text
cd backend
php composer.phar validate --strict
php composer.phar install --no-dev --optimize-autoloader --no-interaction

cd ../frontend
npm ci
npm run build
```

前端正式产物输出到 `backend/public/static/verify`。生产环境只发布锁文件指定的依赖和构建产物，不在服务器上执行 `npm run dev`。

依赖升级后应再次执行：

```text
cd backend
php composer.phar audit --locked

cd ../frontend
npm audit
npm audit --omit=dev
```

审计报告中的每一项都需要判断是否实际影响当前运行路径；不要用 `--ignore`、`--force` 或降低审计级别来掩盖可修复的问题。

## 一次性安装凭据

PR1 合并后，在后端目录通过命令行生成安装凭据：

```text
php think setup:token
```

凭据只在命令行显示一次，服务端只保存哈希，默认有效期为 30 分钟。安装页面通过 HTTPS 的 POST 表单提交凭据；不要把凭据放在 URL、查询字符串、日志或截图中。

初始化成功后安装入口应关闭。初始化失败时先保留既有数据库和配置，修复权限或输入后可以使用仍有效的凭据重试。已经初始化的实例拒绝重复初始化。

## Nginx 入口限制

生产站点只允许 `backend/public/index.php` 作为 PHP 执行入口。下面的片段示意了这一限制，`fastcgi_pass` 和站点目录需要按服务器实际路径调整：

```nginx
server {
    root /srv/group-verify-service/backend/public;

    location / {
        try_files $uri $uri/ /index.php?s=$uri&$query_string;
    }

    location = /index.php {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT $document_root;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
    }

    location ~* \.(?:php[0-9]*|phtml|phar)(?:/|$) {
        return 404;
    }

    location ~* ^/(?:\.env|.*\.(?:db|sqlite|sqlite3|sql|log))$ {
        return 404;
    }
}
```

不要把 `backend` 项目根目录、`.env`、SQLite 文件、`runtime` 或 Composer 缓存设置为 Web 根目录。Vite 开发服务器只用于受控的本地开发环境，禁止直接暴露到公网。

## 回滚

回滚依赖时同时恢复上一版 `backend/composer.json`、`backend/composer.lock`、`frontend/package.json` 和 `frontend/package-lock.json`，并重新执行生产安装和前端构建。部署前保留上一版 `backend/public/static/verify` 构建产物；依赖回滚不应删除 SQLite、`.env` 或运行时数据。
