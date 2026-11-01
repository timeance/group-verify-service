<?php

namespace app\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;

class SetupToken extends Command
{
    protected function configure()
    {
        $this->setName('setup:token')->setDescription('生成仅显示一次、30 分钟有效的网页安装凭据');
    }

    protected function execute(Input $input, Output $output)
    {
        $tokens = new \app\support\SetupToken(root_path());
        $lock = null;
        try {
            $lock = $tokens->lock();
            $token = $tokens->generate();
            $output->writeln('安装凭据（仅显示一次，30 分钟有效；仅通过安装表单 POST 提交）：');
            $output->writeln($token);
            return 0;
        } catch (\Throwable $e) {
            $output->writeln('<error>无法生成安装凭据：系统已初始化或安装状态不可写。</error>');
            return 1;
        } finally {
            if (is_resource($lock)) { flock($lock, LOCK_UN); fclose($lock); }
        }
    }
}
