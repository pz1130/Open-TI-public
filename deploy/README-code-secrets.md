# 代码与密钥泄露（S3-C）配置

平台用 GitHub 代码搜索查找公开代码中提到本机构的文件，再用 gitleaks 扫描这些公开仓库。平台不验证密钥是否有效；扫描结果只保存前 4 个字符、HMAC-SHA256 指纹（密钥为 `OPTI_SECRET_MASK_KEY`，平台与所有采集节点必须相同）、长度、规则和位置；不保存裸 SHA-256，外部无法用猜测值离线比对。搜索与扫描默认关闭。

## 1. 采集节点令牌

按 GitHub 当前要求创建仅供公开代码搜索的最小权限令牌，在采集节点的 `.env.collector` 中设置 `OPTI_SECRET_GITHUB_CODE_TOKEN`。如需提高扫描前仓库信息查询的 API 配额，可设置同样只读的 `OPTI_SECRET_SECRET_SCAN_GITHUB_TOKEN`。不要把令牌写进配置文件或 Git。

## 2. 搜索词

在 `config/connectors/github_code.yaml` 中维护 `internal_terms`（内部主机名、项目代号，不含个人信息）和 `exclude_owners`（本机构 GitHub 账号）。官方域名自动来自关键词规则。连接器每轮最多查询 `max_queries` 个词，默认每 6 小时运行一次。

## 3. 启用与验证

在获授权的境外采集节点上，将 `github_code.yaml` 和 `secret_scan.yaml` 的 `enabled` 设为 `true`。镜像中包含 `git` 与 gitleaks；可执行 `docker compose -f deploy/compose.collector.yml run --rm collector gitleaks version` 检查。扫描前会用 GitHub 仓库元数据排除私有、已删除和超出大小限制的仓库。新命中尽快扫描，成功后 30 天复扫，失败后 1 天重试。

## 4. 发现密钥后

资产负责人可从标准输入提交候选值核对，避免把密钥写进命令行参数和 shell 历史：

```bash
read -rs KEY && printf '%s\n' "$KEY" | docker compose -f deploy/compose.platform.yml exec -T api opti secret-match; unset KEY
```

匹配成功返回 0 并列出仓库与位置，未匹配返回 1。核对只比较 HMAC 指纹（需与扫描时相同的 `OPTI_SECRET_MASK_KEY`）；审计日志只记指纹前 12 位。本机构的密钥应立即轮换或吊销，并检查泄露期间的使用记录。第三方密钥应按仓库的安全策略联系维护者；只有仓库启用私密漏洞报告时，GitHub 私密报告入口才可用。不要使用、测试或转发密钥。

## 遮蔽密钥与升级

- `OPTI_SECRET_MASK_KEY`（≥32 字符，`openssl rand -hex 32`）为必填：平台 api/worker/gateway 与采集节点缺失时拒绝启动，遮蔽函数也拒绝在无密钥时输出（fail closed）。平台与每个采集节点的值必须完全相同，否则同一密钥会得到不同指纹、去重失效。
- 文本中的凭据遮蔽为 `AKIA…[REDACTED:1a2b3c4d]`（前 4 字符 + HMAC 前 8 位），同前缀的不同密钥不再合并。
- 迁移 0034 删除旧扫描结果中的裸 `sha256` 字段（无法从哈希反推 HMAC）。旧发现保留位置与规则，但不再有指纹、无法用 `opti secret-match` 核对；需要时对仓库重新扫描即可生成新指纹。升级平台与采集节点须同时进行：旧节点只上报 `sha256`，平台会丢弃这些条目。
- 轮换 `OPTI_SECRET_MASK_KEY` 会使已有指纹与遮蔽标签全部失效（同一密钥前后标签不同），一般不需要轮换。
