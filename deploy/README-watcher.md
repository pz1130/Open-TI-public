# Watcher 对照基线（设计文档 D3、19.1）

[Watcher](https://github.com/thalesgroup-cert/Watcher)（Thales CERT 开源）与本平台定位最接近，作为对照基线**单独部署**，不与本平台共享数据库或网络。

## 部署

1. 按 Watcher 官方仓库的 Docker 部署说明在一台独立主机上部署（版本、端口、管理员账号以官方文档为准）。
2. 在 Watcher 的 DNS Finder 中加入与 `config/projects/<项目>/keywords.yaml` 中 `domains.brand_tokens` 相同的品牌词，以及官方域名（用于生成相似域名）。
3. 让两个系统**同时运行**至少 1 周（S1 验收）与 30 天（S5 验收）。

## 导出与对照

1. 在 Watcher 中导出对照时段内 DNS Finder 发现的域名。只要文件中有一列域名即可：带表头的 CSV（列名为 `domain`、`domain_name`、`dns_domain`、`fqdn`、`name`、`value` 或 `url` 之一，逗号、分号或制表符分隔）、无表头 CSV（取第一列）或纯文本（每行一个域名或 URL）都可以。
2. 运行：`opti watcher-compare watcher-export.csv --days 30`。输出：
   - `both`：两边都发现的（同一主机或同一可注册域）；
   - `ours_only`：只有本平台发现的；
   - `watcher_only`：只有 Watcher 发现的，`status` 为 `not_found`（漏报候选，须逐个复核原因并补充规则或数据源）、`found_outside_window`（本平台在对照时段之外发现过）或 `protected`（官方域名或已知合法相似方，不算漏报）。
3. 把输出附到交付报告；`opti acceptance --watcher watcher-export.csv` 会把对照结果纳入验收报告。
