# S4-C 威胁情报 Feed 部署

平台默认每 6 小时下载 CISA KEV。若 CISA 主站返回 403，连接器会读取 CISA 维护的公开 GitHub 镜像。所有条目写入 `kev_entry`；只有与本机构软件清单中的厂商和产品名规范化后完全相等的条目，才生成漏洞发现。清单默认空，因此首次导入不会产生漏洞告警。

编辑 `config/software.yaml`，为每个软件填写唯一 `id`、KEV 使用的厂商名和逐个列出的产品名；可选填 `vendor_aliases`、`tier`、`exposed`、`owner`。先运行 `opti kev-products --vendor "厂商名"` 查看目录中的准确写法，再运行 `opti software-check` 校验。修改清单后重启平台 worker，运行 `opti kev-rematch` 可立即补比对；每日 04:00 UTC 也会自动补比对。告警提示补丁优先级，仍须核对实际部署版本是否受影响。

软件清单被 `.dockerignore` 排除在镜像之外。`deploy/compose.platform.yml` 只把该文件只读挂载到平台容器；境外采集节点不挂载，也不会收到清单。若不使用该 Compose 文件，请自行只在平台 worker、API 和命令行容器挂载清单，并用 `OPTI_SOFTWARE` 指向其路径。

ThreatFox 和 OTX 默认未批准，确认机构使用条款后，分别在 `config/connectors/threatfox.yaml`、`config/connectors/otx.yaml` 设置 `license_approved: true`，并在境外采集节点设置 `OPTI_SECRET_THREATFOX_AUTH_KEY`、`OPTI_SECRET_OTX_API_KEY`。ThreatFox 每小时读取最近 48 小时的域名与 URL IOC；OTX 每 6 小时搜索公开 Pulse。两者的连接器只使用 GET，不访问 IOC 或 Pulse 页面；ThreatFox 命中后，平台现有 URL 富化流程可能对目标发起探测。

首次启用前在获授权环境中用 `opti run threatfox --allow-unapproved`、`opti run otx --allow-unapproved --max-items 20` 核对服务返回格式和命中情况。没有密钥时保持未批准状态，避免无效调度。
