# Open-TI 运行手册

本手册面向主平台值班人员。所有命令在仓库根目录执行；容器部署时用 `docker compose -f deploy/compose.platform.yml exec -T api opti ...` 代替下文的 `uv run opti ...`。容器根目录为只读，报告输出请指定 `/app/data/acceptance`。

## 启动与日常检查

全平台监测项目由管理员在“配置 → 管理员 → 项目切换”选择。修改项目标识不会迁移或删除原项目数据；需要找回旧列表时切回原项目。权限、规则恢复与升级要求见 [项目切换说明](../deploy/README-projects.md)。

1. 设置 `.env`、机构规则和连接器实例配置；生产环境把默认开发数据库、对象存储凭据和 API 端口绑定换成机构提供的配置，并在反向代理上启用 TLS。授权编号与允许的监测范围必须先写入项目规则。`.env` 必须填写 `OPTI_SECRET_MASK_KEY`（发现密钥的遮蔽指纹密钥，`openssl rand -hex 32` 生成），缺失时 api、worker、gateway、intake、syslog 与采集节点拒绝启动；远程部署时每个采集节点的 `.env.collector` 必须填相同的值。该值一般不轮换，轮换后已有指纹全部失效，详见 `deploy/README-code-secrets.md`。
2. 运行 `docker compose --env-file .env -f deploy/compose.platform.yml up -d --build`，让 `.env` 中的 Compose 端口和路径插值生效。仅本机用 HTTP 体验时设 `OPTI_COOKIE_SECURE=false`、`OPTI_API_BIND=127.0.0.1`；生产环境按机构反向代理与 TLS 配置。检查 `postgres`、`valkey`、`seaweedfs`、`migrate`、`worker`、`scheduler`、`api` 状态；迁移必须成功后再检查 API。
3. 用 `opti audit-verify` 校验审计哈希链。用 `opti collectors` 查看境外节点心跳；用连接器中心核对准入、最近成功时间和错误状态。远程部署需按 `deploy/compose.collector.yml` 单独启动采集节点并配置 mTLS。
4. 值班时关注高危告警、待取证、连接器连续失败和队列积压。截图对象存储不可用时应先恢复存储，再用 `opti evidence-capture --alert-id ID` 补取证；用 `opti evidence-verify ID` 校验单条证据哈希。

日报、周报与月报由调度器自动生成并推送。月报每天 01:10 UTC 检查一次，按 `config/alerting.yaml` 的 `report_timezone` 生成上一个自然月的报告，同一月份只生成一份；调度器停机错过时，恢复后的下一次检查会补上。需要补生成更早的月份时运行 `opti report-monthly --month 2026-09`（未结束的月份会被拒绝）；已生成的月份不会重新统计。月报在平台“报告”页下载 HTML 后，可用浏览器“打印 → 另存为 PDF”得到 A4 版式。

分析员在告警队列点“提交线索”录入 LinkedIn、微信、Telegram 等渠道发现的冒充或诈骗链接。“配置 → 处置 → 下架渠道”中的平台名单内的链接不会被 HTTP 探测或截图沙箱访问（无论来自人工提交还是自动情报源），必须上传自己截取的截图；短链接（如 tinyurl）跳转到平台页面的情况目前仍会被沙箱跟随访问，这类线索请直接提交跳转后的平台链接；非平台链接只有主机像仿冒域名（命中品牌规则）时才加入监视列表，挂在 `sites.google.com` 等共享主机上的页面不监视，需要时人工复查；截图会被重新编码并去除设备元数据，原文件哈希保留在证据记录中。平台举报入口会变化，定期到各平台官方帮助页核对 `channel`；无法核实的平台把 `channel` 删除，下架时由分析员人工确定渠道。新增平台时只写其自有域名，不要写共享的上级域名（例如写 `weixin.qq.com`，不写 `qq.com`）。

视觉相似线索默认未配置。机构可在本地运行 `opti logo-hash /path/to/owned-logo.png`，将输出的 `dhash64` 以 `{name: "机构主 Logo", dhash64: "..."}` 填入 `config/connectors/screenshot.yaml` 的 `config.logo_hashes`（最多 12 个），再重新部署截图采集节点。只使用机构拥有或获准使用的清晰 Logo 图片；纯色等区分力不足的图片会被拒绝。高危告警的新截图取证会比对当前视口中已加载的图片，并在告警证据区显示可能相似的参考名称和差异值。相似提示不参与评分或自动处置；未提示相似也不代表页面没有冒用 Logo。

站点图标指纹也默认没有参考值。机构可运行 `opti favicon-hash /path/to/owned-favicon.ico`，将输出的 `mmh3` 整数和参考名称写入同一文件的 `config.favicon_hashes`（最多 12 个），重新部署截图采集节点。新取证会在截图和 HTML 快照之后读取页面声明的同源图标，未声明时尝试同源 `/favicon.ico`；只保存哈希、大小和图标地址，不保存图标文件。告警证据区显示指纹及与机构参考值完全相同的名称。相同哈希仅供人工关联，不足以证明同一运营者或仿冒；平台不会自动向外部搜索服务提交图标或哈希。

截图 OCR 默认关闭。需要识别图片型页面文字时，在境外节点的 `.env.collector`（本地沙箱模式则在 `.env`）设置 `OPTI_SANDBOX_OCR_ENABLED=true`，重建并重启 `browser` 服务。境外节点执行 `docker compose --env-file .env.collector -f deploy/compose.collector.yml up -d --build browser`，让该变量参与 Compose 插值；浏览器容器只接收这一项配置，不接收采集令牌。沙箱镜像内含 Tesseract 的英语和简体中文模型；仅对新产生的高危告警截图运行一次，最长 8 秒，失败不影响截图或 HTML 存证。结果只保留品牌词命中和识别字数，完整识别文字不写入数据库。值班人员须对照原始截图复核命中，也不能将无命中视为页面无品牌内容。

仿冒活动由 `opti.recompute_campaigns` 每 10 分钟重算，也可运行 `opti campaign-recompute` 立即重算。参数在“配置 → 监测 → 仿冒活动参数”中修改，保存后立即重算；`config/campaigns.yaml` 只作初始值。若候选活动明显过大，先在活动页查看“被忽略的共享值”，必要时调低 `max_share`。

## Web 配置

关键词规则与机构信息在平台“配置”页编辑：分析员可改规则，平台管理员可改机构信息，所有角色可查看机构信息与生效状态。每次保存生成一个版本并写审计，历史中可查看差异并“恢复为新版本”。

- 在 Web 上保存过之后，以数据库为准；`OPTI_RULES` / `OPTI_ORGANIZATION` 只作为初始值，之后再改文件不会生效。
- 保存后约 10 秒内各进程热加载，不需要重启；页面状态条显示每个进程已加载的版本（绿色已生效、蓝色等待、红色加载失败、灰色超过 10 分钟未上报）。境外采集节点最多再晚 60 秒。
- 修改项目标识前会提示当前项目下的告警数；切换后旧数据不再显示但不会删除，改回原标识即可恢复显示。
- intake 与 syslog 不连数据库：direct 模式从 Valkey 的 `opti:config:rules` 读取规则（由 API 进程发布），gateway 模式从采集网关读取去掉人员类集合的规则。Valkey 中没有该键时用各自的规则文件。
- 某个进程状态为红色时，悬停可看到原因；该进程会继续使用上一份有效配置。修正后保存一个新版本即可。

下架渠道、投诉模板与工单在“配置”页由平台管理员修改，保存后约 10 秒生效。平台名单在“配置 → 处置 → 下架渠道”维护。模板保存时校验首行 `Subject:` 与占位符，页面用示例告警实时预览；“恢复内置模板”取回镜像中的原文。工单的 Webhook 地址与签名密钥在页面上填写后加密存库，可从 `.env` 删除 `OPTI_SECRET_TICKETS_*`；关闭工单后自动推送停止，人工推送返回“未配置”。

连接器的启用、套餐、参数与凭据在“连接器中心”由平台管理员修改，许可批准由合规官修改；设置存在数据库（配置种类 `connectors`），编辑面板的「历史」可查看并恢复参数，详见 `deploy/README-connectors.md`。升级时 `opti db-upgrade` 会导入旧版本的 `data/connector-config.json`，缺少主密钥时升级会停下，配置 `OPTI_ENCRYPTION_KEY` 后重跑。

供应商清单、软件清单与数据外送在“配置”页由平台管理员修改。清单保存后自动在后台重新比对（供应商对近期泄露站帖子，软件对全部 KEV 条目），页面显示排队、完成与新增告警数；每天凌晨的定时比对照常运行。软件产品名必须与 KEV 写法一致，页面按厂商给出补全。数据外送的 syslog 可直接粘贴私有 CA 证书；SIEM 签名密钥与令牌填写后加密存库，可从 `.env` 删除 `OPTI_SECRET_SIEM_*`；syslog 与 Webhook 各有“发送测试事件”。

### 告警推送

“配置 → 告警推送”由平台管理员编辑：平台访问地址、日报汇总级别、报告语言与时区、SMTP 中继，以及多个 Teams / 邮件渠道。每个渠道单独选择立即推送的级别、类别（留空为全部）、接收的报告与运营提醒，并可“发送测试”。

- 升级后未在 Web 上保存时，沿用 `alerting.yaml` 与 `.env`：原 Teams 与邮件分别成为 ID 为 `teams`、`email` 的渠道，历史告警不会重发。
- 在页面上为渠道填写 Webhook、为 SMTP 填写账号口令并保存后，可从 `.env` 删除 `OPTI_SECRET_ALERTING_*`。密钥用 `OPTI_ENCRYPTION_KEY` 加密存库，页面只显示末 4 位；“清除”后即使 `.env` 中仍有同名变量也不再使用。主密钥轮换后运行 `opti rekey`。
- 渠道配错（如缺 Webhook）期间，相关告警保持待推送，修好后自动补发；超过 7 天的未推送告警不再推送。
- 渠道连不上或出错（超时、网络错误、5xx、429、SMTP 临时错误）时，worker 让该渠道退避 5、10、20、30 分钟（封顶 30 分钟）再试，期间告警、报告与运营提醒都跳过它，成功一次即恢复；服务器明确拒收某一条消息（其他 4xx、SMTP 5xx）只算这一条失败。修好渠道后想立即补发，可重启 worker；修改并保存告警配置（例如更换 Webhook）也会清零退避。
- 修改平台访问地址前，如启用了单点登录且 `oidc.yaml` 未写 `redirect_uri`，先在身份提供方登记新的回调地址 `<新地址>/api/v1/auth/oidc/callback`；页面保存时也会提示。

### 对接 Jira Cloud / ServiceNow

“配置 → 工单”的推送方式可选 Jira Cloud 或 ServiceNow（同一时间只用一种）。平台只推送、不回写：工单状态在工单系统里处理，告警状态由分析员在平台上改。告警人工推送、按级别自动推送、凭据暴露受影响账户推送都会走所选系统；同一告警后来新增的受影响账户追加为已有工单的评论（Jira 评论 / ServiceNow 工作备注），不另开新单。

- Jira Cloud：用专用集成账号在 <https://id.atlassian.com/manage-profile/security/api-tokens> 生成 API Token，填入页面。该账号在目标项目需要“浏览项目”“创建问题”“添加评论”权限；问题类型必须在该项目中存在，优先级名称与 Jira 中的写法一致。只支持 `*.atlassian.net`，不支持 Data Center / Server。
- ServiceNow：建议使用专用集成账号，授予 `itil` 角色，或对目标表的 create / read / write ACL。OAuth 方式在“System OAuth → Application Registry”注册客户端并启用 client_credentials 授权（较新版本需开启系统属性 `glide.oauth.inbound.client.credential.grant_type.enabled`，以实例版本的官方文档为准），把 client_id 与 client_secret 填入页面。目标表必须继承 task（如 `incident`、`sn_si_incident`），平台用 `correlation_id` 防止重复建单，“测试连接”会检查目标表有该字段（表为空时无法检查）。
- 防重复：平台在 Jira 工单上打 `opti-alert-<告警编号>` 标签、在 ServiceNow 写 `correlation_id`，推送失败重试前先按它查找已有工单。Jira 搜索索引有几秒延迟，极少数情况下仍可能多建一张，可手工关闭重复单；评论没有防重复。切换推送方式前留下的工单编号（如 Webhook 时代的编号）不会被当成 Jira 问题，后续批次推送会报 `rejected`，需人工处理。
- 员工邮箱：“凭据暴露工单包含员工邮箱”默认关闭，工单只写受影响账户数与平台链接，IT 需登录平台查看名单；打开后每张工单或评论最多列 100 个邮箱，其余在平台查看。打开前确认工单的可见范围（Jira 项目权限 / ServiceNow 表 ACL）只限处理人员。
- 境内部署访问境外工单系统时，在“出口代理”填写代理地址（如 `http://proxy.internal:3128`）；为空时直连。
- 保存后点“测试连接”验证已保存的配置与密钥（Jira 检查账号、项目与问题类型，ServiceNow 读取目标表一行）。推送失败时告警页显示原因：认证失败（`auth`）、请求被拒（`rejected`，附 Jira 拒绝的字段名或 ServiceNow 的错误信息）、不可用（`unavailable`）。自动推送失败的告警下一轮重试。
- 密钥也可放在 `.env`：`OPTI_SECRET_TICKETS_JIRA_API_TOKEN`、`OPTI_SECRET_TICKETS_SERVICENOW_PASSWORD`、`OPTI_SECRET_TICKETS_SERVICENOW_CLIENT_SECRET`。

## 保留期与隐私请求

保留期在“配置 → 平台 → 保留期”中由平台管理员修改；调短任一项时，页面先列出下一次清理将删除的数量，确认后才保存。`config/retention.yaml` 只作初始值。它控制原始数据、举报联系方式、泄露账户、文档、发现、已结案案件、运行记录和报告的期限。审计日志不由自动任务删除。`opti.apply_retention` 每日 02:40 UTC 清理数据库，提交后删除对应版本的证据对象；分区任务每日 00:00 UTC 删除到期的原始数据月分区。文件删除失败会记录日志，须检查对象存储并人工处理孤儿对象。

执行前先运行 `opti retention --dry-run`，保存 JSON 数量并核对异常大幅增长；试运行会回滚数据库更改，也不会删除对象文件。确认后执行 `opti retention`。若某类清理超过单次 5000 个发现，后续运行会继续处理。执行后复查审计日志中的 `retention.purge` 和对象存储删除日志。生产清理前按照机构备份策略保留数据库与对象存储快照。

处理数据主体请求时先核验申请人与授权范围，再运行 `opti dsar --email 'person@example.org'` 或 `opti dsar --name 'Jane Roe'`。输出仅含主体 SHA-256、命中数量和记录 ID 样本；证据截图列为 `evidence_review`，必须人工评估。核对范围后执行相同命令并追加 `--erase --confirm`。原始数据与泄露账户直接删除，其他文本替换为 `[REDACTED]`；审计日志保持不可修改。检索与执行均会写入只含主体哈希和计数的审计记录。执行后再次检索并处理需要人工审查的截图。

## 启用大模型研判

1. 由平台管理员在「设置 → 凭据加密主密钥」生成并备份主密钥（恢复数据库时导入原密钥）。Web 初始化后无需重启；所有平台进程须共享持久化数据目录。也支持原有 `.env` 的 `OPTI_ENCRYPTION_KEY` 部署方式。
2. 以 `platform_admin` 登录，打开「大模型研判」：添加供应商（选预设，填 API 密钥；境外供应商按需填出口代理），点「测试」确认连接成功。
3. 在金标准集上对比：把该供应商选为主用并保存，但先不打开「启用研判」；运行 `uv run opti llm-check` 与 `uv run opti eval-texts --llm`（这两个命令在启用前就使用主用供应商），确认 `rules_llm` 的误报率低于 `rules` 且召回不下降，再正式启用。
4. 选主用（可选备用），打开「启用研判」并保存；最多 2 分钟后生效，不用重启。审计日志中可见 `llm.*` 操作。
5. 境外供应商：页面会提示数据外发；只发送经过滤的公开内容（设计文档 9.4）。
6. 代码仓库密钥研判（可选，默认关闭）：先更新所有采集节点（新节点才回传遮蔽后的上下文），运行 `uv run opti eval-code`，确认 `secret_accuracy` 与 `relation_accuracy` 可接受且 `injections_fooled` 为 0，再在「大模型研判」打开「研判代码仓库密钥」。模型只调整告警排序，不会把扫出密钥的告警压到告警线以下；结论显示在告警详情的「公开代码与密钥」卡片上。

### 主密钥轮换

1. 把当前 `OPTI_ENCRYPTION_KEY` 移到 `OPTI_ENCRYPTION_KEY_PREVIOUS`，写入新生成的 `OPTI_ENCRYPTION_KEY`，重启。
2. 运行 `uv run opti rekey`，确认输出的字段数与供应商的密钥、代理数一致。
3. 删除 `OPTI_ENCRYPTION_KEY_PREVIOUS` 并重启。

### 研判不工作

- 页面顶部红色提示：服务器没有主密钥或格式不对。
- 橙色提示「主用供应商不可用」：密钥缺失、无法解密（轮换后缺 `_PREVIOUS`）或预设未知；排队中的发现已按规则分照常告警。
- 橙色提示「后台研判任务报告：…」：只有研判 worker 遇到的问题（多为 worker 没有配置或配错 `OPTI_ENCRYPTION_KEY`）；API 与 worker 必须使用同一个主密钥。卡片右上角的「后台任务最近检查」超过几分钟没更新，说明 worker 没在运行。
- 「最近测试」失败：看错误里的状态码（401 密钥错误、403/404 地址或模型错误、429 限流、网络错误多为代理或出口问题）。

## 验收与回归

每次规则或连接器交付运行 `opti --rules config/projects/sample-brand/keywords.yaml eval`。域名、URL、文本三套金标准集分别输出召回率、负样本误报率和失败样本；失败时命令返回 1。将失败样本复核后更新规则或金标准集，并记录变更原因。

MTTD 缺样本时，由项目负责人书面批准后使用机构持有的测试域名做端到端金丝雀：记录域名、注册时间和 CT 日志收录时间，让正常的 NRD/CT 连接器发现它，核对首条告警与来源事件时间，并在验收报告中记录每段耗时。不要用手工插入的告警充当生产时延样本；测试结束后按机构流程撤销或标注测试资产。

与 Watcher 对照时按 [Watcher 说明](../deploy/README-watcher.md) 在独立环境部署，保存同期 DNS Finder 导出和运行日期。执行 `opti --rules config/projects/sample-brand/keywords.yaml watcher-compare watcher-export.csv --days 30`。逐条复核 `not_found` 候选；官方域名和已知合法相似方会标为 `protected`，时段外发现标为 `found_outside_window`。没有真实导出或未达到并行运行时长，不能宣称对照验收完成。

用 `opti --rules config/projects/sample-brand/keywords.yaml acceptance --days 30 --out acceptance` 生成 Markdown 与 JSON；容器内将 `--out` 改为 `/app/data/acceptance`。有 Watcher 导出时追加 `--watcher FILE`。报告逐项列出 MTTD、精确率、召回率、MTTR、免费数据源、证据完整率、零付费、金标准集和 Watcher 对照。`fail` 会令命令返回 1；`insufficient` 和 `manual` 仍需补充真实样本或机构监控数据，不能视为最终通过。平台可用性以机构监控系统的 30 天数据人工确认。

## 故障与恢复

- 数据库迁移失败：停止 worker、scheduler 和 API，检查 `migrate` 日志、数据库备份和迁移版本；修复后先单独完成迁移，再恢复服务。
- 连接器无数据：检查连接器中心的 `enabled`、法务许可、凭据是否已配置、节点心跳与最近运行记录；不要临时绕过准入规则。
- 证据缺失：检查 SeaweedFS、沙箱或远程节点日志以及 `evidence_status`，恢复后补取证并校验哈希。对象删除失败须按日志定位键与版本，不能仅删除当前版本标记。
- 告警未送达：检查告警待发送状态、渠道配置及 `dispatch_pending` 任务；修复渠道后由重试任务重新推送，避免手工重复发送。
- 审计校验失败：保留数据库与应用日志快照，暂停相关管理操作并交由安全负责人调查；不得编辑或截断审计记录。

所有生产故障处理和隐私请求均记录工单编号、操作者、时间、审计记录编号与复核结论。对外 SIEM、工单、邮件或 Watcher 服务是否真正送达，需以各外部系统回执确认。
