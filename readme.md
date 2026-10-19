# Open-TI

基于关键词与域名规则的威胁情报和品牌风险监测平台。平台通过连接器采集新闻、社交内容、证书、域名和其他情报，再进行匹配、评分、告警与人工研判。

## 连接器与关键词规则

配置关键词前，先区分两类规则：

- **文本关键词集合**：例如 `brand` 下的 `Sample Brand`、`样本品牌`，用于文本搜索和内容匹配。
- **域名规则**：例如 `domains.brand_tokens` 下的 `sbr`、`samplebrand`，用于域名查询、候选生成及 URL 筛选。

这两类词需要分别配置。并不是在 `brand` 添加一个名称，所有连接器就都会拿它搜索。

| 要了解的内容 | 文档 |
| --- | --- |
| 哪个连接器读取哪个字段、哪些字段会发给外部搜索、哪些只用于本地筛选 | [连接器搜索字段对照表](docs/connector-field-map.md) |
| 如何接入新 API 或新数据源，如何编写实现、描述文件、测试并部署 | [手动新增连接器指南](docs/adding-connectors.md) |
| 已有连接器如何启用、设置 Key、修改周期及恢复历史配置 | [Web 连接器配置说明](deploy/README-connectors.md) |
| 在监视列表管理域名关键词、查看命中域名和触发历史回溯 | [域名关键词使用说明](deploy/README-domain-keywords.md) |
| 新增品牌词何时开始搜索、如何在两个页面手动立即扫描 | [关键词立即扫描说明](deploy/README-keyword-scan.md) |

### 常用字段由谁使用

下表是概览；完整对照表覆盖当前 35 个采集连接器，并链接到具体实现。

| 输入字段 | 主要使用方式 |
| --- | --- |
| 文本集合中允许外部检索的短语 | Google News、Brave News、GDELT、urlscan、OTX、Reddit、GitLab、App Store 按各自限制生成搜索请求 |
| `domains.brand_tokens` | crt.sh 查询、dnstwist 候选生成、urlscan 域名搜索；CT 流、新注册域名和钓鱼列表等还会用于本地筛选 |
| `domains.restricted_tokens` | crt.sh 的品牌词与指定词缀组合查询，以及域名匹配器筛选 |
| `domains.official` | GitHub 代码、HIBP、Hudson Rock 等查询；自有证书、DMARC 等用于归属判断 |
| 连接器自己的 `internal_terms` | GitHub 代码搜索 |
| `candidate_urls` | Common Crawl 精确查询已知 URL 的历史抓取记录 |
| `feeds`、`instances`、`hashtags` | 指定 RSS 订阅、Mastodon 实例与话题等采集范围 |
| 机构与供应商清单、软件清单 | 平台对勒索受害者、KEV 漏洞进行相关性比对 |

文本词进入统一外部搜索计划，需要同时满足：集合角色是 `match`、类型不是 `executive`、未开启 `private`，且词条 `remote_search=true`、`mode=phrase`。例如默认的 `SBR` 是整词模式并关闭外部检索，不会作为这类外部搜索词下发。

部分连接器只查询前 `max_queries` 个词，当前没有自动轮换被截掉的词。保存关键词也不会自动启用连接器；是否运行仍取决于启用状态、准入、凭据、节点就绪和调度。

“监视列表 → 关键词”和“配置 → 关键词规则”均提供“立即扫描”：先保存新词，再选中它单独扫描，可避免因排在末尾而被查询数量上限截掉。界面逐一显示数据源已排队、运行中、间隔不足或不可用的原因；仍遵守连接器准入和最小运行间隔。

## 如何手动添加连接器

### 启用已有连接器

在 Web 的“连接器中心”找到对应数据源，填写套餐、业务参数、凭据与启用状态，并由有权限的账号维护许可批准。轮询类配置调度周期；流式类还需要对应的常驻采集服务。

如果只是增加一条 RSS、一个 Mastodon 话题，或新增品牌词，直接调整已有配置即可，无需另写连接器。

### 接入全新数据源

目前不能只在 Web 填一个任意 API 地址就完成适配。新数据源需要明确鉴权、查询字段、分页、增量游标和返回结构，基本流程为：

1. 在 `src/opti/connectors/<id>/` 增加 `__init__.py`、`connector.py` 和 `connector.yaml`。
2. 在实现中明确选择查询字段，例如文本搜索用 `plan.terms`，域名候选用 `plan.brand_tokens`。
3. 在 manifest 中声明入口类、参数结构、凭据名、执行位置、输出类型和调度；在 `config/connectors/<id>.yaml` 设置初始状态。
4. 增加离线测试，验证实际请求参数、错误处理、分页、游标和稳定记录 ID，以及结果能被现有处理流水线识别。
5. 更新相关平台与采集节点镜像并重启，使注册表发现新连接器，再到 Web 配置启用并核对运行结果。

完整示例和命令见 [手动新增连接器指南](docs/adding-connectors.md)。其中的示例 API 是占位协议，接入真实服务时需按该服务的接口替换。普通新连接器会由注册表发现，但自定义业务展示、特殊结果类型以及“保存关键词后自动回溯”等联动需要单独适配。

新增或修改连接器后，请同步更新 [搜索字段对照表](docs/connector-field-map.md)，注明外部搜索字段与本地筛选字段。

## 部署与运维

- 用户管理已支持 Web：在“配置 → 管理员 → 用户管理”创建本地用户、启停账号、重设密码和分配角色／权限集；“角色与权限集”可配置自定义授权及查看每项权限含义。首次启动自动创建拥有全部权限的 `superadmin`，随机初始密码保存在持久化目录，首次登录须改密。升级需迁移 **0036**，详见 [用户、角色与权限集](deploy/README-users.md)。
- 管理员可在“配置 → 管理员 → 项目切换”切换全平台的监测项目和关键词规则；各项目保留独立规则及历史数据，切回即可查看。详见 [项目切换与旧数据恢复](deploy/README-projects.md)。
- [2026-10-17 QA 修复与服务器复测清单](deploy/README-qa-retest.md)：导航、立即检查回执、权限边界、业务配置及测试数据收尾。
- [部署与运行手册](docs/runbook.md)
- [平台 Docker Compose](deploy/compose.platform.yml)
- [采集节点 Docker Compose](deploy/compose.collector.yml)
- [管理员设置与服务管理](deploy/README-admin-settings.md)
- [证书监控](deploy/README-certificates.md)
- [监视域名内容检查与截图](deploy/README-watchlist-pages.md)
- [告警忽略与变化后恢复](deploy/README-alert-ignore.md)
