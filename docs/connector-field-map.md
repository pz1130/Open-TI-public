# 连接器搜索字段对照表

核对日期：2026-10-16。以下是当前代码的调用关系，不代表服务器上的连接器都已启用。新增或修改连接器时，应同步更新本表。

Web 中有两类设置：

- **配置 → 关键词规则**：文本词条、域名规则，多个连接器共用。
- **连接器中心 → 配置**：某个连接器自己的参数、凭据、启用与调度。字段如何映射成搜索请求由连接器代码决定，目前没有通用的 Web 字段绑定功能。

## 1. 字段从哪里来

| 页面字段 | 代码字段 | 用途 |
| --- | --- | --- |
| `brand` 等集合里的词条 | `rules.sets.<集合>.terms` | 匹配文本；满足条件的词还会成为外部搜索词。不是只认名为 `brand` 的集合。 |
| 角色 | `sets.<集合>.role` | `match` 确认相关性；`booster` 辅助分类和评分；`negative` 抑制被排除短语覆盖的命中。 |
| 类型、仅本地匹配 | `sets.<集合>.type`、`private` | 控制文本词是否进入外部搜索计划；人员类型不进入计划。 |
| 模式、下发外部检索 | `terms[].mode`、`remote_search` | 只有允许外部检索的短语词进入统一外部搜索计划。 |
| 区分大小写、共现条件 | `case_sensitive`、`require_any_within` | 本地匹配条件，通常不会成为外部搜索 API 的查询约束。 |
| 官方域名 | `domains.official` | 区分自有资产、识别嵌入伪装；也用于域名泄露查询、代码搜索等。 |
| 域名品牌词 | `domains.brand_tokens` | 域名搜索、候选生成、域名和 URL 匹配。与上面的文本词条不是同一列表。 |
| 受限品牌词 | `domains.restricted_tokens` | 只有品牌词与指定词缀组合才算域名命中；crt.sh 会生成对应组合查询。 |
| 组合词缀、诈骗词缀 | `domains.combo_affixes`、`fraud_affixes` | 域名/URL 匹配与短词候选生成；诈骗词缀还会影响风险信号。 |
| 短词长度阈值 | `domains.short_token_max_len` | 决定短词的保守匹配和部分连接器的查询方式。 |
| 页面当前称“已知仿冒域名”的字段 | `domains.known_lookalikes` | **实际上是合法相似第三方排除名单**，不要填已确认的恶意域名。 |

[查询计划生成器](../src/opti/sdk/plan.py)把规则转换成 [QueryPlan](../src/opti/sdk/models.py)：

```text
plan.terms             ← role=match 且 type≠executive 且 private=false
                         且词条 remote_search=true 且 mode=phrase
plan.domains           ← domains.official
plan.brand_tokens      ← domains.brand_tokens
plan.restricted_tokens ← domains.restricted_tokens
plan.languages         ← languages
plan.project_ids       ← project
```

例如默认 `Sample Brand` 会进入 `plan.terms`；默认 `SBR` 是整词模式并关闭外部检索，不会进入。各组件收到内容后仍可能用 `SBR` 做本地匹配，但某些连接器还有自己的预筛，不能保证所有内容都会回到平台。

`languages` 目前写入查询计划，但下列连接器没有直接读取 `plan.languages`；Google News 使用自己的 `editions`。授权编号、集合权重、审批编号不会自动作为搜索条件；集合权重当前也没有参与文本评分。

## 2. 主动按文本词搜索：8 个

| 连接器（链接到实现） | 发给外部的搜索字段 | 返回后如何处理 | 相关连接器参数 |
| --- | --- | --- | --- |
| [google_news](../src/opti/connectors/google_news/connector.py) | `plan.terms[].value` → Google News RSS 的 `q`，短语加引号；中文词用于中文版本，其他词用于非中文版本 | 标题与摘要进入平台文本匹配，不抓取新闻正文 | `editions`、`max_queries` |
| [brave_news](../src/opti/connectors/brave_news/connector.py) | `plan.terms[].value` → 新闻搜索 `q`，短语加引号 | 获取标题/摘要，按预算尝试抓正文，平台再匹配 | `max_queries`、`freshness`、`max_articles` |
| [gdelt_doc](../src/opti/connectors/gdelt_doc/connector.py) | `plan.terms` 中 ASCII 且至少 3 字符的词 → `query`，每 5 个词用 OR 组合；不直接发送中文/俄文词 | 获取文章链接、尝试抓正文，平台再匹配 | `max_queries` 统计组合后的查询数、`max_articles` |
| [urlscan](../src/opti/connectors/urlscan/connector.py) | `plan.terms` → `page.title:"词"`；同时用长度超过短词阈值的 `plan.brand_tokens` 搜索 `page.domain`，有 Key 时用对应通配字段 | 用域名/URL 规则筛选结果；标题被搜到不保证 URL 一定符合规则并回传 | `lookback`、`size`、`max_pages`；域名通配方式取决于是否有 API Key |
| [otx](../src/opti/connectors/otx/connector.py) | `plan.terms[].value` → OTX Pulse 搜索 `q`，短语加引号 | 接收允许的公开 TLP 情报，平台再做文本匹配 | `max_queries` |
| [reddit_search](../src/opti/connectors/reddit_search/connector.py) | `plan.terms[].value` → Reddit 搜索 `q`，短语加引号 | 连接器先按允许公开使用的文本词筛帖子，平台再匹配 | `max_queries`、`max_pages`；过长查询跳过 |
| [gitlab_projects](../src/opti/connectors/gitlab_projects/connector.py) | `plan.terms` 中长度 2–100 的词 → GitLab 公开项目 `search` | 匹配项目名称/描述等候选内容，不搜索全部仓库代码正文 | `max_queries`、`max_pages`、`page_size`、`exclude_namespaces` |
| [app_store_search](../src/opti/connectors/app_store_search/connector.py) | `plan.terms` 中长度 2–100 的词 → Apple 搜索 `term`，逐个配置的国家商店查询 | 按应用名和开发者名做文本匹配，不下载安装包 | `countries`、`max_queries`、`max_results` |

**覆盖范围注意：** Brave、Reddit、OTX、GitLab、App Store 等按顺序截取前 `max_queries` 个词；Google News 截取生成后的“版本＋词”组合；GDELT 截取合并后的查询。当前没有自动轮换被截掉的词，排在后面的词可能一直没有被这些源检索。`max_queries` 不等于“每轮随机挑几词”。

## 3. 按域名、URL 或内部标记查询/生成：6 个

| 连接器 | 发给外部的字段 / 生成依据 | 本地规则与边界 |
| --- | --- | --- |
| [crtsh](../src/opti/connectors/crtsh/connector.py) | `plan.brand_tokens` 生成 CT 查询；`plan.restricted_tokens` 生成“品牌词＋指定词缀”双向组合查询 | 使用 `DomainMatcher` 再筛选；不是用文本集合中的机构全称搜索。短词查询受 `short_token_max_len` 影响。 |
| [dnstwist](../src/opti/connectors/dnstwist/connector.py) | **从 `plan.brand_tokens` 生成候选标签**，结合 `tlds`、长短词 fuzzers、域名组合/诈骗词缀；对候选发 DNS 查询 | 不是把品牌短语交给搜索引擎，也不是只以官方域名为生成种子；生成后用域名规则筛选、检查注册。受限品牌词不作为独立生成种子。 |
| [common_crawl](../src/opti/connectors/common_crawl/connector.py) | 连接器自己的 `candidate_urls` → Common Crawl 索引精确 URL 查询 | 候选先经 `UrlMatcher` 验证，结果再经 URL 规则筛选；不会按 `brand` 词搜索全网正文。 |
| [github_code](../src/opti/connectors/github_code/connector.py) | `rules.domains.official` ＋连接器 `internal_terms` → GitHub 公开代码查询 | 不读取 `sets.brand.terms`；可用 `exclude_owners` 排除仓库所有者。 |
| [hibp](../src/opti/connectors/hibp/connector.py) | 官方域名，或连接器 `domains` 指定的官方域/其子域 → HIBP 域名泄露查询 | 指定域名必须属于官方域范围，且须在 HIBP 订阅/验证范围内。不是搜索品牌名称。 |
| [hudsonrock](../src/opti/connectors/hudsonrock/connector.py) | 官方域名，或连接器 `domains` 指定的官方域/其子域 → `domain` 参数 | 仅使用机构域名；当前还要求 `schema_verified` 和明确的 `api_url`。 |

urlscan 同时使用文本搜索词和域名品牌词，已在上一表列出，不重复计数。

## 4. 拉取订阅/列表/流，再筛选：12 个

这些组件也会请求外部服务，但不是把项目品牌词作为搜索参数发送。

| 连接器 | 外部获取依据 | 用于筛选的项目字段 |
| --- | --- | --- |
| [rss_feeds](../src/opti/connectors/rss_feeds/connector.py) | `feeds[].url`；`fetch_all` 控制是否为全部条目尝试抓正文 | `TextMatcher(rules)`，先按命中词粗筛标题/摘要，再由平台完整匹配 |
| [bluesky_jetstream](../src/opti/connectors/bluesky_jetstream/connector.py) | 配置的 Jetstream `url`，订阅帖子流，不向服务端发品牌搜索词 | 排除人员/私有集合、排除 `remote_search=false` 词后做文本匹配 |
| [mastodon_tags](../src/opti/connectors/mastodon_tags/connector.py) | `instances` ＋ `hashtags` 读取话题时间线，不会自动把品牌词变为话题 | 与 Bluesky 相同的公开词预筛，再由平台匹配 |
| [malwarebazaar](../src/opti/connectors/malwarebazaar/connector.py) | 获取近期恶意样本元数据 | 文本规则匹配文件名、家族名等；不下载样本 |
| [certstream](../src/opti/connectors/certstream/connector.py) | 配置的 CT WebSocket 流 | `DomainMatcher(rules.domains)`：官方域名、排除域名、域名品牌词、受限词、词缀与短词阈值 |
| [own_domain_ct](../src/opti/connectors/own_domain_ct/connector.py) | 同类 CT 流，不按机构名向 CT 服务端搜索 | 域名规则筛出官方域名证书，连接器 `approved_issuers` 判断签发机构 |
| [nrd](../src/opti/connectors/nrd/connector.py) | `sources` 指定的新注册域名列表、日期窗口 | 完整域名规则本地筛选 |
| [openphish](../src/opti/connectors/openphish/connector.py) | 配置的 `feed_url` | `UrlFeedScanner` / `UrlMatcher`，使用域名规则筛选主机、路径等 |
| [phishing_db](../src/opti/connectors/phishing_db/connector.py) | `lists` 指定的公开钓鱼列表 | 同上 |
| [phishtank](../src/opti/connectors/phishtank/connector.py) | PhishTank feed；凭据决定访问方式 | 同上 |
| [urlhaus](../src/opti/connectors/urlhaus/connector.py) | 近期恶意 URL feed | 同上 |
| [threatfox](../src/opti/connectors/threatfox/connector.py) | 近期 IOC feed，先按 `min_confidence` 筛选 | 域名/URL IOC 用同一 URL 规则筛选 |

域名匹配器使用 `domains` 段。URL 匹配器还会在 URL 路径等位置匹配 `brand_tokens`，而不是直接使用 `sets.brand` 中的文本短语。`known_lookalikes` 和官方资产会影响排除判断。

## 5. 其他采集与推送入口：9 个

| 连接器 | 外部查询/读取依据 | 项目字段在哪一步使用 |
| --- | --- | --- |
| [ransomware_live](../src/opti/connectors/ransomware_live/connector.py) | 聚合源的近期受害者列表，连接器 `api_base` 等设置 | 平台以“机构与供应商”清单比对受害者名称/域名；不是外发 `brand` 搜索 |
| [ransomlook](../src/opti/connectors/ransomlook/connector.py) | 同类近期泄露帖子元数据 | 同上 |
| [cisa_kev](../src/opti/connectors/cisa_kev/connector.py) | 下载 KEV 目录 | 平台以“软件清单”比对 CVE/厂商/产品；不是品牌检索 |
| [report_mailbox](../src/opti/connectors/report_mailbox/connector.py) | `mailbox`、`folder` 读取举报邮件与附件；`ignore_domains` 排除无关指标 | 提取域名/URL 等指标，平台继续做域名、URL 与举报信号处理 |
| [dmarc](../src/opti/connectors/dmarc/connector.py) | `mailbox`、`folder` 读取 DMARC 附件 | `domains.official` 判断报告是否属于本机构；`authorized_networks` 排除已授权来源 IP |
| [hibp_notify](../src/opti/connectors/hibp_notify/connector.py) | `mailbox`、`folder` 收取通知，`senders` / `require_dmarc_pass` 检查来源；另读取公开泄露目录 | 官方域名/连接器 `domains` 限定通知涉及的机构域，不按品牌词搜索邮箱 |
| [canary](../src/opti/connectors/canary/connector.py) | `intake` 金丝雀回调推送；连接器 `fetch()` 不主动采集 | 自有信号和相关域名由入口/平台处理 |
| [public_report](../src/opti/connectors/public_report/connector.py) | `intake` 公众举报推送；连接器 `fetch()` 不主动采集 | 入口/平台处理举报文本、域名与信号 |
| [referer_log](../src/opti/connectors/referer_log/connector.py) | Referer 日志入口推送；连接器 `fetch()` 不主动采集 | 日志聚合器与平台处理相关域名和信号 |

以上共覆盖当前 `src/opti/connectors/*/connector.yaml` 注册的 **35 个连接器**。富化器在 `src/opti/enrichers` 下，通常对单个域名、IP、URL 或文件做补充查询，不等同于按 `brand` 批量发现。`http_probe`、截图/OCR 也会使用文本规则检查已发现页面。

## 6. 配置和运行的常见误解

1. **保存词 ≠ 启用连接器。** 启用、审批、凭据、套餐、节点就绪与调度需分别满足。查“连接器中心”的准入原因及最近运行记录。
2. **开启外部检索 ≠ 所有组件都会搜索该词。** 仍有角色、模式、私有设置、语言、长度与 `max_queries` 限制。
3. **本地筛选指执行匹配的方式，不保证一定在境内服务器执行。** 采集节点也会做本地筛选。当前网关 `overseas_rules()` 只整体剔除人员集合，不能把 `private` 或 `remote_search=false` 当成整份规则绝不传到节点的统一隔离保证。
4. **共现与排除条件通常不传给外部 API。** 它们在匹配阶段生效；当前中文词走单独路径，尚未应用共现条件和排除词遮蔽。
5. **新连接器不会自动获得“保存关键词后立即回溯”。** 当前该回溯服务只绑定 crt.sh / dnstwist。普通新连接器先按自己的调度运行；若要联动，需显式修改 [backfill.py](../src/opti/pipeline/backfill.py) 及相应 API/测试。两个关键词页面另有手动“立即扫描”入口，搜索连接器可声明 `search_inputs: [text]` / `[domain]` 加入；见 [立即扫描说明](../deploy/README-keyword-scan.md)。

## 7. 如何新增

- 已有连接器：按 [Web 配置说明](../deploy/README-connectors.md) 启用、填写参数和凭据。
- 新的数据源：按 [新增连接器指南](adding-connectors.md) 增加实现与 manifest，再更新平台和采集节点镜像。
- 只是增加一条 RSS 订阅：修改 `rss_feeds` 的 `feeds`，无需新写一个连接器。
- 只是增加品牌名或域名：修改对应关键词字段，已有连接器会按本表规则使用它们。
