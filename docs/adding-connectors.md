# 手动新增连接器

关键词页面的“立即扫描”按 manifest 的 `search_inputs` 发现搜索连接器：声明 `[text]`、`[domain]` 或 `[text, domain]`，并读取对应 `QueryPlan` 字段。未声明的连接器继续原调度；声明后也不会自动加入保存关键词后的 crt.sh / dnstwist 回溯。见 [立即扫描说明](../deploy/README-keyword-scan.md)。

配套资料：[连接器搜索字段对照表](connector-field-map.md)、[Web 配置已有连接器](../deploy/README-connectors.md)。本文说明当前仓库的接入方式，不会安装或启用示例连接器。

## 1. 先判断是否需要写代码

| 你要做的事 | 操作位置 | 是否需要开发/更新镜像 |
| --- | --- | --- |
| 启用仓库已有的数据源、换 Key、调周期 | 连接器中心 | 无需新写连接器；配置热加载，部分常驻服务另有启动要求 |
| 给 RSS 加一家媒体 | `rss_feeds` 的 `feeds` | 不需要新连接器 |
| 给 Mastodon 加实例/话题 | `mastodon_tags` 的 `instances` / `hashtags` | 不需要新连接器 |
| 增加机构名称、域名品牌词 | 配置 → 关键词规则 | 不需要新连接器，使用范围见对照表 |
| 接入一个全新的 API、网站、数据格式 | 新增 Python 实现＋manifest | **需要**；目前不能只在 Web 填个 URL 就自动适配任意 API |

新数据源的关键词映射需要在代码中明确选择：搜文章读取 `plan.terms`；搜相似域名读取 `plan.brand_tokens` / `plan.restricted_tokens`；查机构自有资产可用 `plan.domains` 或 `ctx.rules.domains.official`。不要把 API Key、查询条数、套餐这些连接器参数写进品牌词集合。

## 2. 最少新增哪些文件

以 `my_news` 为例，ID 使用小写字母、数字、下划线，且以字母开头：

```text
src/opti/connectors/my_news/
    __init__.py        # 空文件
    connector.py       # 如何查询、解析、分页、维护游标
    connector.yaml     # ID、入口类、参数结构、凭据声明、调度等
config/connectors/my_news.yaml  # 镜像内初始设置，默认关闭
tests/connectors/test_my_news.py
```

[Registry](../src/opti/sdk/registry.py)启动时扫描 `src/opti/connectors/*/connector.yaml`，再按 `entrypoint` 加载类。**通常不用再维护一份连接器注册列表，也不用专门增加 API 路由。** 新增文件后需要重启/更新相关进程，现有进程不会自动重新扫描新 manifest。

目录名、manifest 的 `id`、Python 类的 `id` 必须一致。`entrypoint` 必须是可导入的 `模块:类名`。

## 3. manifest 示例

保存到 `src/opti/connectors/my_news/connector.yaml`。示例接口域名和响应协议都是占位约定，接入真实服务前按该服务的文档调整；不是可直接使用的新闻服务。

```yaml
id: my_news
name: "自定义新闻源"
version: 0.1.0
category: search_news
kind: [poll]
tier: freemium
entrypoint: "opti.connectors.my_news.connector:MyNewsConnector"
commercial_use: unknown
egress: overseas
pii_risk: low
default_enabled: false
credentials:
  - name: api_key
    required: true
    description: "该服务的只读搜索凭据"
plans:
  free:
    rate_limit: { per_second: 1 }
schedule:
  default: "0 */6 * * *"
  min_interval_seconds: 3600
config_schema:
  type: object
  properties:
    api_base:
      type: string
      pattern: '^https://'
      default: "https://api.example.org/v1/search"
    max_pages:
      type: integer
      minimum: 1
      maximum: 20
      default: 3
  additionalProperties: false
outputs: [document]
```

关键字段：

- `kind`：普通定时采集用 `poll`，批处理可用 `batch`，候选生成可用 `generator`；长连接用 `stream`，单对象补充查询属于 `enricher`。
- `egress`：`overseas` 在远程模式下分发给采集节点；`domestic` 在平台侧执行。按实际数据与网络要求选择。
- `credentials`：只声明凭据名与是否必需，**不把真实 Key 写到这里**。运行时用 `ctx.secret("api_key")` 获取 Web 保存或环境中的值。
- `config_schema`：定义可配置业务参数、类型、默认值和边界。连接器中心据此展示/校验；复杂结构可能需要 JSON 方式填写。
- `schedule.default`：五段 Cron，按 UTC 解释。普通轮询/批量/生成类连接器通过准入后，由调度器发现。
- `min_interval_seconds`：最小间隔的元数据，不是限流器。实际每请求限速看套餐 `rate_limit`；也不能把该值当成所有运行入口都会强制去重/限频的保证。
- `default_enabled`：仅在 manifest 写 `true` 不足以启用；实际运行看实例设置与准入结果。
- `outputs`：声明产出类型，**不会自动为未知 payload 增加处理逻辑**。

在 `config/connectors/my_news.yaml` 放初始值：

```yaml
enabled: false
license_approved: false
plan: free
config: {}
```

这只是没有 Web 覆盖时的基础设置。在 Web 保存过该连接器后，数据库里的该项整体覆盖文件设置；继续改 YAML 不会自动覆盖已保存的 Web 配置。

## 4. 实现：按文本词搜索并产出标准文档

以下代码放入 `connector.py`，使用现有 SDK，不直接新建 `requests` / `httpx` 网络客户端。

为说明游标约定，这里的假想 API 接受 `q` / `cursor`，返回：

```json
{
  "items": [{"id": "a1", "url": "https://news.example.org/a1", "title": "Sample Brand update", "summary": "Public summary", "text": "Public article text"}],
  "next_cursor": "checkpoint-2",
  "has_more": false
}
```

其中 `next_cursor` 必须是可持久保存、用于下一次增量读取的检查点；`has_more` 表示本轮还有没有下一页。真实服务如果使用日期窗口、页码、deltaLink 等，需要改写对应部分，不能机械套用。

```python
from collections.abc import AsyncIterator
from hashlib import sha256
from typing import ClassVar

from opti.core.documents import document_payload
from opti.sdk.base import BaseConnector, MissingCredential
from opti.sdk.models import QueryPlan, RawItem, Tier, utcnow


class MyNewsConnector(BaseConnector):
    id: ClassVar[str] = "my_news"
    tier: ClassVar[Tier] = Tier.FREEMIUM

    def validate_config(self) -> None:
        if not self.ctx.secret("api_key"):
            raise MissingCredential("需要 api_key")

    def compile_queries(self, plan: QueryPlan) -> list[str]:
        # 输入已经由统一查询计划过滤；不要自行把 private/人员词重新加入。
        return list(dict.fromkeys(term.value for term in plan.terms))

    async def fetch(self, plan: QueryPlan) -> AsyncIterator[RawItem]:
        endpoint = str(self.config["api_base"])
        headers = {"Authorization": f"Bearer {self.ctx.secret('api_key') or ''}"}
        for query in self.compile_queries(plan):
            key = "since:" + sha256(query.encode()).hexdigest()
            cursor = self.ctx.get_cursor(key)
            for _ in range(int(self.config["max_pages"])):
                params = {"q": query}
                if cursor:
                    params["cursor"] = cursor
                response = await self.ctx.http().get(
                    endpoint, params=params, headers=headers,
                    follow_redirects=False, max_body_bytes=2 * 1024 * 1024,
                )
                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                    raise ValueError("新闻搜索响应格式错误")
                more = data.get("has_more")
                next_cursor = data.get("next_cursor")
                if not isinstance(more, bool) or not isinstance(next_cursor, str) or not next_cursor:
                    raise ValueError("新闻搜索分页检查点错误")
                if more and next_cursor == cursor:
                    raise ValueError("新闻搜索游标没有前进")
                for row in data["items"]:
                    if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                        raise ValueError("新闻条目缺少稳定 ID")
                    url = row.get("url")
                    if not isinstance(url, str) or not url.startswith("https://"):
                        raise ValueError("新闻条目地址错误")
                    yield RawItem(
                        connector_id=self.id, source_item_id=row["id"],
                        fetched_at=utcnow(), url=url,
                        payload=document_payload(
                            url=url, title=str(row.get("title") or ""),
                            summary=str(row.get("summary") or ""),
                            text=str(row.get("text") or ""),
                            source_name="自定义新闻源", query=query,
                        ),
                        project_ids=plan.project_ids,
                    )
                # 本页全部交给调用方后再推进；中断时允许重放，由稳定 ID 去重。
                self.ctx.set_cursor(key, next_cursor)
                cursor = next_cursor
                if not more:
                    break
```

这个例子遍历全部去重后的公开查询词，没有默默截取固定的前 N 个词。若真实服务必须限制每轮查询数，需实现可恢复的轮换位置，或明确说明覆盖范围，避免后面的品牌词长期不被搜索。

`source_item_id` 必须在同一连接器中稳定且唯一。如果供应商的 ID 只在某个栏目内唯一，应包含栏目；如果需要同一文章更新后再次入库，应设计包含修订版本的 ID，而不是直接使用当前时间或随机 UUID。

SDK 的 HTTP 客户端提供超时、退避和限速；API 的日/月总额度不能仅靠进程内每秒限速保障。需要访问结果网页时，复用 `SafeFetcher` / `NewsConnector` 的正文抓取机制。只读采集若必须用 POST，应按现有 `malwarebazaar_recent` 等方式做固定接口的窄范围适配；SDK 的通用 `post_json` 定义为告警/内部服务使用，不应直接拿来绕过采集限制。

## 5. 让结果进入已有业务

平台按 `RawItem.payload` 的结构识别结果，相关分支在 [Processor.process](../src/opti/pipeline/processor.py)：

| 你采到的内容 | 复用方式 | 可参考实现 |
| --- | --- | --- |
| 新闻、社交文本、应用信息 | `document_payload(...)`，平台统一用文本词匹配和评分 | `google_news`、`reddit_search`、`app_store_search` |
| 域名/URL feed | `UrlFeedScanner`，或按已有域名 `matches` 格式产出 | `openphish`、`crtsh`、`nrd` |
| 勒索受害者帖子 | 现有 `leak_post` 结构，平台按机构/供应商比对 | `ransomware_live`、`ransomlook` |
| 软件漏洞 | 现有 `kev` 结构，平台按软件清单比对 | `cisa_kev` |
| 邮箱泄露 | 现有 `exposure` 结构及官方域名检查 | `hibp` |

新加一个任意 JSON 字段不会自动得到告警页面和评分。确需新的结果类型时，还需要扩展解析、处理、持久化及展示，并增加相应测试。只做已有类型适配通常不需要数据库迁移。

## 6. 本地验证

先为新连接器写离线测试，参考 [SDK 测试辅助](../src/opti/sdk/testing.py) 的 `make_context`、`MemoryCursorStore`、`httpx.MockTransport`。至少覆盖：

1. registry 能发现 manifest、加载类，三处 ID 一致。
2. 请求真的使用预期字段，未把私有/人员/关闭外部检索的词重新发出去。
3. 缺少 Key、错误响应、限流、空结果、分页、游标不前进。
4. 同一条记录跨查询出现时有稳定 ID；中断重试不会越过未消费的数据。
5. 结果能被目标 payload 解析；需要告警的测试样例能进入正确处理分支。

在仓库根目录执行：

```sh
uv run pytest tests/connectors/test_my_news.py tests/sdk
uv run ruff check src/opti/connectors/my_news tests/connectors/test_my_news.py
uv run mypy src/opti/connectors/my_news
uv run opti connectors
```

以下命令会真实访问已配置的数据源，需先按你的测试环境设置完成启用、凭据及准入：

```sh
# CLI collect 从规则文件和本地运行时实例设置开始；不直接写入处理流水线。
uv run opti --rules config/projects/sample-brand/keywords.yaml collect my_news --max-items 5 --seconds 30

# 运行一次并进入平台处理流水线，需要数据库等平台依赖。
uv run opti run my_news --max-items 5 --seconds 30
```

**注意 CLI 的配置来源。** 上面的 `collect` 示例显式传了 `--rules`，会直接使用规则文件，不走数据库当前配置加载；调试时需给本地 `config/connectors/my_news.yaml` 配置适当实例设置，并通过测试环境的 secret provider/环境变量供给凭据。不显式传 `--rules` 且配置了数据库时，CLI 会用 `load_current()` 一次性加载当前规则及 Web 覆盖；长驻平台服务还会持续刷新配置。不要为了让 CLI 通过而把真实 Key 写进示例或提交的 YAML。

## 7. 发布后在 Web 上启用

1. 将实现、manifest、默认实例文件和测试放入部署版本。平台 API、worker、scheduler、gateway 以及执行它的采集节点需要获得同一版代码；按实际运行模式更新相关镜像并重启。只重启旧镜像不会安装新代码。
2. 打开连接器中心，找到 `my_news`。配置业务参数、套餐、Key 和启用状态。平台管理员负责参数/凭据；具备审批权限的账号维护许可批准与编号。
3. 轮询类确认有 Cron，流式类另需常驻任务：远程节点把 ID 加入 `OPTI_COLLECTOR_STREAMS`；单机按现有 `stream-bluesky` 服务方式增加对应 `opti stream <id>` 服务。
4. remote 模式下确认节点心跳已上报此连接器可运行；仅平台列表出现并不代表节点具备对应实现。
5. 等一次调度或执行受控的单次运行，核对最近运行、条数、错误以及业务页面中的发现。采集成功不一定产生告警，还取决于匹配结果、评分、抑制和告警策略。

普通新连接器由现有 registry、连接器中心和调度器发现，通常不必新增前端页面。若需要自定义编辑器、额外业务展示或关键词保存后的自动回溯，则另行扩展对应功能；当前关键词回溯只绑定 crt.sh / dnstwist。

## 8. 接入前填写这张小表

| 项目 | 需要明确的内容 |
| --- | --- |
| 连接器 ID / 名称 | 唯一 ID、显示名 |
| 数据源与用途 | 搜索 API、订阅列表、流式数据，还是单对象富化 |
| 查询字段 | 文本词、域名品牌词、官方域名，或连接器自己的参数 |
| API 请求和响应 | 鉴权、查询语法、分页、增量检查点、错误格式 |
| 配额 | 每秒、每日/月额度，单轮覆盖范围 |
| 执行位置 | 平台或采集节点 |
| 产出结构 | document / URL / 域名 / 已有其他类型 |
| 验证样例 | 应命中、不应命中、重复、空结果、错误响应 |

接入完成后把新 ID 与字段映射补入 [搜索字段对照表](connector-field-map.md)，避免后续只看到“配置了品牌词”，却不知道哪些源实际搜索了它。
