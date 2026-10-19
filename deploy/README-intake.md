# 机构自有数据入口（S2-B）

先修改 `config/organization.yaml`，并设置 `OPTI_RULES` 指向本机构的授权关键词规则。默认 `config/projects/example/keywords.yaml` 仅为中性示例。现有部署若继续使用原示例规则，需要显式设置 `OPTI_RULES=config/projects/sample-brand/keywords.yaml`。迁移 0005 只改新项目的租户默认值，不改已有项目归属。

## 本平台内网部署

在 `.env` 填写 `OPTI_SECRET_INTAKE_CANARY_TOKEN`（16–128 位字母、数字、`_` 或 `-`）与 `OPTI_SECRET_INTAKE_REPORT_KEY`（至少 32 字符），然后：

```sh
docker compose -f deploy/compose.platform.yml --profile intake --profile syslog up -d --build
opti canary-snippet --base-url https://www.example.org/ti-intake
```

平台 Compose 的 intake/syslog 只继承规则与任务队列配置，不继承数据库、邮箱或对象存储凭据。两个接收端口默认仅绑定宿主回环地址；同机代理可转发。跨主机转发时按机构内网地址调整端口绑定，仅允许网站服务器连接。入口禁用访问日志，不记录访问者 IP、Cookie 或完整 Referer。

Nginx 代理示例：

```nginx
location /ti-intake/ {
    proxy_pass http://127.0.0.1:8100;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Referer $http_referer;
    client_max_body_size 64k;
    access_log off;
}
```

金丝雀 JS 只在页面主机不属于官方域名时发送回调。CSS 版本依赖浏览器发来的 Referer；Referer 为空时不会生成指标。正确、错误令牌及转交失败都返回相同 GIF。单个主机每 600 秒最多转交一次，同一 UTC 小时在平台去重。

网站后端签名后提交公众举报：

```python
import hashlib
import hmac
import json
import time
import urllib.request

# KEY 由网站后端从密钥存储读取，不能放进浏览器页面。
body = json.dumps({"description": "自称贷款专员并要求先交手续费", "urls": ["https://login-portal.example/apply"], "category": "loan"}).encode()
ts = str(int(time.time()))
signature = hmac.new(KEY, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
request = urllib.request.Request(
    "https://www.example.org/ti-intake/report", data=body, method="POST",
    headers={"Content-Type": "application/json", "X-Opti-Timestamp": ts, "X-Opti-Signature": signature},
)
with urllib.request.urlopen(request, timeout=30) as response:
    print(response.status)
```

成功返回 202 与举报 ID；过期或错误签名 401、重放 409、超大请求 413、格式错误 422、转交失败 503。503 后可重试同一已签名请求，但时间戳仍须有效。签名校验窗口为前后 300 秒。重放状态保存在单个进程，故只运行一个副本；重启时内存状态会清空。在反向代理端保留单实例路由并限制请求速率；需要跨重启或多副本持久重放校验时须换成共享状态存储。

举报联系方式只保存在 `report` Finding 的 `match.context.contact`，不复制到 URL/域名 Finding 或原始数据；每日 UTC 03:10 清除超过 `OPTI_REPORT_CONTACT_DAYS`（默认 90 天）的联系方式，保留举报描述和指标。该清除任务也处理旧原始数据中已有的联系方式。

## 独立对外主机：mTLS 网关转交

入口主机仅部署应用镜像/程序与规则、连接器配置，不提供 `OPTI_DATABASE_URL` 或邮箱凭据。设置：

```sh
export OPTI_INTAKE_FORWARD=gateway
export OPTI_GATEWAY_URL=https://gateway.example.org:8443
export OPTI_NODE_ID=intake
export OPTI_GATEWAY_CA=/pki/ca.pem
export OPTI_NODE_CERT=/pki/node-intake.pem
export OPTI_NODE_KEY=/pki/node-intake.key
# OPTI_SECRET_COLLECTOR_NODE_TOKEN、两个 INTAKE 密钥通过密钥存储注入。
opti intake
```

主平台将 `intake` 加入 `OPTI_GATEWAY_NODES`，设置同值 `OPTI_SECRET_GATEWAY_NODE_INTAKE`，并签发该节点的客户端证书。必须先收到网关接受确认才返回 202。`canary`/`public_report` 连接器的 enabled 与 license_approved 需要放行；网关再次检查。`report_mailbox`、`dmarc`、`referer_log` 为 domestic，不能经境外节点回传。

平台 Compose 的 intake profile 固定用于内网 direct 模式；独立主机使用上面的 gateway 配置。`OPTI_INTAKE_HOST/PORT/PREFIX`、`OPTI_FORWARDED_ALLOW_IPS` 可覆盖监听与可信代理；默认监听 0.0.0.0:8100、路径 `/ti-intake`。

## 邮箱：只读 Microsoft Graph

填写 `config/connectors/report_mailbox.yaml` / `dmarc.yaml` 的邮箱及 `.env` 中对应 `OPTI_SECRET_*_TENANT_ID/CLIENT_ID/CLIENT_SECRET` 后启用。只授予读取正文和附件所需的应用权限 Mail.Read，由管理员将应用访问范围限定到指定邮箱；不移动、删除或标记消息。

`authority` / `graph` 支持国家云，例如世纪互联部署可配置 `https://login.chinacloudapi.cn` 与 `https://microsoftgraph.chinacloudapi.cn/v1.0`。权限与邮箱范围需要在所用租户中配置并验证。

举报邮箱默认每 5 分钟轮询；分页上限后保存 nextLink，下一次继续读取。同一时间戳的消息以 Graph ID 去重。可解析 .eml 邮件封装和 Outlook itemAttachment；普通二进制附件仅计算哈希，不执行、不解压、不保存。内联转发仅可靠提取链接，不把举报员工的发件域当作可疑指标。默认忽略邮件服务域名，可用 ignore_domains 替换。

DMARC 默认每小时读取，处理官方发件域 SPF/DKIM 对齐均失败的记录；在 authorized_networks 的 CIDR 中的来源不告警。XML 禁止 DTD/实体；支持 XML、单报告 gzip/zip，解压后最多 20 MiB。只有公网来源 IP 创建 Finding，不对 IP 做网页富化。

## Referer 日志

`opti syslog` 默认监听 TCP 0.0.0.0:6514，支持换行与 RFC 6587 八位组计数分帧。Web 服务器发送 combined 或 JSON 日志；JSON 字段可为 Nginx 的 request_uri/status/http_referer，或 Cloudflare 的 ClientRequestPath/EdgeResponseStatus/ClientRequestReferer。按一小时窗口聚合，至少 `OPTI_SYSLOG_MIN_HITS` 次才产生盗链 Finding，仅保留来源主机、次数和最多五个资源路径，不保存访客地址或完整 Referer。

同时设置 `OPTI_SYSLOG_TLS_CERT` 与 `OPTI_SYSLOG_TLS_KEY` 可启用 TLS；容器部署需将证书只读挂载，并通过 Compose override 传入这两个变量。仅配置一个会拒绝启动。转交失败的窗口保留在内存中等待重试；进程退出时尝试刷新，非正常退出会丢失内存中的未转交窗口。

接口依据：[Graph 邮件列表](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0)、[读取附件](https://learn.microsoft.com/en-us/graph/api/attachment-get?view=graph-rest-1.0)、[国家云](https://learn.microsoft.com/en-us/graph/deployments)、[DMARC 聚合报告](https://datatracker.ietf.org/doc/html/rfc9990)。
