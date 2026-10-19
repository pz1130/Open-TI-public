# 员工凭据暴露（S3-A）配置

平台发现本机构邮箱出现在公开泄露事件或窃密木马记录中时，生成"凭据暴露"告警；受影响账户只经工单通道推给 IT，平台不直接联系员工。

## 1. 验证域名所有权（两种方式都需要）

在 HIBP 的 Domain Search 页面验证本机构邮箱域名（DNS TXT 记录或向域名的 security@ 等地址发验证邮件）。验证时登记的邮箱会收到之后的泄露通知。

## 2a. 有 HIBP 订阅：域名搜索接口（推荐）

1. 购买覆盖本机构域名规模的订阅（泄露地址超过 10 个的域名需要付费），取得 API 密钥。
2. `.env`：`OPTI_SECRET_HIBP_API_KEY=<密钥>`；`config/connectors/hibp.yaml` 设 `enabled: true`。
3. 连接器每 6 小时查询一次，名单没有变化时不产生新数据。

## 2b. 没有订阅：解析免费通知邮件

1. 在 Entra 中为平台注册应用，按 Exchange Online 的 **Application RBAC** 为接收 HIBP 通知的邮箱授予限定范围的 `Application Mail.Read`，并确认应用只能读取该邮箱。新部署不再采用旧版 `New-ApplicationAccessPolicy`。可与 S2-B 的举报邮箱应用共用，但授权范围必须包含通知邮箱。
2. `.env`：`OPTI_SECRET_HIBP_NOTIFY_TENANT_ID`、`OPTI_SECRET_HIBP_NOTIFY_CLIENT_ID`、`OPTI_SECRET_HIBP_NOTIFY_CLIENT_SECRET`、`OPTI_HIBP_NOTIFY_MAILBOX`；`config/connectors/hibp_notify.yaml` 设 `enabled: true`。
3. 通知只说明"哪个事件涉及本机构、涉及多少地址"，账户明细需在 HIBP 后台查看后由 IT 处理。

## 3. Hudson Rock（可选）

Hudson Rock 官方提供免费**网页工具**；API 文档描述的是需要认证的接口，原计划中的无认证 v2 统计接口及字段尚未得到官方文档证实。适配器只是待验证的实现，默认 `enabled: false`、`license_approved: false`、`schema_verified: false`。取得明确的 API 使用授权后，先在测试环境核对接口版本、认证方式、响应字段和统计口径，更新适配器与定向测试，再填写 `api_url`、设 `schema_verified: true` 并开启许可和启用开关。不要把网页工具的免费使用等同于生产 API 授权。

## 4. 推给 IT

受影响账户通过 `config/tickets.yaml` 配置的工单通道发送（S2-C）：Webhook 的 `details.exposure.accounts`，或发往 `email_to` 的邮件正文。建议把 `email_to` / Webhook 指向 IT 安全团队的队列。`auto_push` 中列出的严重级别会自动推送；也可在告警详情中点"推送 N 个账户给 IT"。

## 5. 个人信息

- 受影响账户只保存在 `exposed_account` 表中；只有 `responder` 角色能在界面查看（每次查看写审计），其他地方只显示数量。
- 最后一次出现超过 `OPTI_EXPOSURE_RETENTION_DAYS`（默认 180）天的记录每日自动删除。
