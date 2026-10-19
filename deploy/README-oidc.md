# 单点登录（OIDC）配置

平台使用 OIDC 授权码流程 + PKCE。浏览器只与平台和身份提供方交互；平台服务器需要能访问身份提供方的发现文档、JWKS 与令牌端点。多因素认证、条件访问等由身份提供方负责。

当前版本优先在「配置 → 管理员 → 登录与单点登录」保存提供方、客户端信息、角色映射和客户端密钥，保存后自动生效。下文 YAML 和环境变量用于初始文件或兼容原部署；已有 Web 版本时使用数据库中的配置。SSO 账号和本地账号的状态、额外角色、权限集均可在 Web 管理，详见 [用户、角色与权限集](README-users.md)。

回调地址（在身份提供方登记）：`https://<平台地址>/api/v1/auth/oidc/callback`
（默认由 `config/alerting.yaml` 的 `public_base_url` 拼出；也可在 `config/oidc.yaml` 中用 `redirect_uri` 指定。）

## Microsoft Entra ID

1. Entra 管理中心 → 应用注册 → 新注册：只限本组织目录中的帐户；重定向 URI 选"Web"，填回调地址。
2. 证书和密码 → 新客户端密码 → 写入 `.env` 的 `OPTI_SECRET_OIDC_CLIENT_SECRET`（到期前更换）。
3. 应用角色 → 创建角色（允许的成员类型：用户/组），值例如 `Opti.Analyst`、`Opti.Responder`、`Opti.Viewer`、`Opti.Auditor`、`Opti.Compliance`、`Opti.PlatformAdmin`。
4. 企业应用程序 → 本应用 → 属性："需要分配"设为"是"；用户和组 → 把安全组分配到上述应用角色。
5. 令牌配置 → 添加可选声明：ID 令牌 `email`（可选）。
6. 如需登出后回到平台：在"重定向 URI"中登记 `post_logout_redirect_uri` 的地址。
7. `config/oidc.yaml`：

```yaml
enabled: true
provider: entra
tenant_id: "<目录（租户）ID>"
client_id: "<应用程序（客户端）ID>"
post_logout_redirect_uri: "https://<平台地址>/"
role_mapping:
  analyst: [Opti.Analyst]
  responder: [Opti.Responder]
  viewer: [Opti.Viewer]
  auditor: [Opti.Auditor]
  compliance_officer: [Opti.Compliance]
  platform_admin: [Opti.PlatformAdmin]
```

使用应用角色（`roles` 声明）而不是组：用户所属组超过 200 个时，ID 令牌不再携带组（组超额），平台会拒绝登录并提示。

参考：[Microsoft 应用角色配置](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)、[组声明与应用角色](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles)。

## Keycloak（或其他 OIDC 身份提供方）

1. 新建领域（realm）与客户端：OpenID Connect、"Client authentication"开启（机密客户端）、只勾选"Standard flow"；有效重定向 URI 填回调地址；高级设置中"Proof Key for Code Exchange Code Challenge Method"选 `S256`。
2. 客户端作用域 → 专用作用域 → 添加映射器"Group Membership"：令牌声明名 `groups`，"Full group path"关闭，"Add to ID token"开启。
3. 凭据页的客户端密钥写入 `OPTI_SECRET_OIDC_CLIENT_SECRET`。
4. `config/oidc.yaml`：

```yaml
enabled: true
provider: generic
label: "单位账号"
issuer: "https://<keycloak 地址>/realms/<领域>"
client_id: "opti"
post_logout_redirect_uri: "https://<平台地址>/"
roles_claim: groups
role_mapping:
  analyst: [opti-analysts]
  responder: [opti-responders]
```

## 应急账号

接入单点登录后保留本地超管应急账号。现在可直接在「配置 → 管理员 → 用户管理」创建本地账号、分配角色、重设密码和停用账号，SSO 用户也可停用；账号停用后身份提供方放行也不能登录。初始超管及恢复命令见 [用户管理说明](README-users.md)。本地登录开关以 Web 中保存的登录配置为准；关闭后本地应急账号暂时无法登录。

口令失败与单点登录发起次数按来源 IP 限流。经过反向代理部署时，把 `OPTI_FORWARDED_ALLOW_IPS` 设为可信代理的 IP，并让代理覆盖客户端送来的 `X-Forwarded-For`；否则所有用户可能被识别为同一个代理地址。

## 角色何时生效

角色在每次单点登录时按身份提供方的组 / 应用角色重新计算；平台每次请求读取账号当前角色，因此角色同步后已有会话也按最新角色判权。身份提供方的变化要等用户重新登录才同步；需要立即撤销时用 `opti user-disable`。
