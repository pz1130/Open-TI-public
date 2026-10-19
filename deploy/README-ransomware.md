# 勒索泄露站与供应商风险（S3-B）配置

平台只从 ransomware.live 和 RansomLook 等聚合服务读取受害者元数据。本机构或维护的供应商出现在名单上时，平台产生告警；不会访问泄露站或下载泄露文件。“被列为受害者”需要人工核实，不等于已确认数据泄露。

## 1. 维护供应商清单

编辑 `config/vendors.yaml`，或用 `OPTI_VENDORS` 指向机构自己的配置文件：

```yaml
vendors:
  - id: payroll-co
    name: "Payroll Co Ltd"
    aliases: ["Payroll Co", "PayrollCo Group"]
    domains: ["payroll-co.example"]
    tier: critical
    owner: "人力资源部 / 采购部"
```

名称去掉常见法律后缀后必须完全相等；请把其他常用写法填入 `aliases`，并尽量提供 `domains`。先运行 `opti vendors-test "Payroll Co" --domain payroll-co.example` 检查匹配。改动后重启 worker，再运行 `opti vendors-rematch` 立即补比对近一年的历史帖子；每天 03:30 UTC 也会自动补比对。本机构名称来自 `config/organization.yaml`，官方域名来自关键词规则。

## 2. 批准数据源

两个连接器都默认关闭且未批准。ransomware.live 的免费接口在设计文档中标为仅限个人用途；机构使用前应核实当前条款并取得适用的 PRO 授权，在 `config/connectors/ransomware_live.yaml` 填写套餐、实际 API 地址及密钥，然后启用。RansomLook 可自建；使用公共实例前应确认条款，自建时填写 `config.api_base` 与 `config.link_hosts`。任何启用前都要用获授权的测试环境核对 API 端点和字段，因为聚合服务可能更新接口。两者仅调用配置的 HTTPS 聚合服务接口；只有配置的聚合站页面链接可点击。

## 3. 告警后

告警会显示帖子、匹配方式、供应商等级与负责团队。由负责团队联系供应商核实，再评估本机构数据是否受影响。不要把帖子本身作为已确认泄露的证据。
