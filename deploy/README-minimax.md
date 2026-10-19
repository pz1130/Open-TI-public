# MiniMax 大模型研判

在「大模型研判 → 添加供应商」中选择 MiniMax，填写该站点的 API Key 和账户可用的模型名，再保存、测试连接。

| 设置 | 国内站 | 国际站 |
| --- | --- | --- |
| 接口地址 | `https://api.minimax.cn/anthropic/v1` | `https://api.minimax.io/anthropic/v1` |
| 请求协议 | Anthropic Messages | Anthropic Messages |
| 鉴权 | Bearer API Key | Bearer API Key |

接口地址必须与 Key 所属站点一致。模型名可手填 `MiniMax-M2`、`MiniMax-M2.7` 等账户支持的模型；新建默认保留 `MiniMax-M2`，不会自动升级已有模型。MiniMax 预设不获取模型列表，也不发送 OpenAI 的 `response_format` 参数。

系统会补齐官方 SDK 示例地址末尾的 `/v1`，也接受完整的 `/anthropic/v1/messages` 地址。最终调用路径为 `/anthropic/v1/messages`，不会重复拼接。

## 已有配置升级

更新并重建、启动 API 和 worker 后，已保存的 MiniMax 预设自动使用 Anthropic 协议。旧版官方地址 `https://api.minimaxi.com/v1` 会按国内站新地址处理，国际站 `.io` 地址保留国际站。该兼容处理同时覆盖连接测试和后台研判，不需要数据库迁移、重新录入 Key 或更换主密钥；模型名、温度和代理配置保持原值。

自定义中转地址保留原主机和路径前缀，但 MiniMax 预设发送的是 Anthropic Messages 格式。如果中转服务只接受 OpenAI 格式，应选择「自定义 OpenAI 兼容」预设，并使用中转服务要求的地址。

## 生成长度和错误提示

MiniMax 的生成上限包含思考过程，本项目将 MiniMax 单次研判上限从通用的 600 调整为 8192 token；这是上限，实际用量取决于模型输出。只提取返回内容中的文本块作为研判结果，不把思考块作为 JSON 解析。达到上限会显示生成长度提示。

测试失败会按 HTTP 状态和已知错误码提示可能原因，包括 Key 或站点不匹配、接口或模型不存在、余额不足和额度限制。错误提示、测试记录和审计日志不会复制供应商返回的错误正文，避免泄漏密钥或输入内容。

官方参考：[Anthropic SDK](https://platform.minimax.cn/docs/api-reference/text-anthropic-api)、[Messages API](https://platform.minimax.cn/docs/api-reference/text-chat-anthropic)、[错误码查询](https://platform.minimax.cn/docs/api-reference/errorcode)。
