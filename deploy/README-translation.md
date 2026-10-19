# Phase 2-U：告警线索的本地按需翻译

默认不启用。启用后，拥有告警与证据读取权限的分析员可以在文档类告警详情中，将已保存的标题和命中片段按需译为界面语言（中文或英文）。平台不读取完整正文，不保存译文，也不改变匹配、评分、告警或原文。译文仅供阅读，需与原文核对。每位用户每分钟最多请求 10 次；审计记录只包含原语言、目标语言、字符数和告警 ID，不包含原文或译文。

API 只接受本机 Unix socket 上的 HTTP 翻译服务，不接受远程翻译 URL。服务须实现兼容 [LibreTranslate `/translate` API](https://github.com/LibreTranslate/Documentation/blob/main/src/content/docs/guides/api_usage.md) 的 `POST`：请求 JSON 的 `q` 为字符串数组，`source` 和 `target` 为两位语言代码，`format` 为 `text`；响应 JSON 的 `translatedText` 为等长字符串数组。可使用[自建 LibreTranslate](https://github.com/LibreTranslate/Documentation/blob/main/src/content/docs/guides/installation.md) 并在同一主机上以 Unix socket 代理其本机监听端口。服务和模型由使用机构自行部署、更新及校验适用许可；模型所支持的语言对取决于实际安装内容。不要把翻译服务暴露到公网，也不要将 socket 代理到第三方服务。

在 Linux 主机上创建仅供平台 API 用户（容器 UID `10001`）连接的 socket 目录。让本机代理监听例如 `/srv/opti/translation/translate.sock`，并转发到仅监听 `127.0.0.1` 的翻译服务。socket 需要对 UID `10001` 可连接；代理进程的权限、重启、健康检查和日志由部署环境管理。将以下覆盖文件交给 Compose（示例路径按实际部署修改）：

```yaml
services:
  api:
    volumes:
      - /srv/opti/translation:/run/opti-translation:ro
```

然后在 `.env` 中设置 `OPTI_TRANSLATION_SOCKET=/run/opti-translation/translate.sock`，重启 API。只向 `api` 服务挂载 socket；worker、采集节点和浏览器沙箱均无需访问。未设置环境变量时页面没有翻译入口；服务不可用或不支持语言对时，单次请求返回错误，原告警仍可正常查看。请求与响应均有长度上限，HTTP 跳转不会跟随。

上线检查：在获授权的测试告警中确认原语言已识别、翻译按钮出现、译文与原文同时显示；确认审计记录不含正文；停止本地翻译服务后确认页面只提示本次翻译失败。当前仓库的自动化测试使用模拟的 Unix socket 与翻译服务，没有在真实模型上验证译文质量或生产部署。
