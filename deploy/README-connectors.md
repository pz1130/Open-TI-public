# 在 Web 中配置连接器

字段调用关系见 [连接器搜索字段对照表](../docs/connector-field-map.md)；接入全新数据源见 [手动新增连接器](../docs/adding-connectors.md)。

进入「连接器中心」，平台管理员可以调整启用状态、套餐、参数和凭据。合规官可以单独维护许可批准状态与审批编号。批准与启用是两道独立的检查；缺少必需凭据时连接器仍不会运行。

Web 配置存在数据库里（配置种类 `connectors`），只记录在 Web 上改过的连接器，每一项整体替换镜像内 `config/connectors/<id>.yaml` 的同名设置；没改过的连接器仍按 YAML。每次保存生成一个版本并写审计，备份数据库即包含这些设置。API、worker、scheduler 和 gateway 约 10 秒内热加载，scheduler 在下一次取定时任务（每分钟）时按新设置排程；修改正在运行的本地流式采集或启动时创建的富化器后，重启相应服务。境外采集节点通过已有的 mTLS 网关每分钟刷新配置，凭据只留在节点内存中；平台 `.env` 里的连接器凭据不会下发给节点。

凭据用平台主密钥加密后存库，接口只返回是否已设置。首次使用由平台管理员在「设置 → 凭据加密主密钥」生成并备份，或导入原主密钥恢复已有凭据；也支持环境变量 `OPTI_ENCRYPTION_KEY`。Web 初始化的密钥保存在共享数据目录 `secrets/master-key`，API、worker、scheduler 与 gateway 均须共享该持久化目录，保存后自动可用。没有主密钥时，连接器编辑面板提供设置入口。

库中没有某个凭据时仍读取环境变量 `OPTI_SECRET_<连接器ID>_<名称>`。凭据无法解密时，编辑面板会提示。已有主密钥不会被 Web 初始化覆盖；轮换时，设置新的 `OPTI_ENCRYPTION_KEY` 和旧的 `OPTI_ENCRYPTION_KEY_PREVIOUS`，运行 `opti rekey`（连接器凭据包含在“配置密钥”里），确认完成后再移除旧密钥。备份数据库时应同时保留主密钥；只恢复其中一项将无法解密凭据。

轮询、批量和生成型连接器的定时采集时间可在编辑面板修改（五段数字 Cron、UTC；留空恢复默认），自动生效，并与其他参数一起进入配置历史。流式连接器保持常驻运行，富化器由业务任务触发，不单独设置 Cron。

Web 中点击「清除」会清除该凭据，并覆盖同名环境变量。留空输入框则保持原值。修改写入审计日志，凭据值不进入日志。

编辑面板的「历史」只列出改动过这个连接器的版本及其差异；平台管理员可以“恢复参数到此版本”，只恢复启用、套餐与参数，法务批准与凭据不变（批准请在审批表单中重新填写）。凭据改动不进版本记录，可在审计日志中查看。

从旧版本升级：旧版本把 Web 配置保存在共享数据目录的 `connector-config.json`。`opti db-upgrade`（Compose 的 `migrate` 服务）会在数据库还没有连接器设置时把它整份导入，并把文件改名为 `connector-config.json.migrated`。文件里有加密凭据而服务器没有配置 `OPTI_ENCRYPTION_KEY`、或其中有无法解密的凭据或无效的连接器设置时，升级报错退出且文件与数据库都不改动；修正后重新运行即可。确认导入无误后可删除 `.migrated` 文件。

## 单机部署 Bluesky

先在 Web 配置中打开启用开关并点击「保存配置」，再保存许可审批。关闭配置面板不会保存修改。Bluesky 无需 API Key，但属于持续运行的流式连接器，单机部署还需启动对应服务。在服务器仓库根目录执行：

```sh
docker compose -f deploy/compose.platform.yml --profile local-social up -d --build stream-bluesky
```

此服务与 API 共用 `opti-data`，读取 Web 保存的配置。它适用于 `OPTI_COLLECTOR_MODE=local`；远程模式应将 `bluesky_jetstream` 加入采集节点的 `OPTI_COLLECTOR_STREAMS` 并重建该节点。若仍显示停用，展开该行查看准入原因；若已可运行但从未运行，检查流式采集服务是否启动。
