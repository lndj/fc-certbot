# ESA NS → FC 证书自动续期操作手册

适用于本仓库的 ESA 入口；以下域名、邮箱、资源名均为占位符。权限策略、完整参数和恢复细节见 [ESA 指南](ESA.zh-CN.md)，离线测试见 [验证记录](VALIDATION.md)。不要把实际配置或证书放进 Git。

## 1. 部署前准备

- ESA 站点须 **NS 接入且已生效**；核对 SiteId、zone、完整 NS 清单和 ESA 控制面地域。FC/ESA 地域分别配置，域名、站点、地域均受白名单限制。
- 专用执行角色仅信任 FC，逐次从 `context.credentials` 获取临时 STS，不嵌入长期 AK。9 项运行 API 见 [权限审查](ESA.zh-CN.md#先决条件与权限审查)；ESA 删除记录、CAS/FC 部分操作需 `Resource: "*"`，代码白名单不等于 RAM 隔离。部署身份权限另审。
- 准备同地域 VPC、交换机、安全组、加密 NFS NAS 和 SLS，确认费用及协议。NAS 仅开放所需源网段，保留 `root_squash`；共享网段不是函数独占隔离。
- 按映射 UID/GID（示例 `10003:10003`）创建 NAS 私有目录，目录 `0700`、状态/私钥 `0600`；挂载该远端目录到 `/mnt/certbot`，开启传输加密，实测属主和可写性。
- 确认联系邮箱、Let's Encrypt 协议，以及私钥存 NAS、经 HTTPS 发往 CAS/FC 的授权。staging/production 配置及状态根隔离；首次部署 timer 关闭。

## 2. 私有配置、构建和部署

按 [构建说明](ESA.zh-CN.md#本地配置与可重复构建) 准备 Python `3.10.17`、`uv 0.6.16` 和 lock 依赖；仓库根目录执行：

```sh
umask 077
cp src/esa-certbot/config.example.json config.local.json
cp s-esa.example.yaml s-esa.local.yaml
# 先填写并审核两个私有配置文件，再构建。
.venv/bin/python tools/build_esa.py --config config.local.json
chmod 600 config.local.json s-esa.local.yaml build/esa/fc-certbot-esa.zip
```

填写 `provider=esa`、已确认的邮箱/`agree_tos=true`，以及 `api.example.com` / zone `example.com`、SiteId、NS、地域、经审核的源站 `tls_connect_host`。生产 ACME 地址为 `https://acme-v02.api.letsencrypt.org/directory`，保持 `allow_issuance=true`、`renew_before_days=30`。

| FC 配置 | 值或要求 |
| --- | --- |
| Runtime / handler | `python3.10` / `index.handler` |
| `PYTHONPATH` | `/code/python:/code` |
| `ESA_CERTBOT_CONFIG` | `/code/config.json` |
| `ESA_CERTBOT_STATE_ROOT` | `/mnt/certbot/production/state`，必须位于真实 NFS 挂载内 |
| 资源 / 超时 | 示例 1 核、2 GB、实例并发 1、FC 900 秒；Certbot 进程组上限 720 秒 |

FC 保留 `FC_` 前缀，上述环境变量保持原名。ZIP 内代码/依赖/非密钥配置 `0644`，本地 ZIP `0600`（覆盖旧包后也执行 chmod），记录 SHA256。包含私有配置，不公开；AK、STS、私钥和本地 `.venv` 不入包。

审核私有 YAML 的角色、函数、NAS/VPC、SLS 和状态路径，只部署专用证书函数：

```sh
npx --yes @serverless-devs/s@3.1.10 -t s-esa.local.yaml deploy
```

本次实测使用控制台上传 ZIP 并配置；以上 CLI 部署命令未实测。

## 3. 首次签发与安装

1. staging 手动调用 `{"action":"issue","target":"api"}`，预期 `status=uploaded` 及 CAS ID/名称；staging 证书不安装。
2. 使用独立 production 配置/状态调用同一事件。`issue` 签发并上传候选，**不创建 FC 域名**；有效候选可复用，它不是强制重签开关。
3. 首次人工创建/绑定 FC 域名和生产候选，核对原路由、认证、TLS；如需 DNS 指向，配置经审核的 FC CNAME（仅 DNS）。自动化没有创建域名权限。
4. 调用 `{"action":"renew","target":"api"}`，预期 `status=verified`；CAS、FC、源站 TLS 指纹一致，公信链及 SNI/主机名通过。应用 `404` 不代表 TLS 失败。

TXT 使用完整 `_acme-challenge.api.example.com`，只清理本次 RecordId，保留同名其他 TXT。权威 NS 首次命中后须连续稳定 **300 秒**；搜索预算 180 秒，总计 480 秒。先核对 SOA 负缓存，不能因本地命中就缩短等待。

CAS/FC 共用 RSA PKCS#8 → PKCS#1 转换并校验公钥匹配。旧 PKCS#8 上传恢复时保留旧证书，用独立 `-rsa` 名称上传兼容格式；首次安装和续期走同一实现，无需手工转换或重签。

## 4. 每日续期和告警

首次绑定与必要检查完成、操作者批准后，启用唯一 timer；模板 payload **只填内层 JSON**：

```yaml
enable: true
cronExpression: CRON_TZ=Asia/Shanghai 0 0 3 * * *
payload: '{"action":"renew","target":"api"}'
```

每天北京时间 03:00，等价于 UTC `0 0 19 * * *`。FC 自动添加 `triggerTime/triggerName/payload` 外层，入口解包一次后检查白名单；timer 不填完整外层。手动调用使用第 3 节事件。保存后读回名称、版本、cron、payload、启用及下次时间，同步私有 YAML。

未临期 `renew` 复用候选并检查安装/TLS；剩余 **小于 30 天**才续签。顺序：新签 → 新上传 CAS → 仅更新 FC `certConfig` → 读回 → 实际 TLS；旧证书保留。

SLS 先预览实际字段/索引；替换占位函数名，确认邮件接收人，关闭短信/语音：

| 规则 | 查询与触发条件 | 频率 / 重复通知 |
| --- | --- | --- |
| 失败 | `functionName:"fc-certbot-esa-example" AND ("failed" OR hasFunctionError:true)`，最近 15 分钟条数 `> 0` | 每 5 分钟 / 60 分钟 |
| 漏跑 | `functionName:"fc-certbot-esa-example" AND "fc_certbot" AND "verified" \| SELECT count(*) AS successful_runs`，最近 24 小时 `successful_runs < 1`，连续 3 次 | 每小时 / 24 小时；约最后成功后 26–27 小时首次提醒 |

查询成功不等于邮件送达；故障演练/通知发送须在授权范围内。

## 5. 日志、恢复和回退

记录 FC 调用时间、RequestId、固定错误码，在专用 SLS 以 `functionName`、时间、RequestId 定位。成功事件为 `event=fc_certbot, phase=verified`。原始 Certbot 日志只在受限 NAS；不公开完整日志、TXT token、凭据或 PEM。

| 现象 / 错误 | 优先处理 |
| --- | --- |
| NAS 权限错误 / 代码不可读 | 核对真实 NFS、UID/GID、远端私有目录与 ZIP 内模式；保留 `root_squash` 和私钥 `0600` |
| `EVENT_SCOPE` / `STAGING_INSTALL_FORBIDDEN` | 核对内层事件、配置中的目标 ID 和 ACME 环境，不放宽白名单 |
| ACME `NXDOMAIN` / 传播超时 | 对照 `dns_created` → `dns_stable` → CA 结果 → cleanup 时间线及 SOA；失败后 TXT 被清理不能证明从未创建，不盲重签 |
| `DNS_CREATE_UNKNOWN` / `CAS_UPLOAD_UNKNOWN` / `FC_UPDATE_UNCONFIRMED` | 保留 journal/候选，先精确读回实际结果；未知状态不重复创建、上传或更新 |
| `LOCK_BUSY` / `LOCK_STALE` / `LOCK_QUARANTINED` | 先停对应 timer，确认旧 FC 执行、Certbot/hook 整组进程及在途请求已结束；保留证据，不因锁超时盲删或抢锁 |
| `TLS_VERIFY_FAILED` / `FC_CERTIFICATE_CONFLICT` / `STATE_SCOPE_CHANGED` | 停止覆盖，核对源站/SNI/链/指纹及配置归属，按 [恢复指南](ESA.zh-CN.md#锁恢复和回退) 处理；不删除 state 重新开始 |

增加域名须新增目标及 timer，审查站点/角色/地域并首次绑定；现有目标变化会触发状态保护。测试/正式分别管理角色、函数、状态；不用改阈值、删状态或旧证书强制重签。

回退：停 timer → 确认无活动执行 → 旧 CAS 证书恢复 FC → 验证 TLS/路由 → 校准 CAP/NAS 状态 → 再批准启用。没有自动回滚/旧证书清理，证书保持单一写入方。

## 6. 本次已验证与未验收（2026-10-26）

- 已验证：49 项离线单元/模拟测试和旧入口回归；真实 NAS 私有目录权限、ESA TXT 传播及精确清理、staging/production 签发、CAS 格式恢复、FC 首次绑定、可信链/主机名/指纹一致；两次真实未到期 `renew` 及一次官方外层事件手动调用复用原证书。
- 已配置并读回：唯一每日 03:00 timer 已启用；失败/漏跑邮件规则已启用，实际查询评估成功。邮箱激活成功；未发送验收邮件，未验证通知送达。操作者决定先完成主流程，不等待演练。
- 未验收：真实定时触发、真实到期轮换、多实例 NAS 崩溃恢复和故障通知链路；这些不能由手动调用或 mock 代替。
- CAP 只读部署预览无待部署变更，没有重部署业务。代码不更新 CAP 期望配置；后续 CAP 部署是否覆盖证书仍需单独验证，不能声称已通过。
