# ESA NS 自动签发与 FC 换证（中文操作指南）

这是基于 [devsapp/fc-certbot](https://github.com/devsapp/fc-certbot) 0.0.7 源码的可选 ESA 实现。原 AliDNS 模板 `src/s.yaml` 保留；ESA 使用独立入口 `src/esa-certbot/index.py` 和 `s-esa.example.yaml`，不要部署原模板来接入 ESA。新入口把签发与 manager 合并为一个 Python 3.10 函数，默认只部署国内一个地域、只处理事件中明确选择的一个目标，不列举全账号 FC 域名。

本次工作只进行了本地实现、离线测试和打包。没有读私有云凭据，没有创建角色、部署、改 DNS、申请真实证书、上传 CAS、更新 FC/CAP 或启用定时器。下述云操作必须由操作者另行授权后执行。

## 行为和边界

- `provider: esa` 为显式选择；原 AliDNS 入口仍可用。新入口只支持每个目标一个普通 ASCII FQDN，不支持 URL、通配符、多 SAN、CNAME 挑战委派或自定义 Vanity NS。需要这些能力时先扩展测试，不能放宽事件校验绕过。
- 事件只能包含 `action` 和 `target`，不能覆盖域名、SiteId、地域、ACME 地址或邮箱。目标配置与 ACME 环境的摘要固定在状态文件中，配置边界变化会报 `STATE_SCOPE_CHANGED`，需单独迁移。
- 读取 ESA `GetSite`，核对 SiteId、站点根域、`NS` 接入、`active` 状态及已分配 NS 列表。`CreateRecord` 使用完整 `_acme-challenge.api.example.com`、`TXT`、`Proxied=false`、`Data.Value` 和独立随机备注，不查找并覆盖已有 TXT。
- 传播检查读取 zone 的 NS，再向配置清单中**每个** NS 的可达地址直接查询 TXT，要求权威回答 AA、完整名称和本次 token 匹配。UDP 截断回退 TCP，拒绝 CNAME。首次命中后还须持续命中 `dns_stable_seconds`（默认 300 秒）；中途缺失或查询异常会重新计时，总预算为 `dns_timeout + dns_stable_seconds`（默认 480 秒，最多 600 秒）。每个 NS 至少一个地址成功；不是对全部 anycast 节点的证明，也不做 DNSSEC 验证。部署前检查 SOA 的负缓存有效期 `min(SOA TTL, SOA.MINIMUM)`，稳定窗口应覆盖它；若超过目前 300 秒上限，先评估调整等待和函数超时，不能盲重试。依据 [Let's Encrypt DNS-01 说明](https://letsencrypt.org/docs/challenge-types/)，本地命中不能保证 CA 的网络节点同时可见；仍须独立网络和 staging 验收。
- 每次挑战持久化随机备注、token、RecordId。创建超时先按 SiteId、完整名称、类型、值、随机备注精确读回；查不到即停止，不盲目再创建。cleanup 只删除这些字段均匹配的本次 RecordId；同名其他 TXT 保留，删除结果未知也读回。
- 换证顺序：新签发 → 新名称上传 CAS → 按名称读回并校验证书/私钥 → 只更新 FC `certConfig` → 读回 FC 叶证书指纹 → 实际 TLS 校验证书链、主机名、叶证书指纹。TLS 连接使用用户审核过的 FC 源站连接主机，SNI 使用业务域名。
- **不删除任何旧 CAS 证书**。新名称仍带 `devs-certbot-generated-` 前缀；新入口下一轮按显式目标和 NAS 状态继续管理，不依赖旧名称扫描。保留旧证书可能积累费用/配额，清理必须制定显式保留期、引用检查和独立权限策略。
- Certbot 与 shell/hook 使用独立 Unix 进程组。超时、异常及父进程退出后，先 TERM、再按需 KILL，确认整个进程组消失后才进行 cleanup 或释放锁；无法确认则撤销 owner token 的有效期并隔离保留锁，阻止下一执行。
- SDK 禁用自动重试。DNS/CAS 未知结果只读回，仍未知则失败并保留意图；FC 更新未知先读回，下一次调用再次读回后才决定是否重发。成功候选会复用，避免 FC/TLS 失败导致重新签发。

## 先决条件与权限审查

此方案要求**已有、经审核的专用 FC 执行角色、同地域 NAS/VPC、安全组和 SLS 日志目标**。示例不自动创建 RAM 角色，也不授予 FullAccess。部署身份和运行身份分开审查。

运行时只从 Python 3.10 `context.credentials` 获取 FC 角色临时 AK/Secret/STS，逐次调用刷新；没有本地凭据文件或长期 AK 的兜底。缺少 STS 直接失败。勿在配置、模板、仓库或环境变量里手填长期 AK。Python 3.12 的凭据接口不同，不能直接改 runtime；见[官方上下文文档](https://help.aliyun.com/zh/functioncompute/contexts)。

| 操作 | 运行时需要 | 官方资源授权边界 |
| --- | --- | --- |
| ESA `GetSite`、`ListRecords`、`CreateRecord` | 是 | 可限制到 `acs:esa:<ESA_REGION>:<ACCOUNT_ID>:site/<SITE_ID>` |
| ESA `DeleteRecord` | 是 | 当前官方文档仅支持 `Resource: "*"`；代码内校验不是 RAM 隔离 |
| CAS `ListUserCertificateOrder`、`GetUserCertificateDetail`、`UploadUserCertificate` | 是 | `yundun-cert:` 操作级授权，`Resource: "*"`；详情接口可读私钥，权限很敏感 |
| CAS `DeleteUserCertificate` | 否 | 不授予；旧证书清理由独立流程负责 |
| FC `GetCustomDomain`、`UpdateCustomDomain` | 是 | 这两个 API 当前官方文档均列 `Resource: "*"`；不能虚构域名级 Resource 限制 |
| FC `CreateCustomDomain`、`ListCustomDomains`、`InvokeFunction` | 否 | 初次绑定是人工操作；新入口不调用其他函数或扫描账号 |
| CAP 配置/部署写入 | 否 | 本实现不更新 CAP 期望配置 |

下面仅为**需要管理员审查的运行权限草案**，不可直接当作已验证的最小权限。替换占位符并核对 ESA 站点实际控制面地域、当前产品 RAM 文档和组织条件策略；必须接受 `DeleteRecord`/CAS/FC 的较宽操作边界后再授权。

```json
{
  "Version": "1",
  "Statement": [
    {"Effect":"Allow","Action":["esa:GetSite","esa:ListRecords","esa:CreateRecord"],"Resource":"acs:esa:<ESA_REGION>:<ACCOUNT_ID>:site/<SITE_ID>"},
    {"Effect":"Allow","Action":["esa:DeleteRecord"],"Resource":"*"},
    {"Effect":"Allow","Action":["yundun-cert:ListUserCertificateOrder","yundun-cert:GetUserCertificateDetail","yundun-cert:UploadUserCertificate"],"Resource":"*"},
    {"Effect":"Allow","Action":["fc:GetCustomDomain","fc:UpdateCustomDomain"],"Resource":"*"}
  ]
}
```

另外独立审查 FC 信任策略、NAS 挂载/目录权限、VPC 出网和 SLS 写日志权限。部署身份需要的创建/更新函数、PassRole、触发器等权限不属于上述运行策略。不要为通过部署临时改用整套 FullAccess。

官方依据：[CreateRecord](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-createrecord)、[DeleteRecord](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-deleterecord)、[GetSite](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-getsite)、[ListRecords](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-listrecords)、[ESA 接入点](https://help.aliyun.com/zh/edge-security-acceleration/esa/api-esa-2024-09-10-endpoint)、[CAS 授权](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-ram)、[CAS 上传及 ClientToken](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-uploadusercertificate)、[FC GetCustomDomain](https://help.aliyun.com/zh/functioncompute/api-fc-2023-03-30-getcustomdomain)、[FC UpdateCustomDomain](https://help.aliyun.com/zh/functioncompute/api-fc-2023-03-30-updatecustomdomain)。

## 本地配置与可重复构建

1. 固定 Python `3.10.17`、`uv 0.6.16`。CLI 部署示例固定 `@serverless-devs/s@3.1.10` 和模板组件 `fc3@0.1.27`。运行依赖全部版本和发行包 SHA256 位于 `requirements.lock`，SDK 请求/响应按已安装的真实模型测试。升级需重新生成 lock 并跑完整测试。
2. 从仓库根目录执行离线测试（安装步骤需要访问公共 PyPI，不访问云账号）：

   ```sh
   uv venv --python 3.10.17 .venv
   uv pip install --python .venv/bin/python --require-hashes -r src/esa-certbot/requirements.lock
   .venv/bin/python -m unittest discover -s tests -v
   node tests/test_legacy.cjs
   ```

3. 复制配置和部署文件；`.local.json`、`.local.yaml`、`build/` 已忽略，仍须人工检查 `git diff --cached`，不要公开实际域名、SiteId、角色、NAS/SLS 参数、邮箱或证书：

   ```sh
   cp src/esa-certbot/config.example.json config.local.json
   cp s-esa.example.yaml s-esa.local.yaml
   ```

4. 填写配置，**先由证书联系人确认真实通知邮箱及 Let's Encrypt 协议**，确认后才能将 `agree_tos` 改为 `true`。示例邮箱不可用于生产。配置项：

   | 参数 | 含义 |
   | --- | --- |
   | `provider` | 固定 `esa`，不能回退 AliDNS |
   | `email` / `agree_tos` | 实际证书联系人邮箱与已确认的协议授权 |
   | `acme_directory` | 仅允许 Let's Encrypt 官方 staging 或 production 地址；staging 禁止 `renew` 安装 |
   | `regions` / `targets.<id>.region` | 显式 FC 地域清单和目标地域，默认 `cn-shanghai` |
   | `domain` / `zone` / `site_id` | 精确业务域名、ESA NS zone、数值 SiteId；GetSite 必须一致 |
   | `esa_region` | ESA API 控制面地域，只允许杭州/新加坡，和 FC 上海地域不是同一概念 |
   | `nameservers` | ESA 分配的完整 NS 清单，2–6 个、小写、无末尾点 |
   | `tls_connect_host` | 经审核、能直连 FC HTTPS 源站的主机；不能填写 ESA 代理入口来冒充 FC 验证 |
   | `renew_before_days` / `dns_timeout` | 默认临期 30 天续签、传播搜索预算 180 秒；范围分别为 7–60 天、10–300 秒 |
   | `dns_stable_seconds` | 首次权威命中后持续匹配窗口，默认 300 秒，范围 30–300 秒；额外计入总等待，至少覆盖经核实的 SOA 负缓存有效期 |

   `ESA_CERTBOT_CONFIG=/code/config.json` 指向打包配置；`ESA_CERTBOT_STATE_ROOT=/mnt/certbot/state` 必须落在实际 `nfs`/`nfs4` 挂载中。`/tmp`、本地磁盘、OSS 挂载不能承担共享锁，入口会拒绝。staging 与生产使用不同函数、不同 NAS 状态根；不能直接拿 staging 状态切生产。

   函数计算保留 `FC_` 前缀，不能用此前缀定义部署环境变量；请保持模板中的 `ESA_CERTBOT_` 名称。

   Certbot 进程组总超时为 720 秒，包含最多 600 秒 DNS 检查和剩余 ACME/API 时间；FC 超时保持 900 秒。hook 仅输出不含 TXT 的 `dns_created` / `dns_stable` 时间事件，便于对照 CA 失败与 cleanup 时序。看到 ACME `NXDOMAIN` 时先查这些现有日志、SOA 和清理记录，避免直接重复签发。

5. 构建 Linux x86_64 包，可在 macOS 交叉打包；原生扩展强制使用 Linux wheel，少量纯 Python SDK 源码包使用固定 setuptools/wheel 构建：

   ZIP 内的代码、依赖和非密钥部署配置使用 `0644`，以便 FC 解压后运行用户可读取；本地 ZIP 仍为 `0600`。证书私钥和临时凭据不得进入代码包，NAS 中的状态与私钥权限仍为 `0600`。

   ```sh
   .venv/bin/python tools/build_esa.py --config config.local.json
   .venv/bin/python tools/build_esa.py --config config.local.json --reuse-deps
   ```

   输出 `build/esa/fc-certbot-esa.zip` 和 SHA256。固定 ZIP 顺序、时间戳和模式；`--reuse-deps` 会核对 lock 摘要。包包含配置，因此也按私密部署产物保存，不上传公开附件。默认不传 `--config` 会打包拒绝运行的占位配置。不要打包 macOS 的 `.venv`。

6. 编辑 `s-esa.local.yaml` 的执行角色、唯一函数名、同地域 NAS/VPC、安全组和 SLS。专用 NAS 目录设为函数映射 UID/GID 可写、其他主体不可读；证书/私钥、ACME 账户、挑战 token 和私有 Certbot 日志均在 NAS 上。启用 NAS 加密、传输加密和受限备份；不能把此目录同步回 Git。实例并发设为 1，但跨实例互斥仍依赖 NAS 锁。

## 部署、首次签发与初次绑定（待云授权后）

本节所有命令都属于后续云验收；本次未执行。先确认该环境允许云写入和 ACME 请求，再按顺序操作。

```sh
npx --yes @serverless-devs/s@3.1.10 -t s-esa.local.yaml deploy
```

定时器示例为 `enable: false`。首次部署保持关闭，核查变更计划只包含新的 certbot 函数，不包含业务函数、域名路由或 CAP 服务。挂载与公网出网（DNS UDP/TCP 53、ACME/ESA/CAS/FC HTTPS）均需实际验证。

1. 先使用专用 staging 配置与独立状态根，在函数控制台手动发送：

   ```json
   {"action":"issue","target":"api"}
   ```

   这会真正创建临时 DNS TXT、请求 staging ACME 并上传 staging 证书到 CAS，仍需明确云写入授权。确认 TXT 正确传播且精确清理，同名已有 TXT 完整保留。staging 证书不安装至业务域名。
2. 审核生产邮箱、协议、限流风险、权限与部署差异后，部署**独立生产状态根**的 production 配置，再运行同一 `issue` 事件。返回 CAS `cert_id` 与带管理前缀的 `cert_name`，不会自动创建 FC 域名。
3. 在正确地域，人工在 FC/CAP 管理流程中把已有业务自定义域名绑定到该 CAS 证书，保留原路由、认证和 TLS 协议。若尚未建立域名，也由人工创建绑定；自动化没有 CreateCustomDomain 权限。
4. 发送：

   ```json
   {"action":"renew","target":"api"}
   ```

   初次运行只接管与已签发候选指纹相同的绑定。旧证书与候选不同会报 `FC_CERTIFICATE_CONFLICT`，避免覆盖任意现有证书。成功必须返回 `verified`，且从 `tls_connect_host:443`、以业务域名作为 SNI 得到同一叶证书指纹及有效公信链。ESA 开启代理时须另外核查浏览器到边缘的证书，边缘 TLS 不代表 FC TLS。
5. 人工记录旧证书、CAS ID、路由、域名归属、完整链、有效期和验证结果，检查只提交 `certConfig` 的部分更新语义在当前 FC API 上成立。代码不带旧路由快照，避免覆盖并发路由配置；FC API 没有在此实现中使用证书条件写入/ETag，外部同时改证书仍有竞态。生产期间需约定证书只有一个写入方。

## 定时续期与告警

云验收通过后才由操作者将生产模板中的 timer 改为 `enable: true` 并重新部署。示例每天北京时间 03:00 对 `api` 目标执行 `renew`；新增目标要增加显式配置与独立 timer payload，不能改成账号扫描。每次先处理遗留挑战，再复用候选；临期 30 天签发新证书，其余时候检查当前安装和 TLS。生产环境不要用手工改状态或设置异常阈值来强制签发测试。

失败输出单行结构化事件，例如：

```json
{"event":"fc_certbot","target":"api","phase":"failed","code":"DNS_PROPAGATION_TIMEOUT"}
```

入口抛出同一固定错误码，使 FC 记录失败调用；日志不包含域名、AK、STS、TXT token、PEM 或 SDK 原始响应。Certbot 子进程输出被抑制，原始日志只落受限 NAS。返回值含 CAS ID/名称，留在私有调用记录。

**告警交付边界：**代码已提供可测试的失败事件和 FC 失败调用；模板仅给出 SLS 接入字段，尚未配置或演练任何真实告警/收件人。正式启用 timer 前，操作者需在实际 Logstore 确认字段提取，创建 `event=fc_certbot AND phase=failed` 告警以及 FC 调用失败/超时告警；另设每天没有成功事件、证书剩余天数的独立外部监测。对 `LOCK_BUSY` 的持续发生也告警。用权限拒绝或受控不可达的独立测试配置触发一次失败，验证通知到达；没有通知回执不能算告警验收通过。不要直接打印完整异常排错。

## 锁、恢复和回退

NAS 每个目标使用原子 `mkdir` 锁，目录中以随机 owner 命名的 token 存储 owner 和 1200 秒到期时间，函数超时配置为 900 秒。每个变更阶段及 hook 检查 owner/到期时间。正常退出仅移除自己的 token；旧 owner 丢失 token 后不能释放新 owner 的锁。**到期只报告，不自动抢锁**，这是避免旧执行仍在云端完成写入的保守取舍，不承诺自动故障转移或 exactly-once。

- `ACME_PROCESS_GROUP_UNCONFIRMED` / `LOCK_QUARANTINED`：禁止 cleanup 和自动释放锁。先停 timer，确认相应 FC 实例中整个 Certbot/shell/hook 进程组已终止（必要时由操作者回收实例），再核查可能在途的云请求。保留隔离锁及挑战 journal；确认安全后才能人工恢复，不能仅因主调用返回或锁到期而重入。
- `LOCK_BUSY`：不排队、不签发；稍后重试。`LOCK_STALE`/空锁目录：先禁用对应 timer，并通过 FC 确认旧执行和 hook 均已终止、外部云请求已稳定；再把整个旧锁目录重命名至隔离位置保存证据，重新调用。绝不能仅凭墙钟到期删除仍在工作的锁。
- `DNS_CREATE_UNKNOWN`：保留 `challenges/*.json`。按本次随机备注、SiteId、完整名称和 token 复查 ESA 与审计日志，未知时不得重复创建。记录后来可见后重试，cleanup 会只回收匹配的 ID。只有明确确认创建**未执行**后，才能在停机审核下重置该意图；不能以一次列表为空作为未执行证明。
- `DNS_OWNERSHIP_CHANGED`/`DNS_OWNERSHIP_AMBIGUOUS`：不要自动删除，人工逐条核对。`DNS_CLEANUP_FAILED` / `DNS_CLEANUP_UNCONFIRMED`：保留状态，下一轮继续精确清理。未知创建恢复时使用同一次查询返回的记录；没有持久化删除意图时，一次空列表不会被当作已清理。失败会阻止进一步签发，不会擅自删除其他 TXT。
- `CAS_UPLOAD_UNKNOWN`：候选文件、固定名称及 SHA256 ClientToken 已保留。先按名称读回 CAS 并核对实际证书/私钥，下一轮发现成功上传即可复用。仍未知不重传；明确未执行后才可在受控恢复中重置 `cas_attempted`，再次上传使用同一 token。不能删除旧证书腾位置来掩盖失败。
- `FC_UPDATE_UNCONFIRMED`：旧 CAS 保留。下一轮先读 FC；已经安装新候选则仅核验 TLS，仍是旧受管指纹才重发 `certConfig`，其他指纹立即冲突停止。
- `TLS_VERIFY_FAILED`：FC 可能已换成候选，但还未标记 verified，不自动删除或回滚；检查 FC 源站连接主机、SNI、公信链、出网和传播，再重试。不会因为验证失败重复签发。
- `STATE_SCOPE_CHANGED`、NAS 丢失、配置迁移、候选临期未安装：停 timer，备份状态，审核 CAS/FC 当前事实后单独迁移或重新走人工首次绑定。不能删除 state.json 后继续覆盖现有域名。

人工回退：先停 timer、确保无活动调用；从保留的旧 CAS 证书/私有备份恢复 FC 证书，验证真实 TLS 和业务路由，并同步 CAP 期望配置。此时 NAS 仍记录新指纹，下一轮会拒绝冲突；完成受控状态校准与验收后再恢复 timer。代码没有自动回滚，也没有自动旧证书清理。API 列表最多读取 100 页，超限会失败告警，不静默截断。

## CAP 必须单独验收

实现只调用 FC `UpdateCustomDomain`，**不修改 CAP 项目期望配置**。[官方服务生命周期文档](https://help.aliyun.com/zh/functioncompute/manage-services/)描述配置暂存后部署同步云资源。由此推断 CAP 后续部署可能重新下发旧证书；这是风险推断，尚未在用户项目上验证。

操作者必须在独立测试环境完成：记录 FC 当前叶证书指纹 → 运行换证并确认新指纹 → CAP 保存/再次部署同一业务服务 → 再查 FC certConfig、源站 TLS、路由和 CAP 差异。若 CAP 恢复旧证书，先解决 CAP 的证书配置来源/写入职责，再启用自动续期；不能把 FC API 成功当作 CAP 集成已通过。

## 验收分层

| 层次 | 本次状态 | 后续通过标准 |
| --- | --- | --- |
| 单元/模拟/真实 SDK 模型 | 本地已执行，见 `docs/VALIDATION.md` | 测试全过，未知结果/并发/日志路径覆盖 |
| Linux 包构建 | 本地交叉打包，非 FC 运行验证 | Linux 原生扩展正确；同源包可重复；FC 冷启动依赖导入通过 |
| 实际 DNS | 未执行 | 授权测试 zone 的所有权威 NS 看见 token，超时可靠失败，多 TXT 保留，cleanup 仅精确本次记录 |
| ACME | 未执行 | 先 staging 独立环境，再授权 production；邮箱/协议与配额确认；失败无 CAS/FC 换证 |
| CAS/FC/TLS 换证 | 未执行 | 新上传可复用，旧证书保留，故障读回与恢复，路由不变，源站 TLS 通过 |
| NAS 并发/崩溃/告警 | 仅离线模拟 | 两个真实 FC 实例共享 NAS 互斥，kill 后保守恢复，报警实际送达 |
| CAP 再部署 | 未执行，必须完成 | 重新部署后不覆盖新证书，或已有经验证的配置同步机制 |

## 上游与许可

保留上游 Git 历史、作者署名、原 README 和发布元数据。基线 commit 为 `4437a26`（版本元数据 0.0.7），源码中未附独立 LICENSE 文件，因此本 fork 没有擅自添加 MIT/Apache 等许可授权。继续分发和生产使用前请向上游确认适用许可。fork 的 registry 发布 workflow 已加上游仓库条件，避免个人 fork 意外发布原模板。

原 AliDNS 路径仅额外去除了 token 明文日志和“先删除旧 CAS 证书”的行为，并让 manager 使用新 CAS 名称；它仍保留历史的扫描/钩子设计，不具备本指南所述 ESA 状态、权威传播和 TLS 核验保证。ESA 应始终使用新入口。
