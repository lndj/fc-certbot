# 验证记录

日期：2026-10-26。上游基线：`4437a262051d2bc9593d92e2d48ea17bd597dd7f`（模板元数据 0.0.7）。实现工作区为独立 checkout，未操作其他项目工作区。

## 实际执行

- macOS arm64，隔离 CPython 3.10.17，Certbot 5.8.0；ESA SDK 3.16.0、FC SDK 4.8.3、CAS SDK 3.9.4、dnspython 2.7.0。完整依赖固定版本及包哈希随源码提交。
- `python -m unittest discover -s tests -v`：**49 项通过**。测试使用真实 SDK 请求模型与本地生成的模拟证书，云客户端/网络均被替换；不会向 ACME/云 API 申请或安装证书。
- `node tests/test_legacy.cjs`：通过。验证原 manager 采用新 CAS 名称、容忍缺失 certConfig，且只发送 certConfig。
- Python `compileall`、Node `--check`、`git diff --check`：通过。
- `certbot --version` / `--help all`：实际执行，核对本实现使用的 manual hook、目录、RSA 和邮箱选项；未执行 certonly。
- `tools/build_esa.py`：实际交叉构建 Linux x86_64 Python 3.10 包；全版本/哈希约束。纯 Python SDK 源码包使用固定构建依赖，原生库强制使用 Linux wheel。
- 以固定顺序、时间戳重打包，并清空目标依赖目录后从已校验缓存重新安装、再次构建，产物字节一致（`cmp` 通过）。这是本地可重复性检查，不是任意平台间字节一致性的承诺。
- 包内 13 个 `.so` 逐一确认 ELF magic 和 `e_machine=62`（x86_64）；没有打包测试证书、`.local.*` 或本地虚拟环境。包含拒绝运行的占位配置，未含实际用户参数。

本地占位包：`build/esa/fc-certbot-esa.zip`，14,072,459 字节，SHA256：

```text
0622681a0ad725b540fcd82e0fce9c457e7248a62117936e10e099576398c0ca
```

包不提交 Git；部署时必须用私有配置重新构建，内容和 hash 会改变。

传播稳定性回归：假时钟验证默认首次命中后仍等待 300 秒，中途缺失重置连续窗口，反复出现/消失只消耗有界总预算；稳定时间配置拒绝越界与非整数值。Certbot 进程组总预算相应调整为 720 秒，并断言 hook 收到配置。上述测试均不发起 DNS 写入或 ACME 请求；连续本地权威命中仍不能证明所有全球 anycast 节点和 CA 递归缓存同步。

RSA 格式回归：使用本地生成的真实 RSA 密钥，将其编码为 Certbot 使用的 PKCS#8，确认 CAS/FC 收到对应的 PKCS#1 且密钥完全一致；模拟已存在的 PKCS#8 CAS 上传，确认新名称/ClientToken、旧上传保留、只上传一次、复用证书且不重签。

定时入口回归：按 FC 官方 `triggerTime/triggerName/payload` 外层，实际经过 `index.handler`、配置白名单与引擎的未到期续期路径（云/DNS/TLS 使用模拟对象），三种输入编码均复用原候选、不签发/上传/改 FC；18 种空、恶意或扩大范围的外层/payload 在访问凭据、NAS、云客户端之前拒绝。手动顶层事件保持兼容。本项是官方事件结构的离线入口验证，不代表真实定时调度已经启用或触发。

## 主要故障覆盖

| 范围 | 可运行的检查 |
| --- | --- |
| 授权边界 | 精确事件、zone 标签边界、SiteId 类型、FC/ESA 地域、GetSite 实际归属/NS/状态；拒绝任意域名、URL、通配符、外部参数覆盖 |
| DNS | 同名多 TXT、两个挑战清理互不干扰、Create 超时已提交/未明、未知时不重建、所有权被改拒删、删除超时读回、首次列表空而第二次刚可见时实际删除、空列表无删除意图拒绝成功、删除后 journal 未提交的恢复、传播有界重试、所有 NS 的 AA 与精确 TXT、拒绝 CNAME、NS 变化失败 |
| 签发与证书 | ACME 失败清理且不上传、签发文件先于 journal 写入的崩溃恢复、SAN 与私钥不匹配拒绝、staging 与生产隔离、过早切换站点拒绝 |
| CAS | 上传未知先读回、重复调用复用候选、名字冲突、未知未执行不重传、失败不删旧；上游旧 CAS 路径同样验证不删旧 |
| FC/TLS | 首次绑定必须人工、临期续期、新 certName 下一轮继续管理、FC 失败保留旧、更新超时读回成功、重试复用候选、TLS 失败后只重验、源站连接/SNI/叶指纹逻辑、仅提交 certConfig |
| 并发与日志 | 真实本地文件系统的 owner 锁互斥、到期不抢锁、旧 owner 不释放新 owner、缺少 STS/共享 NAS 拒绝、SDK 敏感异常不输出、Certbot stdout/stderr 抑制；真实本地三级进程树在超时/父进程失败后整组退出、延迟 marker 不写入；进程组无法确认时跳过 cleanup 并保留隔离锁 |

## 未执行与限制

真实 DNS 传播、ACME staging/production、RAM 权限、NAS 多实例/中断、FC 冷启动与部分更新语义、TLS 公信链握手、告警收件人通知、CAP 再部署均未云验收。包在本机做交叉构建与 ELF 检查，没有宣称已经在 FC 运行。

没有创建云资源、角色、长期 AK、DNS 记录、CAS 证书、FC 域名、CAP 配置或定时任务。运行锁新增依赖是已有专用共享 NAS，原因是 FC 临时盘不能做跨实例互斥/持久化；锁不自动抢占，崩溃可能需要人工恢复。外部并发写证书仍需单一写入方约定，不能承诺原子跨云事务。真实云验收步骤、权限宽度、CAP 风险和回退详见 [中文操作指南](ESA.zh-CN.md)。

仓库新增 GitHub Actions 离线测试工作流；远端执行结果以 PR Checks 为准，不能把本地测试通过当作远端 CI 已通过。

## 独立复核修复

2026-10-26 修复两个 P1：DNS cleanup 不再用首次过期列表判断后续恢复的 RecordId；Certbot 不再只终止直接子进程。前者先新增精确回归并确认旧代码失败，再修复为实际删除并读回。后者使用独立进程组、整组 TERM/KILL 与退出确认，无法确认则保留隔离 NAS 锁。新增真实本地父进程 → hook → 延迟写 marker 子孙测试，分别覆盖超时与父进程失败，并断言 cleanup 时整组已消失、锁仍持有。所有测试均未调用云 API。
