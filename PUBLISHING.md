# 发布整理与脱敏说明

本仓库由本机开发版本建立独立发布副本，再初始化全新 Git 历史。原开发目录和正在使用的 DSH profile 保持原状。

## 纳入的内容

- 插件 `lib`、`bin`、`locale`、包清单和 bundle patch。
- 全部可复用 `*.test.mjs`，以及测试需要的 `helpers/duplex.mjs` 和 `fixtures/fake-host.mjs`。
- 独立 relay 及其测试、Docker 和 systemd 示例。
- 新增通用配置示例、中文入门说明、许可证、第三方软件说明、开发锁文件、发布检查和 CI。

## 排除与替换

采用文件白名单纳入原开发目录的 79 个文件，排除 39 个本机文件：测试令牌、实机连接 patch、运行报告与 marker、主机日志、依赖真实机器/云实例的测试驱动、本机诊断与重启脚本，以及本机桌面启动脚本。

- 本机 VM 网络默认地址替换为 loopback；跨机器 TCP 使用者需显式设置 controller 地址。
- 网络工具注释改用标准文档网段。
- POSIX 辅助脚本中的本机特定 Node 目录替换为通用可配置目录。
- 实例地址、SSH 用户、个人路径和原始测试报告不进入仓库。
- 测试中的合成密码、合成令牌、全零低阶测试公钥、虚构邀请以及通用 `/home/user` 路径保留，它们验证协议行为。

`.gitignore` 和 `.dockerignore` 排除本机状态、秘密文件和依赖目录；发布扫描对常见 token/私钥格式、带凭据 URL、个人 Windows 路径和非示例 IPv4 进行检查，只输出问题位置。

## 整理时修正

- Dockerfile 的插件目录从 v1 修正为 v2。
- Docker 构建说明明确使用仓库根目录作为上下文。
- systemd 的安装目录、工作目录和入口统一为 v2，并移除与 V8 JIT 冲突的 `MemoryDenyWriteExecute` 设置。
- QR 独立比对依赖固定为开发依赖 `qrcode@1.5.4`，运行时代码保持零外部依赖。
- 添加跨平台测试入口，避免 shell 通配符差异。
- 修正 guest 安装闭包测试在 Linux 上解析 PowerShell 相对路径时的分隔符处理。

## 验证范围

发布前在 Windows 上运行全部插件和 relay 自动化测试、JavaScript 语法检查和脱敏扫描，并进行独立只读敏感信息审查。测试覆盖加密/签名、重放与篡改拒绝、relay、配对、v1/v2 协议、断线行为、安装文件闭包、组件生命周期、浏览器模块契约和 QR 参考比对。

GitHub Actions 配置了 Windows/Linux 与 Node.js 22/24 的矩阵测试。未在本机实际部署 Docker 容器或 Linux systemd 服务，也不使用已排除的实机/云实例配置重新进行端到端测试。DSH 浏览器测试主要通过模块/生命周期契约模拟验证；它不等于完整浏览器界面验收。

公开前的静态检查与人工审查未发现真实凭据和个人身份信息。自动扫描是有限的模式检查，后续修改仍需审查待提交内容。

## 后续发布

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm check
pnpm test
git diff --cached --check
git diff --cached --stat
```

不要复用开发环境的 Git 历史、配置目录或运行日志来发布新版本；使用通用示例并在本机维护不提交的配置。
