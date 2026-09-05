# Theatropolis

Theatropolis is a web-based master–agent manager for sing-box fleets. It manages
servers, proxy relay trees, end-user credentials, traffic quotas, configuration
subscriptions, and software updates from one control panel.

The project is under active development. Back up the master before upgrading a
production deployment.

[English](#english) · [简体中文](#简体中文)

## English

### What Theatropolis manages

- One **Master** provides the web UI and control plane.
- Each server runs an unprivileged **Agent** and a supervised sing-box process.
- A **Proxy Node** is a routing tree with one entrance, ordered matching rules,
  relay Links, child Hops, and Direct or Reject terminal exits.
- **Users** can receive access to multiple Proxy Nodes, each with an independent
  quota and expiration time.
- Every user receives Clash, Surge, and sing-box configuration-subscription
  URLs.

Relay Links support Shadowsocks 2022, AnyTLS, and Hysteria2. Compatible logical
Links can share one physical listener while retaining separate credentials and
authenticated-user routing identities.

### Requirements

- Debian or Ubuntu with systemd
- Linux amd64 or arm64
- Root access for installation
- A public domain pointing to the Master
- TCP port 80 and the selected HTTPS port available when using the bundled
  Caddy setup
- The required proxy listener ports open on Agent servers

The installer downloads signed prebuilt releases. It does not install a Go
toolchain or compile the project on the server.

### 1. Install the Master

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh |
sudo sh -s -- master
```

The installer interactively asks for:

1. The public domain name.
2. The Caddy HTTPS port (`443` for normal HTTPS; the default is `8443`).
3. The administrator username and password.

After installation, open the displayed HTTPS address and sign in. The web UI
uses the browser language on the first visit and remembers an explicit language
choice in a cookie.

For a Master and Agent on the same machine, use the all-in-one role:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh |
sudo sh -s -- all --server edge-1
```

In all-in-one mode, the Agent automatically dials the local Caddy listener over
loopback while retaining the public domain for TLS verification. The same
detection applies when an Agent is installed separately beside a matching local
Master. When both roles are installed on one server, the installer also keeps
public port 80 on Caddy and relays only ACME HTTP-01 challenge requests to the
Agent on loopback port `19091`. Remote and Agent-only servers continue to let
sing-box use public port 80 directly. The Master applies the alternate port only
to a capability-confirmed co-located Agent, and the server page reports
**Local relay ready**. No NAT hairpin support or additional installer argument
is required.

Installing or upgrading the Master beside an existing Agent also upgrades that
Agent binary from the same verified release, preserving its identity and
settings. Removing only the Master restarts an active surviving Agent to return
ACME to direct port-80 operation.

### 2. Add an Agent server

1. Open **Servers** and select **Add Server**.
2. Give the server an administrative name.
3. Copy the generated one-time installation command.
4. Run it as root on the Agent server.
5. Wait for the server to show as connected.

The equivalent manual command is:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh |
sudo sh -s -- agent \
  --master master.example.com:443 \
  --token 'ONE_TIME_TOKEN'
```

Use `host:port` for `--master`, without `https://`. Reinstalling an Agent with a
token from another Master transfers control to that Master and clears the old
Master's active profile before the new authoritative profile is applied.
On a fresh Agent, the installer selects the newest compatible signed stable or
release-candidate sing-box build from the dedicated Theatropolis patched-build
repository. Reinstalling an Agent keeps its existing sing-box version when that
binary and its required managed-user build tags are healthy.

To replace existing hardware without losing the server record or retained
profile, open that server's settings and generate a replacement command. The
old Agent remains authorized until the replacement token is redeemed.

### 3. Create a Proxy Node

1. Open **Proxy Nodes** and create a Node.
2. Select the entrance Agent, inbound protocol, listener, and terminal exit.
3. Select the entrance or a Hop and choose **Create Branch**.
4. Define the matching rule first, then select the destination Agent and relay
   protocol.
5. Add more branches or child Hops as needed.
6. Drag sibling rule cards to change first-match priority.
7. Use an `ALL` branch to relay unmatched traffic, or leave the Hop's terminal
   as Direct or Reject.

Topology changes are validated and deployed immediately. There is no separate
topology Save step. Changing a Hop's Agent keeps its downstream subtree;
replacing a Link's destination deletes that Link's old subtree and creates a new
terminal Hop.

When Shadowsocks multiplexing is enabled, Theatropolis explicitly uses `smux`
with `max_connections: 4` and `min_streams: 4` on the relay outbound.

### 4. Create users and grant access

1. Open **Users** and create a user. The displayed name is the administrator's
   internal management name.
2. Generate the one-time registration link and send it to the user.
3. The user opens the link and chooses a login username and password.
4. From the user's page, select **Add Node** and configure the monthly quota and
   subscription duration. Access can also be granted from a Proxy Node's Users
   dialog.

User-plane changes take effect immediately. Normal user additions, removals,
credential resets, quota changes, and expiration changes use the patched
sing-box live-user API without restarting sing-box. If that API fails, the Agent
falls back to a full restart to restore authoritative state.

A quota-reached Node remains visible in the user's subscription with the same
credential, but the credential is removed from the live entrance until the
quota resets. Expired Nodes are omitted. Resetting the traffic counter does not
change the monthly reset date.

### 5. Configuration subscriptions

Every user automatically receives separate Clash, Surge, and sing-box URLs.
The user can sign in through the same login page as the administrator and view:

- subscription URLs;
- accessible Nodes;
- quota usage and reset time;
- expiration time; and
- daily traffic history.

Open **Configuration Subscriptions** in the administrator UI to edit the one
universal ordered rule policy used by every user. Rules can route to **Proxy**,
**Direct**, or **Reject**. The Proxy group contains all Nodes available to that
user plus Direct and Reject.

### 6. Updates and migration

- Open **Servers → Server Settings** to update all connected Agents or select a
  patched sing-box version for the fleet.
- Open **Settings** to update the Master.
- Open **Settings → Master Migration** to export an encrypted data archive,
  restore it on another Master, and switch connected Agents to the new control
  address. The archive does not replace the destination Master's administrator
  login.

Agents that are offline during a Master cutover must be reinstalled manually
against the new Master.

### Useful service commands

```sh
# Master
sudo systemctl status theatropolis-master --no-pager
sudo journalctl -u theatropolis-master -n 100 --no-pager

# Agent
sudo systemctl status theatropolis-agent --no-pager
sudo journalctl -u theatropolis-agent -n 100 --no-pager

# Versions
sudo /usr/local/bin/theatropolis-master version
sudo /usr/local/bin/theatropolis-agent version
sudo /usr/local/bin/sing-box version
```

### Uninstall

Download the uninstaller and select the installed role:

```sh
# Master (also removes only Theatropolis' Caddy entry)
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/uninstall.sh |
sudo sh -s -- master

# Agent (child server)
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/uninstall.sh |
sudo sh -s -- agent

# All-in-one installation
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/uninstall.sh |
sudo sh -s -- all
```

The script asks for an explicit terminal confirmation. By default it removes
the selected role's state and credentials permanently. Add `--keep-data` to
retain `/var/lib/theatropolis/master` or `/var/lib/theatropolis/agent` for
recovery together with its state-owning service account. Add `--yes` only for
secured automation. Removing the Master does not uninstall Caddy or modify
other Caddy sites.

## 简体中文

### Theatropolis 管理什么

- 一台**主控端（Master）**提供网页管理界面和控制平面。
- 每台服务器运行一个非 root 的**代理端（Agent）**，并由其管理
  sing-box 进程。
- 一个**代理节点（Proxy Node）**是一棵路由树，包含一个入口、有序匹配
  规则、中继链路、下游服务器，以及直连或拒绝终端。
- 一个**用户**可以拥有多个代理节点的权限；每个节点权限都有独立的流量
  配额和到期时间。
- 每位用户都会自动获得 Clash、Surge 和 sing-box 三种配置订阅地址。

中继链路支持 Shadowsocks 2022、AnyTLS 和 Hysteria2。兼容的逻辑链路可以
共用同一个物理监听器，同时仍然使用各自独立的凭据和认证用户路由标识。

### 安装要求

- 使用 systemd 的 Debian 或 Ubuntu
- Linux amd64 或 arm64
- 安装时拥有 root 权限
- 一个指向主控端的公网域名
- 使用安装器自带的 Caddy 配置时，TCP 80 和选定的 HTTPS 端口可用
- 代理端服务器已放行需要使用的代理监听端口

安装器只下载经过签名的预编译版本，不会在服务器上安装 Go 工具链或现场
编译程序。

### 1. 安装主控端

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh |
sudo sh -s -- master
```

安装器会在终端中依次询问：

1. 公网域名。
2. Caddy HTTPS 端口（标准 HTTPS 使用 `443`，默认值为 `8443`）。
3. 管理员用户名和密码。

安装完成后，打开终端中显示的 HTTPS 地址并登录。网页首次打开时会跟随浏览
器语言；手动切换语言后会通过 Cookie 记住选择。

如果主控端和代理端安装在同一台服务器，可以使用一体化安装模式：

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh |
sudo sh -s -- all --server edge-1
```

一体化安装时，代理端会自动通过 loopback 连接本机 Caddy，同时继续使用公网域
名完成 TLS 验证。之后在同机单独安装代理端时，只要指定的主控地址与本机主控
完全一致，也会自动启用该路径。主控端和代理端同机时，安装器会让 Caddy 继续
占用公网 80 端口，并只把 ACME HTTP-01 验证请求转发到代理端的 loopback
`19091` 端口。远程代理端和仅安装代理端的服务器仍由 sing-box 直接使用公网
80 端口。主控端只会对已确认支持本机中继的代理端注入备用端口，服务器页面会
显示**本地中继已就绪**；无需 NAT 回环支持或额外安装参数。

在已有代理端的服务器上安装或升级主控端时，也会使用同一已验证发行版升级
代理端程序，保留其身份和设置。仅卸载主控端时，会重启正在运行的代理端，
让 ACME 恢复直接使用公网 80 端口。

### 2. 添加代理端服务器

1. 打开**服务器**页面，点击**添加服务器**。
2. 为服务器设置一个便于管理的名称。
3. 复制网页生成的一次性安装命令。
4. 在代理端服务器上以 root 身份运行该命令。
5. 等待网页显示服务器已连接。

等价的手动命令为：

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/install.sh |
sudo sh -s -- agent \
  --master master.example.com:443 \
  --token '一次性令牌'
```

`--master` 只填写 `主机名:端口`，不要添加 `https://`。如果使用另一个主控
端签发的令牌重新安装代理端，控制权会转移到新主控端；旧主控端留下的活动
配置会先被清除，再应用新主控端保存的权威配置。

首次安装代理端时，Installer 会从 Theatropolis 专用 patched-build 仓库选择
最新且兼容的已签名 sing-box 正式版或候选版。重新安装代理端时，如果现有
sing-box 及其托管用户 build tags 均正常，则保留现有版本，不会自动替换。

如果只是更换服务器硬件，可以打开该服务器的设置并生成替换命令。旧代理端
会保持授权，直到新服务器兑换替换令牌；服务器记录和主控端保存的配置不会
丢失。

### 3. 创建代理节点

1. 打开**代理节点**页面并创建节点。
2. 选择入口服务器、入口协议、监听器和终端出口。
3. 点击入口或某个下游服务器，然后选择**创建分支**。
4. 先设置匹配规则，再选择目标服务器和中继协议。
5. 按需要继续添加分支或下游服务器。
6. 拖动同级规则卡片即可调整优先级；规则按照从上到下首次匹配执行。
7. 使用 `ALL` 分支可以把未匹配流量继续中继；否则流量会使用当前服务器的
   直连或拒绝终端。

每次拓扑修改都会立即进行完整验证和部署，不需要另外点击保存。直接修改某个
下游服务器所使用的 Agent 会保留其后续子树；从链路上替换目标服务器则会删
除旧子树，并在新服务器上创建一个新的终端节点。

启用 Shadowsocks 多路复用时，中继出口会明确使用 `smux`，并设置
`max_connections: 4` 和 `min_streams: 4`。

### 4. 创建用户并授予节点权限

1. 打开**用户**页面并创建用户。这里填写的名称是供管理员识别的内部管理名
   称。
2. 生成一次性注册链接并发送给用户。
3. 用户打开链接后自行设置登录用户名和密码。
4. 在用户页面点击**添加节点**，设置每月流量配额和订阅时长。也可以从代理
   节点的用户窗口授予权限。

用户相关修改会立即生效。正常添加、删除用户，重置凭据，修改配额或到期时间
时，Theatropolis 会通过 patched sing-box 的在线用户 API 更新，不会重启
sing-box。如果该 API 异常，代理端会回退到完整重启，以恢复主控端保存的权
威状态。

用户流量用尽后，该节点仍会保留在配置订阅中，凭据也不会改变，但入口会暂时
停用该凭据；流量重置后会自动恢复。已经到期的节点不会出现在配置订阅中。
手动重置已用流量不会改变每月重置日期。

### 5. 配置订阅

每位用户都会自动获得 Clash、Surge 和 sing-box 三种订阅地址。用户和管理
员使用同一个登录页面；系统会根据账号权限进入对应界面。用户登录后可以查看：

- 配置订阅地址；
- 已获得权限的节点；
- 流量用量、配额和重置时间；
- 到期时间；
- 每日流量记录。

管理员可以打开**配置订阅**页面，编辑应用于所有用户的通用有序规则。规则只
会路由到**代理**、**直连**或**拒绝**。代理组包含该用户当前可用的全部节点，
并始终提供直连和拒绝选项。

### 6. 更新与迁移

- 打开**服务器 → 服务器设置**，可以批量更新所有在线代理端，或为整个服务
  器组选择 patched sing-box 版本。
- 打开**设置**页面可以更新主控端。
- 打开**设置 → 主控端迁移**，可以导出加密数据包，在另一台主控端恢复，然后
  将在线代理端切换到新的控制地址。恢复数据不会替换新主控端的管理员登录凭
  据。

主控端切换时处于离线状态的代理端不会自动迁移，需要之后手动使用新主控端重
新安装。

### 常用服务命令

```sh
# 主控端
sudo systemctl status theatropolis-master --no-pager
sudo journalctl -u theatropolis-master -n 100 --no-pager

# 代理端
sudo systemctl status theatropolis-agent --no-pager
sudo journalctl -u theatropolis-agent -n 100 --no-pager

# 查看版本
sudo /usr/local/bin/theatropolis-master version
sudo /usr/local/bin/theatropolis-agent version
sudo /usr/local/bin/sing-box version
```

### 卸载

下载卸载脚本并指定已安装的角色：

```sh
# 主控端（同时仅移除 Theatropolis 的 Caddy 配置）
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/uninstall.sh |
sudo sh -s -- master

# 代理端（子服务器）
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/uninstall.sh |
sudo sh -s -- agent

# 一体化安装
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/masterauguste/theatropolis/main/uninstall.sh |
sudo sh -s -- all
```

脚本会要求在终端中明确确认。默认会永久删除对应角色的状态和凭据；如需保留
`/var/lib/theatropolis/master` 或 `/var/lib/theatropolis/agent` 以便恢复，
请添加 `--keep-data`；对应的状态目录服务账号也会一并保留。`--yes` 仅用于安
全的自动化环境。卸载主控端不会卸载 Caddy，也不会修改其他 Caddy 站点。

## Security and further documentation / 安全与更多文档

The Master, Agent, and sing-box run as dedicated unprivileged users. A small
root-only update helper verifies signed releases and performs narrowly scoped
binary replacement. See [SECURITY.md](SECURITY.md) for the security boundary and
known limitations.

主控端、代理端和 sing-box 都使用独立的非 root 用户运行。只有一个用途受限的
root 更新助手负责验证签名并替换程序文件。安全边界和已知限制请参阅
[SECURITY.md](SECURITY.md)。

For the complete topology, persistence, deployment, and migration model, see
[docs/proxy-node-manager-design.md](docs/proxy-node-manager-design.md).

完整的拓扑、持久化、部署和迁移设计请参阅
[docs/proxy-node-manager-design.md](docs/proxy-node-manager-design.md)。

The configuration-subscription workflow is inspired by
[Sub-Store](https://github.com/sub-store-org/Sub-Store). The exporter is an
independent implementation and does not copy Sub-Store source code.

配置订阅的使用流程参考了
[Sub-Store](https://github.com/sub-store-org/Sub-Store)；导出器为独立实现，未
复制 Sub-Store 的源代码。
