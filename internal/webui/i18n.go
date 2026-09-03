package webui

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/masterauguste/theatropolis/internal/proxynode"
)

const (
	localeEnglish           = "en"
	localeSimplifiedChinese = "zh-CN"
	languageCookieName      = "theatropolis_language"
	languageCookieLifetime  = 365 * 24 * time.Hour
)

var simplifiedChinese = map[string]string{
	"Account access":                                                                              "账户登录",
	"Password or access key":                                                                      "密码或访问密钥",
	"The username or password was not accepted.":                                                  "用户名或密码不正确。",
	"The access key was not accepted.":                                                            "访问密钥不正确。",
	"Too many attempts. Wait one minute and try again.":                                           "尝试次数过多。请等待一分钟后重试。",
	"The topology change failed and the previous branch order was restored.":                      "拓扑更改失败，已恢复先前的分支顺序。",
	"The configuration could not be queued.":                                                      "无法将配置加入队列。",
	"Your session expired.":                                                                       "会话已过期。",
	"The master update could not be scheduled.":                                                   "无法安排主控端更新。",
	"The pool entry could not be saved.":                                                          "无法保存出口池条目。",
	"Use a valid entry name: letters, numbers, dots, underscores, and hyphens only.":              "请输入有效的条目名称，只能使用字母、数字、点、下划线和连字符。",
	"Enter a supported proxy URI or one complete outbound JSON object with a non-empty \"type\".": "请输入支持的代理 URI，或包含非空 \"type\" 的完整出口 JSON 对象。",
	"Keep the remark to 256 characters or fewer.":                                                 "备注不得超过 256 个字符。",
	"The configuration does not satisfy the managed-agent safety policy.":                         "配置不符合托管代理端的安全策略。",
	"The configuration could not be deployed.":                                                    "无法部署配置。",
	"The agent disconnected before the configuration could be delivered.":                         "配置交付前代理端已断开连接。",
	"A configuration deployment is already in progress for this server.":                          "此服务器已有配置部署正在进行。",
	"The server entry no longer exists.":                                                          "服务器条目已不存在。",
	"The agent could not accept the update request.":                                              "代理端无法接受更新请求。",
	"The agent went offline before the update request could be delivered.":                        "更新请求交付前代理端已离线。",
	"Choose an exact signed Theatropolis managed-user sing-box build.":                            "请选择准确且已签名的 Theatropolis 托管用户 sing-box 构建。",
	"sing-box update control is unavailable until this server is online with a compatible agent.": "服务器上线并运行兼容代理端后，才能使用 sing-box 更新控制。",
	"The agent could not accept the sing-box update request.":                                     "代理端无法接受 sing-box 更新请求。",
	"The server entry could not be created.":                                                      "无法创建服务器条目。",
	"Use 1–60 letters or numbers; ordinary spaces and . _ - are allowed.":                         "名称应为 1 至 60 个字母或数字，可包含普通空格及 .、_、-。",
	"That server name is already in use.":                                                         "该服务器名称已被使用。",
	"The server name could not be changed.":                                                       "无法修改服务器名称。",
	"This Server is still used by one or more Proxy Nodes. Move the affected Hops, or delete the branches or Proxy Nodes that use them before removing it.":        "此服务器仍被一个或多个代理节点使用。请先迁移受影响的节点，或删除使用这些节点的分支或代理节点。",
	"This Server is still used by Proxy Node topology. Review its assignments and finish the topology change before removing it.":                                  "此服务器仍被代理节点拓扑使用。请检查分配情况并完成拓扑变更后再移除。",
	"This Server still owns an applied Proxy Node configuration. Finish or retry the topology change before removing it.":                                          "此服务器仍保留着已应用的代理节点配置。请先完成或重试拓扑变更，再移除此服务器。",
	"Wait for the current Proxy Node change to finish, then try removing this Server again.":                                                                       "请等待当前代理节点变更完成，再重新尝试移除此服务器。",
	"This Server cannot be removed while Proxy Nodes use it. Move the affected Hops to another Server, or delete the branches or Proxy Nodes that use them first.": "此服务器仍被代理节点使用，无法移除。请先把受影响的节点迁移到其他服务器，或删除使用这些节点的分支或代理节点。",
	"This Server still owns an applied managed configuration. Finish or retry the Proxy Node change before removing it.":                                           "此服务器仍保留着已应用的托管配置。请先完成或重试代理节点变更，再移除此服务器。",
	"This Server is not used by any Proxy Node.":                                           "此服务器尚未用于任何代理节点。",
	"Use a valid server ID: letters, numbers, dots, underscores, and hyphens only.":        "请输入有效的服务器 ID，只能使用字母、数字、点、下划线和连字符。",
	"That server ID is already enrolled.":                                                  "该服务器 ID 已注册。",
	"That server already has a valid enrollment command. Use it or wait for it to expire.": "该服务器已有有效的注册命令，请使用现有命令或等待其过期。",
	"The current Agent remains authorized until the replacement uses its one-time token. At that moment the old connection is closed and this master immediately deploys the retained profile to the replacement.": "在替换服务器使用一次性令牌前，当前代理端仍保持授权。令牌被使用后，旧连接会关闭，主控端会立即向替换服务器部署保留的配置。",
	"This immediately closes an active control session and invalidates enrollment credentials. It does not uninstall the remote agent or stop its current sing-box process.":                                       "此操作会立即关闭活动控制会话并使注册凭据失效，但不会卸载远程代理端，也不会停止当前 sing-box 进程。",
	"I understand that this agent will need a new enrollment credential to reconnect.":                                                                                                                             "我了解此代理端需要新的注册凭据才能重新连接。",
	"Force removal is only available while the Server is enrolled and offline. Wait for the Agent to disconnect, then try again.":                                                                                   "仅当服务器已注册且离线时才能强制移除。请等待代理端断开连接后重试。",
	"This Server reconnected before it could be removed. Wait until the Agent is offline, then try again.":                                                                                                          "此服务器在移除前已重新连接。请等待代理端离线后重试。",
	"Only when this machine is permanently gone: forget this Server without delivering a retirement profile. Remaining Proxy Node references turn into deleted-Server entries that you redirect or delete afterwards, and pending changes that wait for this Server finish locally. If the machine ever comes back, its Agent stays locked out and must be reinstalled.": "仅当此机器已永久丢失时：不交付退役配置即移除此服务器。剩余的代理节点引用会变成“已删除服务器”条目，之后可将其重定向或删除，等待此服务器的待处理变更将在本地完成。如果该机器重新上线，其代理端将保持锁定状态，必须重新安装。",
	"I understand the machine is permanently gone and its last configuration cannot be withdrawn remotely.": "我了解此机器已永久丢失，其最后一份配置无法远程撤回。",
	"Force remove offline Server": "强制移除离线服务器",
	"This command contains a credential that expires at":                              "此命令包含一项凭据，到期时间为",
	"and becomes unusable after enrollment. The master persists only its hash.":       "，并会在完成注册后失效。主控端只保存其哈希值。",
	"This master still uses its existing access key. Rerun the master installer with": "此主控端仍在使用现有访问密钥。准备迁移时，请使用以下参数重新运行主控端安装程序：",
	"when you are ready to migrate it.":                                               "。",
	"No matching options":                                                             "没有匹配的选项",
	"Filter options":                                                                  "筛选选项",
	"Clear filter":                                                                    "清除筛选",
	"Select an option":                                                                "请选择",
	"Select a Geosite rule set":                                                       "请选择 Geosite 规则集",
	"Subscription Addresses":                                                          "订阅连接地址",
	"Configuration Subscription":                                                      "配置订阅",
	"My Subscription":                                                                 "我的配置订阅",
	"Administrator Subscription":                                                      "管理员配置订阅",
	"Administrator Proxy Access":                                                      "管理员代理权限",
	"Administrator Access":                                                            "管理员权限",
	"All Proxy Nodes · Unlimited":                                                     "所有代理节点 · 不限流量",
	"Enabled":                                                                         "已启用",
	"Off":                                                                             "已关闭",
	"Enable Proxy Access?":                                                            "启用管理员代理权限？",
	"Disable Proxy Access?":                                                           "关闭管理员代理权限？",
	"Enable Access":                                                                   "启用权限",
	"Disable Access":                                                                  "关闭权限",
	"This grants the administrator unlimited, non-expiring access to every Proxy Node.":             "这会授予管理员所有代理节点的不限流量、永不过期权限。",
	"This revokes the administrator credential and configuration subscription on every Proxy Node.": "这会撤销管理员在所有代理节点上的凭据和配置订阅。",
	"Administrator proxy access enabled.":                                                           "管理员代理权限已启用。",
	"Administrator proxy access disabled.":                                                          "管理员代理权限已关闭。",
	"Administrator proxy access could not be updated.":                                              "无法更新管理员代理权限。",
	"Choose whether administrator proxy access is enabled.":                                         "请选择是否启用管理员代理权限。",
	"User Subscription":            "用户配置订阅",
	"Universal Export Policy":      "通用导出策略",
	"Entrance Traffic":             "入口流量",
	"Finite Quota Allocated":       "已分配有限配额",
	"Finite Quota Used":            "已使用有限配额",
	"Unlimited Users":              "不限流量用户",
	"System Access":                "系统权限",
	"System Access · Unlimited":    "系统权限 · 不限流量",
	"Protected":                    "受保护",
	"Open My Subscription":         "打开我的配置订阅",
	"Administrator":                "管理员",
	"Address Families":             "地址类型",
	"IPv4 and IPv6":                "IPv4 和 IPv6",
	"IPv4 Only":                    "仅 IPv4",
	"IPv6 Only":                    "仅 IPv6",
	"Rule Set":                     "规则集",
	"Loading Geosite options…":     "正在加载 Geosite 规则集…",
	"Geosite catalog unavailable.": "无法加载 Geosite 规则集目录。",
	"Close entrance settings":      "关闭入口设置",
	"Delete Proxy Node?":           "删除此代理节点？",
	"Entrance settings for":        "入口设置：",
	"Listener and protocol":        "监听器与协议",
	"Saved pool destination":       "已保存的出口池目标",
	"The fleet outbound pool is unavailable. Direct and Reject remain usable.":    "全局出口池暂不可用，仍可选择直连或拒绝。",
	"Port 80 is reserved for ACME HTTP-01 and cannot be used by a proxy inbound.": "端口 80 保留给 ACME HTTP-01，不能用于代理入站。",
	"Every routing rule needs at least one match value.":                          "每条路由规则至少需要一个匹配值。",
	"The configuration root must be a JSON object.":                               "配置根节点必须是 JSON 对象。",
	"Update complete. Reconnecting to the updated master…":                        "更新完成。正在重新连接更新后的主控端…",
	"The master update failed.":                                                   "主控端更新失败。",
	"No versions available":                                                       "没有可用版本",
	"Loading…":                                                                    "正在加载…",
	"Checking…":                                                                   "正在检查…",
	"Copied":                                                                      "已复制",
	"Show":                                                                        "显示",
	"Hide":                                                                        "隐藏",
	"Show password":                                                               "显示密码",
	"Hide password":                                                               "隐藏密码",
	"Theatropolis user portal":                                                    "Theatropolis 用户中心",
	"The passwords do not match.":                                                 "两次输入的密码不一致。",
	"This invitation is invalid or has expired.":                                  "邀请链接无效或已过期。",
	"This login username is already in use.":                                      "该登录名已被使用。",
	"Account setup is busy. Try again in a moment.":                               "账户设置繁忙，请稍后重试。",
	"Too many account setup attempts. Wait one minute and try again.": "账户设置尝试过多，请等待一分钟后重试。",
	"The account could not be created.":                               "无法创建账户。",
	"username must contain between 1 and 64 ASCII characters":         "登录名须包含 1 至 64 个 ASCII 字符。",
	"username must match [a-z0-9][a-z0-9._-]{0,63}":                   "登录名只能使用小写字母、数字、点、下划线和连字符，且必须以字母或数字开头。",
	"password must not exceed 512 bytes":                              "密码不得超过 512 字节。",
	"password must be valid UTF-8":                                    "密码必须是有效的 UTF-8 文本。",
	"password must contain between 12 and 128 Unicode characters":     "密码须包含 12 至 128 个字符。",
	"password must not contain control characters":                    "密码不能包含控制字符。",
	"password is too common or too closely related to the username":   "密码过于常见，或与登录名过于相似。",
	"Create Account":              "创建账户",
	"Create Registration Link":    "创建注册链接",
	"Go to Sign In":               "前往登录",
	"Invitation ready":            "邀请待使用",
	"Invite":                      "邀请",
	"Login username":              "登录名",
	"Management name":             "管理名称",
	"No Node Access":              "暂无节点权限",
	"Not registered":              "未注册",
	"Registered":                  "已注册",
	"Reset Login":                 "重置登录",
	"Reset Registration Token":    "重置注册令牌",
	"Set Up Account":              "设置账户",
	"User Sign In":                "用户登录",
	"User login":                  "用户登录",
	"User portal":                 "用户中心",
	"My Access":                   "我的权限",
	"Traffic Used":                "已用流量",
	"Monthly Quota":               "每月配额",
	"Reset Time":                  "重置时间",
	"Expiration":                  "到期时间",
	"Node Access":                 "节点权限",
	"Configuration Subscriptions": "配置订阅",
	"Available":                   "可用",
	"Configuration subscriptions are unavailable.": "配置订阅暂不可用。",
	"Daily Traffic": "每日流量",
	"Date":          "日期",
	"Total":         "合计",
	"Last 30 Days":  "最近 30 天",
	"No traffic recorded in the last 30 days.": "最近 30 天暂无流量记录。",
	"Clear Log":        "清空日志",
	"Clear Error Log?": "清空错误日志？",
	"This permanently deletes the complete accounting error log.": "此操作会永久删除全部流量统计错误日志。",
	"Accounting error log cleared.":                               "流量统计错误日志已清空。",
	"Accounting Errors":                                           "流量统计错误",
	"Confirm that you want to clear the error log.":               "请确认要清空错误日志。",
	"The error log could not be cleared.":                         "无法清空错误日志。",
	"Accounting is unavailable.":                                  "流量统计服务不可用。",
	"Confirm password":                                            "确认密码",
	"User Portal":                                                 "用户中心",
	"Reset Login?":                                                "重置用户登录？",
	"Reset Registration Token?":                                   "重置注册令牌？",
	"Registration link expires":                                   "注册链接到期时间：",
	"Expires":                                                     "到期时间：",
	" will be signed out everywhere. The current password will stop working and a new invitation will be created.":           " 将从所有设备退出登录，当前密码立即失效，并生成新的邀请链接。",
	"The current registration link will stop working immediately. A new single-use link valid for 24 hours will be created.": "当前注册链接将立即失效，并生成一个有效期为 24 小时的新一次性链接。",

	"Access is active, but no routable entrance address is available yet.":                                                                 "访问已启用，但目前没有可路由的入口地址。",
	"After installation, return to Servers and refresh to see its authenticated connection state.":                                         "安装后返回“服务器”并刷新，即可查看其认证连接状态。",
	"All three format links will stop working immediately.":                                                                                "三种格式的链接都会立即失效。",
	"Create a Proxy Node before assigning access.":                                                                                         "请先创建代理节点，再分配访问权限。",
	"Create an entrance, then add relay branches and grant user access.":                                                                   "创建入口后，可添加中继分支并授予用户访问权限。",
	"Delete this Proxy Node and all of its Links.":                                                                                         "删除此代理节点及其全部链路。",
	"Delete this user and all Proxy Node access.":                                                                                          "删除此用户及其全部代理节点访问权限。",
	"Enter the access key shown when the master was installed.":                                                                            "请输入安装主控端时显示的访问密钥。",
	"Enter your operator username and password.":                                                                                           "请输入管理员用户名和密码。",
	"Immediately revokes this user's access to every active Proxy Node.":                                                                   "立即撤销此用户对所有活动代理节点的访问权限。",
	"Letters, numbers, dots, underscores, and hyphens. Start with a letter or number.":                                                     "可使用字母、数字、点、下划线和连字符，并以字母或数字开头。",
	"Lowercase letters, numbers, dots, underscores, and hyphens.":                                                                          "可使用小写字母、数字、点、下划线和连字符。",
	"No accounting errors have been recorded.":                                                                                             "尚未记录流量统计错误。",
	"No assigned users match this search.":                                                                                                 "没有已分配用户符合搜索条件。",
	"No configuration has been sent to this agent yet.":                                                                                    "尚未向此代理端发送配置。",
	"No deployed inbounds are in the pool yet. Deploy a configuration with Shadowsocks, AnyTLS, or Hysteria2 inbounds to share them here.": "出口池中尚无已部署的入站。请部署包含 Shadowsocks、AnyTLS 或 Hysteria2 入站的配置。",
	"No finite subscriptions match this search.":                                                                                           "没有限时订阅符合搜索条件。",
	"Offline, incompatible, busy, and already-matching Agents are skipped.":                                                                "离线、不兼容、忙碌或版本已匹配的代理端会被跳过。",
	"Patched stable and release-candidate builds with live managed-user APIs are loaded from the dedicated public build repository. Any published managed build can be installed, including downgrades.": "带实时用户管理 API 的稳定版和候选版从专用公共构建仓库加载。可以安装任何已发布的托管版本，包括降级。",
	"Preferred hostname when this server's AnyTLS or Hysteria2 inbounds are used as outbounds. IPv4 and IPv6 remain available.":                                                                          "此服务器的 AnyTLS 或 Hysteria2 入站作为出口时优先使用的主机名。IPv4 和 IPv6 仍可选择。",
	"Resetting the credential immediately invalidates the previous import credential.":                                                                                                                   "重置凭据会立即使旧的导入凭据失效。",
	"Revokes memberships and immediately removes this Node's listeners and Links from the fleet.":                                                                                                        "所有用户权限会被撤销，此节点的监听器和链路也会立即从全部服务器中移除。",
	"Run this command as a sudo-capable user on the destination server.":                                                                                                                                 "请在目标服务器上以可使用 sudo 的用户运行此命令。",
	"The command is generated from the master’s trusted public URL, not from browser request headers.":                                                                                                   "此命令根据主控端受信任的公开 URL 生成，而不是浏览器请求头。",
	"The credential becomes unusable after this period or immediately after enrollment.":                                                                                                                 "凭据会在此期限后或完成注册后立即失效。",
	"The current subscription URLs and every Proxy Node credential for this user will stop working immediately.":                                                                                         "此用户当前的订阅 URL 和所有代理节点凭据都会立即失效。",
	"This credential will stop working immediately.":                                                                                                                                                     "此凭据会立即失效。",
	" credential will stop working immediately. Other Node credentials and subscription links will not change.":                                                                                          " 的凭据会立即失效；其他节点的凭据和订阅链接不受影响。",
	"The outbound pool is not available on this master.":                                                                                                                                                 "此主控端未启用出口池。",
	"The verified release is being installed. This page will reconnect after the master restarts.":                                                                                                       "正在安装已验证的版本。主控端重启后，此页面会自动重新连接。",
	"These values contain secrets. Copy them only to the intended user.":                                                                                                                                 "这些值包含敏感信息，请只复制给目标用户。",
	"Use the 43-character value printed once by the installer.":                                                                                                                                          "请输入安装程序仅显示一次的 43 位值。",
	"Your credentials are verified locally. The master never stores your plaintext password.":                                                                                                            "凭据在本地验证，主控端不会存储明文密码。",
	"The master stores no plaintext copy. Keep the value printed by the installer in your password manager.":                                                                                             "主控端不会保存明文副本。请将安装程序显示的值保存在密码管理器中。",
	"TLS-protected sign-in. The master stores only a hash of your access key.":                                                                                                                           "登录受 TLS 保护。主控端只保存访问密钥的哈希值。",
	"TLS-protected sign-in. Your password is stored as a salted, memory-hard verifier.":                                                                                                                  "登录受 TLS 保护。密码以加盐的内存困难校验值存储。",
	"Enter DNS hostnames without a scheme, port, path, wildcard, or IP address.":                                                                                                                         "请输入纯 DNS 域名，不要包含协议、端口、路径、通配符或 IP 地址。",

	"Access maintenance": "权限管理", "Access roster": "已授权用户", "Accounting errors": "流量统计错误",
	"Action": "操作", "Actions": "操作", "Active": "正常", "Add a server": "添加服务器",
	"Add another server": "继续添加服务器", "Add compensation": "添加补偿", "Add Node": "添加节点",
	"Add or replace": "添加或替换", "Add rule": "添加规则", "Add server": "添加服务器", "Add user": "添加用户",
	"Add your first server": "添加第一台服务器", "Address family": "地址族", "Address overrides": "地址覆盖",
	"Affected subscriptions": "受影响的订阅", "Agent": "服务器", "Agent diagnostic": "Agent 诊断",
	"Agent software": "Agent 程序", "Agent version": "Agent 版本", "sing-box version": "sing-box 版本", "Applying topology change…": "正在应用拓扑…",
	"TCP latency": "TCP 延迟", "QUIC latency": "QUIC 延迟", "TCP Loss": "TCP 丢包", "QUIC Loss": "QUIC 丢包", "Live TCP Probe": "实时 TCP 检测", "Live QUIC Probe": "实时 QUIC 检测", "Probe Again": "重新检测", "Link Monitor": "链路监控", "Average": "平均延迟", "History range": "历史范围", "Link latency and loss history": "链路延迟与丢包历史", "Not measured": "尚未测量", "Select a destination": "请选择目标服务器", "Stale": "数据已过期",
	"Assign a Node": "添加节点", "Assign role": "确认添加", "Authenticated sessions": "登录会话",
	"Authenticated user": "认证用户", "Automatic": "自动", "Automatic IP addresses": "自动使用 IP 地址", "Awaiting installation": "等待安装",
	"Bandwidth": "带宽", "Branch": "分支", "Calendar months": "自然月",
	"Cancel": "取消", "Certificate mode": "证书模式", "TLS Certificate Domain/IP": "TLS 证书域名/IP",
	"Change sing-box version": "更改 sing-box 版本", "Check again": "重新检查", "Checking for updates…": "正在检查更新…",
	"Child exit": "子节点默认出口", "Choose a Node": "选择节点", "Close": "关闭", "Command lifetime": "命令有效期",
	"Compensate": "补偿", "Compensation": "补偿", "Conditional": "条件", "Configure manually": "手动配置",
	"Configured sets": "已配置规则集", "Confirm": "确认", "Connection": "连接", "Connection target": "连接目标",
	"Control connection": "控制连接", "Copy": "复制", "Copy command": "复制命令", "Create Branch": "创建分支",
	"Create Proxy Node": "创建代理节点", "Create replacement command": "创建替换命令", "Create subscription": "创建订阅",
	"Create user": "创建用户", "Create your first Proxy Node": "创建第一个代理节点", "Credential": "凭据",
	"Current version": "当前版本", "Custom domains": "自定义域名", "Custom Rule Set": "自定义规则集", "Custom Rule Sets": "自定义规则集",
	"Days": "天", "Default route": "默认路由", "FINAL (Unmatched Rules)": "FINAL（未匹配规则）", "Delete": "删除",
	"Delete and apply": "删除并应用", "Delete Branch": "删除分支", "Delete Proxy Node": "删除代理节点",
	"Delete rule": "删除规则", "Delete user": "删除用户", "Destination": "目标", "Destination port": "目标端口",
	"Details": "详情", "Direct": "直连", "Disabled": "已禁用", "Disconnect and invalidate this identity": "断开连接并使此身份失效", "offline": "离线",
	"Domain keyword": "域名关键词", "Domain regex": "域名正则",
	"Domain suffix": "域名后缀", "Domain": "域名", "Done": "完成", "Download Mbps": "下载 Mbps",
	"Downstream": "下游", "Duration": "时长", "Edit Relay": "编辑中继", "Edit rule": "编辑规则", "Edit": "编辑",
	"Enabled (smux)": "已启用（smux）", "End user": "用户", "End users": "用户列表", "Enrollment": "注册",
	"Enrollment lifetime": "注册有效期", "Enrollment ready": "注册已就绪", "Entrance Agent": "入口代理端",
	"Entrance configuration": "入口设置", "Entrance exit": "入口默认出口", "Entrance protocol": "入口协议", "Entrance server": "入口服务器", "Entrance": "入口",
	"Entry name": "条目名称", "Legacy file certificate": "旧版文件证书", "Exit": "出口", "Expire after a duration": "按时长过期",
	"Extend by": "延长", "Extend subscription": "延长订阅", "Failure": "失败", "Fallback": "回退",
	"Fleet maintenance": "批量维护", "Fleet outbound pool": "全局出口池", "Fleet": "服务器组", "Global identities": "用户管理",
	"Global settings": "系统设置", "Global user": "用户", "Grant access": "添加权限", "Hop": "节点",
	"Hops": "节点", "Hours": "小时", "HTTPS SRS URL": "HTTPS SRS URL", "Import credentials": "导入凭据",
	"Inactive": "未启用", "Included": "已包含", "Inbound": "入站", "Infrastructure": "服务器管理", "Install selected sing-box version": "安装所选 sing-box 版本",
	"IP addresses": "IP 地址", "IPv4 domain": "IPv4 域名", "IPv6 domain": "IPv6 域名", "Known to this master": "已被主控端识别", "Last update": "最近更新",
	"Latest available": "最新可用版本", "Latest deployment": "最近部署", "Legacy sign-in": "旧版登录",
	"Link multiplex": "链路多路复用", "Listen address": "监听地址", "Listen port": "监听端口", "Listener": "监听器",
	"Loading fleet outbounds…": "正在加载舰队出口…", "Loading releases…": "正在加载版本…", "Loading servers…": "正在加载服务器…",
	"Loading signed releases…": "正在加载已签名版本…", "Logical services": "代理服务", "Manual entries": "手动条目",
	"Master software": "主控端软件", "Master update": "主控端更新", "Master": "主控端", "Match type": "匹配类型",
	"Match": "匹配", "Method": "方法", "Minutes": "分钟", "Monthly quota": "每月配额", "Monthly traffic quota": "每月流量配额",
	"Move Hop": "更换服务器", "Move this identity and its profile to another server": "将此身份及其配置迁移到另一台服务器",
	"Multiplex": "多路复用", "Name": "名称", "Needs attention": "需要处理", "Network": "网络", "New logical service": "新建逻辑服务",
	"New Proxy Node": "新建代理节点", "New": "新建", "No expiration": "永不过期", "No manual entries yet.": "尚无手动条目。",
	"No node access": "无节点访问权限", "No Nodes available.": "没有可用节点。", "No Proxy Nodes exist yet": "尚未创建代理节点",
	"No Resolve":         "不解析域名",
	"No Proxy Nodes yet": "尚无代理节点", "No rules": "尚无规则", "No servers enrolled yet": "尚无已注册服务器",
	"No subscription link": "无订阅链接", "No users assigned": "尚未分配用户", "No users available.": "没有可用用户。",
	"No users have been created.": "尚未创建用户。", "Node role": "节点访问权限", "Node roles": "节点访问权限", "Nodes": "节点",
	"Obfuscation": "混淆", "Offline or expired": "离线或已过期", "Online": "在线", "Open Proxy Node": "打开代理节点",
	"Open Proxy Nodes": "打开代理节点", "Open user": "打开用户", "Operations": "操作", "Operator access": "管理员访问",
	"Optional": "可选", "Outage ended (UTC+8)": "故障结束时间（UTC+8）", "Outage started (UTC+8)": "故障开始时间（UTC+8）",
	"Outbound JSON": "出口 JSON", "Outbound pool": "出口池", "Password": "密码", "Pending": "待处理",
	"Physical listener": "物理监听器", "Port": "端口", "Port 80 remains reserved for ACME.": "端口 80 保留给 ACME。",
	"Private-key path": "私钥路径", "Process name": "进程名称",
	"Protocol": "协议", "Proxy Node name": "代理节点名称", "Proxy Node readiness": "代理节点状态", "Proxy Node roles": "代理节点访问权限", "Proxy Node Assignments": "代理节点分配",
	"Proxy Node settings": "代理节点设置", "Proxy Nodes": "代理节点", "Proxy Node": "代理节点", "Proxy runtime": "代理运行时",
	"Proxy URI or outbound JSON": "代理 URI 或出口 JSON", "Proxy": "代理", "Quota (GiB)": "配额（GiB）", "Ready": "就绪",
	"Reject": "拒绝", "Relay address family": "中继地址族", "Relay Branch": "中继分支", "Relay map": "路由拓扑", "Relay": "中继",
	"Remark": "备注", "Rename or delete this Proxy Node": "重命名或删除此代理节点", "Rename Proxy Node": "编辑节点名称", "Rename": "保存名称",
	"Replace Agent": "替换代理端", "Replace Destination": "替换目标", "Reported running": "报告为运行中",
	"Replacing the destination deletes":                                                   "替换目标会删除",
	"and its entire downstream subtree. To keep the subtree, move the child Hop instead.": "及其全部下游分支。如需保留子树，请改为在子 Hop 上更换服务器。",
	"Reset ": "重置 ", " credential?": " 的凭据？", "Reset all credentials": "重置全部凭据", "Reset all credentials?": "重置全部凭据？", "Reset credential": "重置凭据",
	"Reset link and credentials": "重置链接和凭据", "Reset subscription link": "重置订阅链接", "Reset subscription link?": "重置订阅链接？",
	"Reset traffic": "重置流量", "Resets after": "下次重置", "Return to servers": "返回服务器", "Return to settings": "返回设置",
	"Revision": "版本", "Revoke access": "撤销权限", "Revoke link": "撤销链接", "Review Proxy Nodes": "查看代理节点", "Role allowance": "配额与有效期",
	"Route ALL": "路由全部流量", "Routes to": "路由至", "Routing mode": "路由模式", "Routing resources": "路由资源",
	"Routing Rule": "路由规则", "Routing trees": "路由拓扑", "Route": "路由", "Rule Sets": "规则集", "Rules": "规则", "Rule": "规则",
	"Running version": "运行版本", "Save address overrides": "保存地址覆盖", "Save allowance": "保存额度",
	"Save and apply Rule Set": "保存并应用规则集", "Save Entrance": "保存入口设置", "Save entrance": "保存入口设置", "Save Exit": "保存默认出口", "Save pool entry": "保存池条目",
	"Save Relay": "保存中继", "Save Rule": "保存规则", "Save server settings": "保存服务器设置", "Save": "保存",
	"Search affected users": "搜索受影响的用户", "Search assigned users": "搜索用户", "Search available Proxy Nodes": "搜索可用代理节点",
	"Filter by user name": "按用户名筛选", "Clear affected-user search": "清除受影响用户筛选",
	"Search users": "搜索用户", "Secure enrollment": "安全注册", "Select Agent": "选择服务器", "Select an enrolled Agent": "选择已注册的服务器",
	"Self-signed by Agent": "由代理端自签名", "Server addresses": "服务器地址", "Server and software actions": "服务器与软件操作",
	"Server ID": "服务器 ID", "Server Name": "服务器名称", "Server Record ID": "服务器记录 ID", "Rename Server": "重命名服务器", "Save Name": "保存名称", "Server identity": "服务器身份", "Server management": "服务器管理", "Server settings": "服务器设置",
	"Servers": "服务器", "Set a monthly quota": "设置每月配额", "Settings": "设置", "Shown once.": "仅显示一次。",
	"Sign in to continue": "登录以继续", "Sign in": "登录", "Sign out": "退出登录", "Single use": "仅限一次",
	"Skip to content": "跳至内容", "Source port": "源端口", "Status": "状态", "Subscription compensation": "订阅补偿",
	"Subscription addresses": "订阅地址", "Subscription expiration": "订阅到期方式", "Subscription link": "订阅链接", "Subscription links": "订阅链接",
	"Subscription rule": "订阅规则", "Subscriptions": "配置订阅", "Subscription": "订阅", "Supported OS": "支持的操作系统",
	"Swipe to explore": "横向滑动查看", "Tag": "标签", "Target version": "目标版本", "Target": "目标", "Terminal Exit": "默认出口",
	"Terminal": "终端", "Time": "时间", "TLS listener": "TLS 监听器", "TLS mode": "TLS 模式", "Total servers": "服务器总数",
	"Traffic used": "已用流量", "Transport": "传输", "Unavailable": "不可用", "Unit": "单位", "Universal export policy": "通用导出策略",
	"Unknown": "未知", "Unlimited": "不限", "Unmatched traffic": "未匹配流量", "Update Agent software": "更新代理端软件",
	"Update agent to latest": "将代理端更新到最新版", "Update all Agents": "更新所有代理端", "Update diagnostic": "更新诊断",
	"Update interval": "更新间隔", "Update status": "更新状态", "Updated": "已更新", "Updating Theatropolis": "正在更新 Theatropolis",
	"Upload Mbps": "上传 Mbps", "Used": "已用", "User access": "用户权限", "User name": "用户名", "User subscription": "用户订阅", "Username": "用户名", "Users": "用户",
	"Values": "值", "View users and address settings": "查看用户和地址设置", "Wait for the agent to connect": "等待代理端连接",
	"Primary navigation": "主导航", "Breadcrumb": "面包屑导航", "Theatropolis servers": "Theatropolis 服务器",
	"Close outbound details": "关闭出口详情", "Clear Node search": "清除节点搜索", "Clear user search": "清除用户搜索", "Available Proxy Nodes": "可用代理节点",
	"Assigned Proxy Node roles": "已分配的代理节点权限", "Monthly traffic": "每月流量", "Access key": "访问密钥",
	"Enrolled": "已注册", "Expired": "已过期", "Not connected": "未连接", "Offline": "离线", "Queued": "已排队",
	"Topology Pending": "拓扑等待应用", "Entrance Offline": "入口失联", "Relay Offline": "中继失联", "Current topology": "当前运行拓扑",
	"Entrance Server Deleted": "入口服务器已删除", "Relay Server Deleted": "中继服务器已删除", "deleted": "已删除",
	"Choose another server to remove this stale reference. The old server cannot be cleaned remotely.": "请选择另一台服务器以清除这条残留引用。主控端无法再远程清理原服务器。",
	"Choose another server or delete its branch to remove this stale reference. The old server cannot be cleaned remotely.": "请选择另一台服务器或删除对应分支，以清除这条残留引用。主控端无法再远程清理原服务器。",
	"Proxy Node status": "代理节点状态", "Saved changes are not yet active.": "变更已保存，但尚未生效。",
	"Saved changes are not yet active. The relay map shows the saved topology.": "变更已保存，但尚未生效。路由拓扑显示的是已保存的版本。",
	"Entrance is not available until topology is applied.":                      "拓扑应用前，入口暂不可用。",
	"ready": "已就绪", "waiting for Agent": "等待服务器上线", "waiting for address": "等待可用地址",
	"Validating": "正在验证", "Validated": "验证通过", "Deploying": "正在部署", "Applied": "已应用",
	"Configured": "已配置", "Pending Apply": "等待应用", "Pending Removal": "等待删除", "Old configuration is still running.": "旧配置仍在运行。", "Pending Retirement": "等待移除", "Topology Retirement Pending": "等待清理旧拓扑", "Move Proxy Node Hops First": "请先迁移代理节点",
	"Runtime failure": "运行失败", "Validation failed": "验证失败", "Activation failed": "激活失败",
	"Agent error": "代理端错误", "Delivery failed": "交付失败", "Quota reached": "已达到配额",
	"Entrance sample collection failed": "入口采样失败", "Master could not persist usage": "主控端无法保存用量",
	"Accounting failure": "流量统计失败", "Release Candidate": "候选版本", "Stable": "稳定版",
	"ALL": "全部", "IP / CIDR": "IP / CIDR", "Source IP/CIDR": "源 IP/CIDR",
	"assigned": "已分配", "available": "可用", "total": "总计", "on port": "端口", "selected": "已选择",
	"Established": "已建立", "Not established": "未建立", "Refresh server status": "刷新服务器状态",
	"Refresh": "刷新", "Fleet summary": "服务器概览", "Close server settings": "关闭服务器设置", "Queuing…": "正在排队…",
	"Master Migration": "主控端迁移", "Migration": "迁移", "Close Migration": "关闭迁移",
	"Move From This Master": "从当前主控端迁出", "Receive On This Master": "在当前主控端接收", "Receive Migration": "接收迁移",
	"Source Master": "原主控端", "Destination Master": "新主控端", "Close Source Migration": "关闭迁出操作", "Close Destination Migration": "关闭接收操作",
	"Passphrase": "加密口令", "Confirm Passphrase": "确认加密口令", "Download Archive": "下载迁移包", "Exporting…": "正在导出…",
	"Show passphrase": "显示加密口令",
	"Archive":         "迁移包", "Confirmation": "确认文字", "Restore And Restart": "恢复并重启", "Restoring…": "正在恢复…",
	"New Master": "新主控端", "Switch Online Servers": "切换在线服务器", "Switching…": "正在切换…",
	"Restoring Master": "正在恢复主控端", "Restarting Master": "正在重启主控端", "Return To Settings": "返回设置",
	"Scheduling…": "正在安排…", "Pool": "出口池", "recorded": "条记录", "Access and allowances": "用户与配额",
	"Topology change": "拓扑更新", "Left-to-right relay tree": "从左到右的路由拓扑", "Close details": "关闭详情",
	"Relay Hop": "中继节点", "Unmatched Traffic": "未匹配流量", "Yes": "是", "No": "否", "Auto": "自动",
	"Duplicate Branch": "复制分支", "Add Rule": "添加规则", "Rule branch": "规则分支", "Reject branch": "拒绝分支",
	"New Branch from": "新分支，来源", "Reachability depends on runtime DNS or Rule Set data": "可达性取决于运行时 DNS 或规则集数据",
	"Runtime-dependent path": "依赖运行时数据的路径", "Drag to change priority": "拖动以更改优先级", "View": "查看",
	"Move Rule up": "上移规则", "Move Rule down": "下移规则", "Reorder Rule": "调整规则顺序", "Delete branch": "删除分支",
	"custom": "自定义", "exit": "出口", "user": "用户", "Link": "链路", "Links": "链路",
	"Create install command": "创建安装命令", "Server": "服务器", "ACME email": "ACME 邮箱",
	"IPv4 override": "IPv4 覆盖", "IPv6 override": "IPv6 覆盖", "TLS-secured gRPC": "TLS 加密的 gRPC",
	"loading available versions…": "正在加载可用版本…", "loading…": "正在加载…",
	"sing-box release": "sing-box 版本", "sing-box runtime": "sing-box 运行时", "sing-box update diagnostic": "sing-box 更新诊断",
}

func parseLocalizedTemplates() (map[string]*template.Template, error) {
	paths, err := webFiles.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("read web UI templates: %w", err)
	}
	result := make(map[string]*template.Template, 2)
	for _, locale := range []string{localeEnglish, localeSimplifiedChinese} {
		activeLocale := locale
		set := template.New("webui").Funcs(template.FuncMap{
			"count": func(count int, kind string) string {
				return localizedCount(activeLocale, count, kind)
			},
		})
		for _, entry := range paths {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".html") {
				continue
			}
			path := "templates/" + entry.Name()
			content, readErr := webFiles.ReadFile(path)
			if readErr != nil {
				return nil, fmt.Errorf("read web UI template %q: %w", path, readErr)
			}
			source := string(content)
			if locale == localeSimplifiedChinese {
				source = localizeTemplateSource(source)
			}
			if _, parseErr := set.New(entry.Name()).Parse(source); parseErr != nil {
				return nil, fmt.Errorf("parse %s web UI template %q: %w", locale, path, parseErr)
			}
		}
		result[locale] = set
	}
	return result, nil
}

func localizedCount(locale string, count int, kind string) string {
	if normalizeLocale(locale) == localeSimplifiedChinese {
		switch kind {
		case "hop", "node":
			return fmt.Sprintf("%d 个节点", count)
		case "relay-hop":
			return fmt.Sprintf("%d 个中继节点", count)
		case "link":
			return fmt.Sprintf("%d 条链路", count)
		case "user":
			return fmt.Sprintf("%d 位用户", count)
		case "exit":
			return fmt.Sprintf("%d 个出口", count)
		case "available-node":
			return fmt.Sprintf("%d 个可用节点", count)
		case "proxy-access":
			return fmt.Sprintf("已授权 %d 个代理节点", count)
		case "reference":
			return fmt.Sprintf("%d 个配置", count)
		default:
			return fmt.Sprintf("共 %d 项", count)
		}
	}
	noun := map[string]string{
		"hop": "Hop", "node": "Node", "relay-hop": "Relay Hop", "link": "Link", "user": "user", "exit": "exit",
		"available-node": "Node available",
		"proxy-access":   "Proxy Node access grant", "reference": "reference",
	}[kind]
	if noun == "" {
		return fmt.Sprintf("%d total", count)
	}
	if count != 1 {
		switch kind {
		case "available-node":
			noun = "Nodes available"
		default:
			noun += "s"
		}
	}
	return fmt.Sprintf("%d %s", count, noun)
}

type templateTranslation struct{ english, chinese string }

func localizeTemplateSource(source string) string {
	replacements := make([]templateTranslation, 0, len(simplifiedChinese))
	for english, chinese := range simplifiedChinese {
		replacements = append(replacements, templateTranslation{english: english, chinese: chinese})
	}
	sort.Slice(replacements, func(left, right int) bool {
		if len(replacements[left].english) == len(replacements[right].english) {
			return replacements[left].english < replacements[right].english
		}
		return len(replacements[left].english) > len(replacements[right].english)
	})
	return localizeHTMLTemplate(source, replacements)
}

var localizableTemplateAttribute = regexp.MustCompile(`\b(?:aria-label|aria-description|placeholder|title|data-label|data-async-loading-label|data-submit-label|data-copy-label|data-secret-label)\s*=\s*"[^"]*"`)

func localizeHTMLTemplate(source string, replacements []templateTranslation) string {
	var translated strings.Builder
	for len(source) > 0 {
		start := strings.IndexByte(source, '<')
		if start < 0 {
			translated.WriteString(localizeTemplateText(source, replacements))
			break
		}
		translated.WriteString(localizeTemplateText(source[:start], replacements))
		source = source[start:]
		end := templateTagEnd(source)
		if end < 0 {
			translated.WriteString(source)
			break
		}
		tag := source[:end+1]
		translated.WriteString(localizableTemplateAttribute.ReplaceAllStringFunc(tag, func(attribute string) string {
			quote := strings.IndexByte(attribute, '"')
			if quote < 0 {
				return attribute
			}
			return attribute[:quote+1] + localizeTemplateText(attribute[quote+1:len(attribute)-1], replacements) + `"`
		}))
		source = source[end+1:]
	}
	return translated.String()
}

func localizeTemplateText(source string, replacements []templateTranslation) string {
	var translated strings.Builder
	for len(source) > 0 {
		start := strings.Index(source, "{{")
		if start < 0 {
			translated.WriteString(replaceTemplateText(source, replacements))
			break
		}
		translated.WriteString(replaceTemplateText(source[:start], replacements))
		end := strings.Index(source[start+2:], "}}")
		if end < 0 {
			translated.WriteString(source[start:])
			break
		}
		end += start + 4
		translated.WriteString(source[start:end])
		source = source[end:]
	}
	return translated.String()
}

func replaceTemplateText(source string, replacements []templateTranslation) string {
	var translated strings.Builder
	for offset := 0; offset < len(source); {
		matchAt := -1
		var match templateTranslation
		for _, candidate := range replacements {
			searchFrom := offset
			for searchFrom <= len(source)-len(candidate.english) {
				relative := strings.Index(source[searchFrom:], candidate.english)
				if relative < 0 {
					break
				}
				index := searchFrom + relative
				if templateTranslationBoundary(source, index, candidate.english) {
					if matchAt < 0 || index < matchAt {
						matchAt, match = index, candidate
					}
					break
				}
				searchFrom = index + 1
			}
		}
		if matchAt < 0 {
			translated.WriteString(source[offset:])
			break
		}
		translated.WriteString(source[offset:matchAt])
		translated.WriteString(match.chinese)
		offset = matchAt + len(match.english)
	}
	return translated.String()
}

func templateTranslationBoundary(source string, index int, english string) bool {
	if english == "" {
		return false
	}
	if asciiWordByte(english[0]) && index > 0 && asciiWordByte(source[index-1]) {
		return false
	}
	end := index + len(english)
	return !asciiWordByte(english[len(english)-1]) || end == len(source) || !asciiWordByte(source[end])
}

func asciiWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_'
}

func templateTagEnd(source string) int {
	var quote byte
	for index := 1; index < len(source); index++ {
		if strings.HasPrefix(source[index:], "{{") {
			if end := strings.Index(source[index+2:], "}}"); end >= 0 {
				index += end + 3
				continue
			}
			return -1
		}
		character := source[index]
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '"' || character == '\'' {
			quote = character
			continue
		}
		if character == '>' {
			return index
		}
	}
	return -1
}

func normalizeLocale(locale string) string {
	if strings.EqualFold(strings.TrimSpace(locale), localeSimplifiedChinese) ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(locale)), "zh") {
		return localeSimplifiedChinese
	}
	return localeEnglish
}

func localeForRequest(request *http.Request) (string, bool) {
	if cookie, err := request.Cookie(languageCookieName); err == nil {
		switch cookie.Value {
		case localeEnglish, localeSimplifiedChinese:
			return cookie.Value, true
		}
	}
	return localeFromAcceptLanguage(request.Header.Get("Accept-Language")), false
}

func localeFromAcceptLanguage(header string) string {
	bestLocale := localeEnglish
	bestQuality := -1.0
	for _, preference := range strings.Split(header, ",") {
		parts := strings.Split(preference, ";")
		tag := strings.ToLower(strings.TrimSpace(parts[0]))
		quality := 1.0
		valid := tag != ""
		for _, parameter := range parts[1:] {
			name, value, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				valid = false
				break
			}
			quality = parsed
		}
		if !valid || quality == 0 {
			continue
		}
		locale := ""
		switch {
		case tag == "zh" || strings.HasPrefix(tag, "zh-"):
			locale = localeSimplifiedChinese
		case tag == "en" || strings.HasPrefix(tag, "en-"), tag == "*":
			locale = localeEnglish
		}
		if locale != "" && quality > bestQuality {
			bestLocale = locale
			bestQuality = quality
		}
	}
	return bestLocale
}

func (h *Handler) languagePreferenceCookie(locale string) *http.Cookie {
	return &http.Cookie{
		Name: languageCookieName, Value: normalizeLocale(locale), Path: "/",
		MaxAge: int(languageCookieLifetime.Seconds()), Expires: h.currentTime().Add(languageCookieLifetime),
		Secure: h.publicScheme == "https" && !isLocalDevelopmentHost(h.publicHost), SameSite: http.SameSiteLaxMode,
	}
}

func (h *Handler) changeLanguage(response http.ResponseWriter, request *http.Request) {
	requested := request.PathValue("locale")
	locale := normalizeLocale(requested)
	if requested != localeEnglish && requested != localeSimplifiedChinese {
		http.NotFound(response, request)
		return
	}
	http.SetCookie(response, h.languagePreferenceCookie(locale))
	target := "/servers"
	if _, ok := h.sessionToken(request); !ok {
		target = "/login"
	}
	switch request.URL.Query().Get("return_to") {
	case "/portal", "/portal/login", "/claim":
		target = request.URL.Query().Get("return_to")
	}
	if referer := request.Referer(); referer != "" {
		if parsed, err := url.Parse(referer); err == nil && parsed.Scheme == h.publicScheme && parsed.Hostname() == h.publicHost && effectiveURLPort(parsed) == h.publicPort && strings.HasPrefix(parsed.Path, "/") && !strings.HasPrefix(parsed.Path, "//") {
			target = parsed.RequestURI()
		}
	}
	http.Redirect(response, request, target, http.StatusSeeOther)
}

func isLocalDevelopmentHost(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
}

func effectiveURLPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	if parsed.Scheme == "https" {
		return "443"
	}
	if parsed.Scheme == "http" {
		return "80"
	}
	return ""
}

func localizedText(locale, text string) string {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return text
	}
	if translated, ok := simplifiedChinese[text]; ok {
		return translated
	}
	for suffix, translated := range map[string]string{
		" subscription": " · 订阅",
		" entrance":     " · 入口",
		" access":       " · 用户权限",
		" Rule Sets":    " · 规则集",
	} {
		if strings.HasSuffix(text, suffix) {
			return strings.TrimSuffix(text, suffix) + translated
		}
	}
	for prefix, translated := range map[string]string{
		"Expires ":                  "到期时间：",
		"Link to ":                  "链路至 ",
		"Terminal on ":              "终端位于 ",
		"Relay to ":                 "中继至 ",
		"Entrance listener · port ": "入口监听器 · 端口 ",
		"Incoming Link · port ":     "入站链路 · 端口 ",
	} {
		if strings.HasPrefix(text, prefix) {
			return translated + strings.TrimPrefix(text, prefix)
		}
	}
	return text
}

func localizePageData(locale string, data *pageData) {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return
	}
	data.Title = localizedText(locale, data.Title)
	data.Error = localizedText(locale, data.Error)
	data.Notice = localizedText(locale, data.Notice)
	data.MigrationNotice = localizedText(locale, data.MigrationNotice)
	data.ReleaseCatalogWarning = localizedText(locale, data.ReleaseCatalogWarning)
	data.SingBoxCatalogWarning = localizedText(locale, data.SingBoxCatalogWarning)
	for index := range data.Agents {
		data.Agents[index].EnrollmentLabel = localizedText(locale, data.Agents[index].EnrollmentLabel)
		data.Agents[index].ConnectionLabel = localizedText(locale, data.Agents[index].ConnectionLabel)
	}
	if data.Agent != nil {
		localizeAgentDetail(locale, data.Agent)
	}
	if data.MasterUpdate != nil {
		localizeAgentUpdate(locale, data.MasterUpdate)
	}
	if data.ProxyDeployment != nil {
		data.ProxyDeployment.Label = localizedText(locale, data.ProxyDeployment.Label)
		data.ProxyDeployment.Error = localizedText(locale, data.ProxyDeployment.Error)
		for index := range data.ProxyDeployment.Agents {
			data.ProxyDeployment.Agents[index].Status = localizedText(locale, data.ProxyDeployment.Agents[index].Status)
		}
	}
	for index := range data.ProxyNodes {
		data.ProxyNodes[index].Entrance = localizedText(locale, data.ProxyNodes[index].Entrance)
	}
	for index := range data.EndUsers {
		data.EndUsers[index].LoginStatus = localizedText(locale, data.EndUsers[index].LoginStatus)
	}
	for index := range data.ListenerOptions {
		option := &data.ListenerOptions[index]
		option.Label = fmt.Sprintf("%s · %s:%d · %s", option.ProtocolLabel, option.Listen, option.ListenPort, localizedCount(locale, option.ReferenceCount, "reference"))
	}
	if data.ProxyNode != nil {
		localizeProxyNodeDetail(locale, data.ProxyNode)
	}
	if data.EndUser != nil {
		localizeEndUserDetail(locale, data.EndUser)
	}
	if data.EndUserPortal != nil {
		localizeDailyUsage(locale, data.EndUserPortal.DailyUsage)
		for index := range data.EndUserPortal.Nodes {
			node := &data.EndUserPortal.Nodes[index]
			plan := membershipPlanView{
				QuotaLabel: node.QuotaLabel, ResetLabel: node.ResetLabel, ResetAt: node.ResetAt,
				ExpirationLabel: node.ExpirationLabel, ExpirationAt: node.ExpirationAt, StatusLabel: node.StatusLabel,
			}
			localizeMembershipPlan(locale, &plan)
			node.QuotaLabel = plan.QuotaLabel
			node.ResetLabel = plan.ResetLabel
			node.ResetAt = plan.ResetAt
			node.ExpirationLabel = plan.ExpirationLabel
			node.ExpirationAt = plan.ExpirationAt
			node.StatusLabel = plan.StatusLabel
		}
	}
	if data.UserSubscription != nil {
		for index := range data.UserSubscription.Nodes {
			data.UserSubscription.Nodes[index].Status = localizedText(locale, data.UserSubscription.Nodes[index].Status)
		}
	}
	if data.SubscriptionPolicy != nil {
		for index := range data.SubscriptionPolicy.Rules {
			data.SubscriptionPolicy.Rules[index].MatchLabel = localizedText(locale, data.SubscriptionPolicy.Rules[index].MatchLabel)
			data.SubscriptionPolicy.Rules[index].ActionLabel = localizedText(locale, data.SubscriptionPolicy.Rules[index].ActionLabel)
		}
	}
	for index := range data.AccountingFailures {
		data.AccountingFailures[index].Reason = localizedText(locale, data.AccountingFailures[index].Reason)
	}
}

func localizeAgentDetail(locale string, view *agentDetailView) {
	view.EnrollmentLabel = localizedText(locale, view.EnrollmentLabel)
	view.ConnectionLabel = localizedText(locale, view.ConnectionLabel)
	view.ConfigurationHint = localizedText(locale, view.ConfigurationHint)
	view.SingBoxUpdateHint = localizedText(locale, view.SingBoxUpdateHint)
	view.UpdateHint = localizedText(locale, view.UpdateHint)
	view.RevokeLabel = localizedText(locale, view.RevokeLabel)
	for index := range view.ProxyNodeReferences {
		reference := &view.ProxyNodeReferences[index]
		reference.DesiredRelayHopLabel = localizedCount(locale, reference.DesiredRelayHops, "relay-hop")
		reference.AppliedRelayHopLabel = localizedCount(locale, reference.AppliedRelayHops, "relay-hop")
	}
	if view.Deployment != nil {
		view.Deployment.StatusLabel = localizedText(locale, view.Deployment.StatusLabel)
		view.Deployment.Diagnostic = localizedText(locale, view.Deployment.Diagnostic)
	}
	if view.Update != nil {
		localizeAgentUpdate(locale, view.Update)
	}
	if view.SingBoxUpdate != nil {
		localizeAgentUpdate(locale, view.SingBoxUpdate)
	}
}

func localizeAgentUpdate(locale string, view *agentUpdateView) {
	view.StatusLabel = localizedText(locale, view.StatusLabel)
	view.Diagnostic = localizedText(locale, view.Diagnostic)
}

func localizeMembershipPlan(locale string, view *membershipPlanView) {
	if normalizeLocale(locale) == localeSimplifiedChinese && strings.HasSuffix(view.QuotaLabel, " / month") {
		view.QuotaLabel = "每月 " + strings.TrimSuffix(view.QuotaLabel, " / month")
	}
	view.QuotaLabel = localizedText(locale, view.QuotaLabel)
	view.ResetLabel = localizedMembershipTime(locale, view.ResetLabel)
	view.ExpirationLabel = localizedMembershipTime(locale, view.ExpirationLabel)
	view.StatusLabel = localizedText(locale, view.StatusLabel)
}

func localizedMembershipTime(locale, label string) string {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return label
	}
	value := strings.TrimPrefix(label, "Expires ")
	for _, candidate := range []struct {
		parseLayout   string
		displayLayout string
	}{
		{parseLayout: "Jan 2, 2006 15:04", displayLayout: "2006年1月2日 15:04"},
		{parseLayout: "Jan 2, 2006", displayLayout: "2006年1月2日"},
	} {
		parsed, err := time.ParseInLocation(candidate.parseLayout, value, proxynode.BillingLocation())
		if err == nil {
			return parsed.Format(candidate.displayLayout)
		}
	}
	return localizedText(locale, label)
}

func localizedBillingTime(locale, label string) string {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return label
	}
	const zoneSuffix = " (UTC+8)"
	value := strings.TrimSuffix(strings.TrimPrefix(label, "Expires "), zoneSuffix)
	for _, candidate := range []struct {
		parseLayout   string
		displayLayout string
	}{
		{parseLayout: "Jan 2, 2006 15:04", displayLayout: "2006年1月2日 15:04"},
		{parseLayout: "Jan 2, 2006", displayLayout: "2006年1月2日"},
	} {
		parsed, err := time.ParseInLocation(candidate.parseLayout, value, proxynode.BillingLocation())
		if err == nil {
			return parsed.Format(candidate.displayLayout) + "（UTC+8）"
		}
	}
	return localizedText(locale, label)
}

func localizeEndUserDetail(locale string, view *endUserDetailView) {
	view.Login.StatusLabel = localizedText(locale, view.Login.StatusLabel)
	view.Login.InviteExpiresAt = localizedBillingTime(locale, view.Login.InviteExpiresAt)
	if view.Login.Invitation != nil {
		view.Login.Invitation.ExpiresAt = localizedBillingTime(locale, view.Login.Invitation.ExpiresAt)
	}
	localizeMembershipPlan(locale, &view.DefaultPlan)
	localizeDailyUsage(locale, view.DailyUsage)
	for index := range view.AssignedAccess {
		view.AssignedAccess[index].EntranceLabel = localizedText(locale, view.AssignedAccess[index].EntranceLabel)
		localizeMembershipPlan(locale, &view.AssignedAccess[index].Plan)
	}
	for index := range view.AvailableAccess {
		view.AvailableAccess[index].EntranceLabel = localizedText(locale, view.AvailableAccess[index].EntranceLabel)
	}
}

func localizeDailyUsage(locale string, days []dailyUsageDayView) {
	if normalizeLocale(locale) != localeSimplifiedChinese {
		return
	}
	for index := range days {
		days[index].DateLabel = days[index].Date.In(proxynode.BillingLocation()).Format("2006 年 1 月 2 日")
	}
}

func localizeProxyNodeDetail(locale string, view *proxyNodeDetailView) {
	localizeMembershipPlan(locale, &view.DefaultPlan)
	view.EntranceFallback = localizedText(locale, view.EntranceFallback)
	for index := range view.UserAccess {
		if view.UserAccess[index].System {
			view.UserAccess[index].Name = localizedText(locale, view.UserAccess[index].Name)
		}
		localizeMembershipPlan(locale, &view.UserAccess[index].Plan)
	}
	if view.Tree != nil {
		localizeProxyTreeHop(locale, view.Tree)
	}
}

func localizeProxyTreeHop(locale string, hop *proxyTreeHopView) {
	hop.IngressProtocol = localizedText(locale, hop.IngressProtocol)
	hop.IngressLabel = localizedText(locale, hop.IngressLabel)
	for index := range hop.Routes {
		localizeProxyTreeRoute(locale, &hop.Routes[index])
	}
	localizeProxyTreeRoute(locale, &hop.Fallback)
	for index := range hop.Branches {
		hop.Branches[index].RuleLabel = localizedText(locale, hop.Branches[index].RuleLabel)
		hop.Branches[index].RuleValues = localizedText(locale, hop.Branches[index].RuleValues)
		if hop.Branches[index].Child != nil {
			localizeProxyTreeHop(locale, hop.Branches[index].Child)
		}
	}
	for index := range hop.Children {
		if hop.Children[index].Child != nil {
			localizeProxyTreeHop(locale, hop.Children[index].Child)
		}
	}
	hop.NewRule.MatchLabel = localizedText(locale, hop.NewRule.MatchLabel)
}

func localizeProxyTreeRoute(locale string, route *proxyTreeRouteView) {
	route.Label = localizedText(locale, route.Label)
	route.TargetLabel = localizedText(locale, route.TargetLabel)
	route.TargetDetail = localizedText(locale, route.TargetDetail)
}
