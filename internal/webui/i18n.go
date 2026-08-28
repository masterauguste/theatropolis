package webui

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	localeEnglish           = "en"
	localeSimplifiedChinese = "zh-CN"
	languageCookieName      = "theatropolis_language"
	languageCookieLifetime  = 365 * 24 * time.Hour
)

var simplifiedChinese = map[string]string{
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
	"Use a valid server ID: letters, numbers, dots, underscores, and hyphens only.":               "请输入有效的服务器 ID，只能使用字母、数字、点、下划线和连字符。",
	"That server ID is already enrolled.":                                                         "该服务器 ID 已注册。",
	"That server already has a valid enrollment command. Use it or wait for it to expire.":        "该服务器已有有效的注册命令，请使用现有命令或等待其过期。",
	"The current Agent remains authorized until the replacement uses its one-time token. At that moment the old connection is closed and this master immediately deploys the retained profile to the replacement.": "在替换服务器使用一次性令牌前，当前代理端仍保持授权。令牌被使用后，旧连接会关闭，主控端会立即向替换服务器部署保留的配置。",
	"This immediately closes an active control session and invalidates enrollment credentials. It does not uninstall the remote agent or stop its current sing-box process.":                                       "此操作会立即关闭活动控制会话并使注册凭据失效，但不会卸载远程代理端，也不会停止当前 sing-box 进程。",
	"I understand that this agent will need a new enrollment credential to reconnect.":                                                                                                                             "我了解此代理端需要新的注册凭据才能重新连接。",
	"This command contains a credential that expires at":                              "此命令包含一项凭据，到期时间为",
	"and becomes unusable after enrollment. The master persists only its hash.":       "，并会在完成注册后失效。主控端只保存其哈希值。",
	"This master still uses its existing access key. Rerun the master installer with": "此主控端仍在使用现有访问密钥。准备迁移时，请使用以下参数重新运行主控端安装程序：",
	"when you are ready to migrate it.":                                               "。",
	"No matching options":                                                             "没有匹配的选项",
	"Select an option":                                                                "请选择",
	"Select a Geosite rule set":                                                       "请选择 Geosite 规则集",
	"Subscription Addresses":                                                          "订阅连接地址",
	"Configuration Subscription":                                                      "配置订阅",
	"Address Families":                                                                "地址类型",
	"IPv4 and IPv6":                                                                   "IPv4 和 IPv6",
	"IPv4 Only":                                                                       "仅 IPv4",
	"IPv6 Only":                                                                       "仅 IPv6",
	"Rule Set":                                                                        "规则集",
	"Loading Geosite options…":                                                        "正在加载 Geosite 规则集…",
	"Geosite catalog unavailable.":                                                    "无法加载 Geosite 规则集目录。",
	"Close entrance settings":                                                         "关闭入口设置",
	"Delete Proxy Node?":                                                              "删除此代理节点？",
	"Entrance settings for":                                                           "入口设置：",
	"Listener and protocol":                                                           "监听器与协议",
	"Saved pool destination":                                                          "已保存的出口池目标",
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

	"Access maintenance": "权限管理", "Access roster": "已授权用户", "Accounting errors": "流量统计错误",
	"Action": "操作", "Actions": "操作", "Active": "正常", "Add a server": "添加服务器",
	"Add another server": "继续添加服务器", "Add compensation": "添加补偿", "Add Node": "添加节点",
	"Add or replace": "添加或替换", "Add rule": "添加规则", "Add server": "添加服务器", "Add user": "添加用户",
	"Add your first server": "添加第一台服务器", "Address family": "地址族", "Address overrides": "地址覆盖",
	"Affected subscriptions": "受影响的订阅", "Agent": "服务器", "Agent diagnostic": "Agent 诊断",
	"Agent software": "Agent 程序", "Agent version": "Agent 版本", "Applying topology change…": "正在应用拓扑…",
	"Assign a Node": "添加节点", "Assign role": "确认添加", "Authenticated sessions": "登录会话",
	"Authenticated user": "认证用户", "Automatic": "自动", "Awaiting installation": "等待安装",
	"Bandwidth": "带宽", "Branch": "分支", "Branch settings": "分支设置", "Calendar months": "自然月",
	"Cancel": "取消", "Certificate identity": "证书标识", "Certificate mode": "证书模式", "Certificate path": "证书路径",
	"Change sing-box version": "更改 sing-box 版本", "Check again": "重新检查", "Checking for updates…": "正在检查更新…",
	"Child exit": "子节点默认出口", "Choose a Node": "选择节点", "Close": "关闭", "Command lifetime": "命令有效期",
	"Compensate": "补偿", "Compensation": "补偿", "Conditional": "条件", "Configure manually": "手动配置",
	"Configured sets": "已配置规则集", "Confirm": "确认", "Connection": "连接", "Connection target": "连接目标",
	"Control connection": "控制连接", "Copy": "复制", "Copy command": "复制命令", "Create Branch": "创建分支",
	"Create Proxy Node": "创建代理节点", "Create replacement command": "创建替换命令", "Create subscription": "创建订阅",
	"Create user": "创建用户", "Create your first Proxy Node": "创建第一个代理节点", "Credential": "凭据",
	"Current version": "当前版本", "Custom Rule Set": "自定义规则集", "Custom Rule Sets": "自定义规则集",
	"Days": "天", "Default route": "默认路由", "Default TLS address": "默认 TLS 地址", "Delete": "删除",
	"Delete and apply": "删除并应用", "Delete Branch": "删除分支", "Delete Proxy Node": "删除代理节点",
	"Delete rule": "删除规则", "Delete user": "删除用户", "Destination": "目标", "Destination port": "目标端口",
	"Details": "详情", "Direct": "直连", "Disabled": "已禁用", "Disconnect and invalidate this identity": "断开连接并使此身份失效", "offline": "离线",
	"Domain keyword": "域名关键词", "Domain or certificate identity": "域名或证书标识", "Domain regex": "域名正则",
	"Domain suffix": "域名后缀", "Domain": "域名", "Done": "完成", "Download Mbps": "下载 Mbps",
	"Downstream": "下游", "Duration": "时长", "Edit Relay": "编辑中继", "Edit rule": "编辑规则", "Edit": "编辑",
	"Enabled (smux)": "已启用（smux）", "End user": "用户", "End users": "用户列表", "Enrollment": "注册",
	"Enrollment lifetime": "注册有效期", "Enrollment ready": "注册已就绪", "Entrance Agent": "入口代理端",
	"Entrance configuration": "入口设置", "Entrance exit": "入口默认出口", "Entrance protocol": "入口协议", "Entrance server": "入口服务器", "Entrance": "入口",
	"Entry name": "条目名称", "Existing files": "现有文件", "Exit": "出口", "Expire after a duration": "按时长过期",
	"Extend by": "延长", "Extend subscription": "延长订阅", "Failure": "失败", "Fallback": "回退",
	"Fleet maintenance": "批量维护", "Fleet outbound pool": "全局出口池", "Fleet": "服务器组", "Global identities": "用户管理",
	"Global settings": "系统设置", "Global user": "用户", "Grant access": "添加权限", "Hop": "节点",
	"Hops": "节点", "Hours": "小时", "HTTPS SRS URL": "HTTPS SRS URL", "Import credentials": "导入凭据",
	"Inactive": "未启用", "Inbound": "入站", "Infrastructure": "服务器管理", "Install selected sing-box version": "安装所选 sing-box 版本",
	"IP addresses": "IP 地址", "Isolation": "隔离", "Known to this master": "已被主控端识别", "Last update": "最近更新",
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
	"No Proxy Nodes yet": "尚无代理节点", "No rules": "尚无规则", "No servers enrolled yet": "尚无已注册服务器",
	"No subscription link": "无订阅链接", "No users assigned": "尚未分配用户", "No users available.": "没有可用用户。",
	"No users have been created.": "尚未创建用户。", "Node role": "节点访问权限", "Node roles": "节点访问权限", "Nodes": "节点",
	"Obfuscation": "混淆", "Offline or expired": "离线或已过期", "Online": "在线", "Open Proxy Node": "打开代理节点",
	"Open Proxy Nodes": "打开代理节点", "Open user": "打开用户", "Operations": "操作", "Operator access": "管理员访问",
	"Optional": "可选", "Outage ended (UTC+8)": "故障结束时间（UTC+8）", "Outage started (UTC+8)": "故障开始时间（UTC+8）",
	"Outbound JSON": "出口 JSON", "Outbound pool": "出口池", "Password": "密码", "Pending": "待处理",
	"Physical listener": "物理监听器", "Port": "端口", "Port 80 remains reserved for ACME.": "端口 80 保留给 ACME。",
	"Private branch credential and auth_user": "分支专用凭据和 auth_user", "Private-key path": "私钥路径", "Process name": "进程名称",
	"Protocol": "协议", "Proxy Node name": "代理节点名称", "Proxy Node readiness": "代理节点状态", "Proxy Node roles": "代理节点访问权限",
	"Proxy Node settings": "代理节点设置", "Proxy Nodes": "代理节点", "Proxy Node": "代理节点", "Proxy runtime": "代理运行时",
	"Proxy URI or outbound JSON": "代理 URI 或出口 JSON", "Proxy": "代理", "Quota (GiB)": "配额（GiB）", "Ready": "就绪",
	"Reject": "拒绝", "Relay address family": "中继地址族", "Relay Branch": "中继分支", "Relay map": "路由拓扑", "Relay": "中继",
	"Remark": "备注", "Rename or delete this Proxy Node": "重命名或删除此代理节点", "Rename Proxy Node": "编辑节点名称", "Rename": "保存名称",
	"Replace Agent": "替换代理端", "Replace Destination": "替换目标", "Reported running": "报告为运行中",
	"Reset ": "重置 ", " credential?": " 的凭据？", "Reset all credentials": "重置全部凭据", "Reset all credentials?": "重置全部凭据？", "Reset credential": "重置凭据",
	"Reset link and credentials": "重置链接和凭据", "Reset subscription link": "重置订阅链接", "Reset subscription link?": "重置订阅链接？",
	"Reset traffic": "重置流量", "Resets after": "下次重置", "Return to servers": "返回服务器", "Return to settings": "返回设置",
	"Revision": "版本", "Revoke access": "撤销权限", "Revoke link": "撤销链接", "Role allowance": "配额与有效期",
	"Route ALL": "路由全部流量", "Routes to": "路由至", "Routing mode": "路由模式", "Routing resources": "路由资源",
	"Routing Rule": "路由规则", "Routing trees": "路由拓扑", "Route": "路由", "Rule Sets": "规则集", "Rules": "规则", "Rule": "规则",
	"Running version": "运行版本", "Save address overrides": "保存地址覆盖", "Save allowance": "保存额度",
	"Save and apply Rule Set": "保存并应用规则集", "Save Entrance": "保存入口设置", "Save entrance": "保存入口设置", "Save Exit": "保存默认出口", "Save pool entry": "保存池条目",
	"Save Relay": "保存中继", "Save Rule": "保存规则", "Save server settings": "保存服务器设置", "Save": "保存",
	"Search affected users": "搜索受影响的用户", "Search assigned users": "搜索用户", "Search available Proxy Nodes": "搜索可用代理节点",
	"Filter by user name": "按用户名筛选", "Clear affected-user search": "清除受影响用户筛选",
	"Search users": "搜索用户", "Secure enrollment": "安全注册", "Select Agent": "选择服务器", "Select an enrolled Agent": "选择已注册的服务器",
	"Self-signed by Agent": "由代理端自签名", "Server addresses": "服务器地址", "Server and software actions": "服务器与软件操作",
	"Server ID": "服务器 ID", "Server identity": "服务器身份", "Server management": "服务器管理", "Server settings": "服务器设置",
	"Servers": "服务器", "Set a monthly quota": "设置每月配额", "Settings": "设置", "Shown once.": "仅显示一次。",
	"Sign in to continue": "登录以继续", "Sign in": "登录", "Sign out": "退出登录", "Single use": "仅限一次",
	"Skip to content": "跳至内容", "Source port": "源端口", "Status": "状态", "Subscription compensation": "订阅补偿",
	"Subscription expiration": "订阅到期方式", "Subscription link": "订阅链接", "Subscription links": "订阅链接",
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
	"Validating": "正在验证", "Validated": "验证通过", "Deploying": "正在部署", "Applied": "已应用",
	"Runtime failure": "运行失败", "Validation failed": "验证失败", "Activation failed": "激活失败",
	"Agent error": "代理端错误", "Delivery failed": "交付失败", "Quota reached": "已达到配额",
	"Entrance sample collection failed": "入口采样失败", "Master could not persist usage": "主控端无法保存用量",
	"Accounting failure": "流量统计失败", "Release Candidate": "候选版本", "Stable": "稳定版",
	"ALL": "全部", "IP / CIDR": "IP / CIDR", "Source IP/CIDR": "源 IP/CIDR",
	"assigned": "已分配", "available": "可用", "total": "总计", "on port": "端口", "selected": "已选择",
	"Established": "已建立", "Not established": "未建立", "Refresh server status": "刷新服务器状态",
	"Refresh": "刷新", "Fleet summary": "服务器概览", "Close server settings": "关闭服务器设置", "Queuing…": "正在排队…",
	"Scheduling…": "正在安排…", "Pool": "出口池", "recorded": "条记录", "Access and allowances": "用户与配额",
	"Topology change": "拓扑更新", "Left-to-right relay tree": "从左到右的路由拓扑", "Close details": "关闭详情",
	"Relay Hop": "中继节点", "Unmatched Traffic": "未匹配流量", "Yes": "是", "No": "否", "Auto": "自动",
	"Duplicate Branch": "复制分支", "Add Rule": "添加规则", "Rule branch": "规则分支", "Reject branch": "拒绝分支",
	"New Branch from": "新分支，来源", "Reachability depends on runtime DNS or Rule Set data": "可达性取决于运行时 DNS 或规则集数据",
	"Runtime-dependent path": "依赖运行时数据的路径", "Drag to change priority": "拖动以更改优先级", "View": "查看",
	"Move Rule up": "上移规则", "Move Rule down": "下移规则", "Delete branch": "删除分支",
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
			return fmt.Sprintf("%d 个引用", count)
		default:
			return fmt.Sprintf("共 %d 项", count)
		}
	}
	noun := map[string]string{
		"hop": "Hop", "node": "Node", "link": "Link", "user": "user", "exit": "exit",
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

func localeForRequest(request *http.Request) string {
	if cookie, err := request.Cookie(languageCookieName); err == nil {
		if locale := normalizeLocale(cookie.Value); locale == localeSimplifiedChinese || cookie.Value == localeEnglish {
			return locale
		}
	}
	for _, language := range strings.Split(request.Header.Get("Accept-Language"), ",") {
		language = strings.TrimSpace(strings.SplitN(language, ";", 2)[0])
		if strings.HasPrefix(strings.ToLower(language), "zh") {
			return localeSimplifiedChinese
		}
		if strings.HasPrefix(strings.ToLower(language), "en") {
			return localeEnglish
		}
	}
	return localeEnglish
}

func (h *Handler) changeLanguage(response http.ResponseWriter, request *http.Request) {
	requested := request.PathValue("locale")
	locale := normalizeLocale(requested)
	if requested != localeEnglish && requested != localeSimplifiedChinese {
		http.NotFound(response, request)
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name: languageCookieName, Value: locale, Path: "/", MaxAge: int(languageCookieLifetime.Seconds()),
		Expires:  h.currentTime().Add(languageCookieLifetime),
		Secure:   h.publicScheme == "https" && !isLocalDevelopmentHost(h.publicHost),
		SameSite: http.SameSiteLaxMode,
	})
	target := "/servers"
	if _, ok := h.sessionToken(request); !ok {
		target = "/login"
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
	}
	for index := range data.ProxyNodes {
		data.ProxyNodes[index].Entrance = localizedText(locale, data.ProxyNodes[index].Entrance)
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
	view.ResetLabel = localizedText(locale, view.ResetLabel)
	view.ExpirationLabel = localizedText(locale, view.ExpirationLabel)
	view.StatusLabel = localizedText(locale, view.StatusLabel)
}

func localizeEndUserDetail(locale string, view *endUserDetailView) {
	localizeMembershipPlan(locale, &view.DefaultPlan)
	for index := range view.AssignedAccess {
		view.AssignedAccess[index].EntranceLabel = localizedText(locale, view.AssignedAccess[index].EntranceLabel)
		localizeMembershipPlan(locale, &view.AssignedAccess[index].Plan)
	}
	for index := range view.AvailableAccess {
		view.AvailableAccess[index].EntranceLabel = localizedText(locale, view.AvailableAccess[index].EntranceLabel)
	}
}

func localizeProxyNodeDetail(locale string, view *proxyNodeDetailView) {
	localizeMembershipPlan(locale, &view.DefaultPlan)
	view.EntranceFallback = localizedText(locale, view.EntranceFallback)
	for index := range view.UserAccess {
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
