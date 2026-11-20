# Gotify Android · HTTPS RR / IP4P / 动态端口 Fork

本仓库是 [gotify/android](https://github.com/gotify/android) 的 fork，基于上游 `2.10.1`
（`211682f`）。在保留原有 Gotify 客户端功能的前提下，增加了对 **RFC 9460 HTTPS RR**、
**NATMap IP4P** 和 **动态端口** 的支持，主要用于 Gotify 服务端位于 NAT 之后、
公网入口地址/端口由 DDNS 或 NATMap 动态发布的场景。

- Fork 仓库：<https://github.com/zhoufla/gotify-android-httpsrr>
- 关键提交：`c3eaf36` — `feat: support HTTPS RR, IP4P and dynamic ports`
- License：MIT（与上游一致）

## 功能概览

| 能力 | 说明 |
| --- | --- |
| HTTPS RR 查询 | 对 `https://` 地址查询 `HTTPS`（type 65）记录，解析优先级、目标、端口、`ipv4hint`/`ipv6hint` 与 TTL |
| AliasMode | 支持 `priority=0` 的别名记录，最多跟随一层；并保留 `_端口._https.` 服务前缀 |
| IP4P（NATMap） | 从 `AAAA` 中解码 `2001::<port>:<ipv4-hi>:<ipv4-lo>`，得到真实 IPv4 地址和端口 |
| 动态端口 | 在 URL 末尾加 `:0` 作为标记，运行时用解析到的端口改写连接目标，同时保留原始 `Host` 头 |
| A/AAAA 回退 | HTTPS RR 不存在、格式错误或查询失败时，自动回退到普通 A/AAAA 解析 |
| 系统解析兜底 | 自实现 DNS 查询无结果时，最后使用系统 `InetAddress` 解析 |
| TTL 缓存 | 正缓存按记录 TTL（上限 1 小时），负缓存 30 秒，最多 64 条 LRU |
| 网络切换 | 网络可用时清空 DNS 缓存、连接池并重建 WebSocket；失败时按主机失效缓存 |
| 全链路覆盖 | REST API、WebSocket 消息流、Coil 图片加载、相对 URL 拼接、登录校验均使用同一套 URL/解析逻辑 |
| CI 产物 | GitHub Actions 上传 debug APK；打 `v*` 标签时构建签名 release APK 并发布 Release |

## 使用方法

Gotify 服务地址仍然填写在 App 的登录页，按需选择下面几种形式：

```text
# 1. 普通 HTTPS：自动查询 HTTPS RR
https://gotify.example.com

# 2. 显式非默认端口：查询 _8443._https.gotify.example.com
#    HTTPS RR 中的端口会被忽略，仍使用 8443；hints/TTL 仍然生效
https://gotify.example.com:8443

# 3. NATMap 动态端口（HTTPS）：:0 是标记，不是真实端口
#    先去 :0 后按 443 建连，端口优先级：
#    HTTPS RR 的 port > AAAA 中 IP4P 的 port > 443
https://gotify.example.com:0

# 4. NATMap 动态端口（HTTP）
http://gotify.example.com:0
```

### `:0` 标记规则

- 只在 URL 的 **authority 末尾** 生效：`https://host:0`、`https://host:0/path` 会被识别；
  `https://host/path:0`、`https://host/?x=:0` 中的 `:0` 不会被误删。
- 支持带用户信息的 URL 和带方括号的 IPv6 字面量（`https://[::1]:0`）。
- 去标记后使用默认端口（HTTPS 443 / HTTP 80）参与 URL 解析，真实端口由 DNS 结果在运行时注入。
- 解析到端口后由 OkHttp 拦截器改写 URL 的端口，并把 `Host` 头恢复为原始域名（不带端口），
  因此 TLS SNI 与证书校验仍然针对原域名，不会被动态端口破坏。

### 解析优先级

1. `https://` 地址查询 HTTPS RR：
   - AliasMode（`priority=0`）→ 跟随目标名，最多一层；
   - ServiceMode → 取 `priority > 0` 中最小的一条，读取 `port`、`ipv4hint`、`ipv6hint`、TTL。
2. 若 HTTPS RR 不可用，查询 A/AAAA。
3. 仅当 URL 带 `:0` 时解码 IP4P；启用 IP4P 时优先使用解码出的 IPv4，避免把不可达的
   普通 A/AAAA 混入结果。未带 `:0` 时，看起来像 IP4P 的 AAAA 会被过滤。
4. 自实现查询仍无结果时，调用系统解析器兜底。

### 缓存与刷新

- 正缓存 key = `(host, ResolveOptions)`，TTL 取相关记录的最小值，最大 3600 秒；0 TTL 不缓存。
- 负缓存 30 秒，避免失败时反复查询。
- 最多 64 条，按访问顺序做 LRU 淘汰；同一 key 的并发解析会串行化。
- WebSocket 网络恢复：清空 DNS 缓存、`connectionPool.evictAll()`，必要时重建连接。
- WebSocket 失败：只失效当前主机缓存并清空连接池，随后走原有指数退避重连。

## 实现位置

| 文件 | 作用 |
| --- | --- |
| `app/src/main/kotlin/com/github/gotify/dns/ConnectionUrl.kt` | URL 校验、`:0` 标记剥离、生成解析选项与 Retrofit base URL |
| `app/src/main/kotlin/com/github/gotify/dns/DnsWire.kt` | 最小 DNS 报文编解码：A、AAAA、HTTPS（RFC 9460）、SvcParam、压缩指针与边界校验 |
| `app/src/main/kotlin/com/github/gotify/dns/HostResolver.kt` | 解析编排、TTL/负缓存、锁、AliasMode、A/AAAA 回退、系统兜底 |
| `app/src/main/kotlin/com/github/gotify/dns/Ip4p.kt` | NATMap IP4P 解码（`2001::<port16>:<ipv4>`） |
| `app/src/main/kotlin/com/github/gotify/dns/AndroidDnsTransport.kt` | Android 10+ 使用 `DnsResolver.rawQuery` 查询任意类型 |
| `app/src/main/kotlin/com/github/gotify/dns/HostResolverProvider.kt` | 在 `Application.onCreate` 初始化全局解析器 |
| `app/src/main/kotlin/com/github/gotify/dns/OkHttpHostDns.kt` | OkHttp `Dns` 实现 + 动态端口拦截器 + `enableHttpsDns()` 扩展 |
| `app/src/main/kotlin/com/github/gotify/api/ClientFactory.kt` | REST 客户端接入 HTTPS RR / 动态端口 |
| `app/src/main/kotlin/com/github/gotify/service/WebSocketConnection.kt` | WebSocket 接入、网络切换与失败时缓存失效 |
| `app/src/main/kotlin/com/github/gotify/CoilInstance.kt` | 图片加载复用同一套 DNS；缓存 key 增加 base URL |
| `app/src/main/kotlin/com/github/gotify/Utils.kt` | 相对图片 URL 拼接前先归一化掉 `:0` |
| `app/src/main/kotlin/com/github/gotify/login/LoginActivity.kt` | 登录页使用 `ConnectionUrl` 校验地址 |

DNS 查询只对当前配置的 Gotify 主机生效；图片 CDN 等其他主机继续使用系统 DNS。

## 兼容性与限制

- `minSdk 26`（Android 8.0）。HTTPS RR 依赖 Android 10（API 29）的
  `DnsResolver.rawQuery`；Android 8/9 上 HTTPS RR 不可用，会自动回退到系统解析，
  IP4P 仍可通过 `InetAddress.getAllByName` 拿到 AAAA 后解码。
- 使用系统 DNS 作为传输，不包含 DoH/DoT，也不引入第三方 DNS 库。
- IP4P 采用 NATMap 的编码格式，不是通用 NAT64；`2001::/32` 之外、端口为 0、
  或 IPv4 首字节为 0 的记录会被拒绝。
- A/AAAA 查询依赖递归解析器返回的应答记录；不会自行展开额外的 CNAME 链
  （HTTPS 的 AliasMode 会显式跟随）。
- 动态端口目前只对**当前配置的 Gotify 源**生效；跳转到其他主机的绝对 URL 不会改写。

## 构建

### 本地构建

要求：

- JDK 17
- Android SDK Platform 36（Build-Tools 35.0.0；缺失时 AGP 会自动安装）

```bash
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME=/path/to/android-sdk
./gradlew build
```

产物：

- Debug APK：`app/build/outputs/apk/debug/app-debug.apk`
- `build` 同时会执行单元测试与 lint。

只跑新增的 DNS 单元测试：

```bash
./gradlew testDebugUnitTest --tests 'com.github.gotify.dns.*'
```

签名 Release（本地）：

```bash
export RELEASE_STORE_FILE=/path/to/keystore.jks
export RELEASE_STORE_PASSWORD=...
export RELEASE_KEY_ALIAS=...
export RELEASE_KEY_PASSWORD=...
./gradlew -Psign build
```

### 云端构建（GitHub Actions）

工作流：`.github/workflows/main.yml`

- 触发：`push`、`pull_request`、`workflow_dispatch`
- 非 `v*` 标签：执行 `./gradlew build --stacktrace`，上传 artifact `gotify-debug`
- `v*` 标签：使用 Secrets 中的签名信息执行 `./gradlew -Psign build`，复制为
  `Gotify.apk`，上传 artifact `gotify-release` 并创建 GitHub Release
- 启用了 Gradle 缓存、并发取消（同一 ref 的新构建会取消旧构建）和 30 分钟超时

Release 构建需要配置的 Secrets：

| Secret | 用途 |
| --- | --- |
| `RELEASE_KEY` | base64 编码的 keystore |
| `STOREPASS` | keystore 密码 |
| `KEYPASS` | key 密码 |

## 测试

`app/src/test/kotlin/com/github/gotify/dns/` 下新增 30 个 JVM 单元测试：

- `ConnectionUrlTest`（8）：`:0` 剥离、IPv6、路径/查询中的 `:0`、非法 URL、HTTPS RR 查询名
- `DnsWireTest`（6）：HTTPS ServiceMode/AliasMode、压缩名称、SvcParam 顺序/截断、A/AAAA
- `HostResolverTest`（12）：hints/端口/TTL、缓存、AliasMode、IP4P 开关、回退、负缓存
- `Ip4pTest`（4）：正常解码、真实 IPv6、零端口、零 IPv4

## 验证结果

### 本地构建（2026-11-21）

- 环境：Temurin JDK 17.0.21.1、Android SDK Platform 36 / Build-Tools 35.0.0、
  Gradle 8.14.2（wrapper）、AGP 8.11.0、Kotlin 2.2.0
- 命令：

  ```bash
  export JAVA_HOME=/path/to/jdk17
  export ANDROID_HOME=/path/to/android-sdk-36
  export GRADLE_USER_HOME=/path/to/gradle-home
  ./gradlew --no-daemon build
  ```

- 结果：`BUILD SUCCESSFUL in 2m 27s`，152 个任务（125 个执行、27 个 up-to-date）
- 单元测试：debug / release / development 三个变体各运行 30 个用例，全部通过，
  0 失败、0 错误、0 跳过
- lint：`lintDebug` 通过，没有阻断构建的问题
- 产物：

| 变体 | 路径 | 大小 |
| --- | --- | --- |
| debug | `app/build/outputs/apk/debug/app-debug.apk` | 8.1 MB（8,493,559 字节） |
| development | `app/build/outputs/apk/development/app-development.apk` | 8.1 MB（8,491,855 字节） |
| release | `app/build/outputs/apk/release/app-release.apk` | 6.5 MB（6,782,675 字节） |

debug APK 的 SHA-256：

```text
9df528075eda30d1f60c233061056b2c551da5e786e8e14073678be0c4a0677f
```

### GitHub Actions 云端构建

- 验证提交：`c3eaf36`（临时分支 `ci-verify`）
- Run：<https://github.com/zhoufla/gotify-android-httpsrr/actions/runs/44778708097>
- Job `Check` 完成，所有步骤均为 success：checkout、setup-java (17)、Gradle 缓存、
  `./gradlew build --stacktrace`、上传 `gotify-debug`
- 产物：artifact `gotify-debug`，7.02 MB（`app/build/outputs/apk/debug/app-debug.apk`）
- 非 `v*` 标签，签名 Release / GitHub Release 步骤按预期跳过

本地与云端均使用同一个 Gradle wrapper 和同一套 30 个 DNS 单元测试；云端产物
与本地 `app-debug.apk` 来自同一提交。
