# NucleAgent clients

NucleAgent 的 Windows 与 Android 薄客户端。两个 WebView 直接访问 **https://nucleagent.whitestone.top**，复用线上主壳、登录页面及 iframe 子应用，不包含业务逻辑或本地前端资产。移动浏览器直接访问同一地址即可使用 H5。

## 目录与配置

- `shared/client.json`：品牌、应用 ID、远程 URL、可信域名及预留深度链接 scheme。`nucleagent` scheme 当前仅为共享配置，尚未注册系统协议处理器。
- `desktop/src-tauri`：Tauri 2。窗口默认为 1280×800，可缩放；构建脚本检查共享 URL、品牌和应用 ID 与 Tauri 配置一致。
- `mobile`：Capacitor 6.2.2 与 Android API 34 原生工程。配置直接读取共享 JSON。

远程站点更新无需重新发布客户端。客户端必须联网，离线时没有本地应用副本。账号密码由线上登录页处理；原生代码不读取或存储密码。WebView 会保留正常的登录会话数据。

## 导航与原生权限

PC 仅在窗口内放行 HTTPS 的 `whitestone.top` 及其真实子域名，端口限 443，不接受 URL 用户信息。外部 HTTP(S)、邮件及电话链接交给系统处理；其余协议拦截。新窗口请求采用相同检查。没有注册 IPC 命令、插件或远程 capability。

Tauri 配置包含 CSP，但 **Tauri 的静态资产 CSP 不会替远程 HTTP 响应添加 CSP**；线上主壳的响应策略仍由服务器负责。导航守卫与 IPC 权限隔离不依赖该 CSP。参见 [Tauri 配置](https://v2.tauri.app/reference/config/) 和 [WebView 导航 API](https://docs.rs/tauri/latest/tauri/webview/struct.WebviewWindowBuilder.html)。

Android 禁止明文流量与混合内容，显式接受 WebView 第三方 Cookie，以支持 iframe 认证。硬件/手势返回优先返回 WebView 历史，无历史时弹出退出确认。状态栏与启动屏在原生层设置，无需修改主壳。系统备份关闭；生产 WebView 调试关闭。

## Android 构建

需要 Node.js、JDK 17，以及 `~/android-sdk` 下的 Android command-line tools、platform-tools、`platforms;android-34`、`build-tools;34.0.0`。无需系统 Gradle。SDK 安装来源为 [Android 官方工具](https://developer.android.com/studio#command-tools)。

```bash
npm ci
bash scripts/build-android.sh
```

产物：`mobile/android/app/build/outputs/apk/debug/app-debug.apk`。

脚本将 Gradle 下载、缓存、临时文件、Android 用户状态及默认 debug keystore 收敛到 SDK 目录。`mobile/android/local.properties` 仅为本机生成文件，不入库。Debug APK 使用自动生成的 debug keystore，仅用于体验和验收，不是正式发布签名。

Capacitor 在 `server.url` 模式下允许 `www` 不存在；sync 的“Cannot copy web assets”提示表示无本地 Web 资产，不影响远程加载。需先创建 `mobile/android/app/src/main/assets`（脚本已处理）。[Capacitor 6 配置文档](https://capacitorjs.com/docs/v6/config)。

## Windows 构建

需要已安装的 Rust MSVC 工具链、Visual Studio C++ 构建工具、Tauri 2 CLI、WebView2。将仓库放到 Windows 本地目录，保留 `shared` 和 `desktop` 的相对路径：

```powershell
cd desktop
cargo tauri build
```

安装器目录：`desktop/src-tauri/target/release/bundle/msi/` 与 `desktop/src-tauri/target/release/bundle/nsis/`。签名证书通过发布环境提供，不能提交私钥或密码。无代码签名的体验包可能出现 Windows 的发布者提示。

## 检查与发布

```bash
npm run check
cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
```

在 Windows 原生 Rust 环境执行 `cargo test --manifest-path desktop/src-tauri/Cargo.toml` 验证导航白名单边界。发布前还须逐端实测：安装并打开登录页、builtin 登录、core iframe 操作与刷新不回弹、PC 外链转系统浏览器和窗口缩放、Android 返回历史及退出确认。普通浏览器测试不能替代原生 WebView 验收。

更新版本、执行检查与原生验收后，使用作者 `Biwei.Lai <biwei.lai@qq.com>` 提交至 `main`，创建版本标签及 GitHub Release，上传 MSI、NSIS EXE、APK 与 SHA256 清单。正式 Android 发布应使用独立受控签名，不沿用 debug keystore。

iOS 不在当前交付范围。
