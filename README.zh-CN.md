<h1 align="center">hy2</h1>

<p align="center">
  <b>一键部署 Hysteria2 + Xray (VLESS&nbsp;Reality)，自带订阅与管理面板。</b>
</p>

<p align="center">
  <a href="#特性"><img alt="status" src="https://img.shields.io/badge/状态-就绪-4ade80?style=flat-square"></a>
  <a href="#一键部署"><img alt="platform" src="https://img.shields.io/badge/平台-Debian%20%7C%20Ubuntu-60a5fa?style=flat-square"></a>
  <img alt="license" src="https://img.shields.io/badge/license-MIT-d1d5db?style=flat-square">
  <a href="README.md"><img alt="lang" src="https://img.shields.io/badge/lang-English-f87171?style=flat-square"></a>
</p>

<p align="center">
  <a href="#特性">特性</a> ·
  <a href="#架构">架构</a> ·
  <a href="#一键部署">部署</a> ·
  <a href="#管理面板">面板</a> ·
  <a href="#配置">配置</a> ·
  <a href="#安全说明">安全</a>
</p>

---

## 特性

- ⚡  **Hysteria2** 监听 `:443/udp`，启用 Salamander 混淆 + UDP 端口跳跃 `20000-40000/udp`。
- 🛡️ **Xray VLESS + Reality** 主端口 `:443/tcp`，备用端口 `:8443/tcp`，伪装成 `www.bing.com`。
- 🎛️ **内置管理面板** —— 浏览器里创建用户、查看实时流量、维护订阅模板和路由规则；侧边栏布局，深色主题，移动端自适应。
- 📊 **每用户配额 + 设备数限制** —— 1 分钟周期任务拉取 hysteria + xray 流量统计，超限自动踢人，每月 21 号重置。
- 🔗 **每用户独立订阅 URL**，按请求渲染 Clash YAML，自动注入对应密码与 UUID。
- 🚀 **一键部署** —— 填好 `.env`，跑 `./deploy.sh`，一分钟内完成。

## 架构

```
        ┌──────────────────────────────────────────────┐
        │  客户端（Clash / sing-box / mihomo）          │
        └───────────────────┬──────────────────────────┘
                            │ 订阅 → http://host/sub/<user>?token=…
                            ▼
        ┌──────────────────────────────────────────────┐
        │  nginx :80   →   subscription_service.py     │
        │                  127.0.0.1:8081              │
        └───────┬────────────────┬─────────────────────┘
                │ /admin         │ /sub/<user>
                ▼                ▼ （渲染 template.yaml）
        ┌──────────────┐    ┌──────────────────────────┐
        │   面板 UI    │    │  users.json + usage.json │
        └──────────────┘    └──────────────────────────┘

                  数据面
        ┌──────────────────────────────────────────────┐
        │  hysteria2 :443/udp  +  端口跳跃 20000-40000  │
        │  xray vless+reality  :443/tcp 与 :8443/tcp   │
        └──────────────────────────────────────────────┘
```

## 一键部署

```bash
git clone https://github.com/lhzyyds666/hy2.git
cd hy2
cp .env.example .env
$EDITOR .env             # 按行内提示填好每一项
sudo ./deploy.sh
```

`deploy.sh` 做的事：

1. 安装官方 `hysteria` 与 `xray` 二进制。
2. 用 `.env` 的值渲染所有配置模板。
3. 文件分发到 `/root/hysteria/`、`/usr/local/etc/xray/`、`/etc/systemd/system/`。
4. 不存在则生成 Hysteria 用的自签名 TLS 证书。
5. `systemctl daemon-reload`，启用并启动所有服务，安装 nginx 反向代理。

### `.env` 必填项

| 变量 | 生成方式 |
|---|---|
| `HY_SERVER_HOST` | 你的 VPS 公网 IP 或域名 |
| `HY_API_SECRET` | `openssl rand -hex 24` |
| `HY_OBFS_PASSWORD` | `openssl rand -base64 24 \| tr -d '/+='` |
| `XRAY_REALITY_PRIVATE_KEY` / `_PUBLIC_KEY` | `xray x25519` |
| `XRAY_REALITY_SHORT_ID` | `openssl rand -hex 8` |
| `XRAY_CLIENT_UUID` | `xray uuid`（或 `uuidgen`） |

## 管理面板

部署完成后：

- **管理后台** —— `http://<server>/admin` —— 首次访问会让你设置管理员密码（哈希后存到 `subscription_meta.json`）。
- **创建用户** —— 在面板里点一下，立即得到订阅链接 `http://<host>/sub/<name>?token=<token>`。
- **用户面板** —— `http://<server>/panel/<user>?token=<token>` —— 单用户的流量与设备统计。
- **模板配置** —— 在线编辑全局 Clash YAML 模板（JSON 视图，带语法校验、格式化、折叠/展开）。
- **路由规则** —— 增删改 proxy/direct/reject 规则，与模板实时同步。
- **清零日志** —— 每一次流量清零的完整审计记录。

面板每 5 秒轮询 `/admin/usage.json` 拉取最新数据，标签页隐藏时自动暂停，使用内存行索引避免每帧重查 DOM。

## 配置

### 端口分布

| 端口 | 服务 |
|---|---|
| `80/tcp` | nginx → 反向代理到 `127.0.0.1:8081`（面板 + 订阅） |
| `443/tcp` | Xray —— VLESS + Reality |
| `443/udp` | Hysteria2 |
| `8443/tcp` | Xray —— VLESS + Reality（备用） |
| `20000-40000/udp` | iptables REDIRECT → `443/udp`（端口跳跃） |

### 不进 git 的文件（已在 `.gitignore`）

这些是单机密钥或运行时状态，**绝不提交**：

- `.env` —— 真实密钥
- `server.crt`、`server.key` —— TLS 证书（`deploy.sh` 自动生成）
- `users.json` —— 用户名册（含密码哈希与订阅 token）
- `subscription_meta.json` —— 管理员密码哈希
- `state/` —— 流量计数、在线快照、清零日志

## 安全说明

- 订阅服务**只**绑定 `127.0.0.1:8081`，对外暴露的是 nginx `:80`。
- 所有模板文件用 `__PLACEHOLDER__` 占位，**真实密钥只存在于 `.env` 和 `/root/hysteria/` 下渲染后的文件**，两者都已 gitignore。
- Hysteria 管理 API 仅监听本地，由 `HY_API_SECRET` 鉴权——把它当 SSH key 看待。
- 管理员认证使用 PBKDF2-SHA256（20 万轮 + per-secret 盐），会话用 HttpOnly + `SameSite=Lax` cookie。
- 每用户的 `sub_token` 是 24 字节 URL-safe 随机串；轮换 token 即可让泄露的订阅链接立即失效，且不影响用户本身。
- 暴露到公网前请配真实 TLS 证书（例如 `certbot --nginx`）——内置的自签证书只用于 Hysteria 端点。

## 项目结构

```
.
├── deploy.sh                       # 一键安装脚本
├── .env.example                    # 密钥模板（复制为 .env）
├── hysteria/
│   ├── config.yaml.tpl             # hysteria2 服务端配置
│   ├── auth_backend.py             # auth-by-command 认证桥
│   ├── subscription_service.py     # 管理面板 + /sub 渲染
│   ├── traffic_limiter.py          # 1 分钟任务：流量统计 + 自动踢人
│   └── clash-default.yaml.tpl      # 订阅模板
├── xray/config.json.tpl            # vless+reality 配置
├── nginx/hysteria-panel.conf       # :80 反向代理
├── scripts/hysteria-porthop.sh     # iptables 端口跳跃脚本
└── systemd/                        # 各服务 unit 文件
```

## 许可

MIT —— 详见 `LICENSE`，若无文件则默认 MIT。

---

<p align="center"><sub>English docs → <a href="README.md">README.md</a></sub></p>
