# 1. 基础全局配置
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
unified-delay: true
tcp-concurrent: true

profile:
  store-selected: true
  store-fake-ip: true

# 2. DNS 配置 (fake-ip 模式)
dns:
  enable: true
  ipv6: false
  cache-algorithm: arc
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "localhost"
    - "+.home.arpa"
    - "+.miwifi.com"
    - "+.tplinkwifi.net"
    - "+.tplogin.cn"
    - "+.router.asus.com"
    - "+.push.apple.com"
    - "*.msftconnecttest.com"
    - "*.msftncsi.com"
    - "*.microsoft.com"
    - "*.microsoftonline.com"
    - "*.windows.com"
    - "*.windowsupdate.com"
    - "*.mp.microsoft.com"
    - "*.xboxlive.com"
    - "*.xboxservices.com"
    - "*.gamepass.com"
    - "*.sciencedirect.com"
    - "*.sciencedirectassets.com"
    - "*.els-cdn.com"
    - "*.elsevier.com"
    - "*.elsevier-ae.com"
    - "*.elsevier.io"
    - "*.scopus.com"
    - "*.springer.com"
    - "*.springernature.com"
    - "*.nature.com"
    - "*.wiley.com"
    - "*.tandfonline.com"
    - "*.jstor.org"
    - "*.ieee.org"
    - "*.acs.org"
    - "*.rsc.org"
    - "*.sagepub.com"
    - "*.science.org"
    - "*.cell.com"
    - "*.thelancet.com"
    - "*.bmj.com"
    - "*.oup.com"
    - "*.cambridge.org"
  use-hosts: true

  nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query

  fallback:
    - tls://8.8.8.8
    - tls://1.1.1.1

  direct-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  # DIRECT 流量始终使用国内解析，避免国内 CDN 被分配到境外节点。
  direct-nameserver-follow-policy: false

  nameserver-policy:
    # .cn 域名不参与境外 fallback 竞速，优先拿到本地运营商/CDN 地址。
    '+.cn':
      - 223.5.5.5
      - 119.29.29.29
      - https://doh.pub/dns-query
      - https://dns.alidns.com/dns-query
    '+.github.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.githubusercontent.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.githubassets.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.github.io':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.githubapp.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.github.dev':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.ghcr.io':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.githubcopilot.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.github-cloud.s3.amazonaws.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.openai.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.chatgpt.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.oaistatic.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.oaiusercontent.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.openaiusercontent.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.ai.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.auth0.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.arkoselabs.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.statsigapi.net':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.featuregates.org':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.google.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.gmail.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.googlemail.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.googleapis.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.gstatic.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.googleusercontent.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.ggpht.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.gvt1.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.googlevideo.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.youtube.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.ytimg.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.youtu.be':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.google.com.hk':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.google.com.tw':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.googleadservices.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.googlesyndication.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.google-analytics.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.googletagmanager.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.googletagservices.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.doubleclick.net':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.recaptcha.net':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.gvt2.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.gvt3.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.appspot.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.firebaseapp.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.firebaseio.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.blogger.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.blogspot.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.telegram.org':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.telegram.me':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.telegram.dog':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.t.me':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.telegra.ph':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.tdesktop.com':
      - https://1.1.1.1/dns-query
      - https://8.8.8.8/dns-query
    '+.steamcontent.com':
      - 223.5.5.5
      - 119.29.29.29
    '+.steamserver.net':
      - 223.5.5.5
      - 119.29.29.29
    '+.steampowered.com':
      - 223.5.5.5
      - 119.29.29.29

  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32

# 3. 节点 (password 和 uuid 由 subscription_service.py 在下发订阅时按用户注入)
proxies:
  - name: 🇺🇸 美国 UDP (端口跳跃)
    type: hysteria2
    server: __HY_SERVER_HOST__
    port: 443
    ports: 20000-40000
    password: PLACEHOLDER
    obfs: salamander
    obfs-password: __HY_OBFS_PASSWORD__
    sni: hysteria2
    skip-cert-verify: true
    udp: true
    up: 100 Mbps
    down: 400 Mbps
    transport:
      type: udp
      hopInterval: 30s

  - name: 🇺🇸 美国 UDP TUIC
    type: tuic
    server: __HY_SERVER_HOST__
    port: 9443
    uuid: 00000000-0000-0000-0000-000000000000
    password: TUIC_PASSWORD_PLACEHOLDER
    alpn:
      - h3
    disable-sni: true
    reduce-rtt: true
    request-timeout: 8000
    udp-relay-mode: native
    congestion-controller: bbr
    skip-cert-verify: true
    udp: true

  - name: 🇺🇸 美国 TCP (VLESS+REALITY)
    type: vless
    server: __HY_SERVER_HOST__
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    network: tcp
    tls: true
    udp: false
    flow: xtls-rprx-vision
    reality-opts:
      public-key: __XRAY_REALITY_PUBLIC_KEY__
      short-id: __XRAY_REALITY_SHORT_ID__
    servername: www.bing.com
    client-fingerprint: chrome
    skip-cert-verify: true

  - name: 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
    type: vless
    server: __HY_SERVER_HOST__
    port: 8443
    uuid: 00000000-0000-0000-0000-000000000000
    network: tcp
    tls: true
    udp: false
    flow: xtls-rprx-vision
    reality-opts:
      public-key: __XRAY_REALITY_PUBLIC_KEY__
      short-id: __XRAY_REALITY_SHORT_ID__
    servername: www.bing.com
    client-fingerprint: chrome
    skip-cert-verify: true

# 4. 策略组
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ⚡ GitHub 加速
      - 🤖 GPT 优化
      - 🌐 Google 优化
      - 📚 学术访问
      - ✈️ Telegram 优化
      - 🔄 自动选择
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 UDP TUIC
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
      - DIRECT

  - name: 🔄 自动选择
    type: fallback
    proxies:
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 UDP TUIC
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
    url: https://www.gstatic.com/generate_204
    interval: 30
    timeout: 5000

  - name: ⚡ GitHub 加速
    type: url-test
    proxies:
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 UDP TUIC
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
    url: https://github.com/favicon.ico
    interval: 120
    timeout: 5000
    tolerance: 100

  - name: 🤖 GPT 优化
    type: url-test
    proxies:
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 UDP TUIC
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
    url: https://chatgpt.com/cdn-cgi/trace
    interval: 60
    timeout: 5000
    tolerance: 100

  - name: 🌐 Google 优化
    type: fallback
    proxies:
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 UDP TUIC
    url: https://www.gstatic.com/generate_204
    interval: 60
    timeout: 3000

  - name: 📚 学术访问
    type: select
    proxies:
      - DIRECT
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 UDP TUIC

  - name: ✈️ Telegram 优化
    type: url-test
    proxies:
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 UDP TUIC
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
    url: https://telegram.org/img/website_icon.svg
    interval: 60
    timeout: 5000
    tolerance: 100

# 5. 规则集（每天自动更新）
rule-providers:
  private:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt
    path: ./ruleset/private.yaml
    interval: 86400

  reject:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt
    path: ./ruleset/reject.yaml
    interval: 86400

  icloud:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt
    path: ./ruleset/icloud.yaml
    interval: 86400

  apple:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt
    path: ./ruleset/apple.yaml
    interval: 86400

  proxy:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt
    path: ./ruleset/proxy.yaml
    interval: 86400

  direct:
    type: http
    behavior: domain
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt
    path: ./ruleset/direct.yaml
    interval: 86400

  telegramcidr:
    type: http
    behavior: ipcidr
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt
    path: ./ruleset/telegramcidr.yaml
    interval: 86400

  cncidr:
    type: http
    behavior: ipcidr
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt
    path: ./ruleset/cncidr.yaml
    interval: 86400

  lancidr:
    type: http
    behavior: ipcidr
    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt
    path: ./ruleset/lancidr.yaml
    interval: 86400

# 6. 规则
rules:
  - 'IP-CIDR,47.245.53.96/32,DIRECT,no-resolve'
  - 'IP-CIDR,192.238.178.243/32,DIRECT,no-resolve'
  - 'DOMAIN,ipv6.msftconnecttest.com,REJECT'
  - 'DOMAIN,ipv6.msftncsi.com,REJECT'
  - 'IP-CIDR6,::/0,REJECT,no-resolve'
  - 'DOMAIN-SUFFIX,msftconnecttest.com,DIRECT'
  - 'DOMAIN-SUFFIX,msftncsi.com,DIRECT'
  - 'DOMAIN-SUFFIX,microsoft.com,DIRECT'
  - 'DOMAIN-SUFFIX,microsoftonline.com,DIRECT'
  - 'DOMAIN-SUFFIX,windows.com,DIRECT'
  - 'DOMAIN-SUFFIX,windowsupdate.com,DIRECT'
  - 'DOMAIN-SUFFIX,mp.microsoft.com,DIRECT'
  - 'DOMAIN-SUFFIX,xboxlive.com,DIRECT'
  - 'DOMAIN-SUFFIX,xboxservices.com,DIRECT'
  - 'DOMAIN-SUFFIX,gamepass.com,DIRECT'
  - 'DOMAIN-SUFFIX,playfabapi.com,DIRECT'
  - 'DOMAIN-SUFFIX,sciencedirect.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,sciencedirectassets.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,els-cdn.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,elsevier.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,elsevier-ae.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,elsevier.io,📚 学术访问'
  - 'DOMAIN-SUFFIX,elseviercdn.cn,📚 学术访问'
  - 'DOMAIN-SUFFIX,scopus.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,springer.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,springernature.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,nature.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,wiley.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,tandfonline.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,jstor.org,📚 学术访问'
  - 'DOMAIN-SUFFIX,ieee.org,📚 学术访问'
  - 'DOMAIN-SUFFIX,acs.org,📚 学术访问'
  - 'DOMAIN-SUFFIX,rsc.org,📚 学术访问'
  - 'DOMAIN-SUFFIX,sagepub.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,science.org,📚 学术访问'
  - 'DOMAIN-SUFFIX,cell.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,thelancet.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,bmj.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,oup.com,📚 学术访问'
  - 'DOMAIN-SUFFIX,cambridge.org,📚 学术访问'
  - 'DOMAIN-SUFFIX,arxiv.org,📚 学术访问'
  - 'DOMAIN-SUFFIX,nih.gov,📚 学术访问'
  - 'DOMAIN-SUFFIX,openai.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,chatgpt.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,oaistatic.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,oaiusercontent.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,openaiusercontent.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,ai.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,auth0.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,arkoselabs.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,statsigapi.net,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,featuregates.org,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,intercom.io,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,intercomcdn.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,sentry.io,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,browser-intake-datadoghq.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,chatgpt.livekit.cloud,🤖 GPT 优化'
  - 'DOMAIN,challenges.cloudflare.com,🤖 GPT 优化'
  - 'DOMAIN-SUFFIX,google.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,google.com.hk,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,google.com.tw,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,gmail.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googlemail.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googleapis.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,gstatic.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googleusercontent.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,ggpht.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,gvt1.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,gvt2.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,gvt3.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googlevideo.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,youtube.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,ytimg.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,youtu.be,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,withgoogle.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googleblog.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googleadservices.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googlesyndication.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,google-analytics.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googletagmanager.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,googletagservices.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,doubleclick.net,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,recaptcha.net,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,appspot.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,firebaseapp.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,firebaseio.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,blogger.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,blogspot.com,🌐 Google 优化'
  - 'DOMAIN-SUFFIX,telegram.org,✈️ Telegram 优化'
  - 'DOMAIN-SUFFIX,telegram.me,✈️ Telegram 优化'
  - 'DOMAIN-SUFFIX,telegram.dog,✈️ Telegram 优化'
  - 'DOMAIN-SUFFIX,t.me,✈️ Telegram 优化'
  - 'DOMAIN-SUFFIX,telegra.ph,✈️ Telegram 优化'
  - 'DOMAIN-SUFFIX,tdesktop.com,✈️ Telegram 优化'
  - 'DOMAIN-SUFFIX,github.com,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,github.io,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,githubusercontent.com,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,githubassets.com,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,githubapp.com,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,github.dev,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,ghcr.io,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,githubcopilot.com,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,github-cloud.s3.amazonaws.com,⚡ GitHub 加速'
  - 'DOMAIN-SUFFIX,overleaf.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,overleafusercontent.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,sharelatex.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,steamcontent.com,DIRECT'
  - 'DOMAIN-SUFFIX,steamserver.net,DIRECT'
  - 'DOMAIN-SUFFIX,steampowered.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,cloudflare.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,cdnjs.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,jsdelivr.net,🚀 节点选择'
  - 'DOMAIN-SUFFIX,bootstrapcdn.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,fontawesome.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,fontawesomecdn.com,🚀 节点选择'
  # 先保留广告/恶意域名拦截，再进入本地国内域名表。
  - 'RULE-SET,reject,REJECT'
  # 国内表来自参考配置；优先于通用在线直连/代理规则，规则集更新失败时仍可直连。
  - 'DOMAIN-SUFFIX,cn,DIRECT'
  - 'DOMAIN-SUFFIX,com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,net.cn,DIRECT'
  - 'DOMAIN-SUFFIX,org.cn,DIRECT'
  - 'DOMAIN-SUFFIX,gov.cn,DIRECT'
  - 'DOMAIN-SUFFIX,edu.cn,DIRECT'
  - 'DOMAIN-SUFFIX,ip111.cn,DIRECT'
  - 'DOMAIN-SUFFIX,ip.cn,DIRECT'
  - 'DOMAIN-SUFFIX,qq.com,DIRECT'
  - 'DOMAIN-SUFFIX,tencent.com,DIRECT'
  - 'DOMAIN-SUFFIX,weixin.com,DIRECT'
  - 'DOMAIN-SUFFIX,wechat.com,DIRECT'
  - 'DOMAIN-SUFFIX,wx.qq.com,DIRECT'
  - 'DOMAIN-SUFFIX,weixin.qq.com,DIRECT'
  - 'DOMAIN-SUFFIX,qpic.cn,DIRECT'
  - 'DOMAIN-SUFFIX,gtimg.cn,DIRECT'
  - 'DOMAIN-SUFFIX,gtimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,idqqimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,qlogo.cn,DIRECT'
  - 'DOMAIN-SUFFIX,myqcloud.com,DIRECT'
  - 'DOMAIN-SUFFIX,tenpay.com,DIRECT'
  - 'DOMAIN-SUFFIX,tengxun.com,DIRECT'
  - 'DOMAIN-SUFFIX,taobao.com,DIRECT'
  - 'DOMAIN-SUFFIX,tmall.com,DIRECT'
  - 'DOMAIN-SUFFIX,alipay.com,DIRECT'
  - 'DOMAIN-SUFFIX,aliyun.com,DIRECT'
  - 'DOMAIN-SUFFIX,alicdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,alibaba.com,DIRECT'
  - 'DOMAIN-SUFFIX,alibabacloud.com,DIRECT'
  - 'DOMAIN-SUFFIX,aliyuncs.com,DIRECT'
  - 'DOMAIN-SUFFIX,1688.com,DIRECT'
  - 'DOMAIN-SUFFIX,aliexpress.com,DIRECT'
  - 'DOMAIN-SUFFIX,alimama.com,DIRECT'
  - 'DOMAIN-SUFFIX,alipayobjects.com,DIRECT'
  - 'DOMAIN-SUFFIX,mmstat.com,DIRECT'
  - 'DOMAIN-SUFFIX,tbcdn.cn,DIRECT'
  - 'DOMAIN-SUFFIX,taobaocdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,cainiao.com,DIRECT'
  - 'DOMAIN-SUFFIX,ele.me,DIRECT'
  - 'DOMAIN-SUFFIX,elemecdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,amap.com,DIRECT'
  - 'DOMAIN-SUFFIX,autonavi.com,DIRECT'
  - 'DOMAIN-SUFFIX,dingtalk.com,DIRECT'
  - 'DOMAIN-SUFFIX,dingtalkapps.com,DIRECT'
  - 'DOMAIN-SUFFIX,xiami.com,DIRECT'
  - 'DOMAIN-SUFFIX,youku.com,DIRECT'
  - 'DOMAIN-SUFFIX,ykimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,tudou.com,DIRECT'
  - 'DOMAIN-SUFFIX,cibntv.net,DIRECT'
  - 'DOMAIN-SUFFIX,ucweb.com,DIRECT'
  - 'DOMAIN-SUFFIX,baidu.com,DIRECT'
  - 'DOMAIN-SUFFIX,baidubce.com,DIRECT'
  - 'DOMAIN-SUFFIX,baidustatic.com,DIRECT'
  - 'DOMAIN-SUFFIX,bdstatic.com,DIRECT'
  - 'DOMAIN-SUFFIX,bdimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,bcebos.com,DIRECT'
  - 'DOMAIN-SUFFIX,baiducontent.com,DIRECT'
  - 'DOMAIN-SUFFIX,baidupcs.com,DIRECT'
  - 'DOMAIN-SUFFIX,baifubao.com,DIRECT'
  - 'DOMAIN-SUFFIX,hao123.com,DIRECT'
  - 'DOMAIN-SUFFIX,nuomi.com,DIRECT'
  - 'DOMAIN-SUFFIX,tieba.com,DIRECT'
  - 'DOMAIN-SUFFIX,pan.baidu.com,DIRECT'
  - 'DOMAIN-SUFFIX,bytedance.com,DIRECT'
  - 'DOMAIN-SUFFIX,bytedance.net,DIRECT'
  - 'DOMAIN-SUFFIX,bytecdn.cn,DIRECT'
  - 'DOMAIN-SUFFIX,byteimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,bytegoofy.com,DIRECT'
  - 'DOMAIN-SUFFIX,douyin.com,DIRECT'
  - 'DOMAIN-SUFFIX,douyincdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,douyinpic.com,DIRECT'
  - 'DOMAIN-SUFFIX,douyinstatic.com,DIRECT'
  - 'DOMAIN-SUFFIX,amemv.com,DIRECT'
  - 'DOMAIN-SUFFIX,snssdk.com,DIRECT'
  - 'DOMAIN-SUFFIX,toutiao.com,DIRECT'
  - 'DOMAIN-SUFFIX,toutiaocdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,toutiaoimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,pstatp.com,DIRECT'
  - 'DOMAIN-SUFFIX,ixigua.com,DIRECT'
  - 'DOMAIN-SUFFIX,ixiguavideo.com,DIRECT'
  - 'DOMAIN-SUFFIX,huoshan.com,DIRECT'
  - 'DOMAIN-SUFFIX,huoshanzhibo.com,DIRECT'
  - 'DOMAIN-SUFFIX,feiliao.com,DIRECT'
  - 'DOMAIN-SUFFIX,zjurl.cn,DIRECT'
  - 'DOMAIN-SUFFIX,zijieapi.com,DIRECT'
  - 'DOMAIN-SUFFIX,feishu.cn,DIRECT'
  - 'DOMAIN-SUFFIX,feishucdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,larkoffice.com,DIRECT'
  - 'DOMAIN-SUFFIX,bilibili.com,DIRECT'
  - 'DOMAIN-SUFFIX,bilivideo.com,DIRECT'
  - 'DOMAIN-SUFFIX,bilivideo.cn,DIRECT'
  - 'DOMAIN-SUFFIX,biliapi.net,DIRECT'
  - 'DOMAIN-SUFFIX,biliapi.com,DIRECT'
  - 'DOMAIN-SUFFIX,hdslb.com,DIRECT'
  - 'DOMAIN-SUFFIX,acgvideo.com,DIRECT'
  - 'DOMAIN-SUFFIX,im9.com,DIRECT'
  - 'DOMAIN-SUFFIX,163.com,DIRECT'
  - 'DOMAIN-SUFFIX,126.com,DIRECT'
  - 'DOMAIN-SUFFIX,netease.com,DIRECT'
  - 'DOMAIN-SUFFIX,netease.im,DIRECT'
  - 'DOMAIN-SUFFIX,ntes.com,DIRECT'
  - 'DOMAIN-SUFFIX,ydstatic.com,DIRECT'
  - 'DOMAIN-SUFFIX,youdao.com,DIRECT'
  - 'DOMAIN-SUFFIX,163yun.com,DIRECT'
  - 'DOMAIN-SUFFIX,neteasegames.com,DIRECT'
  - 'DOMAIN-SUFFIX,nie.netease.com,DIRECT'
  - 'DOMAIN-SUFFIX,yeah.net,DIRECT'
  - 'DOMAIN-SUFFIX,jd.com,DIRECT'
  - 'DOMAIN-SUFFIX,jd.hk,DIRECT'
  - 'DOMAIN-SUFFIX,jdcloud.com,DIRECT'
  - 'DOMAIN-SUFFIX,jdpay.com,DIRECT'
  - 'DOMAIN-SUFFIX,360buyimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,jcloudcache.com,DIRECT'
  - 'DOMAIN-SUFFIX,jcloudcdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,jddebug.com,DIRECT'
  - 'DOMAIN-SUFFIX,jdcache.com,DIRECT'
  - 'DOMAIN-SUFFIX,iqiyi.com,DIRECT'
  - 'DOMAIN-SUFFIX,iqiyipic.com,DIRECT'
  - 'DOMAIN-SUFFIX,qiyi.com,DIRECT'
  - 'DOMAIN-SUFFIX,qiyipic.com,DIRECT'
  - 'DOMAIN-SUFFIX,pps.tv,DIRECT'
  - 'DOMAIN-SUFFIX,ppstream.com,DIRECT'
  - 'DOMAIN-SUFFIX,qy.net,DIRECT'
  - 'DOMAIN-SUFFIX,sina.com,DIRECT'
  - 'DOMAIN-SUFFIX,sina.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,sinaimg.cn,DIRECT'
  - 'DOMAIN-SUFFIX,sinajs.cn,DIRECT'
  - 'DOMAIN-SUFFIX,sina.cn,DIRECT'
  - 'DOMAIN-SUFFIX,weibo.com,DIRECT'
  - 'DOMAIN-SUFFIX,weibo.cn,DIRECT'
  - 'DOMAIN-SUFFIX,weibocdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,miaopai.com,DIRECT'
  - 'DOMAIN-SUFFIX,zhihu.com,DIRECT'
  - 'DOMAIN-SUFFIX,zhimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,xiaomi.com,DIRECT'
  - 'DOMAIN-SUFFIX,xiaomi.cn,DIRECT'
  - 'DOMAIN-SUFFIX,mi.com,DIRECT'
  - 'DOMAIN-SUFFIX,miui.com,DIRECT'
  - 'DOMAIN-SUFFIX,miwifi.com,DIRECT'
  - 'DOMAIN-SUFFIX,xiaomiyoupin.com,DIRECT'
  - 'DOMAIN-SUFFIX,duokan.com,DIRECT'
  - 'DOMAIN-SUFFIX,huawei.com,DIRECT'
  - 'DOMAIN-SUFFIX,vmall.com,DIRECT'
  - 'DOMAIN-SUFFIX,huaweicloud.com,DIRECT'
  - 'DOMAIN-SUFFIX,hicloud.com,DIRECT'
  - 'DOMAIN-SUFFIX,hichina.com,DIRECT'
  - 'DOMAIN-SUFFIX,dbankcloud.com,DIRECT'
  - 'DOMAIN-SUFFIX,kuaishou.com,DIRECT'
  - 'DOMAIN-SUFFIX,gifshow.com,DIRECT'
  - 'DOMAIN-SUFFIX,yxixy.com,DIRECT'
  - 'DOMAIN-SUFFIX,kwimgs.com,DIRECT'
  - 'DOMAIN-SUFFIX,kuaishouzt.com,DIRECT'
  - 'DOMAIN-SUFFIX,pinduoduo.com,DIRECT'
  - 'DOMAIN-SUFFIX,yangkeduo.com,DIRECT'
  - 'DOMAIN-SUFFIX,pinduoduo.net,DIRECT'
  - 'DOMAIN-SUFFIX,meituan.com,DIRECT'
  - 'DOMAIN-SUFFIX,meituan.net,DIRECT'
  - 'DOMAIN-SUFFIX,dianping.com,DIRECT'
  - 'DOMAIN-SUFFIX,dpfile.com,DIRECT'
  - 'DOMAIN-SUFFIX,maoyan.com,DIRECT'
  - 'DOMAIN-SUFFIX,didiglobal.com,DIRECT'
  - 'DOMAIN-SUFFIX,didialift.com,DIRECT'
  - 'DOMAIN-SUFFIX,xiaojukeji.com,DIRECT'
  - 'DOMAIN-SUFFIX,udache.com,DIRECT'
  - 'DOMAIN-SUFFIX,sohu.com,DIRECT'
  - 'DOMAIN-SUFFIX,sogou.com,DIRECT'
  - 'DOMAIN-SUFFIX,sogoucdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,sogo.com,DIRECT'
  - 'DOMAIN-SUFFIX,so.com,DIRECT'
  - 'DOMAIN-SUFFIX,360.cn,DIRECT'
  - 'DOMAIN-SUFFIX,360.com,DIRECT'
  - 'DOMAIN-SUFFIX,qihoo.com,DIRECT'
  - 'DOMAIN-SUFFIX,qhimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,qhimgs.com,DIRECT'
  - 'DOMAIN-SUFFIX,douban.com,DIRECT'
  - 'DOMAIN-SUFFIX,doubanio.com,DIRECT'
  - 'DOMAIN-SUFFIX,ctrip.com,DIRECT'
  - 'DOMAIN-SUFFIX,c-ctrip.com,DIRECT'
  - 'DOMAIN-SUFFIX,ly.com,DIRECT'
  - 'DOMAIN-SUFFIX,qunar.com,DIRECT'
  - 'DOMAIN-SUFFIX,fliggy.com,DIRECT'
  - 'DOMAIN-SUFFIX,tuniu.com,DIRECT'
  - 'DOMAIN-SUFFIX,suning.com,DIRECT'
  - 'DOMAIN-SUFFIX,suning.cn,DIRECT'
  - 'DOMAIN-SUFFIX,vip.com,DIRECT'
  - 'DOMAIN-SUFFIX,vipstatic.com,DIRECT'
  - 'DOMAIN-SUFFIX,gome.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,xunlei.com,DIRECT'
  - 'DOMAIN-SUFFIX,sandai.net,DIRECT'
  - 'DOMAIN-SUFFIX,wandoujia.com,DIRECT'
  - 'DOMAIN-SUFFIX,coolapk.com,DIRECT'
  - 'DOMAIN-SUFFIX,oppo.com,DIRECT'
  - 'DOMAIN-SUFFIX,vivo.com,DIRECT'
  - 'DOMAIN-SUFFIX,meizu.com,DIRECT'
  - 'DOMAIN-SUFFIX,flyme.cn,DIRECT'
  - 'DOMAIN-SUFFIX,lenovo.com,DIRECT'
  - 'DOMAIN-SUFFIX,zol.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,ccb.com,DIRECT'
  - 'DOMAIN-SUFFIX,icbc.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,boc.cn,DIRECT'
  - 'DOMAIN-SUFFIX,abchina.com,DIRECT'
  - 'DOMAIN-SUFFIX,psbc.com,DIRECT'
  - 'DOMAIN-SUFFIX,cmbchina.com,DIRECT'
  - 'DOMAIN-SUFFIX,unionpay.com,DIRECT'
  - 'DOMAIN-SUFFIX,bankcomm.com,DIRECT'
  - 'DOMAIN-SUFFIX,spdb.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,cebbank.com,DIRECT'
  - 'DOMAIN-SUFFIX,cmbc.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,ifeng.com,DIRECT'
  - 'DOMAIN-SUFFIX,thepaper.cn,DIRECT'
  - 'DOMAIN-SUFFIX,caixin.com,DIRECT'
  - 'DOMAIN-SUFFIX,yicai.com,DIRECT'
  - 'DOMAIN-SUFFIX,jiemian.com,DIRECT'
  - 'DOMAIN-SUFFIX,cctv.com,DIRECT'
  - 'DOMAIN-SUFFIX,cctv.cn,DIRECT'
  - 'DOMAIN-SUFFIX,xinhuanet.com,DIRECT'
  - 'DOMAIN-SUFFIX,people.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,chinadaily.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,huanqiu.com,DIRECT'
  - 'DOMAIN-SUFFIX,guancha.cn,DIRECT'
  - 'DOMAIN-SUFFIX,cankaoxiaoxi.com,DIRECT'
  - 'DOMAIN-SUFFIX,bjnews.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,csdn.net,DIRECT'
  - 'DOMAIN-SUFFIX,oschina.net,DIRECT'
  - 'DOMAIN-SUFFIX,gitee.com,DIRECT'
  - 'DOMAIN-SUFFIX,iteye.com,DIRECT'
  - 'DOMAIN-SUFFIX,infoq.cn,DIRECT'
  - 'DOMAIN-SUFFIX,51cto.com,DIRECT'
  - 'DOMAIN-SUFFIX,cnblogs.com,DIRECT'
  - 'DOMAIN-SUFFIX,jianshu.com,DIRECT'
  - 'DOMAIN-SUFFIX,juejin.cn,DIRECT'
  - 'DOMAIN-SUFFIX,segmentfault.com,DIRECT'
  - 'DOMAIN-SUFFIX,xuetangx.com,DIRECT'
  - 'DOMAIN-SUFFIX,icourse163.org,DIRECT'
  - 'DOMAIN-SUFFIX,mooc.cn,DIRECT'
  - 'DOMAIN-SUFFIX,study.163.com,DIRECT'
  - 'DOMAIN-SUFFIX,yuketang.cn,DIRECT'
  - 'DOMAIN-SUFFIX,taptap.com,DIRECT'
  - 'DOMAIN-SUFFIX,taptapdada.com,DIRECT'
  - 'DOMAIN-SUFFIX,37.com,DIRECT'
  - 'DOMAIN-SUFFIX,4399.com,DIRECT'
  - 'DOMAIN-SUFFIX,7k7k.com,DIRECT'
  - 'DOMAIN-SUFFIX,yy.com,DIRECT'
  - 'DOMAIN-SUFFIX,duowan.com,DIRECT'
  - 'DOMAIN-SUFFIX,huya.com,DIRECT'
  - 'DOMAIN-SUFFIX,douyu.com,DIRECT'
  - 'DOMAIN-SUFFIX,douyucdn.cn,DIRECT'
  - 'DOMAIN-SUFFIX,douyutv.com,DIRECT'
  - 'DOMAIN-SUFFIX,aliyuncdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,alikunlun.com,DIRECT'
  - 'DOMAIN-SUFFIX,kunlunaq.com,DIRECT'
  - 'DOMAIN-SUFFIX,kunlunca.com,DIRECT'
  - 'DOMAIN-SUFFIX,kunlunsl.com,DIRECT'
  - 'DOMAIN-SUFFIX,kunlunpi.com,DIRECT'
  - 'DOMAIN-SUFFIX,kunlungr.com,DIRECT'
  - 'DOMAIN-SUFFIX,cdnhwc2.com,DIRECT'
  - 'DOMAIN-SUFFIX,cdnhwc3.com,DIRECT'
  - 'DOMAIN-SUFFIX,hwcloudcdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,baishan.com,DIRECT'
  - 'DOMAIN-SUFFIX,baishancloud.com,DIRECT'
  - 'DOMAIN-SUFFIX,baishancdnx.com,DIRECT'
  - 'DOMAIN-SUFFIX,qiniucdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,qiniudn.com,DIRECT'
  - 'DOMAIN-SUFFIX,qbox.me,DIRECT'
  - 'DOMAIN-SUFFIX,upyun.com,DIRECT'
  - 'DOMAIN-SUFFIX,upaiyun.com,DIRECT'
  - 'DOMAIN-SUFFIX,clouddn.com,DIRECT'
  - 'DOMAIN-SUFFIX,ksyuncdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,ksyun.com,DIRECT'
  - 'DOMAIN-SUFFIX,ks-cdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,kscdnx.com,DIRECT'
  - 'DOMAIN-SUFFIX,chinanetcenter.com,DIRECT'
  - 'DOMAIN-SUFFIX,wangsu.com,DIRECT'
  - 'DOMAIN-SUFFIX,wscdns.com,DIRECT'
  - 'DOMAIN-SUFFIX,wsglb0.com,DIRECT'
  - 'DOMAIN-SUFFIX,cdn20.com,DIRECT'
  - 'DOMAIN-SUFFIX,cdn30.com,DIRECT'
  - 'DOMAIN-SUFFIX,staticdn.net,DIRECT'
  - 'DOMAIN-SUFFIX,bdydns.com,DIRECT'
  - 'DOMAIN-SUFFIX,bdydns.net,DIRECT'
  - 'DOMAIN-SUFFIX,tencentcloudcdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,dnsv1.com,DIRECT'
  - 'DOMAIN-SUFFIX,tdnsv5.com,DIRECT'
  - 'DOMAIN-SUFFIX,tdnsv6.com,DIRECT'
  - 'DOMAIN-SUFFIX,cdntip.com,DIRECT'
  - 'DOMAIN-SUFFIX,cdntips.com,DIRECT'
  - 'DOMAIN-SUFFIX,cdnle.com,DIRECT'
  - 'DOMAIN-SUFFIX,txcdns.com,DIRECT'
  - 'DOMAIN-SUFFIX,qcloud.com,DIRECT'
  - 'DOMAIN-SUFFIX,qcloudcdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,qcloudimg.com,DIRECT'
  - 'DOMAIN-SUFFIX,qcloudcos.com,DIRECT'
  - 'DOMAIN-SUFFIX,myqcloud.cos,DIRECT'
  - 'DOMAIN-SUFFIX,cloudfront.cn,DIRECT'
  - 'DOMAIN-SUFFIX,mtyun.com,DIRECT'
  - 'DOMAIN-SUFFIX,ctcdn.cn,DIRECT'
  - 'DOMAIN-SUFFIX,ctyun.cn,DIRECT'
  - 'DOMAIN-SUFFIX,ctyunapi.cn,DIRECT'
  - 'DOMAIN-SUFFIX,chinacache.com,DIRECT'
  - 'DOMAIN-SUFFIX,chinacache.net,DIRECT'
  - 'DOMAIN-SUFFIX,ccgslb.com,DIRECT'
  - 'DOMAIN-SUFFIX,ccgslb.net,DIRECT'
  - 'DOMAIN-SUFFIX,lxdns.com,DIRECT'
  - 'DOMAIN-SUFFIX,lxcdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,fastweb.com.cn,DIRECT'
  - 'DOMAIN-SUFFIX,fastcdn.com,DIRECT'
  - 'DOMAIN-SUFFIX,cloudglb.com,DIRECT'
  - 'DOMAIN-SUFFIX,cloudgslb.com,DIRECT'
  - 'RULE-SET,telegramcidr,✈️ Telegram 优化,no-resolve'
  - 'RULE-SET,private,DIRECT'
  - 'RULE-SET,lancidr,DIRECT,no-resolve'
  - 'GEOIP,LAN,DIRECT'
  - 'DOMAIN-SUFFIX,rmbgame.net,DIRECT'
  - 'DOMAIN-KEYWORD,Microsoft,DIRECT'
  - 'DOMAIN-SUFFIX,office.com,DIRECT'
  - 'DOMAIN-SUFFIX,visualstudio.com,DIRECT'
  - 'DOMAIN-SUFFIX,vscode-cdn.net,DIRECT'
  - 'DOMAIN-KEYWORD,vscode,DIRECT'
  - 'DOMAIN-SUFFIX,nvidia.com,DIRECT'
  - 'RULE-SET,icloud,DIRECT'
  - 'RULE-SET,apple,DIRECT'
  - 'RULE-SET,direct,DIRECT'
  - 'RULE-SET,proxy,🚀 节点选择'
  - 'RULE-SET,cncidr,DIRECT,no-resolve'
  - 'GEOIP,CN,DIRECT'
  - 'MATCH,🚀 节点选择'
