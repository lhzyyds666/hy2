# 1. 基础全局配置
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
unified-delay: true

# 2. DNS 配置 (fake-ip 模式)
dns:
  enable: true
  ipv6: false
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true

  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query

  fallback:
    - tls://8.8.8.8
    - tls://1.1.1.1

  direct-nameserver:
    - 223.5.5.5
    - 119.29.29.29

  nameserver-policy:
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

  - name: 🇺🇸 美国 TCP (VLESS+REALITY)
    type: vless
    server: __HY_SERVER_HOST__
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    network: tcp
    tls: true
    udp: true
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
    udp: true
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
      - 🔄 自动选择
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
      - DIRECT

  - name: 🔄 自动选择
    type: fallback
    proxies:
      - 🇺🇸 美国 UDP (端口跳跃)
      - 🇺🇸 美国 TCP (VLESS+REALITY)
      - 🇺🇸 美国 TCP 备用 (VLESS+REALITY)
    url: https://www.gstatic.com/generate_204
    interval: 30
    timeout: 5000

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
  - 'DOMAIN-SUFFIX,steamcontent.com,DIRECT'
  - 'DOMAIN-SUFFIX,steamserver.net,DIRECT'
  - 'DOMAIN-SUFFIX,steampowered.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,googleapis.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,gstatic.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,googleusercontent.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,cloudflare.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,cdnjs.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,jsdelivr.net,🚀 节点选择'
  - 'DOMAIN-SUFFIX,bootstrapcdn.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,fontawesome.com,🚀 节点选择'
  - 'DOMAIN-SUFFIX,fontawesomecdn.com,🚀 节点选择'
  - 'RULE-SET,reject,REJECT'
  - 'RULE-SET,private,DIRECT'
  - 'RULE-SET,lancidr,DIRECT,no-resolve'
  - 'GEOIP,LAN,DIRECT'
  - 'DOMAIN-SUFFIX,rmbgame.net,DIRECT'
  - 'DOMAIN-KEYWORD,Microsoft,DIRECT'
  - 'DOMAIN-SUFFIX,office.com,DIRECT'
  - 'DOMAIN-SUFFIX,windows.com,DIRECT'
  - 'DOMAIN-SUFFIX,visualstudio.com,DIRECT'
  - 'DOMAIN-SUFFIX,vscode-cdn.net,DIRECT'
  - 'DOMAIN-KEYWORD,vscode,DIRECT'
  - 'DOMAIN-SUFFIX,nvidia.com,DIRECT'
  - 'RULE-SET,icloud,DIRECT'
  - 'RULE-SET,apple,DIRECT'
  - 'RULE-SET,direct,DIRECT'
  - 'RULE-SET,proxy,🚀 节点选择'
  - 'RULE-SET,telegramcidr,🚀 节点选择,no-resolve'
  - 'RULE-SET,cncidr,DIRECT,no-resolve'
  - 'GEOIP,CN,DIRECT'
  - 'MATCH,🚀 节点选择'
