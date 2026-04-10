listen: :443

tls:
  cert: /root/hysteria/server.crt
  key: /root/hysteria/server.key

auth:
  type: command
  command: /root/hysteria/auth_backend.py

obfs:
  type: salamander
  salamander:
    password: __HY_OBFS_PASSWORD__

trafficStats:
  listen: 127.0.0.1:25413
  secret: __HY_API_SECRET__

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
