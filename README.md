# Free Proxy List

This repository has the goal to provide working (checked) and constantly tested FREE http, https, socks4 and socks5 proxies.

The list of working proxies:

+ [checked http proxies](./proxies/http_working.txt)
+ [checked https proxies](./proxies/https_working.txt)
+ [checked socks4 proxies](./proxies/socks4_working.txt)
+ [checked socks5 proxies](./proxies/socks5_working.txt)

## How to test a proxy?

Testing a socks5 proxy:

```bash
curl https://httpbin.org/ip --socks5 45.12.132.212:51991
curl https://api.ipapi.is/ip --socks5 51.210.111.216:47878
curl https://api.ipapi.is/ip --socks5 121.169.46.116:1090
curl https://engine.proxydetect.live/test --socks5 121.169.46.116:1090
```

Testing a socks4 proxy:

```bash
curl https://httpbin.org/ip --socks4 64.202.184.249:15986
curl https://api.ipapi.is/ip --socks4 64.202.184.249:15986
```

Testing a http proxy:

```bash
curl -x http://54.245.34.166:8000 https://api.ipapi.is/ip -k
curl -x http://200.208.96.194:443 https://icanhazip.com/ -k
curl -x 8.243.197.200:999 https://engine.proxydetect.live/test -k
```
