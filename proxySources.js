// Curated free proxy sources — pruned 404s (Firmfox/Proxify), exact duplicates
// (hookzof/socks5_list == proxifly), and ultra-low-yield dumps (zebbern: 87k
// lines / 0.01% unique yield); added live-verified active 2026 feeds.

const socks5sources = [
  // Existing active sources
  'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt',
  'https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt',
  'https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/SOCKS5.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt',
  'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/socks5.txt',
  'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/socks5.txt',
  'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/refs/heads/main/socks5_checked.txt',
  'https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks5/raw/all.txt',
  // Fixed URL (raw.githubusercontent.com) + newly verified active 2026 sources
  'https://raw.githubusercontent.com/zloi-user/hideip.me/master/socks5.txt',
  'https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/main/verified/socks5.txt',
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
  'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt',
  'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all',
  'https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/socks5/global/socks5_checked.txt',
  'https://raw.githubusercontent.com/stormsia/proxy-list/main/socks5.txt',
  'https://raw.githubusercontent.com/maximilianfeix/free-proxy-list/main/socks5.txt',
  'https://raw.githubusercontent.com/Skillter/ProxyGather/master/proxies/working-proxies-socks5.txt',
  'https://raw.githubusercontent.com/Dahono-com/free-proxy-list/main/proxies/socks5.txt',
  'https://raw.githubusercontent.com/cmahmud/proxies/main/alive/socks5.txt',
  'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks5.txt',
  'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt',
  'https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt',
  'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt',
];

const socks4sources = [
  // Existing active sources
  'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt',
  'https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks4_proxies.txt',
  'https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/SOCKS4.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt',
  'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/socks4.txt',
  'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks4.txt',
  'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/socks4.txt',
  'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/refs/heads/main/socks4_checked.txt',
  'https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks4/raw/all.txt',
  // Fixed URL + newly verified active 2026 sources
  'https://raw.githubusercontent.com/zloi-user/hideip.me/master/socks4.txt',
  'https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/main/verified/socks4.txt',
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',
  'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt',
  'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all',
  'https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/socks4/global/socks4_checked.txt',
  'https://raw.githubusercontent.com/maximilianfeix/free-proxy-list/main/socks4.txt',
  'https://raw.githubusercontent.com/Skillter/ProxyGather/master/proxies/working-proxies-socks4.txt',
  'https://raw.githubusercontent.com/Dahono-com/free-proxy-list/main/proxies/socks4.txt',
  'https://raw.githubusercontent.com/cmahmud/proxies/main/alive/socks4.txt',
  'https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks4.txt',
  'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt',
  'https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt',
];

const httpSources = [
  // Existing active sources
  'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt',
  'https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt',
  'https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/HTTP.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt',
  'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/http.txt',
  'https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/PROXY/ALL_PROXY_Lists.csv',
  'https://raw.githubusercontent.com/mmpx12/proxy-list/refs/heads/master/proxies.txt',
  'https://raw.githubusercontent.com/mmpx12/proxy-list/refs/heads/master/http.txt',
  'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/http.txt',
  'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/refs/heads/main/http_checked.txt',
  'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/http.txt',
  'https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/http/raw/all.txt',
  // Fixed URL + newly verified active 2026 sources
  'https://raw.githubusercontent.com/zloi-user/hideip.me/master/http.txt',
  'https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/main/verified/http.txt',
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
  'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt',
  'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
  'https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/http/global/http_checked.txt',
  'https://raw.githubusercontent.com/maximilianfeix/free-proxy-list/main/http.txt',
  'https://raw.githubusercontent.com/Skillter/ProxyGather/master/proxies/working-proxies-http.txt',
  'https://raw.githubusercontent.com/ProxcyDev/Proxies/master/http.txt',
];

const httpsSources = [
  // Existing active sources
  'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt',
  'https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/https.txt',
  'https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/https.txt',
  'https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/https.txt',
  // Fixed URL + newly verified active 2026 sources
  'https://raw.githubusercontent.com/zloi-user/hideip.me/master/https.txt',
  'https://raw.githubusercontent.com/vmheaven/VMHeaven.io-Free-Proxy-List/main/verified/https.txt',
  'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt',
  'https://raw.githubusercontent.com/Dahono-com/free-proxy-list/main/proxies/https.txt',
  'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
  'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
];

module.exports = {
  socks5sources,
  socks4sources,
  httpSources,
  httpsSources,
};
