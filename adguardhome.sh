#!/bin/sh

change_dns() {
if [ "$(nvram get adg_redirect)" = 1 ]; then
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#5335
EOF
/sbin/restart_dhcpd
logger -t "AdGuardHome" "添加DNS转发到5335端口"
fi
}
del_dns() {
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1#5335/d' /etc/storage/dnsmasq/dnsmasq.conf
/sbin/restart_dhcpd
}

set_iptable()
{
    if [ "$(nvram get adg_redirect)" = 2 ]; then
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
		iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
	done

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
		ip6tables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
	done
    logger -t "AdGuardHome" "重定向53端口"
    fi
}

clear_iptable()
{
	OLD_PORT="5335"
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		iptables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		ip6tables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done
	
}

getconfig(){
adg_file="/etc/storage/adg.sh"
if [ ! -f "$adg_file" ] || [ ! -s "$adg_file" ] ; then
	cat > "$adg_file" <<-\EEE
bind_host: 0.0.0.0
bind_port: 3030
beta_bind_port: 0
users:
- name: xiaoyangzai
  password: $2a$10$Z3uQ9O8/FH1niemCGWFdI.egeqnkciOj8VdC8UHvuK0Sf6X7bXnv6
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: ""
debug_pprof: false
web_session_ttl: 600
dns:
  bind_hosts:
  - 0.0.0.0
  port: 5335
  statistics_interval: 1
  querylog_enabled: true
  querylog_file_enabled: true
  querylog_interval: 24h
  querylog_size_memory: 1000
  anonymize_client_ip: false
  protection_enabled: true
  blocking_mode: default
  blocking_ipv4: ""
  blocking_ipv6: ""
  blocked_response_ttl: 10
  parental_block_host: family-block.dns.adguard.com
  safebrowsing_block_host: standard-block.dns.adguard.com
  ratelimit: 20
  ratelimit_whitelist: []
  refuse_any: true
  upstream_dns:
  - '[/dhylmr.cn/]223.5.5.5'
  - '[/dhylmr.com/]223.5.5.5'
  - '[/xiaoyangzai.work/]223.5.5.5'
  - '[/xiaoyangzai.xyz/]119.29.29.29'
  - https://dns.pub/dns-query
  - https://dns.alidns.com/dns-query
  - https://doh.360.cn/dns-query
  upstream_dns_file: ""
  bootstrap_dns:
  - 114.114.115.115
  all_servers: false
  fastest_addr: false
  fastest_timeout: 1s
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts:
  - version.bind
  - id.server
  - hostname.bind
  trusted_proxies:
  - 127.0.0.0/8
  - ::1/128
  cache_size: 4194304
  cache_ttl_min: 600
  cache_ttl_max: 86400
  cache_optimistic: true
  bogus_nxdomain: []
  aaaa_disabled: true
  enable_dnssec: false
  edns_client_subnet: false
  max_goroutines: 150
  ipset: []
  filtering_enabled: true
  filters_update_interval: 24
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: false
  safebrowsing_cache_size: 1048576
  safesearch_cache_size: 1048576
  parental_cache_size: 1048576
  cache_time: 30
  rewrites: []
  blocked_services: []
  upstream_timeout: 10s
  private_networks: []
  use_private_ptr_resolvers: true
  local_ptr_upstreams: []
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  dnscrypt_config_file: ""
  allow_unencrypted_doh: false
  strict_sni_check: false
  certificate_chain: ""
  private_key: ""
  certificate_path: ""
  private_key_path: ""
filters:
- enabled: true
  url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  name: AdGuard DNS filter
  id: 1
- enabled: true
  url: https://adaway.org/hosts.txt
  name: AdAway Default Blocklist
  id: 2
- enabled: true
  url: https://someonewhocares.org/hosts/zero/hosts
  name: Dan Pollock's List
  id: 1658238573
- enabled: true
  url: https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt
  name: Game Console Adblock List
  id: 1658238574
- enabled: true
  url: https://abp.oisd.nl/basic/
  name: OISD Blocklist Basic
  id: 1658238575
- enabled: true
  url: https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt
  name: Perflyst and Dandelion Sprout's Smart-TV Blocklist
  id: 1658238576
- enabled: true
  url: https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext
  name: Peter Lowe's List
  id: 1658238577
- enabled: true
  url: https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareAdGuardHome.txt
  name: Dandelion Sprout's Anti-Malware List
  id: 1658238578
- enabled: true
  url: https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt
  name: NoCoin Filter List
  id: 1658238579
- enabled: true
  url: https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/adguard.txt
  name: Scam Blocklist by DurableNapkin
  id: 1658238580
- enabled: true
  url: https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hosts
  name: The Big List of Hacked Malware Web Sites
  id: 1658238581
- enabled: true
  url: https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt
  name: Online Malicious URL Blocklist
  id: 1658238582
- enabled: true
  url: https://anti-ad.net/easylist.txt
  name: 'CHN: anti-AD'
  id: 1658238583
- enabled: true
  url: https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
  name: WindowsSpyBlocker - Hosts spy rules
  id: 1658238584
whitelist_filters:
- enabled: true
  url: https://fastly.jsdelivr.net/gh/privacy-protection-tools/dead-horse@master/anti-ad-white-list.txt
  name: anti-AD (Whitelist)
  id: 1658238585
user_rules:
- '||_vlmcs._tcp.lan^$dnsrewrite=NOERROR;SRV;0 100 1688 my.router'
- '||app.drivereasy.com'
- '@@||datayi.cn^$important'
- '@@||launches.appsflyer.com^$important'
dhcp:
  enabled: false
  interface_name: ""
  local_domain_name: lan
  dhcpv4:
    gateway_ip: ""
    subnet_mask: ""
    range_start: ""
    range_end: ""
    lease_duration: 86400
    icmp_timeout_msec: 1000
    options: []
  dhcpv6:
    range_start: ""
    lease_duration: 86400
    ra_slaac_only: false
    ra_allow_slaac: false
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: true
    hosts: true
  persistent: []
log_compress: false
log_localtime: false
log_max_backups: 0
log_max_size: 100
log_max_age: 3
log_file: ""
verbose: false
os:
  group: ""
  user: ""
  rlimit_nofile: 0
schema_version: 14


EEE
	chmod 755 "$adg_file"
fi
}

dl_adg(){
logger -t "AdGuardHome" "下载AdGuardHome"
curl -k -s -o /media/AiDisk_a1/AdGuardHome --connect-timeout 10 --retry 3 https://ghproxy.com/https://github.com/YY-China/Adguardhome-Config/releases/download/Adguardhome/AdGuardHome
if [ ! -f "/media/AiDisk_a1/AdGuardHome" ]; then
logger -t "AdGuardHome" "AdGuardHome下载失败，请检查是否能正常访问github!程序将退出。"
nvram set adg_enable=0
exit 0
else
logger -t "AdGuardHome" "AdGuardHome下载成功。"
chmod 777 /media/AiDisk_a1/AdGuardHome
fi
}

start_adg(){
	mkdir -p /etc/storage/AdGuardHome
	if [ ! -f "/media/AiDisk_a1/AdGuardHome" ]; then
	dl_adg
	fi
	getconfig
	change_dns
	set_iptable
	logger -t "AdGuardHome" "运行AdGuardHome"
	eval "/media/AiDisk_a1/AdGuardHome -c $adg_file -w /media/AiDisk_a1 -v" &

}
stop_adg(){
#rm -rf /tmp/AdGuardHome
killall -9 AdGuardHome
del_dns
clear_iptable
}


case $1 in
start)
	start_adg
	;;
stop)
	stop_adg
	;;
*)
	echo "check"
	;;
esac
