/*
 * Stag Prime Sentinel | OpenVPN Community Edition handbook
 * Read-only UI data: no passwords, private keys or remote execution.
 * Explicit {{TOKENS}} are rendered only from locally entered non-secret values.
 */
export type CommandKind = 'linux' | 'windows' | 'config' | 'information'
export type RiskLevel = 'read' | 'change' | 'sensitive' | 'reference'
export type GuideBlock = { title: string; detail: string; code: string; kind?: CommandKind; risk?: RiskLevel; note?: string }
export type GuideStep = { id: string; group: string; title: string; subtitle: string; introduction: string; checkpoint: string; notes: string[]; blocks: GuideBlock[] }
export type HelpItem = { id: string; area: string; issue: string; cause: string; fix: string; code?: string; kind?: CommandKind; risk?: RiskLevel }

export const GUIDE_STEPS: GuideStep[] = [
  {
    id:'start', group:'START HERE', title:'Start here: server & credentials map', subtitle:'কোন কমান্ড কোথায় চলবে?',
    introduction:'নিচের Personalization অংশে Client/Device ID, Server Public IP, SSH Address, SSH Username এবং নিজের Windows PPK Path বসাও। Commands-এ এই তথ্য স্বয়ংক্রিয়ভাবে বসবে। Server Password, CA Passphrase বা Private Key কখনো এই UI-তে দেবে না।',
    checkpoint:'Linux PuTTY বনাম Windows CMD/PowerShell পার্থক্য বোঝা হয়েছে',
    notes:['Linux PuTTY: Ubuntu Server-এ কমান্ড চালাবে। Windows CMD: নিজের PC-তে PSCP দিয়ে File Download করবে। Configuration Text: OpenVPN .conf-এ Paste করবে; Terminal-এ Command হিসেবে চালাবে না।','Client ID হলো Easy-RSA Certificate Common Name। Username/Password আলাদা ব্যবস্থা; Certificate-only mode-এ Login Password দরকার নেই।','নিচের Workflow শুধু নতুন ও অনুমোদিত Ubuntu 24.04 VPS-এর জন্য। EU-01, EU-02, MENA-01-এর Running Instance-এ Fresh Install Step চালাবে না।'],
    blocks:[
      {title:'Linux — SSH connection & permission (read-only)', detail:'Ubuntu VPS-এ PuTTY দিয়ে লগইন করার পরে চালাবে।',code:String.raw`whoami
hostname
cat /etc/os-release
sudo -v && echo 'ADMIN ACCESS VERIFIED'
command -v openvpn || true
systemctl list-units --all 'openvpn*' --no-pager`,kind:'linux',risk:'read'},
      {title:'Windows CMD — PSCP কোথায় আছে?',detail:'নিজের Windows CMD-এ চালাবে। Linux SSH Terminal-এ এই Command দেবে না।',code:String.raw`where pscp
if exist "%ProgramFiles%\PuTTY\pscp.exe" echo PuTTY PSCP FOUND
if exist "{{PPK_PATH}}" echo SSH PPK FOUND`,kind:'windows',risk:'read'}
    ]
  },
  {
    id:'preflight',group:'01 / PREPARATION',title:'Fresh VPS assessment & safeguards',subtitle:'Operating system, cloud rules, existing VPN',
    introduction:'সার্ভারে আগে কোনো VPN, Firewall, PKI, App বা Data আছে কি না নিশ্চিত হও। Client-এর অনুমতি ছাড়া কোনো Production Server Reinstall বা Reset করবে না।',checkpoint:'Fresh VPS নিশ্চিত, SSH/Cloud Console recovery জানা এবং existing OpenVPN নেই',
    notes:['Oracle Cloud-এ Private IP (যেমন 10.0.0.x) এবং Public IP আলাদা হতে পারে। WAN Interface route থেকে সনাক্ত করতে হবে; Public IP কখনো অনুমান করবে না।','Ubuntu 24.04 LTS উদাহরণ; Debian/AlmaLinux-এ Package ও Service Path আলাদা।'],blocks:[
      {title:'Linux — OS, network, open services',detail:'সব Command Read-only।',code:String.raw`cat /etc/os-release
uname -r
ip -br -4 addr
ip -4 route show default
sudo ss -luntp
systemctl list-units --all 'openvpn*' --no-pager
sudo ufw status verbose || true
sudo iptables -S FORWARD
sudo iptables -t nat -S POSTROUTING`,kind:'linux',risk:'read'},
      {title:'Linux — confirm no existing OpenVPN material',detail:'Output থাকলে Fresh Install থামিয়ে Existing Setup Audit করো।',code:String.raw`sudo find /etc/openvpn -maxdepth 3 -type f -printf '%p\n' 2>/dev/null | head -n 60
sudo test ! -e /etc/openvpn/server/server.conf && echo 'NO SERVER CONF FOUND' || echo 'STOP: EXISTING SERVER CONF'`,kind:'linux',risk:'read'},
    ]
  },
  {
    id:'packages',group:'02 / INSTALL',title:'Install OpenVPN Community Edition',subtitle:'Ubuntu repository · not Access Server',introduction:'OpenVPN CE Ubuntu-এর Official Repository থেকে ইনস্টল করো। Community Edition-এ Access Server-এর লাইসেন্সভিত্তিক Concurrent Seat Limit নেই, কিন্তু Server Hardware/Provider Bandwidth-এর বাস্তব সীমা আছে।',checkpoint:'openvpn, Easy-RSA, ACL ও OpenSSL ইনস্টল এবং Version যাচাই',notes:['apt ইনস্টল শুধু অনুমোদিত Fresh VPS-এ। Cloud Firewall-এ UDP 1194 আলাদাভাবে Allow করতে হবে।'],blocks:[
      {title:'Linux — install dependencies',detail:'Package index এবং OpenVPN Community Edition ইনস্টল হবে।',code:String.raw`sudo apt update
sudo apt install -y openvpn easy-rsa acl openssl ca-certificates curl`,kind:'linux',risk:'change'},
      {title:'Linux — verify binaries & service templates',detail:'openvpn version এবং systemd Template দেখো।',code:String.raw`openvpn --version | head -n 5
command -v make-cadir
command -v setfacl
systemctl cat openvpn-server@.service | head -n 45`,kind:'linux',risk:'read'}]
  },
  {
    id:'pki',group:'03 / SECURITY',title:'Certificate Authority & server keys',subtitle:'Easy-RSA · unique server identity',introduction:'PKI/CA VPN-এর Trust Root। Production-এ CA Private Key Offline/Admin Host-এ রাখা উত্তম। নিচের Simple Fresh-VPS Workflow ছোট পরীক্ষামূলক Deployment-এর জন্য; CA Backup/Separation পরিকল্পনা ছাড়া বড় Client Production-এ ব্যবহার করবে না।',checkpoint:'CA, Server Certificate, Server Key, DH, tls-crypt key তৈরি হয়েছে',notes:['CA Passphrase Input Terminal-এ হবে; Chat বা Browser UI-তে নয়।','init-pki বা build-ca দ্বিতীয়বার চালালে Existing Clients অকার্যকর হতে পারে।','নতুন Device-এর জন্য পৃথক Client Certificate ব্যবহার করলে Revoke/Tracking সহজ হয়।'],blocks:[
      {title:'Linux — initialize brand-new PKI',detail:'Existing /etc/openvpn/easy-rsa থাকলে থামবে।',code:String.raw`if sudo test -e /etc/openvpn/easy-rsa; then
  echo 'STOP: existing Easy-RSA / PKI directory: review first'
else
  sudo make-cadir /etc/openvpn/easy-rsa && cd /etc/openvpn/easy-rsa && sudo ./easyrsa init-pki && sudo ./easyrsa build-ca
fi`,kind:'linux',risk:'sensitive',note:'build-ca চলাকালে CA Passphrase ও Common Name চাইবে। CA Passphrase ভুলে গেলে Client Cert Sign করা যাবে না।'},
      {title:'Linux — server request, signing & DH',detail:'Sample CN sentinel-server; চাইলে কোম্পানি-সম্মত আলাদা নাম ব্যবহার করো।',code:String.raw`cd /etc/openvpn/easy-rsa
sudo ./easyrsa gen-req sentinel-server nopass
sudo ./easyrsa sign-req server sentinel-server
sudo ./easyrsa gen-dh`,kind:'linux',risk:'sensitive'},
      {title:'Linux — install certificates without overwriting existing files',detail:'প্রথমবারের আগে নিশ্চিত হবে Destination-এ পুরোনো Server Files নেই।',code:String.raw`sudo install -d -o root -g root -m 700 /etc/openvpn/server
sudo test ! -e /etc/openvpn/server/ca.crt && sudo test ! -e /etc/openvpn/server/tls-crypt.key && sudo test ! -e /etc/openvpn/server/sentinel-server.key && sudo install -m 644 /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/server/ca.crt
sudo install -m 644 /etc/openvpn/easy-rsa/pki/issued/sentinel-server.crt /etc/openvpn/server/sentinel-server.crt
sudo install -m 600 /etc/openvpn/easy-rsa/pki/private/sentinel-server.key /etc/openvpn/server/sentinel-server.key
sudo install -m 644 /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/server/dh.pem
sudo openvpn --genkey tls-crypt /etc/openvpn/server/tls-crypt.key
sudo chmod 600 /etc/openvpn/server/tls-crypt.key`,kind:'linux',risk:'sensitive',note:'এগুলো Secret-bearing Files; Server Admin ছাড়া Access দেবে না।'},
    ]
  },
  {
    id:'serverconfig',group:'04 / SERVER',title:'OpenVPN server.conf — exact file & lines',subtitle:'Copy configuration text; do not execute in shell',introduction:'কোথায় Paste করবে: PuTTY-তে sudoedit /etc/openvpn/server/server.conf খুলে নিচের Configuration Text Paste করো। একে Shell Command হিসেবে Execute করবে না। Full-Tunnel চাইলে Network Policy যাচাই করে Route Push Line-গুলো চালু করতে হবে।',checkpoint:'server.conf reviewed, original/new destination confirmed, certificates paths match',notes:['Dev tun0 ব্যবহৃত হলেও Existing EU-01-এ tun-eu01 ছিল: Fresh VPS Example Production-এর Existing Config-এ প্রয়োগ করবে না।','OpenVPN CE 2.6 অনুযায়ী status-version 3 Tab-separated; Sentinel Session Parser এটি সমর্থন করে।','UDP 1194 Protocol; Client .ovpn-এও একই proto/port থাকবে।'],blocks:[
      {title:'Linux — open configuration editor (new setup only)',detail:'বড় Config Paste করার আগে প্রথম Check SUCCESS হতে হবে।',code:String.raw`sudo test ! -e /etc/openvpn/server/server.conf && sudoedit /etc/openvpn/server/server.conf`,kind:'linux',risk:'change'},
      {title:'CONFIG TEXT — paste INSIDE /etc/openvpn/server/server.conf',detail:'এই Block Linux Terminal-এ Run করা যাবে না; editor-এ Paste করবে।',code:String.raw`port 1194
proto udp
dev tun0
topology subnet
server 10.8.0.0 255.255.255.0
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/sentinel-server.crt
key /etc/openvpn/server/sentinel-server.key
dh /etc/openvpn/server/dh.pem
tls-crypt /etc/openvpn/server/tls-crypt.key
data-ciphers AES-256-GCM:AES-128-GCM
tls-version-min 1.2
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
status /var/log/openvpn/status-server.log 10
status-version 3
verb 3
explicit-exit-notify 1
# Review networking policy before enabling FULL TUNNEL:
# push "redirect-gateway def1"
# push "dhcp-option DNS 1.1.1.1"`,kind:'config',risk:'reference',note:'Certificate + PAM Username/Password চাইলে অতিরিক্ত Plugin Line লাগবে—পরের Authentication Section দেখো।'},
      {title:'Linux — prepare status file for OpenVPN runtime',detail:'OpenVPN nobody:nogroup-এ Privilege Drop করলে Status File লেখার অনুমতি থাকবে।',code:String.raw`sudo install -d -o root -g root -m 755 /var/log/openvpn
sudo test ! -e /var/log/openvpn/status-server.log && sudo install -o nobody -g nogroup -m 600 /dev/null /var/log/openvpn/status-server.log
sudo stat -c '%n | %U:%G | %a' /var/log/openvpn/status-server.log`,kind:'linux',risk:'change'}]
  },
  {
    id:'authmap',group:'05 / AUTHENTICATION',title:'Understand VPN Client ID vs Login User ID',subtitle:'Certificate-only vs Certificate + Password',introduction:'এটি সবচেয়ে গুরুত্বপূর্ণ পার্থক্য। Certificate-only Mode-এ VPN User/Device ID = Certificate Common Name; কোনো Login Password লাগে না। Certificate + PAM Mode-এ Client Certificate ছাড়াও আলাদা Linux/PAM Username ও Password লাগে, এবং Server-এ PAM Plugin সঠিকভাবে Configure করতে হবে।',checkpoint:'সঠিক Authentication Method নির্বাচন করা হয়েছে',notes:['একটি Common Name/Certificate বহু ব্যক্তির মধ্যে Share করো না; একই User বারবার Connect করলে Session Count Connection Count, People Count নয়।','PAM User Account এবং Server SSH Admin User কখনো এক করো না; sudo/Admin Role দেওয়া যাবে না।','Large Multi-Client Deployment-এর জন্য Central Identity Provider (RADIUS/LDAP/MFA) পরিকল্পনা করো।'],blocks:[
      {title:'Linux — certificate/device ID কোথায় বসবে?',detail:'নিচের {{VPN_CLIENT_ID}}-তে Customizer-এ দেওয়া Device ID বসবে।',code:String.raw`# DEVICE ID = {{VPN_CLIENT_ID}}
# Certificate generation happens later in section CLIENT CERT.
# Certificate identity is NOT a Linux password login.
cd /etc/openvpn/easy-rsa
sudo ./easyrsa show-cert {{VPN_CLIENT_ID}}`,kind:'linux',risk:'read',note:'Client Certificate এখনো না থাকলে show-cert ব্যর্থ হওয়া স্বাভাবিক।'},
      {title:'Linux — generate an optional strong password locally',detail:'শুধু PAM Mode-এর জন্য Password তৈরি করলে এটি Password Manager-এ Save করবে। Terminal Output অন্য কারও সঙ্গে Share করবে না।',code:String.raw`openssl rand -base64 24`,kind:'linux',risk:'sensitive',note:'Generated Password Linux Account-এ Apply করতে sudo passwd ব্যবহার করবে; শুধু Random String তৈরি করলেই Login Password সেট হয় না।'},
    ]
  },
  {
    id:'pam',group:'06 / PASSWORD LOGIN',title:'Optional PAM User ID + Password setup',subtitle:'Enable only if Username/Password authentication is required',introduction:'শুধু Certificate-ভিত্তিক VPN চাইলে এই ধাপ SKIP করো। Password Login চাইলে PAM Plugin, PAM Service Policy, Linux Account এবং Client auth-user-pass—সবগুলো সঠিকভাবে Configure করতে হবে। Test VPS-এ Pilot করার পরে Production-এ Apply করো।',checkpoint:'যদি PAM নির্বাচিত হয়: Plugin, PAM Service, User Account ও Client Auth Setup যাচাই হয়েছে',notes:['sudo passwd-এ Password Screen-এ দেখা যাবে না। CA Passphrase এবং VPN User Password আলাদা।','Plugin না থাকলে .ovpn-এ auth-user-pass বসিয়েও Login কাজ করবে না; Server Log-এ AUTH_FAILED দেখা যেতে পারে।','সাধারণ Linux PAM Account তৈরি করলেই সে VPN-এ ঢুকতে পারবে না, যতক্ষণ না Server Plugin Config ও Certificate অনুমোদিত।'],blocks:[
      {title:'Linux — verify available PAM plugin path',detail:'Installation অনুযায়ী Plugin Path পরিবর্তিত হতে পারে; পাওয়া Output পরে Config-এ ব্যবহার করবে।',code:String.raw`sudo find /usr/lib /lib -type f -name '*auth-pam*.so' -print 2>/dev/null
sudo test -f /etc/pam.d/openvpn && echo 'EXISTING PAM POLICY: REVIEW FIRST' || echo 'NO OPENVPN PAM POLICY YET'`,kind:'linux',risk:'read'},
      {title:'Linux — create separate non-admin VPN Login User ID',detail:'Customizer-এর {{VPN_USERNAME}} হবে PAM Username, Certificate ID নয়।',code:String.raw`if getent passwd {{VPN_USERNAME}} >/dev/null; then
  echo 'STOP: user already exists; review existing account'
else
  sudo useradd --no-create-home --shell /usr/sbin/nologin {{VPN_USERNAME}} && sudo passwd {{VPN_USERNAME}}
  sudo passwd -S {{VPN_USERNAME}}
fi`,kind:'linux',risk:'sensitive',note:'Account আগে থাকলে useradd দ্বিতীয়বার চালাবে না। passwd-এ নতুন Login Password দুইবার দিতে হবে। sudo Group বা SSH Access দেবে না।'},
      {title:'Linux — create PAM service policy using editor',detail:'Existing /etc/pam.d/openvpn থাকলে Backup ও Review ছাড়া Overwrite করবে না।',code:String.raw`sudo test ! -e /etc/pam.d/openvpn && sudoedit /etc/pam.d/openvpn`,kind:'linux',risk:'change'},
      {title:'CONFIG TEXT — paste inside /etc/pam.d/openvpn',detail:'Ubuntu PAM-এ common-auth/common-account ব্যবহার করে Password ও Account Policy যাচাই করবে।',code:String.raw`# OpenVPN PAM login policy — review Ubuntu PAM configuration
@include common-auth
@include common-account`,kind:'config',risk:'reference'},
      {title:'CONFIG TEXT — add ONE plugin line to server.conf',detail:'প্রথম Block-এর find Command-এ যে Full Path পাওয়া যাবে সেটি এখানে বসাবে; উদাহরণের PLUGIN_PATH_AS_FOUND ব্যবহার করবে না।',code:String.raw`# In /etc/openvpn/server/server.conf (additional line):
plugin PLUGIN_PATH_AS_FOUND openvpn`,kind:'config',risk:'reference',note:'Actual Path উদাহরণ: /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so (Distribution অনুযায়ী আলাদা হতে পারে)। Restart Approval ও Backup লাগবে।'},
      {title:'Linux — verify PAM username has NO admin membership',detail:'Account তৈরি হয়েছে কি না এবং প্রশাসনিক Group-এ আছে কি না দেখো।',code:String.raw`id {{VPN_USERNAME}}
sudo passwd -S {{VPN_USERNAME}}
sudo grep -nE '^(auth|account|@include)' /etc/pam.d/openvpn`,kind:'linux',risk:'read'}]
  },
  {
    id:'network',group:'07 / INTERNET',title:'IP forwarding, NAT & firewall',subtitle:'Full-tunnel + public internet requires review',introduction:'VPN Connect করলেই Internet Routing কাজ করে না। Full-Tunnel চাইলে server.conf-এ redirect-gateway Push, IPv4 Forwarding, WAN NAT, FORWARD Allow, Cloud Firewall, DNS ও IPv6 Policy প্রয়োজন। Wrong Firewall Rules SSH Lockout ঘটাতে পারে।',checkpoint:'WAN detected, Cloud UDP Port, NAT, Forwarding, DNS/IPv6 Strategy verified',notes:['Oracle Cloud-এ Security List/NSG এবং OS Firewall উভয়ই Allow করতে হতে পারে। SSH 22/TCP Access বন্ধ করবে না।','IPv6 Traffic নিয়ন্ত্রণ/Route ছাড়া শুধু IPv4 VPN দিয়ে সব Traffic Tunnel হবে না; DNS/IPv6 Leak Test বাধ্যতামূলক।','iptables-nft ও UFW Rule Persistence যাচাই ছাড়া Production শেষ ঘোষণা করা যাবে না।'],blocks:[
      {title:'Linux — inspect WAN and current firewall safely',detail:'WAN Interface eth0/enp0s5 Server অনুযায়ী ভিন্ন।',code:String.raw`ip -4 route show default
ip -br -4 addr
sudo sysctl net.ipv4.ip_forward
sudo iptables -S FORWARD
sudo iptables -t nat -S POSTROUTING
sudo ufw status verbose || true`,kind:'linux',risk:'read'},
      {title:'Linux — enable IPv4 forwarding (approved fresh VPS only)',detail:'এটি Host Network পরিবর্তন করে; Backup/Cloud Console Recovery প্রস্তুত রাখবে।',code:String.raw`sudo sysctl -w net.ipv4.ip_forward=1
printf '%s\n' 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/60-stagprime-openvpn.conf
sudo sysctl --system`,kind:'linux',risk:'change'},
      {title:'Linux — reviewed iptables rules for FULL TUNNEL',detail:'নির্দিষ্ট tun0 এবং VPN subnet-এর জন্য Idempotent Rules; অন্য Firewall Managers থাকলে Blind Run নয়।',code:String.raw`VPN_NET=10.8.0.0/24
VPN_IF=tun0
WAN_IF=$(ip -4 route show default | awk '$1=="default"{print $5;exit}')
test -n "$WAN_IF" || { echo 'STOP: no WAN interface'; exit 1; }
echo "VPN=$VPN_IF | WAN=$WAN_IF | NET=$VPN_NET"
sudo iptables -C FORWARD -i "$VPN_IF" -s "$VPN_NET" -o "$WAN_IF" -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD 1 -i "$VPN_IF" -s "$VPN_NET" -o "$WAN_IF" -j ACCEPT
sudo iptables -C FORWARD -i "$WAN_IF" -o "$VPN_IF" -d "$VPN_NET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD 1 -i "$WAN_IF" -o "$VPN_IF" -d "$VPN_NET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -C POSTROUTING -s "$VPN_NET" -o "$WAN_IF" -j MASQUERADE 2>/dev/null || sudo iptables -t nat -A POSTROUTING -s "$VPN_NET" -o "$WAN_IF" -j MASQUERADE`,kind:'linux',risk:'change',note:'Reboot-এর পরে Rule Persistence তোমার Distro/Firewall Management অনুযায়ী Configure করতে হবে; UFW/nftables থাকলে এই Example সরাসরি ব্যবহার করো না।'},
      {title:'CONFIG TEXT — Full-tunnel + DNS lines in server.conf',detail:'এই লাইনগুলো server.conf-এর Comment থেকে আনকমেন্ট করতে পারো—তবে NAT, IPv6, DNS Review ছাড়া নয়।',code:String.raw`push "redirect-gateway def1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"`,kind:'config',risk:'reference'},
      {title:'Linux — UFW/Cloud Firewall spot checks',detail:'Cloud Console-এ VPN UDP 1194 Ingress অনুমোদন করো; Production SSH Rule অক্ষত রাখো।',code:String.raw`sudo ufw status numbered
sudo ss -lunp | grep ':1194' || true
sudo iptables -t nat -S POSTROUTING`,kind:'linux',risk:'read'}]
  },
  {
    id:'start-service',group:'08 / VALIDATION',title:'Start OpenVPN & verify server health',subtitle:'Service starts only after review',introduction:'Fresh VPS-এ Config/PKI/Firewall সঠিক হলে OpenVPN Service চালু করো। Existing Production VPN Restart করার আগে Client Approval ও Maintenance Window অপরিহার্য।',checkpoint:'Active service, tun0, UDP 1194 ও status file verified',notes:['tun0 State UNKNOWN দেখানো Linux TUN-এর জন্য স্বাভাবিক হতে পারে।','Status File ফাঁকা বা CLIENT_LIST শূন্য হলে Connected Sessions 0; Unreadable হলে Unknown।'],blocks:[
      {title:'Linux — pre-start certificate and directive checks',detail:'কোনো Private Key Screen-এ দেখানো হবে না।',code:String.raw`sudo test -s /etc/openvpn/server/server.conf
sudo test -s /etc/openvpn/server/ca.crt
sudo test -s /etc/openvpn/server/sentinel-server.crt
sudo test -s /etc/openvpn/server/sentinel-server.key
sudo test -s /etc/openvpn/server/tls-crypt.key
sudo grep -nE '^(port|proto|dev|server|tls-crypt|status|status-version|plugin)' /etc/openvpn/server/server.conf`,kind:'linux',risk:'read'},
      {title:'Linux — enable and start NEW server instance',detail:'এই Command OpenVPN Service চালু করে—শুধু Fresh VPS-এ।',code:String.raw`sudo systemctl enable --now openvpn-server@server`,kind:'linux',risk:'change'},
      {title:'Linux — service, listener, tunnel and status check',detail:'এখানে Session Count File-এর Real Client Rows-এর ওপর নির্ভর করবে।',code:String.raw`systemctl is-active openvpn-server@server
ip -br -4 addr show tun0
sudo ss -lunp | grep ':1194' || true
sudo journalctl -u openvpn-server@server -n 30 --no-pager
sudo stat -c '%n | %s bytes | %y | %U:%G' /var/log/openvpn/status-server.log`,kind:'linux',risk:'read'}]
  },
  {
    id:'client-cert',group:'09 / CLIENT',title:'Create a unique OpenVPN Client / Device ID',subtitle:'Exact place to put user ID',introduction:'Customizer-এ VPN Client / Device ID = {{VPN_CLIENT_ID}} সেট করো। এটি Certificate Common Name। যেমন Device-01, Tariq-Android, Client-Laptop-01—প্রতিটি Device-এর আলাদা Certificate রাখবে।',checkpoint:'Unique Client Certificate + private key generated; matching files exist',notes:['Client Certificate create করলে CA Passphrase চাইতে পারে—সেটি VPN Login Password নয়।','Device Key-তে nopass থাকলে .ovpn Profile-ই Sensitive; Untrusted Messenger/Email-এ পাঠাবে না।','ঐ Client ID Certificate-Only VPN-এর Authentication Identity; PAM Password ব্যবহার করলে অতিরিক্ত User ID আলাদা।'],blocks:[
      {title:'Linux — verify unique ID is not already issued',detail:'Customizer-এর {{VPN_CLIENT_ID}}-কে এক Client/Device-এর জন্য একবার ব্যবহার করবে।',code:String.raw`cd /etc/openvpn/easy-rsa
sudo test ! -e pki/issued/{{VPN_CLIENT_ID}}.crt && echo 'CLIENT ID IS AVAILABLE' || echo 'STOP: CERTIFICATE EXISTS'
sudo test ! -e pki/private/{{VPN_CLIENT_ID}}.key && echo 'KEY PATH AVAILABLE' || echo 'STOP: KEY EXISTS'`,kind:'linux',risk:'read'},
      {title:'Linux — generate and sign unique client certificate',detail:'Certificate-only অথবা PAM দুই পদ্ধতিতেই এই Client Certificate লাগবে।',code:String.raw`cd /etc/openvpn/easy-rsa && sudo test ! -e pki/issued/{{VPN_CLIENT_ID}}.crt && sudo test ! -e pki/private/{{VPN_CLIENT_ID}}.key && sudo ./easyrsa build-client-full {{VPN_CLIENT_ID}} nopass`,kind:'linux',risk:'sensitive',note:'Signature দিতে CA Password চাইতে পারে। Commands-এ {{VPN_CLIENT_ID}} বসে গেছে—সার্টিফিকেটের Identity এই নাম।'},
      {title:'Linux — verify client certificate metadata',detail:'Client-এর Private Key দেখাবে না।',code:String.raw`cd /etc/openvpn/easy-rsa
sudo ./easyrsa show-cert {{VPN_CLIENT_ID}}
sudo test -s pki/issued/{{VPN_CLIENT_ID}}.crt
sudo test -s pki/private/{{VPN_CLIENT_ID}}.key && echo 'CLIENT KEY READY'`,kind:'linux',risk:'read'}]
  },
  {
    id:'ovpn-profile',group:'10 / PROFILE',title:'Build a complete .ovpn profile (inline)',subtitle:'CA + Client Cert + Private Key + tls-crypt',introduction:'এখন একটি .ovpn-এ Certificate, Client Private Key এবং tls-crypt Key সব Embed করব, যেন Mobile/Windows OpenVPN Client-এ এক File Import করা যায়। Script Output-এ Secret Contents ছাপাবে না।',checkpoint:'.ovpn file created in /home/{{SSH_USERNAME}} and permission 600',notes:['{{SERVER_PUBLIC_IP}} অবশ্যই VPN Service-এর Public IP/DNS (Oracle private 10.0.0.x নয়)।','PAM Login চালু থাকলে Customizer-এ Certificate + PAM Mode নির্বাচন করো; এতে .ovpn-এ auth-user-pass Line যোগ হবে।','যে PC-তে Copy করছ সেটি নিরাপদ হতে হবে; .ovpn-এর মধ্যে Private Key থাকে।'],blocks:[
      {title:'Linux — generate self-contained .ovpn profile (fresh workflow)',detail:'Full Block Copy করে Ubuntu PuTTY-তে Run করবে। আগে Certificate, tls-crypt ও Public IP নিশ্চিত করো। Existing .ovpn থাকলে Script থামবে।',code:String.raw`sudo bash <<'PROFILE'
set -euo pipefail
CLIENT='{{VPN_CLIENT_ID}}'
PUBLIC_IP='{{SERVER_PUBLIC_IP}}'
SSH_USER='{{SSH_USERNAME}}'
AUTH_MODE='{{AUTH_MODE}}'
PKI=/etc/openvpn/easy-rsa/pki
TLS=/etc/openvpn/server/tls-crypt.key
DEST="/home/$SSH_USER/$CLIENT.ovpn"

id "$SSH_USER" >/dev/null
for f in "$PKI/ca.crt" "$PKI/issued/$CLIENT.crt" "$PKI/private/$CLIENT.key" "$TLS"; do
  test -s "$f" || { echo 'STOP: required file missing'; exit 1; }
done
test ! -e "$DEST" || { echo 'STOP: profile already exists'; exit 1; }
umask 077
{
  printf '%s\n' 'client' 'dev tun' 'proto udp' "remote $PUBLIC_IP 1194" \
    'resolv-retry infinite' 'nobind' 'persist-key' 'persist-tun' \
    'remote-cert-tls server' 'data-ciphers AES-256-GCM:AES-128-GCM' \
    'auth-nocache' 'verb 3'
  if [ "$AUTH_MODE" = 'pam' ]; then printf '%s\n' 'auth-user-pass'; fi
  printf '<ca>\n'
  sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$PKI/ca.crt"
  printf '</ca>\n<cert>\n'
  sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$PKI/issued/$CLIENT.crt"
  printf '</cert>\n<key>\n'
  cat "$PKI/private/$CLIENT.key"
  printf '\n</key>\n<tls-crypt>\n'
  cat "$TLS"
  printf '\n</tls-crypt>\n'
} > "$DEST"
chown "$SSH_USER:$(id -gn "$SSH_USER")" "$DEST"
chmod 600 "$DEST"
echo 'PROFILE GENERATED (content hidden):'
stat -c '%n | %s bytes | %a | %U:%G' "$DEST"
PROFILE`,kind:'linux',risk:'sensitive',note:'AUTH_MODE শুধু PAM Server Plugin চালু থাকলেই pam হবে। Certificate-only হলে certificate হবে। DEST-এ বর্তমানে File থাকলে Overwrite হবে না।'},
      {title:'Linux — verify .ovpn structure WITHOUT revealing private key',detail:'এই Command Secret Content নয়—শুধু Line Count ও Field Names দেখায়।',code:String.raw`test -s /home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn && echo 'OVPN FILE EXISTS'
stat -c '%n | %s bytes | %a | %U:%G' /home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn
grep -c '^<ca>$' /home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn
grep -c '^<cert>$' /home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn
grep -c '^<key>$' /home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn
grep -c '^<tls-crypt>$' /home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn`,kind:'linux',risk:'read'}]
  },
  {
    id:'windows-download',group:'11 / WINDOWS',title:'Download .ovpn from Windows CMD (PPK key)',subtitle:'No Linux password required if SSH key works',introduction:'এটি আমাদের EU-01-এর মতোই: PuTTY Login-এর জন্য ব্যবহৃত .ppk Private Key Windows CMD-এর pscp.exe-কে দেবে। CMD Command কখনো Ubuntu/PuTTY Terminal-এ চালাবে না।',checkpoint:'Windows PC-তে .ovpn File Download, Size Check, Secure Storage হয়েছে',notes:['PuTTY-এর SSH Key Passphrase থাকলে সেটি চাইতে পারে; Linux Password প্রয়োজন নেই যদি Server ঐ Public Key অনুমোদন করে।','Windows CMD-এ %ProgramFiles%\PuTTY\pscp.exe Path। অন্য Folder হলে where pscp দিয়ে Path যাচাই করো।','PSCP প্রথমবার Host-Key Fingerprint Confirm চাইতে পারে: Server-এর জানা Fingerprint মিলিয়ে Confirm করবে। Blind Accept নয়।','OpenSSH scp -i সরাসরি PuTTY .ppk নিতে পারে না; PuTTYgen দিয়ে OpenSSH Format Export না করলে pscp -i ব্যবহার করো।'],blocks:[
      {title:'Windows CMD — verify local PuTTY pscp & key',detail:'নিচের Command Windows CMD-তে চালাবে; Linux Server-এ নয়।',code:String.raw`where pscp
if exist "{{PPK_PATH}}" echo SSH PRIVATE KEY FOUND
if exist "%ProgramFiles%\PuTTY\pscp.exe" echo PSCP FOUND`,kind:'windows',risk:'read'},
      {title:'Windows CMD — download .ovpn securely over SSH',detail:'Copy করে নিজের CMD-তে চালাবে। Server থেকে Local PC-তে File যাবে।',code:String.raw`if not exist "{{WINDOWS_DEST}}" mkdir "{{WINDOWS_DEST}}"
"%ProgramFiles%\PuTTY\pscp.exe" -i "{{PPK_PATH}}" "{{SSH_USERNAME}}@{{SSH_HOST}}:/home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn" "{{WINDOWS_DEST}}\"`,kind:'windows',risk:'sensitive',note:'No WinSCP Password required; .ppk Key দিয়েই PSCP Login হবে। SSH_HOST এবং VPN Public IP সাধারণত একই হলেও Cloud NAT / Bastion থাকলে ভিন্ন হতে পারে।'},
      {title:'Windows CMD — verify downloaded file exists',detail:'Client File নামটি Customizer থেকে বসবে। CMD Output-এ File Contents দেখাবে না।',code:String.raw`dir "{{WINDOWS_DEST}}\{{VPN_CLIENT_ID}}.ovpn"`,kind:'windows',risk:'read'},
      {title:'Windows CMD — if PSCP is installed elsewhere',detail:'where pscp.exe-তে পাওয়া Path ব্যবহার করে এই Alternative চালাও।',code:String.raw`pscp.exe -i "{{PPK_PATH}}" "{{SSH_USERNAME}}@{{SSH_HOST}}:/home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn" "{{WINDOWS_DEST}}\"`,kind:'windows',risk:'sensitive'}]
  },
  {
    id:'import-test',group:'12 / CLIENT TEST',title:'Import .ovpn, connect & verify public IP',subtitle:'OpenVPN Connect / community GUI client',introduction:'Windows বা Android-এ VPN Client App-এ নিজের .ovpn Import করো। Client Mode certificate হলে Password Prompt নাও থাকতে পারে। Certificate + PAM হলে আলাদা Username/Password চাইবে।',checkpoint:'External device connect, Public IP/DNS/IPv6 Leak ও internet tested',notes:['Windows-এ OpenVPN Connect হলো Client App; Server কিন্তু Community Edition—এটি পরস্পর বিরোধী নয়।','VPN Connected দেখানো এবং সব Internet Traffic VPN দিয়ে যাচ্ছে—দুইটি আলাদা Check।','Security Group/Cloud Firewall-এ UDP 1194 এবং Full-Tunnel NAT, DNS/IPv6 Routing যাচাই করো।'],blocks:[
      {title:'Windows CMD — basic network checks before and after connection',detail:'PowerShell/CMD-এ Browser-এ Public IP/DNS Test-ও করো; CMD Result পুরোটাই যথেষ্ট নয়।',code:String.raw`nslookup example.com
tracert 1.1.1.1`,kind:'windows',risk:'read'},
      {title:'Linux — check live server, tunnel and session status (privacy notice)',detail:'Status File-এ Client Public IP থাকতে পারে। Screenshot নেওয়ার আগে Redact করো।',code:String.raw`systemctl is-active openvpn-server@server
ip -br -4 addr show tun0
sudo stat -c '%n | %s bytes | %y' /var/log/openvpn/status-server.log
sudo journalctl -u openvpn-server@server -n 20 --no-pager`,kind:'linux',risk:'read'}]
  },
  {
    id:'monitoring',group:'13 / SENTINEL',title:'Prepare OpenVPN status for Sentinel SSH',subtitle:'Live sessions · read-only access',introduction:'Sentinel কোন User Connected তা Status File থেকে পড়ে। File-এ Client IP থাকতে পারে; Dashboard-এ Sensitive Information না দেখানো ও Access Control গুরুত্বপূর্ণ। User `{{SSH_USERNAME}}`-কে শুধু File Read Permission দেওয়া হবে, sudo/root নয়।',checkpoint:'Status File freshly updating; SSH User can read; Session Count available',notes:['OpenVPN version 3 = Tab-separated; same Certificate/User Multiple Connection হলে Count আলাদা থাকবে।','Status File পুনরায় তৈরি হলে ACL Reset হতে পারে—কাজ না করলে ACL/Owner আবার পরীক্ষা করো।','OpenVPN Service Name EU-01-এ @eu01, EU-02/MENA-01-এ @server হতে পারে; Fresh Sample @server।'],blocks:[
      {title:'Linux — verify status freshness and current access',detail:'Password বা Client IP প্রকাশ করবে না।',code:String.raw`systemctl is-active openvpn-server@server
sudo stat -c '%n | %s bytes | %y | %U:%G | %a' /var/log/openvpn/status-server.log
sudo -u {{SSH_USERNAME}} test -r /var/log/openvpn/status-server.log && echo 'SENTINEL ACCESS READY' || echo 'READ ACCESS MISSING'`,kind:'linux',risk:'read'},
      {title:'Linux — grant limited READ ACL to SSH monitor user',detail:'Authorization লাগবে; Directory traversal ঠিক থাকতে হবে। 777 Permission দেবে না।',code:String.raw`sudo setfacl -m u:{{SSH_USERNAME}}:r-- /var/log/openvpn/status-server.log
sudo -u {{SSH_USERNAME}} test -r /var/log/openvpn/status-server.log && echo 'STATUS READABLE'
sudo getfacl -p /var/log/openvpn/status-server.log`,kind:'linux',risk:'change'},
      {title:'Linux — check server specific status path/config (read-only)',detail:'কোনো Existing Instance-এর Config থাকলে তার নিজস্ব Service/Status Path ব্যবহার করবে।',code:String.raw`sudo grep -nE '^[[:space:]]*(status|status-version)[[:space:]]+' /etc/openvpn/server/server.conf || true
sudo find /var/log/openvpn /run/openvpn -maxdepth 2 -type f -iname '*status*' -printf '%p | %s bytes\n' 2>/dev/null || true`,kind:'linux',risk:'read'}]
  },
  {
    id:'capacity',group:'14 / PERFORMANCE',title:'High speed, limits & optimization',subtitle:'Measure first; no magic unlimited-bandwidth switch',introduction:'Community Edition-এ Licensed Concurrent Seat Cap নেই। কিন্তু Hardware, CPU Encryption, VPS Network Port, Provider Fair Usage, MTU, UDP Packet Loss, Client Peering এবং Routing-এর সীমা আছে। Performance Change শুধুমাত্র Baseline পরিমাপের পরে করবে।',checkpoint:'Baseline throughput, latency, resource usage & IPv6/MTU policy measured',notes:['UDP সাধারণত VPN Throughput-এর জন্য ভালো; Compression বন্ধ রাখো।','Cumulative Network RX/TX কাউন্টার Live Mbps নয়। 10–60 সেকেন্ডের Delta ও Duration দিয়ে Mbps তৈরি করা দরকার।','DCO Support OpenVPN 2.6 Build, Kernel, Driver এবং Configuration-এর ওপর নির্ভর করে।','mssfix/MTU Adjustment Blindly বদলাবে না; EU-02-এর আগের MTU Problem-এর মতো Measure ও Test দরকার।'],blocks:[
      {title:'Linux — CPU/RAM/Disk/Network baseline',detail:'Traffic Counters cumulative; Live Rate হিসাবের জন্য দুটি Sample লাগবে।',code:String.raw`nproc
free -h
df -h
ip -s link show
ss -s
uptime
openvpn --version | head -n 5`,kind:'linux',risk:'read'},
      {title:'Linux — cipher, DCO and kernel support',detail:'OpenVPN 2.6-এ AES-GCM ও DCO Compatibility Review করো।',code:String.raw`openvpn --show-ciphers | grep -E 'AES-256-GCM|AES-128-GCM|CHACHA20' || true
lsmod | grep -Ei 'ovpn|dco' || true
uname -r
sudo journalctl -u openvpn-server@server -n 60 --no-pager | grep -Ei 'cipher|dco|mtu|warning|error' || true`,kind:'linux',risk:'read'},
      {title:'Linux — optional remote speed test preparation',detail:'iperf3 দিয়ে Client/Server-এর মধ্যকার Throughput Test; কাজের মধ্যে Test চালানোর অনুমতি নেবে।',code:String.raw`command -v iperf3 || echo 'iperf3 not installed'
ip -4 route show default
ip -s link show tun0`,kind:'linux',risk:'read'}]
  },
  {
    id:'revoke',group:'15 / LIFECYCLE',title:'Disable a user, revoke a device certificate',subtitle:'Identity-level access control',introduction:'একজন ব্যবহারকারীর Laptop হারালে বা Access বন্ধ করতে চাইলে শুধু Shared Password পরিবর্তন যথেষ্ট নয়। Unique Certificate Revoke করতে হবে। PAM User Password Lock করলে কেবল Password Mode-এর Login বন্ধ হবে; Certificate-only Clients-এর ওপর প্রভাব নেই।',checkpoint:'Revocation/CRL, PAM Lock ও client distribution policy documented',notes:['EasyRSA Version অনুযায়ী revoke বনাম revoke-issued Command আলাদা হতে পারে। আগে ./easyrsa help revoke দেখে নাও।','Revocation কার্যকর করতে Server Config-এ crl-verify এবং CRL Delivery/Reload Policy থাকতে হবে।','Client Private Key Share করলে স্বতন্ত্র ব্যক্তি শনাক্ত করা যায় না।'],blocks:[
      {title:'Linux — inspect Easy-RSA revocation commands',detail:'Revocation কার্যকর করার আগে Backup ও Client Approval নাও।',code:String.raw`cd /etc/openvpn/easy-rsa
sudo ./easyrsa help revoke
sudo ./easyrsa show-cert {{VPN_CLIENT_ID}}`,kind:'linux',risk:'read'},
      {title:'Linux — revoke compromised certificate (authorized only)',detail:'নির্দিষ্ট Certificate ID Revoke হবে; Production Change Review ছাড়া Execute নয়।',code:String.raw`cd /etc/openvpn/easy-rsa
sudo ./easyrsa revoke {{VPN_CLIENT_ID}}
sudo ./easyrsa gen-crl
# Review and deploy CRL, then apply in server.conf:
# crl-verify /etc/openvpn/server/crl.pem`,kind:'linux',risk:'sensitive',note:'EasyRSA Build-এ revoke-issued প্রয়োজন হলে help Output অনুসরণ করো। শুধু gen-crl করলেই Server Automatically Revoke Enforce করে না।'},
      {title:'Linux — lock optional PAM login (does NOT revoke cert)',detail:'PAM Mode-এর Account Disable; Certificate-only Access আলাদাভাবে Revoke করো।',code:String.raw`sudo passwd -l {{VPN_USERNAME}}
sudo passwd -S {{VPN_USERNAME}}`,kind:'linux',risk:'change'}]
  },
  {
    id:'backups',group:'16 / OPERATIONS',title:'Backups, updates, persistent firewall & rollback',subtitle:'No unapproved service restart',introduction:'Production Service-এ পরিবর্তনের আগে Config, Firewall Rules, CA/PKI Metadata ও Rollback Plan সংরক্ষণ করো। Backup নিরাপদ Encrypted Storage-এ রাখবে; CA Private Key ও Client Keys সাধারণ Reports-এ থাকবে না।',checkpoint:'Verified encrypted backups, rollback, firewall persistence & maintenance plan',notes:['UFW/nftables/iptables Provider Integration অনুযায়ী Persist করবে; Blindly iptables-persistent দিয়ে Existing Firewall Overwrite করবে না।','Client-এর অনুমতি ছাড়া yum/apt upgrade বা OpenVPN Restart করবে না।','OpenVPN Log ও Status Retention-এ Privacy Policy মেনে চলবে।'],blocks:[
      {title:'Linux — inspect configuration & service versions before change',detail:'Read-only Inventory।',code:String.raw`systemctl list-units --all 'openvpn*' --no-pager
openvpn --version | head -n 5
sudo grep -nE '^(port|proto|dev|server|status|plugin)' /etc/openvpn/server/server.conf
sudo iptables-save | head -n 35`,kind:'linux',risk:'read'},
      {title:'Linux — backup existing server.conf safely',detail:'Backup Directory Root-only। No Restart।',code:String.raw`sudo bash -c 'set -eu; CONF=/etc/openvpn/server/server.conf; DEST="/root/openvpn-server-before-$(date -u +%Y%m%dT%H%M%SZ).conf"; test -s "$CONF"; cp -p "$CONF" "$DEST"; chmod 600 "$DEST"; echo "BACKUP: $DEST"'`,kind:'linux',risk:'change'},
      {title:'Linux — status/log diagnostic after a controlled change',detail:'Unexpected Error হলে Blind Repeat Restart নয়; Log Review।',code:String.raw`systemctl is-active openvpn-server@server
sudo journalctl -u openvpn-server@server --since '15 minutes ago' --no-pager | tail -n 80
sudo systemctl status openvpn-server@server --no-pager --lines=15`,kind:'linux',risk:'read'}]
  },
]

export const HELP_ITEMS: HelpItem[] = [
  {id:'authfailed',area:'AUTHENTICATION',issue:'AUTH_FAILED — Username / Password কাজ করছে না',cause:'PAM Plugin/Service Path ভুল, Account Password Locked, Client auth-user-pass অনুপস্থিত বা Account Policy Reject করছে।',fix:'PAM Service ও Plugin Path যাচাই; Password-কে .ovpn-এ Hardcode করবে না। Server Log-এ সঠিক কারণ দেখো।',code:String.raw`sudo find /usr/lib /lib -name '*auth-pam*.so' -type f 2>/dev/null
sudo grep -n '^[[:space:]]*plugin ' /etc/openvpn/server/server.conf || true
sudo grep -nE '^(auth|account|@include)' /etc/pam.d/openvpn || true
sudo journalctl -u openvpn-server@server -n 60 --no-pager`,kind:'linux',risk:'read'},
  {id:'noid',area:'CLIENT ACCOUNT',issue:'OpenVPN User ID কোথায় লিখব?',cause:'Client Certificate Common Name, Linux SSH User এবং PAM Username আলাদা Identifier।',fix:'Certificate: Personalization > Client ID > build-client-full। PAM Login: Personalization > PAM Username > useradd/passwd। .ovpn Profile-এ PAM Mode হলে auth-user-pass থাকবে।'},
  {id:'nopass',area:'CLIENT ACCOUNT',issue:'Password Generate করলেও Login হচ্ছে না',cause:'openssl rand শুধু String তৈরি করে; Linux PAM Account Password সেট করে না।',fix:'sudo passwd USERNAME দিয়ে Password Assign এবং Plugin Configuration নিশ্চিত করো।',code:String.raw`openssl rand -base64 24
sudo passwd {{VPN_USERNAME}}
sudo passwd -S {{VPN_USERNAME}}`,kind:'linux',risk:'sensitive'},
  {id:'tls',area:'TLS / CERTIFICATE',issue:'TLS Error / TLS key negotiation failed',cause:'UDP1194 Cloud Firewall বন্ধ, Remote IP/Port ভুল, tls-crypt Key mismatch অথবা VPS Listening নয়।',fix:'Server UDP Listener ও Cloud Firewall Rules যাচাই। CA/Private Key নতুন করে Generate করবে না।',code:String.raw`sudo ss -lunp | grep ':1194' || true
sudo journalctl -u openvpn-server@server -n 60 --no-pager
ip -4 route show default`,kind:'linux',risk:'read'},
  {id:'cert',area:'TLS / CERTIFICATE',issue:'VERIFY ERROR / Certificate verify failed',cause:'Wrong CA, Expired Certificate, Clock Skew অথবা remote-cert-tls server mismatch।',fix:'Certificate Dates, System Clock, Correct CA; সতর্কতা ছাড়া Certificate Regenerate নয়।',code:String.raw`date -u
sudo openssl x509 -in /etc/openvpn/server/sentinel-server.crt -noout -subject -issuer -dates
sudo journalctl -u openvpn-server@server -n 40 --no-pager`,kind:'linux',risk:'read'},
  {id:'config',area:'SERVER',issue:'OpenVPN Service failed / exit code 1',cause:'server.conf Syntax ভুল, Missing Cert/Key, TUN/Permissions, PAM Plugin ভুল।',fix:'Service Log দেখো; ঠিক করা Config ছাড়া বারবার Restart নয়।',code:String.raw`sudo systemctl status openvpn-server@server --no-pager --lines=50
sudo journalctl -xeu openvpn-server@server --no-pager | tail -n 90`,kind:'linux',risk:'read'},
  {id:'statusmissing',area:'MONITORING',issue:'Sentinel vpn_sessions_state = status_unavailable',cause:'Status Directive নেই, Status File নেই/Unreadable, Stale অথবা Collector ভুল Instance/Path খুঁজছে।',fix:'Config-এ Status Path, Status Version 3, File Freshness ও SSH User Read Access যাচাই। null মানে Zero নয়।',code:String.raw`sudo grep -nE '^[[:space:]]*(status|status-version)[[:space:]]+' /etc/openvpn/server/server.conf || true
sudo find /var/log/openvpn /run/openvpn -maxdepth 2 -type f -iname '*status*' -printf '%p | %s bytes\n' 2>/dev/null || true
sudo stat -c '%n | %s bytes | %y | %a | %U:%G' /var/log/openvpn/status-server.log 2>/dev/null || true`,kind:'linux',risk:'read'},
  {id:'zerocount',area:'MONITORING',issue:'Connected Sessions = 0, কিন্তু VPN Service Active',cause:'Session Count ফাইল সঠিকভাবে Read হচ্ছে, তবে Snapshot মুহূর্তে কোনো Active Connection নেই; Device Connect Fail করলেও এমন হয়।',fix:'Client-কে Connect করে Status Refresh দেখো। Count = Active Connections, Unique People নয়।'},
  {id:'acl',area:'PERMISSIONS',issue:'Status File Permission Denied',cause:'Status File Root/Unprivileged Owner, SSH User Read ACL নেই অথবা Restart-এ File Recreated।',fix:'File Owner/Path যাচাই; নির্দিষ্ট Monitor User-কে ACL Read দাও, chmod 777 নয়।',code:String.raw`sudo stat -c '%a %U:%G %n' /var/log/openvpn/status-server.log
sudo getfacl -p /var/log/openvpn/status-server.log
sudo -u {{SSH_USERNAME}} test -r /var/log/openvpn/status-server.log && echo 'READ OK' || echo 'READ DENIED'`,kind:'linux',risk:'read'},
  {id:'noroute',area:'INTERNET',issue:'VPN Connected, কিন্তু Internet কাজ করছে না',cause:'ip_forward=0, NAT/FORWARD Rules নেই, Cloud Firewall/DNS Problem বা Full-Tunnel Push অনুপস্থিত।',fix:'ip_forward, route, NAT, DNS এবং Config-এর push redirect-gateway যাচাই।',code:String.raw`sudo sysctl net.ipv4.ip_forward
sudo iptables -t nat -S POSTROUTING
sudo iptables -S FORWARD
ip -4 route show default
sudo grep -nE 'redirect-gateway|dhcp-option' /etc/openvpn/server/server.conf || true`,kind:'linux',risk:'read'},
  {id:'dns',area:'INTERNET',issue:'Connected, IP Ping হয় কিন্তু Website খুলে না',cause:'DNS Resolver Push/Client Resolver সমস্যা, DNS Leak বা Firewall।',fix:'Client nslookup Test করো; DNS Server/IPv6 Policy যাচাই।',code:String.raw`nslookup example.com
ipconfig /all`,kind:'windows',risk:'read'},
  {id:'ipv6',area:'INTERNET',issue:'VPN চালু, কিন্তু IPv6 / DNS Leak',cause:'IPv4-only Full Tunnel; Client Native IPv6 Traffic Tunnel-এর বাইরে যাচ্ছে।',fix:'সঠিক IPv6 Tunnel Routing বা অনুমোদিত Client-side IPv6 Policy দরকার; Browser leak check করো।'},
  {id:'mtu',area:'PERFORMANCE',issue:'Connected কিন্তু কিছু Website Slow / Hang',cause:'Path MTU / MSS mismatch, Packet Fragmentation, Provider UDP Path।',fix:'Latency/Packet Loss/MTU Measure; Blind mssfix 1240 Apply নয়।',code:String.raw`ip -s link show tun0
sudo journalctl -u openvpn-server@server -n 80 --no-pager | grep -Ei 'mtu|mss|fragment|warning|error' || true`,kind:'linux',risk:'read'},
  {id:'slow',area:'PERFORMANCE',issue:'Speed খুব কম — High-Speed Tuning কীভাবে?',cause:'VPS CPU, AES support, Network Port, ISP Peering, UDP Loss, DCO Incompatibility।',fix:'CPU/RX-TX Baseline + iperf3 Test; Compression নিষিদ্ধ, Cipher/MTU Provider Constraint Review।',code:String.raw`nproc
free -h
ip -s link show tun0
ss -s
openvpn --version | head -n 5`,kind:'linux',risk:'read'},
  {id:'ppk',area:'WINDOWS TRANSFER',issue:'pscp: No such file / .ppk key not found',cause:'Linux Terminal-এ Windows Command চালানো হয়েছে, PuTTY path ভুল, PPK location আলাদা।',fix:'নিজের Windows CMD-এ where pscp এবং File Existence Check।',code:String.raw`where pscp
if exist "{{PPK_PATH}}" echo KEY FOUND
if exist "%ProgramFiles%\PuTTY\pscp.exe" echo PSCP FOUND`,kind:'windows',risk:'read'},
  {id:'permissiondown',area:'WINDOWS TRANSFER',issue:'pscp Permission denied downloading .ovpn',cause:'SSH User File Read Access নেই বা Profile /root Folder-এ আছে।',fix:'Server থেকে সংশ্লিষ্ট User-এর Home Folder-এ Mode 600 File তৈরি এবং Owner SSH User করো। Profile Private Key Chat-এ পাঠাবে না।',code:String.raw`stat -c '%n %a %U:%G' /home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn
test -r /home/{{SSH_USERNAME}}/{{VPN_CLIENT_ID}}.ovpn && echo READABLE || echo DENIED`,kind:'linux',risk:'read'},
  {id:'keymismatch',area:'SSH',issue:'Permission denied (publickey)',cause:'Private PPK Key/SSH User/Server authorized_keys/Host Key mismatch।',fix:'PuTTY SSH Key Match/Port/Username Verify; Password Chat-এ দেবে না।'},
  {id:'oracle',area:'CLOUD PROVIDERS',issue:'Oracle Cloud VPS-এ VPN Internet কাজ করছে না',cause:'enp0s5 WAN, 10.0.0.3 Private IP, Security Lists/NSG, VNIC Source/Destination Check ইত্যাদি সেটিং দরকার হতে পারে।',fix:'WAN Interface Route থেকে শনাক্ত এবং Oracle Console-এর Networking Security/Source-Destination Policy যাচাই।',code:String.raw`ip -4 route show default
ip -br -4 addr
sudo iptables -t nat -S POSTROUTING`,kind:'linux',risk:'read'},
  {id:'lostclient',area:'CLIENT / REVOCATION',issue:'ফোন হারিয়ে গেছে, একটি Client Block করতে চাই',cause:'একটি Certificate বহু User-এর কাছে থাকলে Individual Block কঠিন।',fix:'Per-device Certificate Revoke + CRL Enforce। PAM Account Lock শুধু Password Login বন্ধ করে।'},
  {id:'logs',area:'LOGS',issue:'OpenVPN Connect হচ্ছে না — কোথায় Error দেখব?',cause:'Service Log, PAM Log, Cloud Firewall অথবা Client-side Log।',fix:'প্রথমে server journal এবং Client App Diagnostic; Redact Client Public IP/Username।',code:String.raw`sudo journalctl -u openvpn-server@server -n 100 --no-pager
systemctl is-active openvpn-server@server
sudo ss -lunp | grep ':1194' || true`,kind:'linux',risk:'read'},
  {id:'reboot',area:'STARTUP',issue:'Reboot-এর পরে VPN চালু থাকে না',cause:'Systemd Disabled, Firewall NAT Rules Persist হয়নি, Config Error।',fix:'Systemd enable state, journal boot logs এবং Rules Persistence যাচাই।',code:String.raw`systemctl is-enabled openvpn-server@server
systemctl is-active openvpn-server@server
sudo journalctl -b -u openvpn-server@server --no-pager | tail -n 60`,kind:'linux',risk:'read'},
]

export const OFFICIAL_LINKS = [
  {name:'Ubuntu Server OpenVPN guide',url:'https://ubuntu.com/server/docs/how-to/security/install-openvpn/'},
  {name:'OpenVPN Community 2.6 manual',url:'https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html'},
  {name:'OpenVPN PAM authentication guide',url:'https://openvpn.net/community-docs/using-alternative-authentication-methods.html'},
  {name:'Easy-RSA project',url:'https://github.com/OpenVPN/easy-rsa'},
  {name:'PuTTY / PSCP documentation',url:'https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html'},
]
