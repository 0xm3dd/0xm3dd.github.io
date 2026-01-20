---
title: CTF Tools and Techniques Guide
published: 2024-01-22
description: 'Essential tools, techniques, and methodologies for solving CTF challenges across various categories'
image: ''
tags: [CTF, Tools, Forensics, Crypto, OSINT]
category: 'Notes'
draft: false
---

# CTF Tools and Techniques Guide

A comprehensive guide to essential tools and techniques for different CTF challenge categories. Perfect for beginners and experienced players alike.

## General CTF Methodology

### Initial Approach
1. Read the challenge description carefully
2. Download and examine all provided files
3. Identify the challenge category
4. Use appropriate tools for reconnaissance
5. Document findings and attempts
6. Think outside the box

### Common Flag Formats
```
FLAG{...}
CTF{...}
flag{...}
HTB{...}
THM{...}
picoCTF{...}
```

## Cryptography

### Basic Encoding/Decoding

#### Base64
```bash
# Encode
echo "text" | base64

# Decode
echo "dGV4dA==" | base64 -d

# Multiple iterations
base64 -d file.txt | base64 -d | base64 -d
```

#### Hexadecimal
```bash
# Hex to ASCII
echo "48656c6c6f" | xxd -r -p

# ASCII to Hex
echo "Hello" | xxd -p

# Using Python
python3 -c "print(bytes.fromhex('48656c6c6f').decode())"
```

#### ROT13/Caesar Cipher
```bash
# ROT13
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Online tool: CyberChef
# Try all rotations: https://www.dcode.fr/caesar-cipher
```

### Common Ciphers

#### XOR
```python
# XOR with single byte key
def xor_single(data, key):
    return bytes([b ^ key for b in data])

# XOR with multi-byte key
def xor_multi(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

# Brute force single-byte XOR
for key in range(256):
    result = xor_single(ciphertext, key)
    if b'flag' in result.lower():
        print(f"Key: {key}, Text: {result}")
```

#### RSA
```python
# Common attacks
# - Small e attack
# - Wiener's attack (large d, small e)
# - Common modulus attack
# - Fermat factorization (p and q close)

# Using RsaCtfTool
python3 RsaCtfTool.py --publickey pubkey.pem --uncipherfile flag.enc

# Manual calculation
from Crypto.Util.number import *
n = ...
e = ...
c = ...
# If you have p and q
d = inverse(e, (p-1)*(q-1))
m = pow(c, d, n)
print(long_to_bytes(m))
```

### Useful Tools
```bash
# CyberChef - All-in-one encoder/decoder
# https://gchq.github.io/CyberChef/

# dCode - Cipher identifier and solver
# https://www.dcode.fr/

# Hashcat - Hash cracking
hashcat -m 0 -a 0 hash.txt rockyou.txt

# John the Ripper
john --wordlist=rockyou.txt hash.txt

# RsaCtfTool - RSA attacks
# https://github.com/Ganapati/RsaCtfTool
```

## Forensics

### File Analysis

#### File Type Identification
```bash
# Check file type
file suspicious.file

# Check magic bytes
xxd suspicious.file | head

# Strings extraction
strings -n 10 file.bin
strings -e l file.bin  # 16-bit little-endian
strings -e b file.bin  # 16-bit big-endian

# Binwalk - Find embedded files
binwalk file.bin
binwalk -e file.bin  # Extract
binwalk --dd='.*' file.bin

# Foremost - File carving
foremost -i file.bin -o output/

# Exiftool - Metadata
exiftool image.jpg
exiftool -all= image.jpg  # Remove all metadata
```

#### Steganography

**Images:**
```bash
# Steghide - Hide/extract data
steghide extract -sf image.jpg
steghide info image.jpg

# Stegsolve - Visual analysis
java -jar stegsolve.jar

# Zsteg - PNG/BMP analysis
zsteg image.png
zsteg -a image.png  # All methods

# StegSeek - Fast steghide cracker
stegseek image.jpg rockyou.txt

# LSB Steganography
# https://github.com/livz/cloacked-pixel
python lsb.py extract image.png output.txt
```

**Audio:**
```bash
# Sonic Visualizer - Spectrogram analysis
# Audacity - Audio analysis
# DeepSound - Hide data in audio

# Check for LSB in audio
python3 -c "import wave; w=wave.open('audio.wav','rb'); print(w.readframes(w.getnframes()))"
```

### Memory Forensics

```bash
# Volatility 2
volatility -f memory.raw imageinfo
volatility -f memory.raw --profile=Win7SP1x64 pslist
volatility -f memory.raw --profile=Win7SP1x64 cmdscan
volatility -f memory.raw --profile=Win7SP1x64 filescan | grep -i flag

# Volatility 3
vol3 -f memory.raw windows.info
vol3 -f memory.raw windows.pslist
vol3 -f memory.raw windows.cmdline
vol3 -f memory.raw windows.filescan | grep flag
```

### Network Forensics

```bash
# Wireshark filters
http.request.method == "POST"
tcp.port == 80
ip.addr == 192.168.1.1

# Extract HTTP objects
# File -> Export Objects -> HTTP

# TShark
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.file_data

# Network Miner - Extract files from PCAP
# Zeek (Bro) - Network analysis
```

### Disk Forensics

```bash
# Autopsy - Digital forensics platform
# FTK Imager - Disk imaging

# Mount disk image
sudo mount -o loop,ro disk.img /mnt/forensics

# TestDisk - Recover partitions
testdisk disk.img

# PhotoRec - File recovery
photorec disk.img
```

## Web Exploitation

### Reconnaissance

```bash
# Directory enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# Subdomain enumeration
ffuf -u http://FUZZ.target.com -w subdomains.txt

# Parameter fuzzing
ffuf -u http://target.com/page?FUZZ=value -w parameters.txt

# Nikto - Web scanner
nikto -h http://target.com

# WhatWeb - Technology identification
whatweb http://target.com
```

### Common Vulnerabilities

```bash
# SQL Injection
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" --forms --batch

# XSS Testing
# Use payloads from: https://github.com/swisskyrepo/PayloadsAllTheThings

# JWT Analysis
# https://jwt.io
# jwt_tool - JWT exploitation
python3 jwt_tool.py <JWT_TOKEN>

# SSTI (Server-Side Template Injection)
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}

# Command Injection
; whoami
| whoami
`whoami`
$(whoami)
```

## Binary Exploitation (PWN)

### Basic Tools

```bash
# GDB with GEF/PEDA/Pwndbg
gdb ./binary
checksec  # Check security features

# Radare2
r2 -d ./binary
aa  # Analyze all
pdf @main  # Print disassembly

# Ghidra - Reverse engineering
# IDA Pro/Free - Disassembler

# pwntools - Exploit development
from pwn import *
p = process('./binary')
# or
p = remote('target.com', 1337)
```

### Common Techniques

```python
# Buffer Overflow
payload = b'A' * offset + p64(ret_address)

# Format String
payload = b'%x ' * 20  # Leak stack
payload = b'%s' + p64(address)  # Read memory

# ROP (Return Oriented Programming)
from pwn import *
rop = ROP('./binary')
rop.call('system', ['/bin/sh'])
```

## Reverse Engineering

### Static Analysis

```bash
# File information
file binary
checksec binary

# Strings
strings binary | grep flag

# ltrace - Library calls
ltrace ./binary

# strace - System calls
strace ./binary

# objdump - Disassembly
objdump -d binary

# Ghidra - Decompiler
# IDA - Interactive disassembler
# Binary Ninja - Reverse engineering platform
```

### Dynamic Analysis

```bash
# GDB debugging
gdb ./binary
break main
run
disas main
info registers

# Frida - Dynamic instrumentation
frida -l script.js ./binary

# Detect anti-debugging
# - ptrace check
# - timing checks
# - debugger detection
```

### Crackmes

```bash
# Common techniques
# - Patching instructions (NOP out checks)
# - Finding serial/key algorithms
# - Bypassing authentication

# Patching with radare2
r2 -w binary
s 0x401234  # Seek to address
wa nop  # Write assembly (NOP)
```

## OSINT (Open Source Intelligence)

### Image Search & Analysis

```bash
# Reverse image search
# - Google Images
# - TinEye
# - Yandex Images

# Exiftool for metadata
exiftool image.jpg

# Geolocation
# - Google Maps
# - Google Earth
# - Overpass Turbo (OpenStreetMap)
```

### Username & Email Investigation

```bash
# Sherlock - Username search
python3 sherlock.py username

# theHarvester - Email gathering
theHarvester -d domain.com -b google

# Hunter.io - Email finder
# Have I Been Pwned - Check breaches

# WHOIS lookup
whois domain.com
```

### Social Media

```bash
# Search engines
site:twitter.com "keyword"
site:linkedin.com "company name"

# Wayback Machine
https://web.archive.org

# Social media intelligence
# - Maltego
# - SpiderFoot
# - Recon-ng
```

## Misc Category

### Programming Challenges

```python
# Pwntools for quick scripts
from pwn import *

r = remote('target.com', 1337)
# or
r = process('./binary')

data = r.recvline()
r.sendline(b'response')
```

### Common Techniques

```bash
# Scripting with Python/Bash
# Automation with expect
# Parsing with regex
# Working with APIs

# Example: Solve math challenge
#!/usr/bin/env python3
from pwn import *
import re

r = remote('target.com', 1337)
while True:
    data = r.recvline().decode()
    match = re.search(r'(\d+) \+ (\d+)', data)
    if match:
        result = int(match.group(1)) + int(match.group(2))
        r.sendline(str(result).encode())
```

## Essential Resources

### Wordlists
```bash
# SecLists
/usr/share/seclists/

# RockYou
/usr/share/wordlists/rockyou.txt

# Custom wordlists with CeWL
cewl http://target.com -w wordlist.txt
```

### Online Resources
- **CyberChef**: https://gchq.github.io/CyberChef/
- **GTFOBins**: https://gtfobins.github.io/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackTricks**: https://book.hacktricks.xyz/
- **CTF Wiki**: https://ctf-wiki.org/

### Practice Platforms
- **HackTheBox**: https://hackthebox.eu
- **TryHackMe**: https://tryhackme.com
- **picoCTF**: https://picoctf.org
- **OverTheWire**: https://overthewire.org
- **pwn.college**: https://pwn.college
- **CryptoHack**: https://cryptohack.org

## Quick Tips

1. **Always read the challenge description** - Hidden hints
2. **Check file extensions and magic bytes** - Files might be mislabeled
3. **Google error messages** - Someone probably solved it
4. **Join CTF Discord communities** - Learn from others
5. **Write writeups** - Solidify your learning
6. **Create your own tools** - Understand the concepts better
7. **Practice regularly** - Skills decay without use
8. **Learn from writeups** - After attempting the challenge

Happy hacking! 🚩
