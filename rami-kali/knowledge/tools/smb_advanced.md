# Advanced SMB/RPC Tools

> Covers: smbmap, smbclient, rpcclient (extends enum4linux.md and smbclient.md)

---

## smbmap — SMB Share Permission Mapper

### Why
Maps share permissions across hosts. Better permission visibility than smbclient. Shows read/write/no-access at a glance.

### When to Use
| Signal | Action |
|---|---|
| Need share permission map | smbmap shows R/W per share |
| Multiple hosts with SMB | smbmap handles ranges |
| enum4linux too verbose | smbmap is cleaner |

### Common Invocations
```bash
# Null session
smbmap -H <target>

# With creds
smbmap -H <target> -u <user> -p <password>

# Pass-the-hash
smbmap -H <target> -u <user> -p ':<ntlm_hash>'

# List files in share
smbmap -H <target> -u <user> -p <pass> -r <share>

# Recursive listing
smbmap -H <target> -u <user> -p <pass> -R <share>

# Download file
smbmap -H <target> -u <user> -p <pass> --download '<share>\path\file.txt'

# Upload file
smbmap -H <target> -u <user> -p <pass> --upload localfile.txt '<share>\remote.txt'

# Execute command (admin required)
smbmap -H <target> -u <user> -p <pass> -x 'whoami'
```

### Output Interpretation
| Permission | Meaning | Action |
|---|---|---|
| READ ONLY | Can browse and download | Search for sensitive files |
| READ, WRITE | Full access | Upload shell if web root |
| NO ACCESS | Denied | Try with different creds |

---

## rpcclient — RPC Enumeration

### Why
Low-level RPC interaction with Windows. Enumerates users, groups, password policy, SIDs. More control than enum4linux (which wraps rpcclient).

### When to Use
| Signal | Action |
|---|---|
| Need specific RPC queries | rpcclient is precise |
| enum4linux partial results | rpcclient for manual enum |
| Need SID resolution | RID cycling |

### Common Invocations
```bash
# Null session connect
rpcclient -U '' -N <target>

# With creds
rpcclient -U '<user>%<password>' <target>

# Then interactive commands:
rpcclient $> enumdomusers         # enumerate users
rpcclient $> enumdomgroups        # enumerate groups
rpcclient $> queryuser <rid>      # user details by RID
rpcclient $> getdompwinfo         # password policy
rpcclient $> querydispinfo        # detailed user info
rpcclient $> enumprinters         # enumerate printers
rpcclient $> netshareenumall      # enumerate shares
rpcclient $> lookupnames <user>   # name → SID
rpcclient $> lookupsids <sid>     # SID → name
```

### RID Cycling (User Enumeration When Blocked)
```bash
# Manually cycle through RIDs
rpcclient $> lookupnames administrator    # get SID base
# Then query RID 500-550, 1000-1200
rpcclient $> queryuser 500   # Administrator
rpcclient $> queryuser 501   # Guest
rpcclient $> queryuser 1000  # First custom user
# ...continue through range
```

---

## SMB Tool Decision Matrix

```
WHAT DO I NEED?
  ├─ List shares + permissions   → smbmap (best overview)
  ├─ Browse + download files     → smbclient (interactive)
  ├─ Full automated enum         → enum4linux (wraps everything)
  ├─ Specific RPC queries        → rpcclient (precise control)
  ├─ Spray creds across network  → crackmapexec (see ad_tools.md)
  └─ Check vulns (MS17-010)      → nmap --script smb-vuln*
```
