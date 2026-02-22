# enum4linux — SMB/NetBIOS Enumeration

## Why
Enumerates Windows/Samba shares, users, groups, policies via SMB/NetBIOS. Essential for any target with ports 135/139/445.

## When to Use

| Signal | Action |
|---|---|
| Port 139 or 445 open | Run immediately |
| Windows target suspected | SMB is primary attack surface |
| Need usernames | SMB user enumeration |
| Need share access | Null session testing |

## Common Invocations

```bash
# Full enumeration
enum4linux -a <target>

# User enumeration
enum4linux -U <target>

# Share enumeration
enum4linux -S <target>

# OS info
enum4linux -o <target>

# Password policy (check before brute)
enum4linux -P <target>

# RID cycling (finds users even when enum blocked)
enum4linux -r <target>
```

## Parsing Priorities

1. **Null session allowed?** → if yes, full enumeration is possible
2. **Usernames found** → direct input for hydra
3. **Shares found** → try access: `smbclient //<target>/<share> -N`
4. **Password policy** → lockout threshold, complexity, age
5. **OS version** → exploit selection (EternalBlue for Win7/2008)
6. **Domain/workgroup** → lateral movement context

## High-Value Finds

| Finding | Action |
|---|---|
| Null session works | Enumerate everything |
| User list | Feed to hydra for SSH/SMB/web |
| Readable shares | Download all, search for creds/configs |
| Writable shares | Potential shell upload vector |
| No lockout policy | Brute force is safe |
| Old OS version | Check for MS17-010, MS08-067 |

## Junior Mistakes

- Ignoring SMB when only scanning for web vulns
- Not trying null session before authenticated access
- Not checking password policy before brute-forcing
- Forgetting to try smbclient for manual share access
- Not correlating found usernames with other services

## Pivot After enum4linux

```
Users found?       → try creds on SSH, web, FTP, SMB
Shares readable?   → smbclient, download, search for secrets
Shares writable?   → test file upload
Null session?      → deeper enumeration
Old Windows?       → MS17-010 check (nmap --script smb-vuln-ms17-010)
Password policy?   → inform hydra strategy
```
