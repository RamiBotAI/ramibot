# smbclient — SMB Share Access

## Why
Directly connects to and interacts with SMB shares. Downloads files, uploads files, browses share contents. Pairs with enum4linux for full SMB exploitation.

## When to Use

| Signal | Action |
|---|---|
| enum4linux found shares | Connect and browse |
| Port 445 open | List shares, try null session |
| Credentials found | Access authenticated shares |
| Need to download files | get/mget from shares |
| Need to upload files | put (if writable) |

## Common Invocations

```bash
# List shares (null session / anonymous)
smbclient -L //<target> -N

# List shares (with creds)
smbclient -L //<target> -U <user>%<password>

# Connect to share (null session)
smbclient //<target>/<share> -N

# Connect to share (with creds)
smbclient //<target>/<share> -U <user>%<password>

# Download all files recursively
smbclient //<target>/<share> -N -c "recurse ON; prompt OFF; mget *"

# Upload a file
smbclient //<target>/<share> -U <user>%<pass> -c "put localfile.txt remotefile.txt"
```

## Interactive Commands (once connected)

```
ls              → list files
cd <dir>        → change directory
get <file>      → download file
put <file>      → upload file
mget *          → download all
mkdir <dir>     → create directory
del <file>      → delete file
recurse ON      → enable recursive operations
prompt OFF      → disable confirmation prompts
```

## Parsing Priorities

1. **Share names** → IPC$, ADMIN$, C$ = admin shares; custom names = user data
2. **File listings** → configs, scripts, backups, credentials
3. **Permissions** → read-only vs read-write
4. **Hidden files** → .config, .env, scripts with hardcoded creds

## High-Value Files to Look For

| File | Why |
|---|---|
| *.conf, *.config | Configuration with creds |
| *.bak, *.old | Backups with passwords |
| *.ps1, *.bat, *.sh | Scripts with hardcoded creds |
| *.kdbx | KeePass database |
| *.doc, *.xlsx | Documents with sensitive info |
| web.config | ASP.NET connection strings |
| *.xml | Config files, sometimes creds |
| id_rsa, *.key, *.pem | Private keys |

## Junior Mistakes

- Not trying null session first (`-N` flag)
- Only listing shares, not connecting to browse them
- Not downloading everything from readable shares
- Forgetting `recurse ON; prompt OFF` for batch download
- Ignoring IPC$ share (can be used for user enumeration)

## Pivot After smbclient

```
Files downloaded?
  ├─ Search for passwords:  grep -ri "password\|passwd\|pwd\|credential" *
  ├─ Search for configs:    find . -name "*.conf" -o -name "*.config"
  ├─ Private keys found?    → SSH login
  └─ KeePass DB found?      → john (keepass2john) → crack

Writable share?
  ├─ Upload web shell (if web root)
  ├─ Upload SCF/URL file (hash capture)
  └─ Note for later exploitation

Creds found in files?
  → Try on ALL services (SSH, web, FTP, RDP, DB)
```
