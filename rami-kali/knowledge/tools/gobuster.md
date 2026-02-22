# gobuster — Directory & DNS Bruteforce

## Why
Discovers hidden paths, files, directories, and subdomains that aren't linked. Critical for finding admin panels, backups, APIs, and sensitive files.

## When to Use

| Signal | Action |
|---|---|
| Web server found | Run after whatweb |
| Need hidden paths | dir mode |
| Need subdomains | dns mode |
| API suspected | dir mode with api-specific wordlist |
| CMS found but need more | dir mode for plugin/theme enum |

## Common Invocations

```bash
# Standard directory brute
gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt

# Larger wordlist, more thorough
gobuster dir -u <url> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# With file extensions
gobuster dir -u <url> -w <wordlist> -x php,txt,html,bak,old,zip

# HTTPS with no cert verify
gobuster dir -u https://<target> -w <wordlist> -k

# Filter by status code
gobuster dir -u <url> -w <wordlist> -s 200,204,301,302,307

# DNS subdomain brute
gobuster dns -d <domain> -w <wordlist>

# With threads (default 10, max ~50 to avoid noise)
gobuster dir -u <url> -w <wordlist> -t 30
```

## Extension Selection Logic

| Stack | Extensions to add |
|---|---|
| PHP | `-x php,phps,php.bak,inc` |
| ASP.NET | `-x asp,aspx,config` |
| Java | `-x jsp,do,action` |
| Python | `-x py` |
| General | `-x txt,html,bak,old,zip,tar.gz,sql,xml,json,conf,log` |
| Backup hunt | `-x bak,old,orig,save,swp,~` |

## Parsing Priorities

1. **200 responses** → accessible content, check everything
2. **301/302 redirects** → follow them, often point to real content
3. **403 Forbidden** → exists but restricted, note for bypass attempts
4. **401 Unauthorized** → auth required, note for cred testing
5. **Large response != empty** → check for info in "error" pages

## High-Value Finds

| Path | Significance |
|---|---|
| `/admin`, `/administrator` | Admin panel → cred testing |
| `/api`, `/v1`, `/v2` | API → enumerate endpoints |
| `/backup`, `/bak` | Potential source code / DB dumps |
| `/.git`, `/.svn` | Source code repository leak |
| `/config`, `/conf` | Configuration files |
| `/upload`, `/uploads` | File upload → possible shell upload |
| `/phpmyadmin` | DB management → default creds |
| `/cgi-bin` | Shellshock test candidate |
| `/server-status` | Apache info leak |
| `/.env` | Environment variables, API keys, DB creds |
| `/wp-content/debug.log` | WordPress debug info |

## Junior Mistakes

- Not checking robots.txt/sitemap.xml first (free intel)
- Using too-small wordlist and calling it done
- Forgetting file extensions (finds /admin but misses /admin.php)
- Running on wrong port (app is on 8080, scanning 80)
- Too many threads = getting rate limited / banned
- Not scanning sub-paths (found /api → now scan /api/ too)

## Pivot After gobuster

```
Admin panel found?     → try default creds, then check for SQLi
API found?             → enumerate methods (GET/POST), test auth
Backup/config found?   → download, search for creds
.git found?            → git-dumper or manual clone
Upload dir found?      → test file upload bypass
Login form found?      → identify auth, test SQLi before hydra
403 dirs?              → try bypass: path traversal, header manipulation
```
