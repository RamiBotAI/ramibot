# hydra — Credential Bruteforce

## Why
Tests credentials against network services. LAST RESORT tool — noisy, slow, detectable.

## When to Use

| Signal | Action |
|---|---|
| Login form found, no other entry | Targeted credential attack |
| Default creds didn't work | Small wordlist first |
| Username known | Reduces search space massively |
| Service accepts password auth | SSH, FTP, HTTP-form, etc. |

## CRITICAL: Pre-Conditions

```
BEFORE RUNNING HYDRA:
  1. ✅ Have you enumerated users?     (don't guess usernames)
  2. ✅ Have you tried default creds?   (admin:admin, root:root, etc.)
  3. ✅ Have you tried cred reuse?      (creds from other services)
  4. ✅ Is there no SQLi/bypass?        (don't brute what you can bypass)
  5. ✅ Is the target scope-approved?   (HIGH risk tool)
  6. ✅ Is there no account lockout?    (check before brute-forcing)
```

## Common Invocations

```bash
# SSH brute
hydra -l <user> -P <wordlist> ssh://<target>

# FTP brute
hydra -l <user> -P <wordlist> ftp://<target>

# HTTP POST form
hydra -l <user> -P <wordlist> <target> http-post-form \
  "/login:username=^USER^&password=^PASS^:F=<failure_string>"

# HTTP Basic Auth
hydra -l <user> -P <wordlist> <target> http-get /protected/

# With username list
hydra -L <userlist> -P <wordlist> ssh://<target>

# Single password spray (better for lockout avoidance)
hydra -L <userlist> -p <password> ssh://<target>

# Limit threads (avoid lockout/detection)
hydra -l <user> -P <wordlist> -t 4 ssh://<target>
```

## HTTP Form Attack Setup

**You MUST identify these before running:**

1. **Form action URL** — where does the form POST to?
2. **Parameter names** — username field name, password field name
3. **Failure indicator** — string that appears on FAILED login
4. **Success indicator** — string that appears on SUCCESS (alternative: use `S=`)

```
# Identify by:
- Reading page source (inspect form)
- Intercepting a login attempt
- Checking network tab / burp proxy
```

## Junior Mistakes

- Running hydra before trying default creds (waste of time)
- Using rockyou.txt full (14M entries, takes forever) — use top 1000 first
- Wrong failure string for HTTP forms (gets false positives)
- Not knowing the username (doubles search space exponentially)
- Too many threads (account lockout, IP ban)
- Attacking a service that doesn't accept password auth (SSH key-only)
- Not checking for CSRF tokens (hydra can't handle them natively)

## Wordlist Strategy

```
PRIORITY ORDER:
  1. Contextual passwords   (company name, target hints, found data)
  2. Default creds list     (small, fast)
  3. Top 100-1000 passwords (from SecLists)
  4. rockyou-top-10000      (still manageable)
  5. Full rockyou.txt       (ONLY if nothing else works, very slow)
```

## Pivot After hydra

```
Creds found?
  ├─ SSH creds     → login, enumerate system, privesc
  ├─ Web creds     → login, check admin functions, upload points
  ├─ FTP creds     → list files, download everything, check for upload
  ├─ DB creds      → connect, dump tables, look for more creds
  └─ ANY creds     → try on ALL other open services (reuse)

No creds found?
  ├─ Try different usernames
  ├─ Try password spray instead of brute
  ├─ Look for other attack vectors (SQLi, LFI, etc.)
  └─ Accept: not every service is brutable
```
