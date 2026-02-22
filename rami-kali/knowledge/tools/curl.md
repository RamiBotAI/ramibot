# curl — HTTP Request Tool

## Why
Manual HTTP requests with full control. Test endpoints, grab headers, submit forms, test injections, download files. Essential for manual web testing when automated tools aren't enough.

## When to Use

| Signal | Action |
|---|---|
| Need to check specific URL | Quick manual request |
| Need response headers | `-I` or `-v` |
| Need to test POST request | Manual form submission |
| Need to test injection | Controlled payload delivery |
| Need to download file | `-O` or `-o` |
| Automated tool can't handle it | Manual precision |

## Common Invocations

```bash
# Basic GET
curl http://<target>/path

# Headers only
curl -I http://<target>

# Verbose (see request + response headers)
curl -v http://<target>

# Follow redirects
curl -L http://<target>

# POST form data
curl -X POST -d "user=admin&pass=test" http://<target>/login

# POST JSON
curl -X POST -H "Content-Type: application/json" -d '{"user":"admin"}' http://<target>/api

# With cookie
curl -b "session=abc123" http://<target>/admin

# With custom header
curl -H "X-Forwarded-For: 127.0.0.1" http://<target>/admin

# Save response
curl -o output.html http://<target>

# Download file (keep original name)
curl -O http://<target>/backup.zip

# HTTPS ignore cert
curl -k https://<target>

# PUT method
curl -X PUT -d "data" http://<target>/api/resource

# DELETE method
curl -X DELETE http://<target>/api/resource/1

# Basic auth
curl -u admin:password http://<target>/protected

# Upload file
curl -F "file=@shell.php" http://<target>/upload
```

## Recon Requests

```bash
# Check robots.txt
curl -s http://<target>/robots.txt

# Check .git exposure
curl -s http://<target>/.git/HEAD

# Check .env file
curl -s http://<target>/.env

# Check server headers
curl -sI http://<target> | grep -i "server\|x-powered\|x-aspnet"

# Check allowed methods
curl -X OPTIONS -I http://<target>

# Test for directory listing
curl -s http://<target>/images/
```

## Testing Payloads

```bash
# SQLi test
curl "http://<target>/page?id=1'"
curl "http://<target>/page?id=1 OR 1=1--"

# LFI test
curl "http://<target>/page?file=../../../etc/passwd"

# XSS test (for reflection check)
curl "http://<target>/search?q=<script>alert(1)</script>"

# Command injection test
curl "http://<target>/ping?host=;id"

# 403 bypass with headers
curl -H "X-Forwarded-For: 127.0.0.1" http://<target>/admin
curl -H "X-Original-URL: /admin" http://<target>/
```

## Junior Mistakes

- Not using `-s` (silent) in scripts (progress bar clutters output)
- Not following redirects (missing the actual content)
- Forgetting `-k` for self-signed HTTPS
- Not checking response headers (server info, cookies, auth type)
- Using curl when a specialized tool would be better

## Pivot After curl

```
Info in headers?       → server version → searchsploit
.git exposed?          → git-dumper or manual download
.env exposed?          → creds, API keys, DB strings
SQLi response differs? → confirm → sqlmap
LFI reads /etc/passwd? → escalate to log poisoning / PHP wrappers
Login form works?      → note params for hydra
```
