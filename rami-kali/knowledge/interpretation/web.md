# Web Response Interpretation — Quick Reference

## HTTP Status Codes — What They Mean for Offense

| Code | Meaning | Offensive Implication |
|---|---|---|
| 200 | OK | Content accessible, analyze it |
| 204 | No Content | Endpoint exists, may accept input |
| 301 | Permanent Redirect | Follow it, map the redirect chain |
| 302 | Temporary Redirect | Often auth redirect → note login URL |
| 400 | Bad Request | Malformed input → may reveal parser |
| 401 | Unauthorized | Auth required → cred testing target |
| 403 | Forbidden | Exists but blocked → bypass attempt |
| 404 | Not Found | Doesn't exist (usually) — custom 404? |
| 405 | Method Not Allowed | Try other methods (POST, PUT, DELETE) |
| 500 | Server Error | Possible injection point, error leak |
| 502 | Bad Gateway | Backend exists, proxy misconfigured |
| 503 | Service Unavailable | Rate limited or overloaded |

## Response Analysis

### Headers to Check

| Header | Significance |
|---|---|
| `Server` | Software + version → searchsploit |
| `X-Powered-By` | Framework/language → attack surface |
| `Set-Cookie` | Session mechanism, flags, domain |
| `X-Frame-Options` | Missing = clickjacking possible |
| `Content-Security-Policy` | Missing = XSS more likely |
| `X-AspNet-Version` | .NET version → specific attacks |
| `X-Generator` | CMS identification |
| `WWW-Authenticate` | Auth mechanism (Basic, Bearer, NTLM) |
| `Allow` | Available HTTP methods |
| `Access-Control-Allow-Origin: *` | CORS misconfiguration |

### Cookie Indicators

| Cookie Name | Indicates |
|---|---|
| `PHPSESSID` | PHP |
| `JSESSIONID` | Java (Tomcat/JBoss) |
| `ASP.NET_SessionId` | ASP.NET |
| `connect.sid` | Node.js Express |
| `csrftoken` | Django |
| `_rails_session` | Ruby on Rails |
| `laravel_session` | Laravel (PHP) |

### Error Messages — Information Leaks

```
"mysql_fetch"         → MySQL + PHP, likely SQLi
"ORA-"                → Oracle DB error
"Microsoft OLE DB"    → MSSQL, ASP
"PostgreSQL"          → PostgreSQL error
"sqlite3"             → SQLite
"SyntaxError"         → Python/Node backend
"stack trace"         → Framework debug mode on
"at /var/www/"        → Server path disclosed
"root:x:0:0"         → LFI confirmed (reading /etc/passwd)
```

## 403 Bypass Techniques

```
TRY IN ORDER:
  1. Path variation:    /admin → /Admin → /ADMIN → /admin/
  2. URL encoding:      /%61dmin
  3. Double encoding:   /%2561dmin
  4. Path traversal:    /whatever/../admin
  5. Add headers:       X-Forwarded-For: 127.0.0.1
  6. Change method:     GET → POST → PUT
  7. Add extension:     /admin.php → /admin.html → /admin.json
  8. Null byte:         /admin%00.jpg (legacy only)
  9. Different port:    Same path on 8080 instead of 80
```

## Technology Stack Fingerprints

| Signal | Stack |
|---|---|
| `.php` URLs, PHPSESSID | PHP (Apache/Nginx) |
| `.aspx`, viewstate | ASP.NET (IIS) |
| `.jsp`, JSESSIONID | Java (Tomcat) |
| No extension, JSON APIs | Node.js or Python |
| `/wp-content/`, `/wp-admin/` | WordPress |
| `/administrator/`, `/components/` | Joomla |
| `/sites/default/`, `/node/` | Drupal |
| `/_next/` | Next.js |
| `/static/admin/` | Django |
| `/rails/info/` | Ruby on Rails (dev mode) |

## Form Analysis Checklist

```
LOGIN FORM FOUND:
  1. View source → form action URL, field names
  2. CSRF token present?   → yes = hydra needs special handling
  3. JavaScript validation? → bypass by direct request
  4. Error messages differ? → "user not found" vs "wrong password" = user enum
  5. Rate limiting?         → try slow, check after 5 attempts
  6. Account lockout?       → test with known-bad creds first
  7. Password reset?        → separate attack surface
  8. Registration open?     → create account, test from inside
```
