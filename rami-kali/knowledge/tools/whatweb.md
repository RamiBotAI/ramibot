# whatweb — Web Fingerprinting

## Why
Identifies web technologies, CMS, frameworks, server software, versions. Fast, low-noise first step for any HTTP target.

## When to Use

| Signal | Action |
|---|---|
| Port 80/443/8080 open | Run immediately |
| Need to know CMS | whatweb identifies WordPress, Joomla, Drupal |
| Before gobuster | Know what you're scanning first |
| Quick recon | Faster than nikto, less noise |

## Common Invocations

```bash
# Standard scan
whatweb <url>

# Aggressive (more plugins, more requests)
whatweb -a 3 <url>

# Multiple targets
whatweb <url1> <url2>

# Follow redirects
whatweb -r <url>
```

## Parsing Priorities

1. **CMS name + version** → direct path to searchsploit
2. **Server software** → Apache/Nginx/IIS + version
3. **Programming language** → PHP/ASP/Python hints at attack surface
4. **Frameworks** → Rails/Django/Laravel = known default paths
5. **Security headers** → missing = potential XSS/clickjacking
6. **Cookies** → session names hint at framework (PHPSESSID, JSESSIONID)

## Key Fingerprints

| Indicator | Means |
|---|---|
| `WordPress` | /wp-admin, /wp-content, wpscan next |
| `Joomla` | /administrator, joomscan next |
| `Drupal` | /CHANGELOG.txt for version |
| `PHP` | test for LFI, SQLi, file upload |
| `ASP.NET` | test for viewstate deserialization |
| `Apache` | check mod_status, mod_info |
| `nginx` | check for misconfigs, alias traversal |

## Junior Mistakes

- Skipping whatweb and going straight to gobuster (wastes time if CMS is obvious)
- Not running on ALL HTTP ports (8080, 8443 often have different apps)
- Ignoring redirect chains (the final destination matters)

## Pivot After whatweb

```
CMS found?        → CMS-specific scanner or manual enum
Version found?    → searchsploit
Login detected?   → note for later, enum dirs first
Nothing special?  → gobuster + nikto
```
