# nikto — Web Vulnerability Scanner

## Why
Checks for known web misconfigurations, dangerous files, outdated software, and common vulnerabilities. Broad sweep, medium noise.

## When to Use

| Signal | Action |
|---|---|
| Web server confirmed | Run after whatweb + gobuster |
| Need vuln enumeration | Known-vuln database check |
| Quick win search | Default files, misconfigs |
| Multiple web ports | Run on each |

## Common Invocations

```bash
# Standard scan
nikto -h <url>

# Specific port
nikto -h <target> -p <port>

# HTTPS
nikto -h https://<target>

# Save output
nikto -h <url> -o report.txt

# Tuning (specific test categories)
nikto -h <url> -Tuning 123bde
# 1=interesting file, 2=misconfig, 3=info disclosure
# b=software ID, d=directories, e=embedded devices
```

## Parsing Priorities

1. **OSVDB references** → known vulnerabilities, cross-ref with searchsploit
2. **Dangerous HTTP methods** → PUT, DELETE enabled = file write
3. **Default files found** → /phpinfo.php, /test.php, /info.php
4. **Directory indexing** → browse freely, look for sensitive files
5. **Missing security headers** → XSS/clickjacking potential
6. **Server version** → searchsploit input

## High-Value Findings

| Finding | Action |
|---|---|
| PUT method allowed | Try uploading shell |
| phpinfo.php found | Read for paths, config, modules |
| Directory listing | Browse for backups, configs |
| Default install pages | Application not hardened |
| Shellshock indicators | Test /cgi-bin/ scripts |
| WebDAV enabled | Potential file upload vector |

## Junior Mistakes

- Running nikto first (it's slow + noisy — whatweb/gobuster first)
- Not scanning all HTTP ports (miss the app on 8080)
- Ignoring "outdated" findings (outdated = potentially exploitable)
- Not correlating with searchsploit

## Pivot After nikto

```
Vuln found?           → verify manually, searchsploit
Dangerous methods?    → test PUT upload
Info disclosure?      → harvest data (paths, versions, configs)
Nothing notable?      → focus on gobuster results, manual testing
```
