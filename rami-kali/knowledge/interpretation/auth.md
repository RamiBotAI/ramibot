# Auth Interpretation — Attack Surface Analysis

## Auth Mechanism Identification

| Signal | Mechanism | Attack Approach |
|---|---|---|
| `WWW-Authenticate: Basic` | HTTP Basic Auth | Creds in base64, brute-forceable |
| `WWW-Authenticate: Bearer` | Token-based (JWT/OAuth) | Token manipulation, not brute |
| `WWW-Authenticate: NTLM` | Windows NTLM | Relay attacks, hash capture |
| HTML login form | Form-based auth | SQLi, default creds, brute |
| SSH password prompt | SSH password auth | Brute if no lockout |
| SSH key rejection | SSH key-only auth | Need key, not password |
| `401` with no WWW-Auth | Custom/broken auth | Probe for bypass |
| Cookie without login | Session fixation risk | Test session handling |

## Default Credentials — Try First

### Web Applications

| Application | Username | Password |
|---|---|---|
| WordPress | admin | admin, password |
| Joomla | admin | admin |
| Drupal | admin | admin |
| Tomcat Manager | tomcat | tomcat, s3cret |
| phpMyAdmin | root | (empty), root, toor |
| Jenkins | admin | admin |
| Grafana | admin | admin |
| Webmin | root | (system password) |
| Zabbix | Admin | zabbix |
| GitLab | root | 5iveL!fe |

### Network Services

| Service | Username | Password |
|---|---|---|
| FTP | anonymous | (empty), anonymous |
| MySQL | root | (empty), root, toor |
| PostgreSQL | postgres | postgres |
| MSSQL | sa | sa, (empty) |
| Redis | (none) | (none) — no auth default |
| MongoDB | (none) | (none) — no auth default |
| VNC | (none) | password, (empty) |
| SNMP | (community) | public, private |
| Telnet | admin | admin, password |

### Network Devices

| Device | Username | Password |
|---|---|---|
| Cisco | admin, cisco | admin, cisco, (empty) |
| MikroTik | admin | (empty) |
| Ubiquiti | ubnt | ubnt |

## Auth Attack Decision Tree

```
AUTH ENCOUNTERED
  │
  ├─ Try default creds (30 seconds, zero noise)
  │   ├─ SUCCESS → you're in
  │   └─ FAIL → continue
  │
  ├─ Check for auth bypass
  │   ├─ SQLi in login form?
  │   ├─ Direct URL access (skip login page)?
  │   ├─ Parameter manipulation (role=admin)?
  │   ├─ Cookie tampering?
  │   └─ IDOR on API endpoints?
  │
  ├─ Enumerate users
  │   ├─ Error message differences ("invalid user" vs "invalid password")
  │   ├─ Timing differences (longer response = user exists)
  │   ├─ Registration page (email already taken)
  │   ├─ Password reset (user enumeration via reset)
  │   └─ SMB/LDAP user enum if available
  │
  ├─ Credential reuse
  │   └─ Found creds ANYWHERE? → try on ALL services
  │
  └─ Brute force (LAST RESORT)
      ├─ Check lockout policy first
      ├─ Single user + password list (if user known)
      ├─ Password spray (few passwords × many users)
      └─ Full brute (only if no lockout, no alternatives)
```

## JWT/Token Analysis

```
IF JWT FOUND (eyJ... format):
  1. Decode payload (base64) → check claims, expiry, role
  2. Check algorithm → "none" algorithm bypass?
  3. Check signature → weak secret? try jwt_tool
  4. Modify claims → change role, user ID
  5. Expired token → does server still accept it?
```

## Session Analysis

```
SESSION COOKIE FOUND:
  1. Predictable?     → sequential IDs = session hijack
  2. HttpOnly flag?   → missing = stealable via XSS
  3. Secure flag?     → missing = interceptable on HTTP
  4. SameSite?        → missing = CSRF possible
  5. Long-lived?      → session timeout too long
  6. Shared across?   → check if valid on other endpoints
```

## Password Hash Identification

| Pattern | Type | Tool |
|---|---|---|
| `$1$...` | MD5crypt | hashcat -m 500, john |
| `$2a$`, `$2b$` | bcrypt | hashcat -m 3200 (slow) |
| `$5$...` | SHA-256crypt | hashcat -m 7400 |
| `$6$...` | SHA-512crypt | hashcat -m 1800 |
| `$y$...` | yescrypt | john |
| 32 hex chars | MD5 | hashcat -m 0 (fast) |
| 40 hex chars | SHA1 | hashcat -m 100 |
| 64 hex chars | SHA256 | hashcat -m 1400 |
| `aad3b...` (32 hex) | NTLM | hashcat -m 1000 (fast) |

Priority: crack fast hashes first (MD5, NTLM, SHA1).
Skip bcrypt/scrypt unless you have GPU and time.
