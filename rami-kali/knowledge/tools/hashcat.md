# hashcat — Password Hash Cracking (GPU)

## Why
Cracks password hashes using GPU acceleration. Orders of magnitude faster than CPU. Use when hashes are found in databases, config files, /etc/shadow, or NTLM dumps.

## When to Use

| Signal | Action |
|---|---|
| Hashes found in DB dump | Identify hash type → crack |
| /etc/shadow readable | Extract hashes → crack |
| NTLM hashes captured | Fast crack (mode 1000) |
| WordPress hashes found | phpass mode 400 |
| Responder captured hashes | NetNTLMv2 mode 5600 |

## CRITICAL: Identify Hash First

```
BEFORE RUNNING:
  1. What hash type? → see interpretation/auth.md hash table
  2. Match to hashcat mode (-m)
  3. Pick wordlist strategy
  4. Estimate time: MD5=seconds, bcrypt=hours
```

## Common Hash Modes

| Mode | Type | Speed |
|---|---|---|
| 0 | MD5 | FAST |
| 100 | SHA1 | FAST |
| 400 | phpass (WordPress/Joomla) | SLOW |
| 500 | md5crypt ($1$) | MEDIUM |
| 1000 | NTLM | FAST |
| 1400 | SHA256 | MEDIUM |
| 1800 | sha512crypt ($6$) | SLOW |
| 3200 | bcrypt ($2a$) | VERY SLOW |
| 5600 | NetNTLMv2 | MEDIUM |
| 7400 | sha256crypt ($5$) | SLOW |
| 13100 | Kerberoast (TGS-REP) | MEDIUM |

## Common Invocations

```bash
# Basic dictionary attack
hashcat -m <mode> <hashfile> <wordlist>

# With rules (mutations: capitalize, append numbers, etc.)
hashcat -m <mode> <hashfile> <wordlist> -r /usr/share/hashcat/rules/best64.rule

# Brute force (mask attack)
hashcat -m <mode> <hashfile> -a 3 ?a?a?a?a?a?a

# Show cracked results
hashcat -m <mode> <hashfile> --show

# Status check
hashcat -m <mode> <hashfile> --status

# Combinator attack (word1+word2)
hashcat -m <mode> <hashfile> -a 1 <wordlist1> <wordlist2>
```

## Mask Charsets

| Charset | Meaning |
|---|---|
| `?l` | lowercase a-z |
| `?u` | uppercase A-Z |
| `?d` | digits 0-9 |
| `?s` | special characters |
| `?a` | all printable |

```
# Common patterns
?u?l?l?l?l?d?d       → Password12 style
?u?l?l?l?l?l?d?d?s   → Passwo1d! style
Company?d?d?d?d       → Company2024 style
```

## Attack Strategy Order

```
1. Wordlist (rockyou-top-10000)           → fast, catches weak passwords
2. Wordlist + rules (best64.rule)          → catches mutations
3. Wordlist (full rockyou) + rules         → broader coverage
4. Targeted wordlist (company/context)     → custom for target
5. Mask attack (known pattern)             → if pattern detected
6. Full brute force                        → ONLY short hashes, last resort
```

## Junior Mistakes

- Not identifying the hash type (wrong mode = zero results)
- Running full brute force first (dictionary + rules is faster for real passwords)
- Cracking bcrypt with brute force (takes weeks — use targeted wordlists)
- Forgetting `--show` to display already-cracked results
- Not using rules (best64 multiplies wordlist effectiveness 64x)
- Ignoring pot file (hashcat remembers previously cracked hashes)

## Pivot After hashcat

```
Password cracked?
  ├─ Try on SSH, FTP, SMB, web, RDP     → credential reuse
  ├─ Same hash in multiple accounts?     → password reuse pattern
  ├─ Pattern detected (Company2024)?     → generate similar for uncr acked
  └─ Admin hash cracked?                 → high-value access

Not cracking?
  ├─ bcrypt/scrypt?     → accept it, move to other vectors
  ├─ Wrong mode?        → re-identify hash
  └─ Try john instead   → different rule engine, may succeed
```
