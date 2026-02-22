# wfuzz — Web Fuzzer

## Why
Flexible web fuzzer. Fuzzes any part of an HTTP request: URL paths, parameters, headers, POST data, cookies. More versatile than gobuster for non-standard fuzzing.

## When to Use

| Signal | Action |
|---|---|
| Need to fuzz parameters | `?FUZZ=value` or `?param=FUZZ` |
| Need to fuzz headers | Virtual host discovery, header injection |
| Need to fuzz POST data | Form field fuzzing |
| Need to fuzz with filters | Hide specific response codes/sizes |
| gobuster not enough | wfuzz is more flexible |
| Subdomain/vhost enum | Host header fuzzing |

## gobuster vs wfuzz — When to Choose

| Scenario | Tool |
|---|---|
| Simple directory brute | gobuster (faster, simpler) |
| Parameter fuzzing | wfuzz |
| Header fuzzing | wfuzz |
| POST body fuzzing | wfuzz |
| Filter by response size | wfuzz (better filtering) |
| Subdomain via DNS | gobuster dns |
| Subdomain via Host header | wfuzz |

## Common Invocations

```bash
# Directory fuzzing (like gobuster)
wfuzz -c -w <wordlist> --hc 404 http://<target>/FUZZ

# File extension fuzzing
wfuzz -c -w <wordlist> --hc 404 http://<target>/FUZZ.php

# Parameter value fuzzing
wfuzz -c -w <wordlist> --hc 404 http://<target>/page?id=FUZZ

# Parameter name fuzzing
wfuzz -c -w <wordlist> --hc 404 http://<target>/page?FUZZ=test

# Virtual host / subdomain discovery
wfuzz -c -w <wordlist> -H "Host: FUZZ.<domain>" --hc 404 --hw <default_word_count> http://<target>

# POST data fuzzing
wfuzz -c -w <wordlist> -d "user=admin&pass=FUZZ" --hc 403 http://<target>/login

# Two wordlists (multi-fuzz)
wfuzz -c -w users.txt -w pass.txt -d "user=FUZ2Z&pass=FUZZ" http://<target>/login

# Cookie fuzzing
wfuzz -c -w <wordlist> -b "session=FUZZ" --hc 403 http://<target>/admin

# Hide by response size (eliminate noise)
wfuzz -c -w <wordlist> --hh <char_count> http://<target>/FUZZ

# Hide by word count
wfuzz -c -w <wordlist> --hw <word_count> http://<target>/FUZZ
```

## Filter Flags (Critical for Usability)

| Flag | Filters by | Use |
|---|---|---|
| `--hc` | Status code | `--hc 404` hide not found |
| `--hl` | Line count | `--hl 10` hide specific page |
| `--hw` | Word count | `--hw 50` hide default page |
| `--hh` | Char count | `--hh 1234` hide exact size |
| `--sc` | Show only code | `--sc 200` show only success |
| `--ss` | Show string match | `--ss "Welcome"` |

## Key Technique: Baseline Then Filter

```
1. Run ONE request manually → note response size/words/lines
2. That's your "default" response
3. Use --hh/--hw/--hl to filter it out
4. What remains = interesting responses
```

## Junior Mistakes

- Not filtering output (thousands of 404s = noise)
- Not doing baseline request first (don't know what to filter)
- Using wfuzz for simple dir brute (gobuster is faster for that)
- Forgetting `-c` for colored output (readability)
- Not using `--hh` for virtual host discovery (all responses are 200, differ by size)

## Pivot After wfuzz

```
Hidden params found?     → test for injection (SQLi, LFI, XSS)
Virtual hosts found?     → scan each independently (different apps)
API endpoints found?     → enumerate methods, test auth
Login bypass via fuzz?   → access admin panel
Hidden files found?      → download, analyze for creds/info
```
