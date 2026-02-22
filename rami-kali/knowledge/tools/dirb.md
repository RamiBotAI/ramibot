# dirb — Web Directory Scanner

## Why
Simple, reliable web directory scanner. Less features than gobuster but comes pre-installed on Kali with good default wordlists. Good fallback.

## When to Use

| Signal | Action |
|---|---|
| Quick directory scan needed | simpler than gobuster |
| gobuster not available | dirb as alternative |
| Need recursive scanning | dirb recurses by default |
| Authentication required | dirb handles basic auth natively |

## gobuster vs dirb — When to Choose

| Scenario | Tool |
|---|---|
| Speed priority | gobuster (multi-threaded) |
| Simple quick scan | dirb (sensible defaults) |
| Recursive discovery | dirb (built-in) |
| Extension brute-force | gobuster (better -x handling) |
| Need fine control | gobuster |
| Default wordlists are fine | dirb (ships with good lists) |

## Common Invocations

```bash
# Default scan (uses /usr/share/dirb/wordlists/common.txt)
dirb http://<target>

# Custom wordlist
dirb http://<target> <wordlist>

# With file extensions
dirb http://<target> -X .php,.txt,.html,.bak

# With basic auth
dirb http://<target> -u admin:password

# With cookie
dirb http://<target> -c "PHPSESSID=abc123"

# Ignore specific HTTP codes
dirb http://<target> -N 403

# Non-recursive
dirb http://<target> -r

# Case insensitive
dirb http://<target> -z 10  # also adds delay (ms) between requests

# HTTPS
dirb https://<target>

# Save output
dirb http://<target> -o results.txt
```

## Default Wordlists (Kali)

```
/usr/share/dirb/wordlists/common.txt          → 4614 entries (quick)
/usr/share/dirb/wordlists/big.txt             → 20469 entries (thorough)
/usr/share/dirb/wordlists/small.txt           → 959 entries (fast)
/usr/share/dirb/wordlists/vulns/              → vulnerability-specific lists
```

## Parsing Priorities

1. **CODE:200** → accessible, analyze content
2. **CODE:301/302** → redirects, follow and note destination
3. **CODE:401** → auth required, target for creds
4. **CODE:403** → exists but forbidden, bypass potential
5. **DIRECTORY entries** → recurse into them

## Junior Mistakes

- Not adding `-X` for extensions (misses .php, .bak files)
- Letting recursive scan run on huge sites (hangs forever, use `-r`)
- Using only the small wordlist (common.txt is minimum)
- Running both dirb and gobuster simultaneously (duplicate work, double noise)

## Pivot After dirb

Same as gobuster → see `tools/gobuster.md` pivot section.
