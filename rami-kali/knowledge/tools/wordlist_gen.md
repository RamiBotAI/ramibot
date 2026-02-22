# Wordlist Generation Tools

> Covers: crunch, cewl

---

## crunch — Pattern-Based Wordlist Generator

### Why
Generates wordlists based on character patterns. When you know password policy or format, generate targeted list instead of using generic rockyou.

### When to Use
| Signal | Action |
|---|---|
| Known password length | Generate exact length |
| Known character set | Targeted generation |
| Known pattern (Company + 4 digits) | Pattern-based generation |
| Existing wordlists too generic | Custom is better |

### Common Invocations
```bash
# Min 6, max 8, lowercase only
crunch 6 8 abcdefghijklmnopqrstuvwxyz -o wordlist.txt

# Specific pattern (@ = lower, , = upper, % = number, ^ = symbol)
crunch 8 8 -t Company%% -o wordlist.txt    # Company00-Company99

# Charset from string
crunch 4 4 0123456789 -o pins.txt          # all 4-digit PINs

# Using predefined charset
crunch 6 6 -f /usr/share/crunch/charset.lst mixalpha-numeric

# Pipe to tool (no file)
crunch 4 4 0123456789 | aircrack-ng -w - capture.cap
```

### Pattern Chars
| Char | Meaning |
|---|---|
| `@` | Lowercase letter |
| `,` | Uppercase letter |
| `%` | Number |
| `^` | Symbol |

---

## cewl — Website Wordlist Generator

### Why
Scrapes a website and generates wordlist from its content. Targets organization-specific terminology. Far more effective than generic wordlists for targeted attacks.

### When to Use
| Signal | Action |
|---|---|
| Target has website | Generate contextual wordlist |
| Need company-specific words | Scrape their site |
| Generic wordlists failing | Targeted approach |
| Before hydra/hashcat | Better wordlist = better results |

### Common Invocations
```bash
# Basic scrape (depth 2)
cewl http://<target> -d 2 -m 5 -w wordlist.txt

# With email extraction
cewl http://<target> -d 2 -m 5 -e --email_file emails.txt -w wordlist.txt

# Deeper crawl
cewl http://<target> -d 4 -m 6 -w wordlist.txt

# Include numbers
cewl http://<target> -d 2 -m 5 --with-numbers -w wordlist.txt

# With authentication
cewl http://<target> -d 2 --auth_type basic --auth_user admin --auth_pass pass -w wordlist.txt
```

### Parameters
| Flag | Meaning |
|---|---|
| `-d` | Crawl depth |
| `-m` | Minimum word length |
| `-w` | Output file |
| `-e` | Extract emails |
| `--with-numbers` | Include words with numbers |
| `-c` | Show word count |

---

## Wordlist Strategy Integration

```
ATTACK ORDER:
  1. cewl <target_website>           → contextual words
  2. Add company name variations     → manual
  3. crunch for known patterns       → Company%%%, etc.
  4. Combine: cat cewl.txt custom.txt > targeted.txt
  5. Use with hashcat rules          → multiply effectiveness
  6. Fallback: rockyou-top-10000     → generic common
  7. Last resort: full rockyou       → slow but comprehensive
```

## Junior Mistakes

- Using only rockyou (misses organization-specific passwords)
- crunch with too wide a range (8-char all ascii = terabytes)
- cewl depth too shallow (miss important pages)
- Not combining cewl output with mutations/rules
- Generating massive wordlists when small targeted ones work better
