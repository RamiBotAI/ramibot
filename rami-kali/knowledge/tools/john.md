# john — John the Ripper (CPU Password Cracker)

## Why
CPU-based password cracker. Better than hashcat for auto-detecting hash types, handling mixed formats, and cracking Linux shadow files directly. Complements hashcat.

## When to Use

| Signal | Action |
|---|---|
| /etc/shadow obtained | john handles it natively |
| Hash type unknown | john auto-detects better |
| Mixed hash file | john handles multiple types at once |
| hashcat not available/failing | Alternative cracking engine |
| zip/rar/pdf password | john has built-in format tools |
| SSH key passphrase | ssh2john → john |

## hashcat vs john — When to Choose

| Scenario | Tool |
|---|---|
| Known hash type + GPU available | hashcat (faster) |
| Unknown hash type | john (auto-detect) |
| /etc/shadow directly | john (native support) |
| Archive passwords (zip, rar, 7z) | john (has *2john tools) |
| SSH/PGP key passphrases | john (ssh2john, gpg2john) |
| Kerberos tickets | john or hashcat |
| Need max speed | hashcat (GPU) |

## Common Invocations

```bash
# Auto-detect and crack
john <hashfile>

# With wordlist
john --wordlist=<wordlist> <hashfile>

# With rules
john --wordlist=<wordlist> --rules <hashfile>

# Specific format
john --format=<format> <hashfile>

# Show cracked
john --show <hashfile>

# Crack /etc/shadow directly
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=<wordlist> unshadowed.txt
```

## Format Extraction Tools (*2john)

```bash
# SSH private key
ssh2john id_rsa > ssh_hash.txt

# ZIP file
zip2john protected.zip > zip_hash.txt

# RAR file
rar2john protected.rar > rar_hash.txt

# PDF file
pdf2john protected.pdf > pdf_hash.txt

# KeePass database
keepass2john database.kdbx > keepass_hash.txt

# 7-Zip
7z2john protected.7z > 7z_hash.txt

# Then crack
john --wordlist=<wordlist> <extracted_hash>
```

## Common Formats

| Format Flag | Type |
|---|---|
| `raw-md5` | Plain MD5 |
| `raw-sha1` | Plain SHA1 |
| `raw-sha256` | Plain SHA256 |
| `nt` | NTLM |
| `bcrypt` | bcrypt |
| `sha512crypt` | Linux $6$ |
| `md5crypt` | Linux $1$ |
| `phpass` | WordPress |
| `krb5tgs` | Kerberoast |

## Junior Mistakes

- Not using `unshadow` to combine passwd + shadow
- Forgetting the *2john extraction step for archives/keys
- Running without `--wordlist` (defaults to incremental = slow)
- Not checking `john --show` for already cracked hashes
- Duplicate work: running john AND hashcat on same hash simultaneously

## Pivot After john

```
Password cracked?
  ├─ System password?    → SSH login, sudo access
  ├─ Archive password?   → extract files, search for more creds
  ├─ SSH key passphrase? → use key to login
  ├─ DB password?        → connect to database
  └─ Any password        → try reuse on all services

Not cracking?
  ├─ Try larger wordlist + rules
  ├─ Try hashcat with GPU
  ├─ Try targeted/contextual wordlist
  └─ Accept and move on to other vectors
```
