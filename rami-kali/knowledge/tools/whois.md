# whois — Domain Registration Lookup

## Why
Retrieves domain registration data. Zero noise, zero risk, pure passive recon. Always run first on domain targets.

## When to Use

| Signal | Action |
|---|---|
| Domain target given | Run immediately (passive) |
| Need registrant info | Organization, email, phone |
| Need infrastructure info | Nameservers, registrar |
| Need date context | Registration, expiry dates |

## Common Invocations

```bash
# Domain lookup
whois <domain>

# IP lookup (different registries)
whois <ip_address>

# Specific WHOIS server
whois -h whois.arin.net <ip_address>
```

## Parsing Priorities

| Field | Why It Matters |
|---|---|
| Registrant Org/Name | Target organization confirmation |
| Registrant Email | Contact, possible username |
| Name Servers | DNS infrastructure, hosting provider |
| Creation Date | How old, established vs recent |
| Updated Date | Recent changes? |
| Registrar | Hosting context |
| Status | Active, locked, pending delete |

## Intelligence Extraction

```
FROM WHOIS RESULTS:
  ├─ Email domain           → possible internal domain
  ├─ Name servers           → hosting provider → shared hosting?
  ├─ Registrant org         → other domains by same org?
  ├─ Phone/address          → OSINT leads
  └─ Privacy guard active?  → less useful, move to DNS recon
```

## Junior Mistakes

- Skipping whois entirely (free intel, zero risk)
- Not checking IP whois separately from domain whois (different data)
- Ignoring nameserver info (reveals hosting infrastructure)

## Pivot After whois

```
Nameservers found?    → dig for zone transfer
Email found?          → note as possible username
Org confirmed?        → context for targeted wordlists
IP range found?       → scope awareness for nmap
Privacy guarded?      → move to dig, DNS enum
```
