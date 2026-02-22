# dig — DNS Lookup & Enumeration

## Why
Queries DNS records. Reveals subdomains, mail servers, nameservers, TXT records. Zone transfer = full domain map. Low noise, high value.

## When to Use

| Signal | Action |
|---|---|
| Domain target given | Run after whois |
| Need subdomains | Zone transfer + brute |
| Need mail server | MX records |
| Port 53 open on target | DNS server → zone transfer attempt |
| Need to verify resolution | A/AAAA records |

## Common Invocations

```bash
# All records
dig <domain> ANY

# Specific record types
dig <domain> A          # IPv4 address
dig <domain> AAAA       # IPv6 address
dig <domain> MX         # Mail servers
dig <domain> NS         # Name servers
dig <domain> TXT        # Text records (SPF, DKIM, verification)
dig <domain> CNAME      # Aliases
dig <domain> SOA        # Start of authority

# Zone transfer (jackpot if it works)
dig axfr @<nameserver> <domain>

# Query specific DNS server
dig @<dns_server> <domain>

# Reverse lookup
dig -x <ip_address>

# Short output
dig +short <domain>

# Trace resolution path
dig +trace <domain>
```

## Parsing Priorities

| Record | Offensive Value |
|---|---|
| A/AAAA | IP addresses → nmap targets |
| MX | Mail servers → SMTP enum, phishing infra |
| NS | Name servers → zone transfer targets |
| TXT | SPF records → email security posture; verification tokens → info leak |
| CNAME | Aliases → subdomain takeover potential |
| SOA | Primary NS, admin email |
| AXFR (zone transfer) | **FULL subdomain map** → massive attack surface |

## Zone Transfer Success

```
IF AXFR WORKS:
  → You now have ALL subdomains
  → Map every IP found
  → Identify internal hostnames (dev, staging, admin, vpn, db)
  → Each subdomain = potential separate target
  → Some may resolve to internal IPs (info leak)
```

## TXT Record Intelligence

```
TXT RECORDS REVEAL:
  ├─ SPF → which IPs can send email (mail server IPs)
  ├─ DKIM → email signing config
  ├─ google-site-verification → uses Google services
  ├─ ms= → uses Microsoft 365
  ├─ facebook-domain → FB business account
  ├─ _dmarc → email security policy strictness
  └─ v=spf1 include:_spf.google.com → hosted on Google Workspace
```

## Junior Mistakes

- Not attempting zone transfer (free complete map if misconfigured)
- Only checking A records (MX, TXT, NS all have intel value)
- Not querying the target's own DNS server (may have different results)
- Ignoring CNAME chains (potential subdomain takeover)

## Pivot After dig

```
Zone transfer success? → nmap every discovered IP
MX servers found?      → SMTP enum on mail servers
Subdomains found?      → whatweb + nmap on each
Internal IPs leaked?   → note for pivot after initial access
SPF/DMARC weak?        → note for social engineering path
```
