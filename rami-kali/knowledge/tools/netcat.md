# netcat (nc) — Network Swiss Army Knife

## Why
Raw TCP/UDP connections. Banner grabbing, port checking, file transfer, reverse shells, listener setup. Most versatile low-level network tool.

## When to Use

| Signal | Action |
|---|---|
| Need banner from unknown service | Raw connect + read |
| Need to test connectivity | Quick port check |
| Need reverse shell listener | nc -lvnp |
| Need file transfer | Sender + receiver |
| Need to interact with service | Manual protocol speaking |
| Unknown port open | Connect and see what responds |

## Common Invocations

```bash
# Banner grab (connect, read, disconnect)
nc -nv <target> <port>

# Banner grab with timeout
nc -nv -w 3 <target> <port>

# Listen for reverse shell
nc -lvnp <port>

# Port scan (basic, use nmap instead for real scanning)
nc -zv <target> <port_range>

# Send file
nc -lvnp <port> > received_file          # receiver
nc -nv <target> <port> < file_to_send     # sender

# UDP connection
nc -u <target> <port>

# Interact with HTTP manually
echo -e "GET / HTTP/1.1\r\nHost: <target>\r\n\r\n" | nc <target> 80

# Interact with SMTP manually
nc <target> 25
# then type: HELO test / VRFY admin / QUIT
```

## Use Cases by Scenario

### Banner Grabbing Unknown Services

```
PORT FOUND, SERVICE UNKNOWN:
  nc -nv -w 3 <target> <port>
  → Read whatever comes back
  → Service often identifies itself in banner
  → SSH, FTP, SMTP, MySQL all send banners
```

### Reverse Shell Listener

```
EXPLOIT WILL SEND SHELL BACK:
  1. Start listener:  nc -lvnp 4444
  2. Trigger exploit with callback to your_ip:4444
  3. Shell appears in netcat
```

### Manual Service Interaction

```
NEED TO SPEAK PROTOCOL:
  FTP:   nc <t> 21  → USER anonymous → PASS → LIST
  SMTP:  nc <t> 25  → HELO x → VRFY root → QUIT
  HTTP:  nc <t> 80  → GET / HTTP/1.0 + two newlines
  Redis: nc <t> 6379 → INFO → KEYS *
```

## Junior Mistakes

- Using nc for port scanning (use nmap, it's better at this)
- Forgetting `-n` flag (DNS resolution delays)
- Not setting timeout `-w` (hangs forever on filtered ports)
- Using wrong netcat version (ncat vs nc vs netcat — flags differ)
- Leaving listener running on common port (conflicts)

## Pivot After netcat

```
Banner grabbed?
  ├─ Service identified     → searchsploit version
  ├─ Custom/unknown service → google the banner string
  └─ No banner              → likely HTTP or encrypted

Shell received?
  ├─ Upgrade to PTY: python3 -c 'import pty;pty.spawn("/bin/bash")'
  ├─ Stabilize: Ctrl+Z → stty raw -echo → fg
  └─ Begin post-exploitation enumeration
```
