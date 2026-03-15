# cve_lookup — NVD CVE Intelligence

## Why
Queries the NIST National Vulnerability Database (NVD) 2.0 API in real time for authoritative CVE details.
Use it to obtain official CVSS scores, descriptions, affected products (CPEs), and references
without fabricating data from training knowledge.

## When to Use

| Signal | Action |
|---|---|
| CVE ID mentioned by user | Look up immediately — do not rely on training data |
| Version discovered (nmap/whatweb) | `keyword="<product> <version>"` |
| Need only HIGH/CRITICAL results | Add `cvss_severity="HIGH"` or `"CRITICAL"` |
| CPE confirmed from earlier output | `cpe_name="cpe:2.3:a:vendor:product:version:..."` |
| Vulnerability confirmed by nuclei/nikto | Enrich with `cve_id="<CVE-ID>"` |
| Writing a report | Validate every CVE cited against NVD |

## Parameters

| Parameter | Type | Description |
|---|---|---|
| `cve_id` | string | Exact CVE ID (e.g. `CVE-2021-44228`). Mutually exclusive with keyword/cpe_name/virtual_match_string |
| `keyword` | string | Product+version keyword (e.g. `"OpenSSH 7.9"`). Mutually exclusive with cve_id |
| `exact_match` | boolean | Require keyword to appear as a whole word. Only with `keyword` |
| `cpe_name` | string | Filter by full CPE 2.3 name (e.g. `"cpe:2.3:a:openbsd:openssh:7.9:*:*:*:*:*:*:*"`) |
| `virtual_match_string` | string | CPE match string pattern (e.g. `"cpe:2.3:a:apache:http_server:2.4.*"`) |
| `cvss_severity` | string | Filter by CVSSv3 severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `pub_start_date` | string | CVEs published on or after this date (`YYYY-MM-DD`) |
| `pub_end_date` | string | CVEs published on or before this date (`YYYY-MM-DD`) |
| `last_mod_start_date` | string | CVEs modified on or after this date (`YYYY-MM-DD`) |
| `last_mod_end_date` | string | CVEs modified on or before this date (`YYYY-MM-DD`) |
| `no_rejected` | boolean | Exclude CVEs with REJECT/Rejected status |
| `max_results` | integer | Max results to return (1–20, default 5). Not used with `cve_id` |

## Invocation Examples

```python
# 1. Exact CVE lookup
cve_lookup(cve_id="CVE-2021-44228")

# 2. Keyword search — product + version (most common after nmap)
cve_lookup(keyword="OpenSSH 7.9", max_results=5)
cve_lookup(keyword="Apache httpd 2.4.38", max_results=10)

# 3. Keyword + severity filter — only critical results
cve_lookup(keyword="OpenSSH 7.9", cvss_severity="CRITICAL")

# 4. Exact keyword match — avoid partial matches
cve_lookup(keyword="openssh", exact_match=True, max_results=10)

# 5. CPE-based lookup — precise product scope
cve_lookup(cpe_name="cpe:2.3:a:openbsd:openssh:7.9:*:*:*:*:*:*:*")

# 6. CPE match string — all 2.4.x versions of Apache httpd
cve_lookup(virtual_match_string="cpe:2.3:a:apache:http_server:2.4.*", cvss_severity="HIGH")

# 7. Date-range query — CVEs published in a time window
cve_lookup(keyword="linux kernel", pub_start_date="2024-01-01", pub_end_date="2024-12-31")

# 8. Recently modified CVEs for a product
cve_lookup(keyword="nginx", last_mod_start_date="2024-06-01", no_rejected=True)
```

## Output Fields

| Field | Meaning |
|---|---|
| CVE ID | Official identifier |
| SERVICE BINDING | Products derived from CPE data — attach CVE only to matching detected services |
| Status | `Analyzed` = fully reviewed; `Awaiting Analysis` = not yet scored |
| Published / Modified | Disclosure and last-update dates |
| CVSSv3.1 score | Base score (0–10) + severity label + vector string |
| Description | Official NVD description — cite verbatim |
| Affected CPEs | Specific product/version combinations confirmed vulnerable |
| References | Advisories, PoCs, patches |

## CVSS Severity Bands

| Score | Label |
|---|---|
| 9.0 – 10.0 | CRITICAL |
| 7.0 – 8.9 | HIGH |
| 4.0 – 6.9 | MEDIUM |
| 0.1 – 3.9 | LOW |
| 0.0 | NONE |

## Evidence Rules

- **Only cite facts present in the NVD output.** Do not fill gaps with training knowledge.
- If `Status: Awaiting Analysis` → CVSS may be preliminary or absent; state this explicitly.
- If no CVE found → state "No confirmed CVEs found for [product version]. Manual research required."
- The **SERVICE BINDING** line in each CVE entry names the affected products from CPE data.
  Attach the CVE only to a detected service that matches — never to an unrelated service on the same host.
- CPEs listed = confirmed affected products. Products not listed = unconfirmed.
- Never assign a severity not present in the output (e.g. do not upgrade MEDIUM to HIGH).

## CVE Query Lock — Mandatory Before Every Call

Before calling `cve_lookup` after service discovery:

```
a. Extract exact product name from Evidence Block (e.g. "OpenSSH")
b. Extract exact version string from Evidence Block (e.g. "7.9p1")
c. Build query: keyword="OpenSSH 7.9"
d. Add application name only if explicitly detected by a tool
e. If no results: "No confirmed CVEs found for OpenSSH 7.9. Manual research required."
```

**NEVER query by host IP. NEVER assume adjacent products (Apache ≠ Log4j).**

## Chaining Strategy

```
1. nmap/whatweb finds version
   → cve_lookup(keyword="<product> <version>")
   → optionally narrow: cve_lookup(keyword="<product> <version>", cvss_severity="HIGH")
   → for each HIGH/CRITICAL CVE: searchsploit_query(query="<CVE-ID>")
   → if exploit found: msf_console or manual exploitation

2. CPE known from earlier scan
   → cve_lookup(cpe_name="<full CPE string>")

3. nuclei confirms CVE
   → cve_lookup(cve_id="<CVE-ID>") to enrich with CVSS + references

4. Report generation
   → cve_lookup(cve_id="<CVE-ID>") per CVE cited to validate score and description
```

## Rate Limit

NVD API allows 5 requests per 30 seconds without an API key.
If multiple lookups are needed, space them out or batch by using keyword+severity to reduce call count.
