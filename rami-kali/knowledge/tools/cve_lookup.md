# cve_lookup — NVD CVE Intelligence

## Why
Queries the NIST National Vulnerability Database (NVD) in real time for authoritative CVE details.
Use it to obtain official CVSS scores, descriptions, affected products (CPEs), and references
without fabricating data from training knowledge.

## When to Use

| Signal | Action |
|---|---|
| CVE ID mentioned by user | Look up immediately — do not rely on training data |
| Version discovered (nmap/whatweb) | Search by keyword to find known CVEs |
| Vulnerability confirmed by nuclei/nikto | Enrich with official CVSS and description |
| Writing a report | Validate every CVE cited against NVD |

## Invocation Modes

```
# Exact CVE lookup
cve_lookup(cve_id="CVE-2021-44228")

# Keyword search (product + version)
cve_lookup(keyword="apache log4j 2.14", max_results=5)
cve_lookup(keyword="openssh 8.9", max_results=10)
cve_lookup(keyword="wordpress 6.0", max_results=5)
```

## Output Fields

| Field | Meaning |
|---|---|
| CVE ID | Official identifier |
| Status | `Analyzed` = fully reviewed by NVD; `Awaiting Analysis` = recent, not yet scored |
| Published / Modified | Disclosure and last-update dates |
| CVSSv3.1 score | Base score (0–10) + severity label + vector string |
| Description | Official NVD description — cite this verbatim |
| Affected CPEs | Specific product/version combinations confirmed vulnerable |
| References | Advisories, PoCs, patches — include in reports |

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
- If no CVE found → state "Not found in NVD" — do not invent a description.
- CPEs listed = confirmed affected products. Products not listed = unconfirmed.
- Never assign a severity not present in the output (e.g. do not upgrade MEDIUM to HIGH).

## Chaining Strategy

```
1. nmap/whatweb finds version
   → cve_lookup(keyword="<software> <version>")
   → for each HIGH/CRITICAL CVE: searchsploit_query(query="<CVE-ID>")
   → if exploit found: msf_console or manual exploitation

2. nuclei confirms CVE
   → cve_lookup(cve_id="<CVE-ID>") to enrich with CVSS + references

3. Report generation
   → cve_lookup per CVE cited to validate score and description
```

## Rate Limit

NVD API allows 5 requests per 30 seconds without an API key.
If multiple lookups are needed, space them out or use keyword search to batch results.
