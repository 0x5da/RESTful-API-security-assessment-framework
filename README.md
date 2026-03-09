## API Security Scanner

RESTful API security assessment framework. Discovers endpoints, performs CORS analysis, tests authentication mechanisms, and identifies common misconfigurations (HSTS, CSP, etc.). Designed for rapid security baseline evaluation of HTTP APIs.

### What It Does

- **Endpoint Discovery**: Brute-force enumeration of API paths and endpoints
- **CORS Analysis**: Tests for overly permissive cross-origin configurations
- **Security Header Audit**: Validates presence of X-Frame-Options, HSTS, CSP, et al
- **Authentication Detection**: Identifies and categorizes auth methods (Bearer, Basic, OAuth2, Digest)
- **Sensitive Data Detection**: Regex-based scanning for exposed API keys, tokens, passwords
- **Response Analysis**: Content-type inspection and status code tracking

### How It Works

The scanner maintains a session with persistent headers (User-Agent, etc.) and performs sequential endpoint testing. For discovery, it combines common API path patterns with endpoint keywords (users, products, admin, etc.). Each endpoint is probed with HTTP HEAD followed by GET for banner analysis. Misconfigurations are detected via response header inspection and pattern matching against response bodies.

### Installation & Usage

```bash
pip install -r requirements.txt
python auditor.py <url> [-w WORDLIST] [-t TIMEOUT] [-o OUTPUT]
```

**Arguments:**
- `url`: Target API base URL (e.g., https://api.example.com)
- `-w, --wordlist`: Custom endpoint wordlist (optional)
- `-t, --timeout`: Request timeout in seconds (default: 5)
- `-o, --output`: Export results to JSON file

**Examples:**
```bash
# Quick baseline scan
python auditor.py https://api.example.com

# With custom wordlist and 10-second timeout
python auditor.py https://api.company.com -w endpoints.txt -t 10

# Full audit with comprehensive output
python auditor.py https://target.com/api/v1 -o audit_report.json
```

### Requirements

- Python 3.8+
- requests 2.28.0+
- urllib3 1.26.0+

### Endpoint Wordlist Format

Plain text file with API paths:
```
/users
/products
/orders
/admin/settings
/api/v2/accounts
```

### Detected Issues

1. **CORS_MISCONFIGURATION**: Overly permissive Access-Control-Allow-Origin headers
2. **MISSING_SECURITY_HEADER**: X-Content-Type-Options, X-Frame-Options, HSTS, etc.
3. **SENSITIVE_DATA_EXPOSURE**: API keys, tokens, passwords in response body

### Sample Output

```
======================================================================
API SECURITY AUDIT REPORT
======================================================================
Target: https://api.example.com
Endpoints Tested: 87
Issues Found: 12

[CRITICAL] SENSITIVE_DATA_EXPOSURE
[HIGH] CORS_MISCONFIGURATION
    Origin: http://evil.com
[MEDIUM] MISSING_SECURITY_HEADER
    Missing: Strict-Transport-Security
```

### Notes

- Endpoint discovery is combinatorial (paths × endpoints); large wordlists = extended runtime
- HEAD requests used for initial probing to minimize traffic; some servers may return errors
- CORS issues detected only if response includes ACAO header; silent/missing headers reported
- Sensitive data detection is regex-based and may produce false positives
- Request timeout applies per-endpoint; slow APIs may time out prematurely

### Common Issues & Workarounds

- **Timeout**: Increase `-t` value if target API is slow
- **No endpoints discovered**: Check base URL format; may need trailing slash
- **Auth errors (401/403)**: Tool does not handle authentication; test on public endpoints only
- **Rate limiting**: Target server may block repeated requests; use `--timeout` to throttle

### Limitations

- Does not test authentication bypass (Auth: none, missing tokens, etc.)
- Parameter injection testing not implemented
- No response body fuzzing
- Does not follow redirects beyond initial hop
