"""
============================================================
 SQL INJECTION VULNERABILITY SCANNER
============================================================
LEGAL/ETHICAL NOTE:
Only test websites/applications you own or have explicit
written permission to test. Running this against sites you
don't control without permission is illegal.

This tool sends common SQLi test payloads to a URL parameter
and checks the response for signs of a database error, which
usually means the input isn't sanitized properly.

Install: pip install requests
============================================================
"""

import requests


# ============================================================
# STEP 1: COMMON SQL INJECTION TEST PAYLOADS
# ============================================================
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' AND '1'='1",
]

# Error messages commonly leaked by misconfigured databases
DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query()",
    "ora-01756",
    "microsoft odbc",
]


# ============================================================
# STEP 2: TEST A SINGLE URL + PARAMETER
# ============================================================
def test_parameter(base_url, param_name):
    """
    Sends each payload as the value of `param_name` in a GET request,
    then checks if the response contains a database error signature.
    """
    findings = []

    for payload in SQLI_PAYLOADS:
        params = {param_name: payload}
        try:
            response = requests.get(base_url, params=params, timeout=5)
            body = response.text.lower()

            for signature in DB_ERROR_SIGNATURES:
                if signature in body:
                    findings.append({
                        "payload": payload,
                        "signature_found": signature,
                        "status_code": response.status_code
                    })
                    break

        except requests.exceptions.RequestException as e:
            print(f"Request failed for payload '{payload}': {e}")

    return findings


# ============================================================
# STEP 3: SCAN MULTIPLE PARAMETERS
# ============================================================
def scan_url(base_url, param_names):
    print(f"\nScanning: {base_url}")
    print(f"Parameters to test: {param_names}\n")

    all_results = {}
    for param in param_names:
        print(f"Testing parameter: '{param}'...")
        results = test_parameter(base_url, param)
        all_results[param] = results

        if results:
            print(f"  [!] Possible SQL Injection vulnerability found on '{param}'")
            for r in results:
                print(f"      Payload: {r['payload']} | Signature: {r['signature_found']}")
        else:
            print(f"  [OK] No obvious vulnerability detected on '{param}'")

    return all_results


# ============================================================
# STEP 4: REPORT SUMMARY
# ============================================================
def print_summary(all_results):
    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    vulnerable = [p for p, r in all_results.items() if r]

    if vulnerable:
        print(f"Vulnerable parameters found: {vulnerable}")
        print("Recommendation: Use parameterized queries / prepared statements.")
    else:
        print("No obvious SQL injection vulnerabilities found with these payloads.")
        print("Note: This is a basic scanner, not a guarantee of full security.")


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=== SQL INJECTION VULNERABILITY SCANNER ===")
    print("(Only use on sites/apps you own or have permission to test)\n")

    url = input("Enter target URL (e.g. http://localhost:5000/search): ").strip()
    params_input = input("Enter parameter names to test, comma-separated (e.g. id,search): ").strip()
    param_list = [p.strip() for p in params_input.split(",")]

    results = scan_url(url, param_list)
    print_summary(results)
