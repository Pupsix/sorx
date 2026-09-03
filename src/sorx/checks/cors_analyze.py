from sorx.data.loader.template import load_template


def analyze(response, task):
    findings = []

    # Load templates
    header_template = load_template("sensitive_headers")
    method_template = load_template("sensitive_method")

    # Response headers & normalization
    headers = response.headers
    allow_origin = headers.get("Access-Control-Allow-Origin", "").strip().lower()
    allow_credentials = headers.get("Access-Control-Allow-Credentials", "").strip().lower()
    attacker_origin = (task.get("origin") or "").strip().lower()

    # Parse headers and methods into sets
    parse_csv = lambda val, case_fn: {case_fn(x.strip()) for x in val.split(",") if x.strip()} if val else set()
    allowed_headers = parse_csv(headers.get("Access-Control-Allow-Headers", ""), str.lower)
    allowed_methods = parse_csv(headers.get("Access-Control-Allow-Methods", ""), str.upper)
    exposed_headers = parse_csv(headers.get("Access-Control-Expose-Headers", ""), str.lower)

    # Sensitive lookup sets
    sensitive_request_headers = {h.lower() for h in header_template["sensitive_request_headers"]}
    sensitive_response_headers = {h.lower() for h in header_template["sensitive_response_headers"]}
    sensitive_methods = {m.upper() for m in method_template["sensitive_methods"]}

    # Basic check flags
    wildcard_origin = allow_origin == "*"
    origin_reflection = bool(attacker_origin and allow_origin == attacker_origin)
    null_origin = allow_origin == "null"
    credentials = allow_credentials == "true"

    validation_bypass = (origin_reflection and task.get("origin_type") == "validation_bypass")

    # Rule checks
    if wildcard_origin:
        findings.append(("CORS-001", "Wildcard origin"))

    if origin_reflection:
        findings.append(
            ("CORS-101", "Attacker origin reflected with credentials")
            if credentials
            else ("CORS-100", "Attacker origin reflected")
        )

    if null_origin:
        findings.append(
            ("CORS-200", "Null origin with credentials")
            if credentials
            else ("CORS-201", "Null origin allowed")
        )

    if validation_bypass:
        findings.append(
            (
                "CORS-501",
                "Origin validation bypass with credentials",
            )
            if credentials
            else (
                "CORS-500",
                "Origin validation bypass",
            )
        )

    # Header & Method checks
    found_sensitive_request_header = bool(allowed_headers & sensitive_request_headers)
    if found_sensitive_request_header:
        findings.append(("CORS-300", "Sensitive request header allowed"))

    if "*" in allowed_headers:
        findings.append(("CORS-301", "Wildcard request headers"))

    if "*" in allowed_methods:
        findings.append(("CORS-302", "Wildcard request methods"))

    if task.get("request_method"):
        requested_method = task["request_method"].strip().upper()
        if (requested_method in allowed_methods and "*" not in allowed_methods):
            findings.append(("CORS-303", "Dynamic request method reflection"))

    if task.get("request_headers"):
        requested_headers = parse_csv(task["request_headers"], str.lower,)

        if (requested_headers and requested_headers <= allowed_headers and "*" not in allowed_headers):
            findings.append(("CORS-304", "Dynamic request header reflection"))

    vary = headers.get("Vary", "")
    if (origin_reflection and "origin" not in parse_csv(vary, str.lower)):
        findings.append(("CORS-305", "Dynamic origin reflection without Vary"))
        
    found_sensitive_response_header = bool(exposed_headers & sensitive_response_headers)
    if found_sensitive_response_header:
        findings.append(("CORS-400", "Sensitive response header exposed"))

    found_sensitive_method = bool(allowed_methods & sensitive_methods)

    # Advanced correlation rules
    if origin_reflection and credentials:
        if "authorization" in allowed_headers:
            findings.append(("CORS-900", "Origin reflection with credentials and Authorization"))

        if found_sensitive_request_header or found_sensitive_response_header:
            findings.append(("CORS-901", "Origin reflection with credentials and sensitive headers"))

        if "*" in allowed_methods or found_sensitive_method:
            findings.append(("CORS-902", "Origin reflection with credentials and broad methods"))

        if "*" in allowed_methods or "*" in allowed_headers:
            findings.append(("CORS-903", "Origin reflection with credentials and wildcard permissions"))

        if found_sensitive_request_header and found_sensitive_response_header:
            findings.append(("CORS-904", "Origin reflection with credentials and sensitive headers"))

    return findings