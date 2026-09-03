"""Web scanner sub-modules.

Each module handles one aspect of web security scanning:
- crawler: async parallel page discovery
- header_scanner: security headers + CORS
- cookie_scanner: cookie flag analysis
- auth_scanner: authentication bypass detection
- param_scanner: SQLi, XSS, path traversal injection
- api_scanner: API endpoint discovery + exposed docs
"""

__all__ = [
    "crawl_pages",
    "check_headers",
    "check_cors",
    "check_cookies",
    "check_auth_bypass",
    "check_sqli",
    "check_xss",
    "check_path_traversal",
    "extract_forms",
    "check_api_endpoints",
]
