"""Web scanner sub-modules.

Each module handles one aspect of web security scanning:
- crawler: async parallel page discovery
- header_scanner: security headers + CORS
- cookie_scanner: cookie flag analysis
- auth_scanner: authentication bypass detection
- param_scanner: SQLi, XSS, path traversal injection
- api_scanner: API endpoint discovery + exposed docs
"""
