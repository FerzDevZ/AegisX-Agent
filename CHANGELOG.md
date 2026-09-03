# Changelog

All notable changes to Aegisx-Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-03

### Added
- **Proxy support**: Route all requests through Burp/ZAP with `--proxy` flag
- **Rate limiting**: Token bucket rate limiter prevents DoS on targets
- **Request size limit**: Max 5MB response by default (configurable)
- **Scan timeout per phase**: Phase 2 (scanning) times out after 300s
- **Scope enforcement**: Exploit modules now check `is_in_scope()` before testing
- **`__all__` exports**: Clean public API for `scanners/web/` package
- **CHANGELOG.md**: Track changes properly
- **GitHub Actions CI/CD**: Automated testing on push/PR

### Changed
- Fixed 29 bare `except Exception` handlers — now use specific exceptions
- Improved error logging across all scanners and exploits
- Updated banner with ASCII art "AEGISX" logo
- Bumped version to 0.1.1

### Fixed
- `install.sh`: Clean ALL old alias entries from `.bashrc` (was only removing marked entries)
- `install.sh`: Fix `cd` issue when installing from within AegisX-Agent directory
- `install.sh`: Fix `ModuleNotFoundError` by ensuring `pip install -e .` runs in correct directory

## [0.1.0] - 2026-09-02

### Added
- **Scanners**: web, secret, config, dependency, network (5 total)
- **Exploits**: SQLi, XSS, CSRF, SSRF (4 total)
- **Reporters**: Markdown, JSON, SARIF, HTML (4 total)
- **CLI**: `aegisx scan`, `aegisx pentest`, `aegisx plugins`, `aegisx info`
- **Plugin system**: pluggy-based architecture for community plugins
- **Async parallel crawling**: 10 concurrent pages, 5 concurrent injections
- **Rate limiter**: Token bucket for outgoing requests
- **WAF detection**: Detects challenge pages (Cloudflare, Vercel)
- **Scope enforcement**: Configurable domain whitelist
- **install.sh**: One-command installer with dependency checking

### Security
- All HTTP clients use `verify=False` by default (necessary for scanning)
- SSRF payloads tested with scope enforcement
- Target URL validation prevents `file://` and `javascript:` schemes
