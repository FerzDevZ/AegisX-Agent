"""Network scanner — port scanning, service detection, and vulnerability checks.

Features:
- TCP port scanning (common + top 100 ports)
- Service fingerprinting and banner grabbing
- SSL/TLS certificate analysis
- DNS enumeration
- Common service vulnerability checks
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from aegisx.core.context import Finding, ScanContext, Severity
from aegisx.scanners.base_scanner import BaseScanner
from aegisx.utils.http_client import create_client
from aegisx.utils.logger import get_logger

logger = get_logger("network_scanner")


# Common ports to scan
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# Top 100 ports (subset for quick scan)
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9200, 11211, 27017,
]

# Dangerous services that should not be exposed
DANGEROUS_SERVICES: dict[int, tuple[str, str, Severity]] = {
    21: ("FTP", "FTP transmits credentials in plaintext", Severity.HIGH),
    23: ("Telnet", "Telnet transmits all data in plaintext", Severity.CRITICAL),
    25: ("SMTP", "Open relay can be used for spam", Severity.MEDIUM),
    111: ("RPCBind", "RPCBind can expose internal services", Severity.HIGH),
    135: ("MSRPC", "Windows RPC exposed to network", Severity.HIGH),
    139: ("NetBIOS", "NetBIOS exposes system information", Severity.HIGH),
    445: ("SMB", "SMB exposed can lead to remote code execution", Severity.CRITICAL),
    1433: ("MSSQL", "Database should not be exposed", Severity.CRITICAL),
    1521: ("Oracle", "Database should not be exposed", Severity.CRITICAL),
    2049: ("NFS", "NFS can expose file systems", Severity.HIGH),
    3306: ("MySQL", "Database should not be exposed", Severity.CRITICAL),
    3389: ("RDP", "RDP brute-force risk", Severity.HIGH),
    5432: ("PostgreSQL", "Database should not be exposed", Severity.CRITICAL),
    5900: ("VNC", "VNC often lacks authentication", Severity.HIGH),
    6379: ("Redis", "Redis often has no authentication", Severity.CRITICAL),
    9200: ("Elasticsearch", "Elasticsearch often lacks auth", Severity.HIGH),
    11211: ("Memcached", "Memcached can be used for DDoS", Severity.HIGH),
    27017: ("MongoDB", "MongoDB often has no authentication", Severity.CRITICAL),
}


@dataclass
class PortResult:
    """Result of a single port scan."""
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    response_time_ms: float = 0.0


class NetworkScanner(BaseScanner):
    """Scans for network-level vulnerabilities: open ports, services, SSL/TLS issues."""

    name = "network_scanner"
    description = "Network port scanning, service detection, and SSL/TLS analysis"

    def __init__(self, context: ScanContext) -> None:
        super().__init__(context)
        self._target_host: str = ""
        self._target_ip: str = ""

    async def validate_target(self) -> bool:
        """Validate that the target host can be resolved."""
        parsed = urlparse(self.config.target_url)
        self._target_host = parsed.hostname or ""

        if not self._target_host:
            logger.error("No hostname found in target URL")
            return False

        try:
            self._target_ip = socket.gethostbyname(self._target_host)
            logger.info("Resolved %s -> %s", self._target_host, self._target_ip)
            return True
        except socket.gaierror as e:
            logger.error("Cannot resolve host %s: %s", self._target_host, e)
            return False

    async def scan(self) -> list[Finding]:
        """Execute all network checks."""
        findings: list[Finding] = []

        # Phase 1: Port scanning
        open_ports = await self._scan_ports()
        logger.info("Found %d open ports", len(open_ports))

        # Phase 2: Service detection on open ports
        service_findings = await self._detect_services(open_ports)
        findings += service_findings

        # Phase 3: SSL/TLS analysis
        findings += await self._check_ssl_tls()

        # Phase 4: DNS checks
        findings += await self._check_dns()

        # Phase 5: HTTP security on non-standard ports
        findings += await self._check_non_standard_http(open_ports)

        return findings

    async def _scan_ports(self) -> list[PortResult]:
        """Scan common ports on the target host."""
        open_ports: list[PortResult] = []

        # Determine which ports to scan
        ports_to_scan = TOP_100_PORTS

        logger.info("Scanning %d ports on %s...", len(ports_to_scan), self._target_host)

        # Async port scan with concurrency limit
        semaphore = asyncio.Semaphore(50)

        async def scan_port(port: int) -> PortResult | None:
            async with semaphore:
                try:
                    start = time.time()
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self._target_ip, port),
                        timeout=2.0,
                    )
                    elapsed = (time.time() - start) * 1000

                    # Try to grab banner
                    banner = ""
                    try:
                        writer.write(b"\r\n")
                        await asyncio.wait_for(writer.drain(), timeout=1.0)
                        data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                        banner = data.decode("utf-8", errors="ignore").strip()
                    except (asyncio.TimeoutError, ConnectionResetError, OSError):
                        pass

                    writer.close()
                    await writer.wait_closed()

                    service_name = COMMON_PORTS.get(port, "Unknown")
                    return PortResult(
                        port=port,
                        is_open=True,
                        service=service_name,
                        banner=banner[:200],
                        response_time_ms=elapsed,
                    )
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        # Run all port scans concurrently
        tasks = [scan_port(port) for port in ports_to_scan]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result and result.is_open:
                open_ports.append(result)

        return sorted(open_ports, key=lambda p: p.port)

    async def _detect_services(self, open_ports: list[PortResult]) -> list[Finding]:
        """Analyze open ports and detect dangerous services."""
        findings: list[Finding] = []

        for port_result in open_ports:
            port = port_result.port
            service = port_result.service

            # Check for dangerous services
            if port in DANGEROUS_SERVICES:
                svc_name, desc, severity = DANGEROUS_SERVICES[port]
                findings.append(Finding(
                    title=f"Exposed Service: {svc_name} (Port {port})",
                    description=(
                        f"{svc_name} is exposed on port {port}. {desc}. "
                        f"Response time: {port_result.response_time_ms:.0f}ms"
                    ),
                    severity=severity,
                    cvss_score=self._calculate_port_cvss(port),
                    cwe_id="CWE-284",
                    owasp_category="A05:2021",
                    url=self.config.target_url,
                    endpoint=f"{self._target_host}:{port}",
                    method="TCP",
                    evidence=f"Port {port} open — Service: {service}" + (f" — Banner: {port_result.banner}" if port_result.banner else ""),
                    remediation=(
                        f"Restrict access to port {port} ({svc_name}) using firewall rules. "
                        "If the service is not needed, disable it. "
                        "If needed, restrict access to specific IP ranges."
                    ),
                    references=[
                        f"https://www.cvedetails.com/vulnerability-list/vendor_id-1/product_id-1/{svc_name}.html",
                    ],
                ))

            # Check for unknown services on high ports
            elif port > 1024 and port not in COMMON_PORTS:
                findings.append(Finding(
                    title=f"Unknown Service on Port {port}",
                    description=(
                        f"An unknown service is running on port {port}. "
                        "Unknown services should be investigated and removed if not needed."
                    ),
                    severity=Severity.LOW,
                    cwe_id="CWE-16",
                    owasp_category="A05:2021",
                    url=self.config.target_url,
                    endpoint=f"{self._target_host}:{port}",
                    method="TCP",
                    evidence=f"Port {port} open — Banner: {port_result.banner}" if port_result.banner else f"Port {port} open — No banner",
                    remediation="Investigate and remove unknown services.",
                ))

            # Check for banner information disclosure
            if port_result.banner:
                disclosure_findings = self._check_banner_disclosure(port_result)
                findings.extend(disclosure_findings)

        return findings

    def _check_banner_disclosure(self, port_result: PortResult) -> list[Finding]:
        """Check if service banners leak version information."""
        findings = []
        banner = port_result.banner.lower()

        # Patterns that reveal version info
        version_patterns = [
            (r"apache/\d+\.\d+", "Apache"),
            (r"nginx/\d+\.\d+", "Nginx"),
            (r"openssh_\d+\.\d+", "OpenSSH"),
            (r"vsftpd\d+\.\d+", "vsftpd"),
            (r"proftpd\d+\.\d+", "ProFTPD"),
            (r"mysql\d+\.\d+", "MySQL"),
            (r"redis_version:\d+\.\d+", "Redis"),
            (r"mongo\d+\.\d+", "MongoDB"),
        ]

        import re
        for pattern, service in version_patterns:
            if re.search(pattern, banner):
                findings.append(Finding(
                    title=f"{service} Version Disclosure (Port {port_result.port})",
                    description=(
                        f"The {service} banner on port {port_result.port} reveals version information. "
                        "This helps attackers identify specific vulnerabilities."
                    ),
                    severity=Severity.LOW,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021",
                    url=self.config.target_url,
                    endpoint=f"{self._target_host}:{port_result.port}",
                    method="TCP",
                    evidence=f"Banner: {port_result.banner}",
                    remediation=f"Configure {service} to hide version information.",
                ))
                break

        return findings

    async def _check_ssl_tls(self) -> list[Finding]:
        """Analyze SSL/TLS configuration."""
        findings = []

        try:
            # Connect with SSL
            parsed = urlparse(self.config.target_url)
            hostname = parsed.hostname or self._target_host
            port = parsed.port or 443

            # Create SSL context
            context = ssl.create_default_context()

            # Try to connect
            loop = asyncio.get_event_loop()

            def ssl_check() -> dict[str, Any]:
                result: dict[str, Any] = {}
                try:
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            version = ssock.version()

                            result["cert"] = cert
                            result["cipher"] = cipher
                            result["tls_version"] = version
                            result["success"] = True
                except (ssl.SSLError, socket.error, OSError) as e:
                    result["error"] = type(e).__name__
                    result["success"] = False
                return result

            ssl_result = await loop.run_in_executor(None, ssl_check)

            if not ssl_result.get("success"):
                error = ssl_result.get("error", "Unknown error")
                if "self-signed" in error.lower():
                    findings.append(Finding(
                        title="Self-Signed SSL Certificate",
                        description=(
                            "The SSL certificate is self-signed. Browsers will show "
                            "security warnings to users."
                        ),
                        severity=Severity.HIGH,
                        cvss_score=7.0,
                        cwe_id="CWE-295",
                        owasp_category="A07:2021",
                        url=self.config.target_url,
                        method="TLS",
                        evidence=f"SSL Error: {error}",
                        remediation="Use a certificate from a trusted Certificate Authority.",
                    ))
                elif "expired" in error.lower():
                    findings.append(Finding(
                        title="Expired SSL Certificate",
                        description="The SSL certificate has expired.",
                        severity=Severity.CRITICAL,
                        cvss_score=9.0,
                        cwe_id="CWE-295",
                        owasp_category="A07:2021",
                        url=self.config.target_url,
                        method="TLS",
                        evidence=f"SSL Error: {error}",
                        remediation="Renew the SSL certificate immediately.",
                    ))
                elif "certificate verify" in error.lower() or "ssl" in error.lower():
                    findings.append(Finding(
                        title="SSL/TLS Connection Failed",
                        description=f"SSL/TLS connection failed: {error}",
                        severity=Severity.HIGH,
                        cwe_id="CWE-295",
                        owasp_category="A07:2021",
                        url=self.config.target_url,
                        method="TLS",
                        evidence=f"SSL Error: {error}",
                        remediation="Configure valid SSL/TLS certificate.",
                    ))
                return findings

            # Analyze certificate
            cert = ssl_result.get("cert", {})
            if cert:
                findings += self._analyze_certificate(cert, hostname)

            # Check TLS version
            tls_version = ssl_result.get("tls_version", "")
            if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                findings.append(Finding(
                    title=f"Outdated TLS Version: {tls_version}",
                    description=(
                        f"The server uses {tls_version} which is deprecated and vulnerable. "
                        "TLS 1.2 or 1.3 should be used."
                    ),
                    severity=Severity.HIGH,
                    cvss_score=7.0,
                    cwe_id="CWE-326",
                    owasp_category="A02:2021",
                    url=self.config.target_url,
                    method="TLS",
                    evidence=f"TLS Version: {tls_version}",
                    remediation="Disable TLS 1.0/1.1 and enable TLS 1.2+.",
                ))

            # Check cipher
            cipher = ssl_result.get("cipher", ())
            if cipher and len(cipher) >= 1:
                cipher_name = cipher[0]
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
                for weak in weak_ciphers:
                    if weak in cipher_name.upper():
                        findings.append(Finding(
                            title=f"Weak Cipher: {cipher_name}",
                            description=f"The cipher suite {cipher_name} is considered weak.",
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-326",
                            owasp_category="A02:2021",
                            url=self.config.target_url,
                            method="TLS",
                            evidence=f"Cipher: {cipher_name}",
                            remediation="Use strong cipher suites (AES-GCM, ChaCha20).",
                        ))
                        break

        except (ssl.SSLError, socket.error, OSError) as e:
            logger.debug("SSL/TLS check failed: %s", type(e).__name__)

        return findings

    def _analyze_certificate(self, cert: dict, hostname: str) -> list[Finding]:
        """Analyze SSL certificate for issues."""
        findings = []

        import datetime

        # Check expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                # Parse the date (format: "Mon DD HH:MM:SS YYYY GMT")
                expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (expire_date - now).days

                if days_left < 0:
                    findings.append(Finding(
                        title="SSL Certificate Expired",
                        description=f"The SSL certificate expired {abs(days_left)} days ago.",
                        severity=Severity.CRITICAL,
                        cvss_score=9.0,
                        cwe_id="CWE-295",
                        owasp_category="A07:2021",
                        url=self.config.target_url,
                        method="TLS",
                        evidence=f"Expired: {not_after}",
                        remediation="Renew the SSL certificate immediately.",
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        title="SSL Certificate Expiring Soon",
                        description=f"The SSL certificate expires in {days_left} days.",
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-295",
                        owasp_category="A07:2021",
                        url=self.config.target_url,
                        method="TLS",
                        evidence=f"Expires: {not_after}",
                        remediation="Renew the SSL certificate before expiration.",
                    ))
            except ValueError:
                pass

        # Check subject
        subject = dict(x[0] for x in cert.get("subject", ()))
        cn = subject.get("commonName", "")
        if cn and cn != hostname and not self._cn_matches_hostname(cn, hostname):
            findings.append(Finding(
                title="SSL Certificate CN Mismatch",
                description=(
                    f"The certificate Common Name '{cn}' does not match "
                    f"the hostname '{hostname}'."
                ),
                severity=Severity.HIGH,
                cvss_score=7.0,
                cwe_id="CWE-297",
                owasp_category="A07:2021",
                url=self.config.target_url,
                method="TLS",
                evidence=f"CN: {cn}, Expected: {hostname}",
                remediation="Issue a certificate with the correct Common Name or SAN.",
            ))

        # Check if using SAN
        san_names = []
        for ext in cert.get("subjectAltName", ()):
            if ext[0] == "DNS":
                san_names.append(ext[1])

        if not san_names:
            findings.append(Finding(
                title="SSL Certificate Without SAN",
                description="The certificate does not use Subject Alternative Names (SAN).",
                severity=Severity.LOW,
                cwe_id="CWE-295",
                owasp_category="A07:2021",
                url=self.config.target_url,
                method="TLS",
                remediation="Use SAN certificates for better compatibility.",
            ))

        return findings

    def _cn_matches_hostname(self, cn: str, hostname: str) -> bool:
        """Check if a certificate CN matches a hostname."""
        if cn.startswith("*."):
            # Wildcard match
            wildcard_domain = cn[2:]
            return hostname.endswith(wildcard_domain) or hostname == wildcard_domain
        return cn == hostname

    async def _check_dns(self) -> list[Finding]:
        """Check DNS configuration for issues."""
        findings = []

        try:
            # Check for zone transfer
            import subprocess
            result = await asyncio.create_subprocess_exec(
                "dig", self._target_host, "+short",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await result.communicate()
            dns_result = stdout.decode().strip()

            if dns_result:
                # Check if IP matches
                ips = dns_result.split("\n")
                for ip in ips:
                    ip = ip.strip()
                    if ip == self._target_ip:
                        break
                else:
                    if ips and ips[0]:
                        findings.append(Finding(
                            title="DNS Mismatch",
                            description=(
                                f"DNS resolves to {ips[0]} but we connected to {self._target_ip}. "
                                "This could indicate DNS poisoning or CDN configuration."
                            ),
                            severity=Severity.LOW,
                            cwe_id="CWE-350",
                            owasp_category="A05:2021",
                            url=self.config.target_url,
                            method="DNS",
                            evidence=f"DNS: {dns_result}, Connected: {self._target_ip}",
                            remediation="Verify DNS configuration is correct.",
                        ))

        except FileNotFoundError:
            # dig not available, skip
            pass
        except (FileNotFoundError, subprocess.SubprocessError, OSError) as e:
            logger.debug("DNS check failed: %s", type(e).__name__)

        return findings

    async def _check_non_standard_http(self, open_ports: list[PortResult]) -> list[Finding]:
        """Check HTTP on non-standard ports."""
        findings = []

        http_ports = [p.port for p in open_ports if p.port not in (80, 443) and p.service in ("HTTP", "HTTP-Proxy", "HTTP-Alt")]

        for port in http_ports:
            try:
                scheme = "https" if port in (8443, 4443) else "http"
                url = f"{scheme}://{self._target_host}:{port}/"

                async with create_client(self.config) as client:
                    response = await client.get(url)

                    # Check for exposed admin panels
                    body = response.text.lower()
                    admin_indicators = ["admin", "login", "dashboard", "phpmyadmin"]
                    if any(indicator in body for indicator in admin_indicators):
                        findings.append(Finding(
                            title=f"HTTP Service on Non-Standard Port {port}",
                            description=(
                                f"An HTTP service with admin/login content is running on "
                                f"non-standard port {port}. This may be an unintended exposure."
                            ),
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-284",
                            owasp_category="A05:2021",
                            url=url,
                            endpoint=f":{port}/",
                            method="GET",
                            evidence=f"HTTP {response.status_code} on port {port}",
                            remediation="Restrict access to non-standard HTTP ports.",
                        ))

            except (httpx.RequestError, httpx.TimeoutException):
                pass

        return findings

    @staticmethod
    def _calculate_port_cvss(port: int) -> float:
        """Calculate CVSS-like score for exposed port."""
        if port in (445, 1433, 3306, 5432, 6379, 27017):
            return 9.0  # Critical — databases/SMB exposed
        if port in (23, 3389):
            return 8.0  # High — Telnet/RDP
        if port in (21, 111, 135, 139, 5900, 9200):
            return 7.0  # High — dangerous services
        if port in (25, 110, 143, 993, 995):
            return 5.0  # Medium — mail services
        return 3.0  # Low — other
