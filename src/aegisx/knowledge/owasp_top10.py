"""OWASP Top 10 2021 knowledge base.

Maps OWASP categories to CWE weakness IDs and provides remediation guidance.
Reference: https://owasp.org/Top10/
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OWASPCategory:
    """A single OWASP Top 10 category."""

    code: str  # e.g. "A03"
    year: int = 2021
    name: str = ""
    description: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)


# OWASP Top 10 2021 — Complete mapping
OWASP_TOP_10: dict[str, OWASPCategory] = {
    "A01": OWASPCategory(
        code="A01",
        year=2021,
        name="Broken Access Control",
        description=(
            "Restrictions on what authenticated users are allowed to do are not properly enforced. "
            "Attackers can exploit flaws to access unauthorized functionality or data."
        ),
        cwe_ids=[
            "CWE-200",  # Exposure of Sensitive Information
            "CWE-201",  # Insertion of Sensitive Information Into Sent Data
            "CWE-284",  # Improper Access Control
            "CWE-285",  # Improper Authorization
            "CWE-352",  # Cross-Site Request Forgery
            "CWE-359",  # Exposure of Private Personal Information
            "CWE-377",  # Insecure Temporary File
            "CWE-402",  # Transmission of Private Data Using Channel Not Encrypted
            "CWE-425",  # Direct Request ('Forced Browsing')
            "CWE-497",  # Exposure of Sensitive System Information
            "CWE-538",  # Insertion of Sensitive Information into Externally-Accessible File
            "CWE-540",  # Inclusion of Sensitive Information in Source Code
            "CWE-548",  # Exposure of Information Through Directory Listing
            "CWE-552",  # Files or Directories Accessible to External Parties
            "CWE-566",  # SQL Injection Through Art Request
            "CWE-601",  # Open Redirect
            "CWE-639",  # Authorization Bypass Through User-Controlled Key
            "CWE-651",  # Exposure of WSDL Information
            "CWE-668",  # Exposure of Resource to Wrong Sphere
            "CWE-706",  # Incorrect Name Resolution
            "CWE-862",  # Missing Authorization
            "CWE-913",  # Improper Control of Dynamically-Managed Code Resources
            "CWE-922",  # Insecure Storage of Sensitive Information
            "CWE-1275",  # Sensitive Cookie Without SameSite Attribute
        ],
        remediation=(
            "Deny by default. Implement access control mechanisms once and re-use them. "
            "Model access controls should enforce record ownership. Disable web server directory listing. "
            "Log and alert access control failures."
        ),
        references=[
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ],
    ),
    "A02": OWASPCategory(
        code="A02",
        year=2021,
        name="Cryptographic Failures",
        description=(
            "Failures related to cryptography which often leads to sensitive data exposure, "
            "data compromise, or system compromise."
        ),
        cwe_ids=[
            "CWE-261",  # Weak Encoding for Password
            "CWE-296",  # Improper Following of a Certificate Chain
            "CWE-310",  # Cryptographic Issues
            "CWE-321",  # Use of Hard-coded Cryptographic Key
            "CWE-322",  # Key Exchange without Entity Authentication
            "CWE-323",  # Reusing a Nonce, Key Pair in Encryption
            "CWE-324",  # Use of a Broken or Risky Cryptographic Algorithm
            "CWE-325",  # Missing Required Cryptographic Step
            "CWE-326",  # Inadequate Encryption Strength
            "CWE-327",  # Use of a Broken or Risky Cryptographic Algorithm
            "CWE-328",  # Reversible One-Way Hash
            "CWE-329",  # Not Using an Unpredictable IV
            "CWE-330",  # Use of Insufficiently Random Values
            "CWE-331",  # Insufficient Entropy
            "CWE-335",  # Incorrect Usage of Seeds in Pseudo-Random Number Generator
            "CWE-336",  # Same Seed in Pseudo-Random Number Generator
            "CWE-337",  # Predictable Seed in Pseudo-Random Number Generator
            "CWE-338",  # Use of Cryptographically Weak Pseudo-Random Number Generator
            "CWE-340",  # Generation of Predictable Numbers
            "CWE-347",  # Improper Verification of Cryptographic Signature
            "CWE-521",  # Weak Password Requirements
            "CWE-720",  # OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities
            "CWE-757",  # Selection of Less-Secure Algorithm During Negotiation
            "CWE-759",  # Use of a One-Way Hash without a Salt
            "CWE-760",  # Use of a One-Way Hash with a Predictable Salt
            "CWE-780",  # Use of RSA Algorithm without Optimal Padding
            "CWE-818",  # Insufficient Transport Layer Protection
            "CWE-916",  # Use of Password Hash With Insufficient Computational Effort
        ],
        remediation=(
            "Classify data and identify which is sensitive. Don't store sensitive data unnecessarily. "
            "Encrypt all sensitive data at rest. Ensure up-to-date and strong standard algorithms. "
            "Use proper key management. Encrypt all data in transit with TLS."
        ),
        references=[
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
    ),
    "A03": OWASPCategory(
        code="A03",
        year=2021,
        name="Injection",
        description=(
            "User-supplied data is not validated, filtered, or sanitized by the application. "
            "Dynamic queries are not parameterized. Hostile data is used in object-relational "
            "mapping (ORM) search parameters."
        ),
        cwe_ids=[
            "CWE-20",  # Improper Input Validation
            "CWE-74",  # Injection (General)
            "CWE-79",  # Cross-site Scripting (XSS)
            "CWE-80",  # Basic XSS
            "CWE-83",  # XSS in Attributes
            "CWE-87",  # XSS in Error Page
            "CWE-89",  # SQL Injection
            "CWE-90",  # LDAP Injection
            "CWE-91",  # XML Injection
            "CWE-93",  # CRLF Injection
            "CWE-94",  # Code Injection
            "CWE-95",  # Eval Injection
            "CWE-96",  # Static Code Injection
            "CWE-97",  # SQL Injection (Stored)
            "CWE-98",  # PHP Remote File Inclusion
            "CWE-99",  # Resource Injection
            "CWE-100",  # HTTP Header Injection
            "CWE-113",  # HTTP Response Splitting
            "CWE-116",  # Improper Encoding or Escaping of Output
            "CWE-138",  # Improper Neutralization of Special Elements
            "CWE-184",  # Incomplete List of Disallowed Inputs
            "CWE-470",  # Use of Externally-Controlled Input to Select Classes or Code
            "CWE-471",  # Modification of Assumed-Immutable Data
            "CWE-564",  # SQL Injection: Hibernate
            "CWE-610",  # Externally Controlled Reference to a Resource in Another Sphere
            "CWE-643",  # XPath Injection
            "CWE-644",  # HTTP Header Injection
            "CWE-652",  # XQuery Injection
            "CWE-917",  # Expression Language Injection
        ],
        remediation=(
            "Use positive server-side input validation. For any residual dynamic queries, "
            "escape special characters using ORM tools. Use LIMIT and other SQL controls "
            "to prevent mass data disclosure. Use parameterized queries."
        ),
        references=[
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    ),
    "A04": OWASPCategory(
        code="A04",
        year=2021,
        name="Insecure Design",
        description=(
            "A category representing different weaknesses in the design phase, "
            "where security controls are not properly designed or are missing entirely."
        ),
        cwe_ids=[
            "CWE-209",  # Generation of Error Message Containing Sensitive Information
            "CWE-256",  # Plaintext Storage of a Password
            "CWE-501",  # Trust Boundary Violation
            "CWE-522",  # Insufficiently Protected Credentials
        ],
        remediation=(
            "Establish and use a secure development lifecycle. Use threat modeling for critical "
            "authentication and access flows. Integrate security language and controls into user stories. "
            "Write integration and unit tests to validate all critical flows."
        ),
        references=[
            "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        ],
    ),
    "A05": OWASPCategory(
        code="A05",
        year=2021,
        name="Security Misconfiguration",
        description=(
            "Missing appropriate security hardening across any part of the application stack, "
            "improperly configured permissions, or unnecessary features enabled."
        ),
        cwe_ids=[
            "CWE-2",  # Environment
            "CWE-11",  # ASP.NET Misconfiguration
            "CWE-13",  # ASP.NET Misconfiguration: Manufacturing Debug Markers
            "CWE-15",  # Group Policy Configuration
            "CWE-16",  # Configuration
            "CWE-260",  # Password in Configuration File
            "CWE-315",  # Cleartext Storage of Sensitive Information in a Cookie
            "CWE-520",  # .NET Misconfiguration: Use of Math Net
            "CWE-526",  # Exposure of Sensitive Information Through Environmental Variables
            "CWE-537",  # Insertion of Sensitive Information into Externally-Accessible File
            "CWE-538",  # Insertion of Sensitive Information into Externally-Accessible File
            "CWE-541",  # Inclusion of Sensitive Information in Source Code Comments
            "CWE-547",  # Use of Hard-coded, Security-relevant Constants
            "CWE-611",  # Improper Restriction of XML External Entity Reference
            "CWE-614",  # Cookie without SameSite Flag
            "CWE-756",  # Missing Custom Error Page
            "CWE-776",  # Improper Restriction of Recursive Entities in DTDs
            "CWE-942",  # Permissive Cross-domain Policy with Untrusted Domains
        ],
        remediation=(
            "A repeatable hardening process makes it fast and easy to deploy another environment "
            "that is appropriately locked down. A minimal platform without any unnecessary features, "
            "components, documentation, and samples. Review and update configurations appropriately. "
            "Automated configuration verification."
        ),
        references=[
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    ),
    "A06": OWASPCategory(
        code="A06",
        year=2021,
        name="Vulnerable and Outdated Components",
        description=(
            "Using components (libraries, frameworks, software) with known vulnerabilities "
            "that can be exploited."
        ),
        cwe_ids=[
            "CWE-1104",  # Use of Unmaintained Third Party Components
        ],
        remediation=(
            "Remove unused dependencies, unnecessary features, components, files, and documentation. "
            "Continuously inventory versions of components. Monitor for vulnerabilities (CVE, NVD). "
            "Only obtain components from official sources. Monitor for unmaintained libraries."
        ),
        references=[
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        ],
    ),
    "A07": OWASPCategory(
        code="A07",
        year=2021,
        name="Identification and Authentication Failures",
        description=(
            "Confirmation of the user's identity, authentication, and session management "
            "is critical to protect against authentication-related attacks."
        ),
        cwe_ids=[
            "CWE-287",  # Improper Authentication
            "CWE-384",  # Session Fixation
            "CWE-521",  # Weak Password Requirements
            "CWE-613",  # Insufficient Session Expiration
            "CWE-640",  # Weak Password Recovery Mechanism
            "CWE-798",  # Use of Hard-coded Credentials
        ],
        remediation=(
            "Where possible, implement multi-factor authentication to prevent credential stuffing "
            "and brute force attacks. Do not ship or deploy with default credentials. "
            "Implement weak password checks. Limit failed login attempts."
        ),
        references=[
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        ],
    ),
    "A08": OWASPCategory(
        code="A08",
        year=2021,
        name="Software and Data Integrity Failures",
        description=(
            "Code and infrastructure that does not protect against integrity violations, "
            "insecure CI/CD pipelines, or auto-update functionality without sufficient integrity verification."
        ),
        cwe_ids=[
            "CWE-345",  # Insufficient Verification of Data Authenticity
            "CWE-353",  # Missing Support for Integrity Check
            "CWE-426",  # Untrusted Search Path
            "CWE-494",  # Download of Code Without Integrity Check
            "CWE-502",  # Deserialization of Untrusted Data
            "CWE-565",  # Reliance on Cookies without Validation
            "CWE-784",  # Reliance on Cookies without Validation
            "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
            "CWE-830",  # Inclusion of Web Functionality from an Untrusted Source
            "CWE-913",  # Improper Control of Dynamically-Managed Code Resources
        ],
        remediation=(
            "Use digital signatures to verify data/software integrity. Ensure libraries and dependencies "
            "are consuming trusted repositories. Use a software supply chain security tool (e.g., OWASP Dependency-Check). "
            "Ensure CI/CD pipeline has proper segregation and configuration."
        ),
        references=[
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        ],
    ),
    "A09": OWASPCategory(
        code="A09",
        year=2021,
        name="Security Logging and Monitoring Failures",
        description=(
            "Insufficient logging, detection, monitoring, and active response allows attackers "
            "to further attack systems, maintain persistence, and tamper with data."
        ),
        cwe_ids=[
            "CWE-117",  # Improper Output Neutralization for Logs
            "CWE-223",  # Omission of Security-Relevant Information
            "CWE-532",  # Insertion of Sensitive Information into Log File
            "CWE-778",  # Insufficient Logging
        ],
        remediation=(
            "Ensure all login, access control, and server-side input validation failures are logged "
            "with sufficient user context. Ensure high-value transactions have an audit trail. "
            "Establish effective monitoring and alerting. Establish an incident response plan."
        ),
        references=[
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        ],
    ),
    "A10": OWASPCategory(
        code="A10",
        year=2021,
        name="Server-Side Request Forgery (SSRF)",
        description=(
            "SSRF flaws occur whenever a web application fetches a remote resource without "
            "validating the user-supplied URL, allowing an attacker to coerce the application "
            "to send crafted requests to unexpected destinations."
        ),
        cwe_ids=[
            "CWE-918",  # Server-Side Request Forgery
        ],
        remediation=(
            "Segment remote resource access functionality in separate networks. Enforce 'deny by default' "
            "firewall policies. Disable HTTP redirections. Sanitize and validate all client-supplied input data."
        ),
        references=[
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        ],
    ),
}


def get_category_by_cwe(cwe_id: str) -> OWASPCategory | None:
    """Find the OWASP category that contains a given CWE ID."""
    for category in OWASP_TOP_10.values():
        if cwe_id in category.cwe_ids:
            return category
    return None


def get_category(code: str) -> OWASPCategory | None:
    """Get an OWASP category by its code (e.g. 'A03')."""
    return OWASP_TOP_10.get(code)


def get_remediation_for_cwe(cwe_id: str) -> str:
    """Get remediation guidance for a CWE ID from OWASP mappings."""
    category = get_category_by_cwe(cwe_id)
    if category:
        return category.remediation
    return "Review the CWE entry for specific remediation guidance."
