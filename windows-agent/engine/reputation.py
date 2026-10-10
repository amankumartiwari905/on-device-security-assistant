"""Process, file hash, domain, and IP reputation with configurable allowlists and blocklists."""

from pathlib import Path
import re


# Default trusted publishers for signature allowlisting
DEFAULT_TRUSTED_PUBLISHERS = {
    "Microsoft Corporation",
    "Microsoft Windows",
    "Google LLC",
    "Mozilla Corporation",
    "Apple Inc.",
}

# Standard legitimate directories for Windows system executables
SYSTEM_CORE_DIRECTORIES = {
    r"c:\windows\system32",
    r"c:\windows\syswow64",
}

# Core system process names that should never run outside system directories
CORE_SYSTEM_PROCESSES = {
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "winlogon.exe",
    "taskhostw.exe",
    "wininit.exe",
}

# Double extension pattern matching deceptive filenames
DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|png|mp4|zip)\.(?:exe|scr|bat|cmd|vbs|ps1|js)$",
    re.I,
)

# Known malicious file hashes (SHA-256) for threat intelligence demonstration
DEFAULT_BLOCKLIST_HASHES = {
    # Emotet sample hash (simulated threat intel indicator)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty File Test Hash (Threat Intel Demonstration)",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Known EICAR Standard Antivirus Test Indicator",
}

# Known malicious IP addresses
DEFAULT_BLOCKLIST_IPS = {
    "198.51.100.66": "Known Cobalt Strike C2 IP (Simulated Threat Intel)",
    "203.0.113.199": "Known Botnet Command & Control (Simulated Threat Intel)",
}

# Known malicious domain names
DEFAULT_BLOCKLIST_DOMAINS = {
    "malicious-c2-test.duckdns.org": "Active Command & Control Endpoint",
    "evil-payload-dist.top": "Phishing & Dropper Distribution Site",
}


class ThreatReputationManager:
    """Manages allowlists, blocklists, and reputation lookups for files, hashes, and network targets."""

    def __init__(
        self,
        trusted_publishers: set[str] | None = None,
        trusted_hashes: set[str] | None = None,
        blocklist_hashes: dict[str, str] | None = None,
        blocklist_ips: dict[str, str] | None = None,
        blocklist_domains: dict[str, str] | None = None,
    ):
        self.trusted_publishers = (
            set(trusted_publishers) if trusted_publishers is not None else set(DEFAULT_TRUSTED_PUBLISHERS)
        )
        self.trusted_hashes = set(trusted_hashes or set())
        self.blocklist_hashes = dict(blocklist_hashes if blocklist_hashes is not None else DEFAULT_BLOCKLIST_HASHES)
        self.blocklist_ips = dict(blocklist_ips if blocklist_ips is not None else DEFAULT_BLOCKLIST_IPS)
        self.blocklist_domains = dict(blocklist_domains if blocklist_domains is not None else DEFAULT_BLOCKLIST_DOMAINS)

    def is_allowlisted_publisher(self, signer: str | None) -> bool:
        """Check if certificate signer is in trusted publishers list."""
        if not signer:
            return False
        signer_clean = signer.strip()
        return any(trusted.lower() in signer_clean.lower() for trusted in self.trusted_publishers)

    def is_allowlisted_hash(self, sha256: str | None) -> bool:
        """Check if file SHA-256 hash is in trusted hashes allowlist."""
        if not sha256:
            return False
        return sha256.lower().strip() in self.trusted_hashes

    def check_hash_reputation(self, sha256: str | None) -> dict:
        """
        Evaluate file hash against blocklist and allowlist.
        Returns reputation assessment.
        """
        if not sha256:
            return {
                "status": "unknown",
                "is_blocklisted": False,
                "is_allowlisted": False,
                "threat_name": None,
                "details": None,
            }

        norm_hash = sha256.lower().strip()

        if norm_hash in self.blocklist_hashes:
            return {
                "status": "malicious",
                "is_blocklisted": True,
                "is_allowlisted": False,
                "threat_name": self.blocklist_hashes[norm_hash],
                "details": f"SHA-256 matched known malicious indicator: {self.blocklist_hashes[norm_hash]}",
            }

        if norm_hash in self.trusted_hashes:
            return {
                "status": "trusted",
                "is_blocklisted": False,
                "is_allowlisted": True,
                "threat_name": None,
                "details": "Hash is present on trusted application allowlist",
            }

        return {
            "status": "unknown",
            "is_blocklisted": False,
            "is_allowlisted": False,
            "threat_name": None,
            "details": None,
        }

    def check_ip_blocklist(self, ip: str) -> dict | None:
        """Check IP address against blocklist."""
        ip_clean = ip.strip()
        if ip_clean in self.blocklist_ips:
            return {
                "ip": ip_clean,
                "threat_name": self.blocklist_ips[ip_clean],
            }
        return None

    def check_domain_blocklist(self, domain: str) -> dict | None:
        """Check domain against blocklist."""
        domain_clean = domain.strip().lower().rstrip(".")
        if domain_clean in self.blocklist_domains:
            return {
                "domain": domain_clean,
                "threat_name": self.blocklist_domains[domain_clean],
            }
        return None

    def check_masquerading(self, process_name: str, executable_path: str | None) -> bool:
        """
        Detect masquerading: core system binary running outside of System32/SysWOW64.
        """
        if not executable_path:
            return False

        name_lower = process_name.lower().strip()
        if name_lower not in CORE_SYSTEM_PROCESSES:
            return False

        try:
            exe_parent = str(Path(executable_path).parent).lower().strip()
            return exe_parent not in SYSTEM_CORE_DIRECTORIES
        except (ValueError, OSError):
            return False

    def check_double_extension(self, filename: str | None) -> bool:
        """Detect deceptive double extensions (e.g. document.pdf.exe)."""
        if not filename:
            return False
        return bool(DOUBLE_EXTENSION_PATTERN.search(filename.strip()))

    def is_hash_blocklisted(self, sha256: str | None) -> bool:
        """Check if SHA-256 hash is in the malicious blocklist."""
        return self.check_hash_reputation(sha256).get("is_blocklisted", False)

    def is_hash_allowlisted(self, sha256: str | None) -> bool:
        """Check if SHA-256 hash is in the trusted allowlist."""
        return self.is_allowlisted_hash(sha256)

    def is_publisher_trusted(self, signer: str | None) -> bool:
        """Check if certificate signer is in the trusted publishers allowlist."""
        return self.is_allowlisted_publisher(signer)

    def has_double_extension(self, filename: str | None) -> bool:
        """Alias for check_double_extension."""
        return self.check_double_extension(filename)

    def is_masquerading(self, process_name: str, executable_path: str | None) -> bool:
        """Alias for check_masquerading."""
        return self.check_masquerading(process_name, executable_path)


# Default shared reputation manager instance
reputation_manager = ThreatReputationManager()

