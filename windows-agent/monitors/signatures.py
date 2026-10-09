
"""Read-only Authenticode signature inspection on Windows."""

import json
import subprocess
from functools import lru_cache


@lru_cache(maxsize=256)
def inspect_signature(executable: str) -> dict:
    if not executable:
        return {
            "status": "unavailable",
            "signer": None,
            "message": "Executable path is unavailable.",
        }

    script = """
    param([string]$FilePath)
    $ErrorActionPreference = 'Stop'
    $s = Get-AuthenticodeSignature -LiteralPath $FilePath
    @{
        status = [string]$s.Status
        signer = if ($s.SignerCertificate) {
            $s.SignerCertificate.Subject
        } else {
            $null
        }
        message = [string]$s.StatusMessage
    } | ConvertTo-Json -Compress
    """

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"& {{ {script} }} -FilePath '{executable.replace(chr(39), chr(39) * 2)}'",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            return {
                "status": "unavailable",
                "signer": None,
                "message": "PowerShell signature inspection failed.",
            }

        data = json.loads(result.stdout)

        return {
            "status": data.get("status", "unknown"),
            "signer": data.get("signer"),
            "message": data.get("message", ""),
        }

    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {
            "status": "unavailable",
            "signer": None,
            "message": "Signature inspection could not be completed.",
        }
