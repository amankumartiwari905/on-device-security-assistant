"""Read-only Authenticode signature inspection on Windows."""

import json
from pathlib import Path
import subprocess
from functools import lru_cache


@lru_cache(maxsize=512)
def inspect_signature(executable: str | None) -> dict:
    """
    Inspect the Authenticode signature of an executable file.
    Returns status, signer, message, and is_valid flag.
    """
    if not executable:
        return {
            "status": "unavailable",
            "signer": None,
            "message": "Executable path is unavailable.",
            "is_valid": False,
        }

    try:
        p = Path(executable)
        if not p.is_file():
            return {
                "status": "unavailable",
                "signer": None,
                "message": f"Executable file not found on disk: {executable}",
                "is_valid": False,
            }
    except (OSError, ValueError):
        pass

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
        escaped_path = str(executable).replace("'", "''")
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"& {{ {script} }} -FilePath '{escaped_path}'",
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
                "is_valid": False,
            }

        data = json.loads(result.stdout)
        status = data.get("status", "unknown")

        return {
            "status": status,
            "signer": data.get("signer"),
            "message": data.get("message", ""),
            "is_valid": status.lower() == "valid",
        }

    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {
            "status": "unavailable",
            "signer": None,
            "message": "Signature inspection could not be completed.",
            "is_valid": False,
        }
