"""
NetSentry AI - PCAP File Security Validator
Enforces file size constraints, extension whitelisting, and magic header byte verification.
Defends against malicious file uploads and format injection.
"""

from pathlib import Path
from typing import Tuple

# Valid PCAP / PCAPNG magic header bytes
PCAP_MAGIC_BYTES = {
    b"\xd4\xc3\xb2\xa1": "PCAP (Little-Endian, Microseconds)",
    b"\xa1\xb2\xc3\xd4": "PCAP (Big-Endian, Microseconds)",
    b"\x4d\x3c\xb2\xa1": "PCAP (Little-Endian, Nanoseconds)",
    b"\xa1\xb2\x3c\x4d": "PCAP (Big-Endian, Nanoseconds)",
    b"\x0a\x0d\x0d\x0a": "PCAP-NG (Next Generation Format)",
}


class FileValidationError(Exception):
    """Raised when an uploaded file fails security validation."""
    pass


def validate_pcap_file(file_path: Path, max_size_bytes: int = 50 * 1024 * 1024) -> Tuple[bool, str]:
    """
    Validates that a file is a legitimate, safe PCAP or PCAPNG file.
    
    Checks:
    1. File exists and is a regular file.
    2. File size is within safe bounds (> 24 bytes header and <= max_size_bytes).
    3. File extension is whitelisted (.pcap, .pcapng, .cap).
    4. Magic bytes match official libpcap or pcapng specifications.
    
    Returns:
        (True, format_description) if valid.
    Raises:
        FileValidationError if invalid.
    """
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        raise FileValidationError("File does not exist or is not a valid file.")

    # 1. Check file size
    size = path.stat().st_size
    if size < 24:
        raise FileValidationError(
            f"File too small ({size} bytes) to contain a valid PCAP header."
        )
    if size > max_size_bytes:
        max_mb = max_size_bytes / (1024 * 1024)
        raise FileValidationError(
            f"File size exceeds the allowed limit of {max_mb:.0f} MB."
        )

    # 2. Check extension whitelisting
    allowed_exts = {".pcap", ".pcapng", ".cap"}
    if path.suffix.lower() not in allowed_exts:
        raise FileValidationError(
            f"Invalid file extension '{path.suffix}'. Allowed: {', '.join(allowed_exts)}"
        )

    # 3. Verify magic bytes header
    with open(path, "rb") as f:
        header = f.read(4)

    format_name = PCAP_MAGIC_BYTES.get(header)
    if not format_name:
        raise FileValidationError(
            "File header does not match any known PCAP or PCAP-NG magic bytes. Upload is corrupt or invalid."
        )

    return True, format_name

