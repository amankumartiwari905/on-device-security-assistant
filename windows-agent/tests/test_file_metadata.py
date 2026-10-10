"""Unit tests for file metadata inspection."""

import hashlib
from pathlib import Path

from monitors.file_metadata import (
    format_file_size,
    inspect_file_metadata,
    is_potentially_writable_location,
    calculate_file_hash,
)


def test_format_file_size():
    assert format_file_size(500) == "500 B"
    assert format_file_size(2048) == "2.0 KB"
    assert format_file_size(1048576) == "1.0 MB"
    assert format_file_size(1073741824) == "1.00 GB"


def test_inspect_file_metadata_with_temp_file(tmp_path: Path):
    test_file = tmp_path / "sample_binary.exe"
    content = b"MZ\x90\x00\x03PhishGuard Test Content"
    test_file.write_bytes(content)

    meta = inspect_file_metadata(str(test_file))

    assert meta["exists"] is True
    assert meta["size_bytes"] == len(content)
    assert meta["size_formatted"] == f"{len(content)} B"
    expected_hash = hashlib.sha256(content).hexdigest()
    assert meta["sha256"] == expected_hash
    assert meta["created_at"] is not None
    assert meta["modified_at"] is not None
    assert isinstance(meta["is_writable_location"], bool)

    direct_hash = calculate_file_hash(test_file)
    assert direct_hash == expected_hash


def test_inspect_file_metadata_nonexistent():
    meta = inspect_file_metadata(r"C:\NonExistent\path\to\binary.exe")

    assert meta["exists"] is False
    assert meta["size_bytes"] == 0
    assert meta["size_formatted"] == "0 B"
    assert meta["sha256"] is None
    assert meta["created_at"] is None
    assert meta["modified_at"] is None


def test_inspect_file_metadata_empty_path():
    meta = inspect_file_metadata("")
    assert meta["sha256"] is None
    assert meta["size_bytes"] == 0
    assert meta["exists"] is False


def test_is_potentially_writable_location():
    assert is_potentially_writable_location(Path(r"C:\Users\Alice\Downloads\tool.exe")) is True
    assert is_potentially_writable_location(Path(r"C:\Users\Alice\AppData\Local\Temp\mal.exe")) is True
    assert is_potentially_writable_location(Path(r"C:\Windows\System32\cmd.exe")) is False
    assert is_potentially_writable_location(Path(r"C:\Program Files\Common\tool.exe")) is False

