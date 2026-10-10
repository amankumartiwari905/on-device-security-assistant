
from monitors.signatures import inspect_signature


def test_missing_executable_path_is_unavailable():
    result = inspect_signature("")

    assert result["status"] == "unavailable"
    assert result["signer"] is None


def test_signature_result_has_expected_fields():
    result = inspect_signature(
        r"C:\Windows\System32\notepad.exe"
    )

    assert "status" in result
    assert "signer" in result
    assert "message" in result
    assert isinstance(result["status"], str)

