"""Unit tests for Windows service monitoring."""

from monitors.services import find_service_changes


def test_service_installed_detected():
    previous = {
        "wuauserv": {
            "name": "wuauserv",
            "display_name": "Windows Update",
            "binpath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "status": "running",
            "start_type": "manual",
        }
    }
    current = {
        "wuauserv": {
            "name": "wuauserv",
            "display_name": "Windows Update",
            "binpath": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
            "status": "running",
            "start_type": "manual",
        },
        "badsvc": {
            "name": "badsvc",
            "display_name": "Suspicious Service",
            "binpath": "C:\\Users\\User\\AppData\\bad.exe",
            "status": "running",
            "start_type": "automatic",
        },
    }

    changes = find_service_changes(previous, current)

    assert len(changes["installed"]) == 1
    assert len(changes["modified"]) == 0
    assert len(changes["removed"]) == 0
    assert changes["installed"][0]["event_type"] == "service_installed"
    assert changes["installed"][0]["name"] == "badsvc"
    assert changes["installed"][0]["display_name"] == "Suspicious Service"
    assert changes["installed"][0]["binpath"] == "C:\\Users\\User\\AppData\\bad.exe"


def test_service_modified_detected():
    previous = {
        "customsvc": {
            "name": "customsvc",
            "display_name": "Custom Service",
            "binpath": "C:\\Program Files\\App\\svc.exe",
            "status": "stopped",
            "start_type": "manual",
        }
    }
    current = {
        "customsvc": {
            "name": "customsvc",
            "display_name": "Custom Service",
            "binpath": "C:\\Program Files\\App\\svc.exe --hijacked",
            "status": "running",
            "start_type": "automatic",
        }
    }

    changes = find_service_changes(previous, current)

    assert len(changes["installed"]) == 0
    assert len(changes["modified"]) == 1
    assert len(changes["removed"]) == 0
    assert changes["modified"][0]["event_type"] == "service_modified"
    assert changes["modified"][0]["name"] == "customsvc"
    assert changes["modified"][0]["binpath"] == "C:\\Program Files\\App\\svc.exe --hijacked"
    assert changes["modified"][0]["status"] == "running"


def test_service_removed_detected():
    previous = {
        "oldsvc": {
            "name": "oldsvc",
            "display_name": "Old Service",
            "binpath": "C:\\Program Files\\App\\old.exe",
        }
    }
    current = {}

    changes = find_service_changes(previous, current)

    assert len(changes["installed"]) == 0
    assert len(changes["modified"]) == 0
    assert len(changes["removed"]) == 1
    assert changes["removed"][0]["event_type"] == "service_removed"
    assert changes["removed"][0]["name"] == "oldsvc"


def test_service_no_changes():
    snapshot = {
        "customsvc": {
            "name": "customsvc",
            "display_name": "Custom Service",
            "binpath": "C:\\Program Files\\App\\svc.exe",
            "status": "running",
            "start_type": "automatic",
        }
    }

    changes = find_service_changes(snapshot, snapshot)
    assert changes["installed"] == []
    assert changes["modified"] == []
    assert changes["removed"] == []

