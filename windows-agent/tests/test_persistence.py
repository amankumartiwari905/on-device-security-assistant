"""Unit tests for startup persistence monitoring."""

from monitors.persistence import find_startup_changes


def test_startup_added_detected():
    previous = {
        ("HKCU_Run", "OneDrive"): {
            "name": "OneDrive",
            "command": "C:\\Program Files\\OneDrive.exe",
            "location": "HKCU_Run",
        }
    }
    current = {
        ("HKCU_Run", "OneDrive"): {
            "name": "OneDrive",
            "command": "C:\\Program Files\\OneDrive.exe",
            "location": "HKCU_Run",
        },
        ("HKCU_Run", "Backdoor"): {
            "name": "Backdoor",
            "command": "C:\\Users\\User\\AppData\\Local\\Temp\\update.exe",
            "location": "HKCU_Run",
        },
    }

    changes = find_startup_changes(previous, current)

    assert len(changes["added"]) == 1
    assert len(changes["modified"]) == 0
    assert len(changes["removed"]) == 0
    assert changes["added"][0]["event_type"] == "startup_item_added"
    assert changes["added"][0]["name"] == "Backdoor"
    assert changes["added"][0]["command"] == "C:\\Users\\User\\AppData\\Local\\Temp\\update.exe"


def test_startup_modified_detected():
    previous = {
        ("HKLM_Run", "Updater"): {
            "name": "Updater",
            "command": "C:\\Program Files\\App\\updater.exe",
            "location": "HKLM_Run",
        }
    }
    current = {
        ("HKLM_Run", "Updater"): {
            "name": "Updater",
            "command": "C:\\Program Files\\App\\updater.exe --hidden-flag",
            "location": "HKLM_Run",
        }
    }

    changes = find_startup_changes(previous, current)

    assert len(changes["added"]) == 0
    assert len(changes["modified"]) == 1
    assert len(changes["removed"]) == 0
    assert changes["modified"][0]["event_type"] == "startup_item_modified"
    assert changes["modified"][0]["previous_command"] == "C:\\Program Files\\App\\updater.exe"
    assert changes["modified"][0]["command"] == "C:\\Program Files\\App\\updater.exe --hidden-flag"


def test_startup_removed_detected():
    previous = {
        ("StartupFolder", "Shortcut.lnk"): {
            "name": "Shortcut.lnk",
            "command": "C:\\Users\\User\\Startup\\Shortcut.lnk",
            "location": "StartupFolder",
        }
    }
    current = {}

    changes = find_startup_changes(previous, current)

    assert len(changes["added"]) == 0
    assert len(changes["modified"]) == 0
    assert len(changes["removed"]) == 1
    assert changes["removed"][0]["event_type"] == "startup_item_removed"
    assert changes["removed"][0]["name"] == "Shortcut.lnk"


def test_startup_no_changes():
    snapshot = {
        ("HKCU_Run", "OneDrive"): {
            "name": "OneDrive",
            "command": "C:\\Program Files\\OneDrive.exe",
            "location": "HKCU_Run",
        }
    }

    changes = find_startup_changes(snapshot, snapshot)
    assert changes["added"] == []
    assert changes["modified"] == []
    assert changes["removed"] == []

