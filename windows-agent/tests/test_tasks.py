"""Unit tests for scheduled task monitoring."""

from monitors.tasks import find_task_changes


def test_task_created_detected():
    previous = {
        "\\Microsoft\\Windows\\Defrag": {
            "task_name": "\\Microsoft\\Windows\\Defrag",
            "task_to_run": "defrag.exe -c",
        }
    }
    current = {
        "\\Microsoft\\Windows\\Defrag": {
            "task_name": "\\Microsoft\\Windows\\Defrag",
            "task_to_run": "defrag.exe -c",
        },
        "\\MaliciousTask": {
            "task_name": "\\MaliciousTask",
            "task_to_run": "powershell.exe -enc AAAA",
        },
    }

    changes = find_task_changes(previous, current)

    assert len(changes["created"]) == 1
    assert len(changes["modified"]) == 0
    assert len(changes["deleted"]) == 0
    assert changes["created"][0]["event_type"] == "scheduled_task_created"
    assert changes["created"][0]["task_name"] == "\\MaliciousTask"
    assert changes["created"][0]["task_to_run"] == "powershell.exe -enc AAAA"


def test_task_modified_detected():
    previous = {
        "\\MyTask": {
            "task_name": "\\MyTask",
            "task_to_run": "calc.exe",
        }
    }
    current = {
        "\\MyTask": {
            "task_name": "\\MyTask",
            "task_to_run": "cmd.exe /c whoami",
        }
    }

    changes = find_task_changes(previous, current)

    assert len(changes["created"]) == 0
    assert len(changes["modified"]) == 1
    assert len(changes["deleted"]) == 0
    assert changes["modified"][0]["event_type"] == "scheduled_task_modified"
    assert changes["modified"][0]["previous_task_to_run"] == "calc.exe"
    assert changes["modified"][0]["task_to_run"] == "cmd.exe /c whoami"


def test_task_deleted_detected():
    previous = {
        "\\OldTask": {
            "task_name": "\\OldTask",
            "task_to_run": "notepad.exe",
        }
    }
    current = {}

    changes = find_task_changes(previous, current)

    assert len(changes["created"]) == 0
    assert len(changes["modified"]) == 0
    assert len(changes["deleted"]) == 1
    assert changes["deleted"][0]["event_type"] == "scheduled_task_deleted"
    assert changes["deleted"][0]["task_name"] == "\\OldTask"


def test_task_no_changes():
    snapshot = {
        "\\MyTask": {
            "task_name": "\\MyTask",
            "task_to_run": "calc.exe",
        }
    }

    changes = find_task_changes(snapshot, snapshot)
    assert changes["created"] == []
    assert changes["modified"] == []
    assert changes["deleted"] == []

