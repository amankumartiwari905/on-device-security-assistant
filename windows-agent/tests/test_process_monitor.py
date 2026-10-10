"""Unit tests for process monitoring and change detection."""

from monitors.processes import (
    find_new_processes,
    find_terminated_processes,
    detect_process_changes,
)


def test_new_process_is_detected():
    previous = {
        100: {"pid": 100, "process_name": "explorer.exe"}
    }
    current = {
        100: {"pid": 100, "process_name": "explorer.exe"},
        200: {"pid": 200, "process_name": "demo.exe"},
    }

    new_processes = find_new_processes(previous, current)

    assert len(new_processes) == 1
    assert new_processes[0]["pid"] == 200
    assert new_processes[0]["process_name"] == "demo.exe"
    assert new_processes[0]["event_type"] == "process_started"


def test_existing_process_is_not_reported_as_new():
    previous = {
        100: {"pid": 100, "process_name": "explorer.exe"}
    }
    current = {
        100: {"pid": 100, "process_name": "explorer.exe"}
    }

    new_processes = find_new_processes(previous, current)

    assert new_processes == []


def test_empty_previous_snapshot_detects_all_current_processes():
    previous = {}
    current = {
        100: {"pid": 100, "process_name": "explorer.exe"},
        200: {"pid": 200, "process_name": "demo.exe"},
    }

    new_processes = find_new_processes(previous, current)

    assert len(new_processes) == 2


def test_terminated_processes_detected():
    previous = {
        100: {"pid": 100, "process_name": "explorer.exe"},
        300: {"pid": 300, "process_name": "notepad.exe"},
    }
    current = {
        100: {"pid": 100, "process_name": "explorer.exe"}
    }

    terminated = find_terminated_processes(previous, current)

    assert len(terminated) == 1
    assert terminated[0]["pid"] == 300
    assert terminated[0]["process_name"] == "notepad.exe"
    assert terminated[0]["event_type"] == "process_terminated"


def test_detect_process_changes_returns_both():
    previous = {
        100: {"pid": 100, "process_name": "explorer.exe"},
        300: {"pid": 300, "process_name": "closing.exe"},
    }
    current = {
        100: {"pid": 100, "process_name": "explorer.exe"},
        400: {"pid": 400, "process_name": "starting.exe"},
    }

    changes = detect_process_changes(previous, current)

    assert len(changes["new"]) == 1
    assert changes["new"][0]["pid"] == 400
    assert len(changes["terminated"]) == 1
    assert changes["terminated"][0]["pid"] == 300
