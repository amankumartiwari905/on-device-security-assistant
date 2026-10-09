
from monitors.processes import find_new_processes


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
