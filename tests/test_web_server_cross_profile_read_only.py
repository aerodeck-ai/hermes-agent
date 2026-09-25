"""Cross-profile SessionDB opens are read-only unless the caller asks to write.

Regression for aerodeck-ai/estate-work#3833: a dashboard running as one OS user
opened another profile's state.db read-write, unlinked its WAL on close, and left
that profile's gateway writing into a deleted WAL until the store was malformed.
"""
import hermes_state
from hermes_cli import web_server


class _Recorder:
    calls: list = []

    def __init__(self, db_path=None, read_only=False):
        _Recorder.calls.append({"db_path": db_path, "read_only": read_only})


def _patch(monkeypatch, tmp_path):
    _Recorder.calls = []
    monkeypatch.setattr(hermes_state, "SessionDB", _Recorder)
    monkeypatch.setattr(web_server, "_cron_profile_home", lambda p: (p, str(tmp_path / p)))


def test_cross_profile_open_defaults_to_read_only(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    web_server._open_session_db_for_profile("other")
    assert _Recorder.calls == [{"db_path": tmp_path / "other" / "state.db", "read_only": True}]


def test_cross_profile_open_writes_only_when_asked(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    web_server._open_session_db_for_profile("other", write=True)
    assert _Recorder.calls[-1]["read_only"] is False


def test_own_profile_open_is_unchanged(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    web_server._open_session_db_for_profile(None)
    assert _Recorder.calls == [{"db_path": None, "read_only": False}]


def test_only_write_endpoints_request_write():
    """Exactly the user write actions open another profile read-write:
    import, bulk delete, delete empty, delete one, rename/pin/archive, and a
    non-dry-run prune. Every other call site stays on the read-only default."""
    import inspect
    import re
    src = inspect.getsource(web_server)
    calls = re.findall(r"_open_session_db_for_profile\(([^()]*)\)", src)
    writes = [c for c in calls if "write=" in c]
    assert sorted(writes) == sorted([
        "profile, write=True",
        "body.profile, write=True",
        "profile, write=True",
        "profile, write=True",
        "body.profile, write=True",
        "body.profile, write=not body.dry_run",
    ])
