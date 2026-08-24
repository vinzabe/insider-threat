import json

import pytest

from insider.cli import EXIT_ELEVATED, EXIT_OK, main


def _log(tmp_path, events):
    p = tmp_path / "events.json"
    p.write_text(json.dumps(events))
    return str(p)


def test_normal_log_not_elevated(tmp_path, capsys):
    events = [{"user": "alice", "group": "eng", "features": {"dl": 5}}
              for _ in range(20)]
    assert main(["assess", _log(tmp_path, events), "--warmup", "10"]) == EXIT_OK


def test_anomaly_elevated(tmp_path, capsys):
    events = [{"user": "alice", "group": "eng", "features": {"dl": 5 + i * 0.01}}
              for i in range(30)]
    events.append({"user": "alice", "group": "eng", "features": {"dl": 5000}})
    rc = main(["assess", _log(tmp_path, events), "--warmup", "10"])
    assert rc == EXIT_ELEVATED
    out = capsys.readouterr().out
    assert "REVIEW" in out and "NOT an accusation" in out


def test_json_output(tmp_path, capsys):
    events = [{"user": "a", "group": "g", "features": {"x": 1}} for _ in range(5)]
    main(["assess", _log(tmp_path, events), "--json"])
    d = json.loads(capsys.readouterr().out)
    assert d[0]["review_required"] in (True, False)


def test_bad_log_errors(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text('{"not": "a list"}')
    assert main(["assess", str(p)]) == 1


def test_version():
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
