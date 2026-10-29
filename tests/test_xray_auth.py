"""The session headers reach xray.

A scan can name an identity: the task carries the identity's cookies and
headers, and the worker has to hand them to xray, because a target that
needs a session answers an anonymous request with a login page.

Xray has no command line option for request headers: they live in the
configuration file, so the worker writes its own copy of it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import xraym.xraym as xraym_module  # noqa: E402
from xraym.xraym import xraym  # noqa: E402

CONFIG = Path(__file__).resolve().parents[1] / "xray" / "config.yaml"


class _Task:
    """A task that carries nothing but a payload."""

    def __init__(self, payload: Any) -> None:
        self.payload = payload


class _Worker(xraym):
    """A worker without a configuration file and without a database."""

    def __init__(self) -> None:
        pass


class _Completed:
    """What a finished xray run reports."""

    stdout = ""
    stderr = ""
    returncode = 0


class _Subprocess:
    """A subprocess module that records the commands instead of running them."""

    PIPE = subprocess.PIPE

    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.config: dict[str, Any] = {}

    def run(self, argv: list[str], **kwargs: Any) -> _Completed:
        self.commands.append(argv)
        if "--config" in argv:
            # The configuration is a scratch file the worker removes
            # once the scan is over, so it is read while it is there.
            with open(argv[argv.index("--config") + 1]) as handle:
                self.config = yaml.safe_load(handle)
        return _Completed()


def _worker(monkeypatch: Any) -> tuple[_Worker, _Subprocess]:
    monkeypatch.setenv("XRAY_CONFIG", str(CONFIG))
    worker = _Worker()
    subprocess = _Subprocess()
    monkeypatch.setattr(xraym_module, "subprocess", subprocess)
    return worker, subprocess


def test_the_session_headers_reach_xray(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    task = _Task(payload={"auth": {"cookies": {"JSESSIONID": "abc"}, "headers": {"X-Test": "1"}}})

    worker.xraycommand("http://example.test", worker.auth_headers(task))

    assert "--config" in subprocess.commands[0]
    headers = subprocess.config["http"]["headers"]
    assert headers["Cookie"] == "JSESSIONID=abc"
    assert headers["X-Test"] == "1"


def test_xray_gets_no_header_without_an_identity(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    task = _Task(payload={})

    worker.xraycommand("http://example.test", worker.auth_headers(task))

    assert "Cookie" not in subprocess.config["http"]["headers"]


def test_the_scratch_configuration_is_removed(monkeypatch: Any) -> None:
    worker, subprocess = _worker(monkeypatch)
    task = _Task(payload={})

    worker.xraycommand("http://example.test", worker.auth_headers(task))

    scratch = subprocess.commands[0][subprocess.commands[0].index("--config") + 1]
    assert not Path(scratch).exists()
