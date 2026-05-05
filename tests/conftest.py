"""Shared pytest setup. Stubs `fcntl` on Windows so the production
modules (which import it at top level) can be loaded for testing."""
import sys
import types


def _install_fcntl_stub() -> None:
    if 'fcntl' in sys.modules:
        return
    stub = types.ModuleType('fcntl')
    stub.LOCK_EX = 0
    stub.LOCK_UN = 0
    stub.flock = lambda *_a, **_k: None
    sys.modules['fcntl'] = stub


_install_fcntl_stub()
