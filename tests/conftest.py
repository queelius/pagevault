"""Shared test fixtures for pagevault tests."""

import tempfile

import pytest


@pytest.fixture(autouse=True)
def isolate_global_config(monkeypatch):
    """Prevent tests from reading the real ~/.config/pagevault/config.yaml.

    Every test gets an empty XDG_CONFIG_HOME so load_global_config() never
    sees the developer's real global config. Tests that need a global config
    should create one under this path.
    """
    with tempfile.TemporaryDirectory() as config_home:
        monkeypatch.setenv("XDG_CONFIG_HOME", config_home)
        yield


@pytest.fixture(scope="session")
def browser():
    """A headless Chromium for the tests/test_browser_*.py suites.

    Prefers the system's Google Chrome (present on GitHub's ubuntu runners),
    so nothing has to be downloaded and nothing can go stale in Playwright's
    browser cache; falls back to Playwright's own Chromium when Chrome is
    not installed. Skips when Playwright itself is not installed.
    """
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(channel="chrome")
        except sync_api.Error:
            b = p.chromium.launch()
        yield b
        b.close()
