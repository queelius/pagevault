"""Tests for the pagevault runtime module (build_region_js)."""

import pytest

from pagevault.config import DefaultsConfig, TemplateConfig
from pagevault.runtime import build_region_js


def test_build_region_js_contains_escape_html():
    """build_region_js output must include escapeHtml function."""
    js = build_region_js()
    assert "function escapeHtml" in js


def test_build_region_js_is_iife_wrapped():
    """build_region_js output must be wrapped in a strict-mode IIFE."""
    js = build_region_js()
    assert "(function()" in js
    assert "})();" in js


def test_config_prelude_injected():
    """Custom TemplateConfig values must appear in the CONFIG prelude."""
    template = TemplateConfig(title="Custom Title")
    js = build_region_js(template=template)
    assert "Custom Title" in js


def test_build_region_js_contains_decrypt_content():
    """build_region_js output must include decryptContent function."""
    js = build_region_js()
    assert "decryptContent" in js


def test_build_region_js_contains_storage_key():
    """build_region_js output must include STORAGE_KEY constant."""
    js = build_region_js()
    assert "STORAGE_KEY" in js


def test_build_region_js_contains_store_credentials():
    """build_region_js output must include storeCredentials function."""
    js = build_region_js()
    assert "storeCredentials" in js


def test_build_region_js_contains_activation():
    """build_region_js output must include __pvActivateContent function."""
    js = build_region_js()
    assert "__pvActivateContent" in js


def test_build_region_js_contains_page_vault_handler():
    """build_region_js output must include PagevaultHandler class."""
    js = build_region_js()
    assert "class PagevaultHandler" in js


def test_build_region_js_contains_init_all():
    """build_region_js output must include initAll function."""
    js = build_region_js()
    assert "initAll" in js


def test_build_region_js_defaults():
    """build_region_js works without explicit template/defaults args."""
    js = build_region_js()
    assert "Protected Content" in js  # default title
    assert "Unlock" in js  # default button text


def test_build_region_js_defaults_config():
    """DefaultsConfig values appear in CONFIG prelude."""
    defaults = DefaultsConfig(remember="session", remember_days=7, auto_prompt=False)
    js = build_region_js(defaults=defaults)
    assert "session" in js
    assert "7" in js
    assert "false" in js
