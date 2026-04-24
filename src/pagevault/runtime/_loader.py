"""Asset loading utilities for the pagevault runtime module."""

from importlib.resources import files

from ..config import DefaultsConfig, TemplateConfig


def _load_asset(relative_path: str) -> str:
    """Load a .js asset from the runtime package.

    Args:
        relative_path: Path relative to the runtime package root,
            e.g. "core/escape.js" or "region/handler.js".

    Returns:
        File contents as a string.
    """
    parts = relative_path.split("/")
    resource = files("pagevault.runtime")
    for part in parts:
        resource = resource / part
    return resource.read_text(encoding="utf-8")


def _js_string(s: str) -> str:
    """Escape a Python string for embedding as a JavaScript string literal.

    Returns a double-quoted JS string with necessary escapes applied.
    """
    return (
        '"'
        + s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("</", "<\\/")
        + '"'
    )


def _escape_for_script_block(s: str) -> str:
    """Escape content for safe embedding inside <script> or <style> blocks.

    Replaces ``</`` with ``<\\/`` to prevent premature closing of the
    enclosing HTML tag.
    """
    return s.replace("</", "<\\/")


def _make_config_prelude(template: TemplateConfig, defaults: DefaultsConfig) -> str:
    """Build a JavaScript CONFIG object from TemplateConfig and DefaultsConfig.

    Returns a JS var declaration that exposes all config values to the runtime.
    """
    return (
        f"  var CONFIG = {{\n"
        f"    title: {_js_string(template.title)},\n"
        f"    buttonText: {_js_string(template.button_text)},\n"
        f"    errorText: {_js_string(template.error_text)},\n"
        f"    placeholder: {_js_string(template.placeholder)},\n"
        f"    usernamePlaceholder: {_js_string(template.username_placeholder)},\n"
        f"    defaultRemember: {_js_string(defaults.remember)},\n"
        f"    rememberDays: {defaults.remember_days},\n"
        f"    autoPrompt: {str(defaults.auto_prompt).lower()}\n"
        f"  }};\n"
    )
