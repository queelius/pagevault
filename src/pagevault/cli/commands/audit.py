"""audit command."""

import math
import os
from pathlib import Path

import click

from pagevault.config import load_config
from pagevault.crypto import PagevaultError
from pagevault.parser import _parse_html, has_pagevault_elements

from ..shared import _resolve_managed_html_files


@click.command()
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Config file path",
)
def audit(config_path):
    """Run comprehensive health checks on configuration and encrypted files.

    Checks password strength, salt quality, config hygiene, and file integrity.

    \b
    Examples:
      pagevault audit
      pagevault audit -c .pagevault.yaml
    """
    # Load configuration
    try:
        cfg = load_config(config_path=Path(config_path) if config_path else None)
    except PagevaultError as e:
        raise click.ClickException(str(e))

    issues = []
    warnings = []
    passed = []

    # --- Password strength ---
    passwords_to_check = []
    if cfg.password:
        passwords_to_check.append(("password", cfg.password))
    if cfg.users:
        for uname, upwd in cfg.users.items():
            passwords_to_check.append((f"user '{uname}'", upwd))

    for label, pwd in passwords_to_check:
        length = len(pwd)
        if length < 8:
            issues.append(f"WEAK: {label} password is only {length} chars (minimum 8)")
        elif length < 12:
            warnings.append(f"{label} password is {length} chars (12+ recommended)")
        else:
            passed.append(f"{label} password length OK ({length} chars)")

        # Character class analysis
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)
        classes = sum([has_lower, has_upper, has_digit, has_special])

        if classes == 1:
            if has_lower:
                issues.append(f"WEAK: {label} password is all lowercase")
            elif has_digit:
                issues.append(f"WEAK: {label} password is all numeric")
        elif classes == 2:
            warnings.append(f"{label} password uses only {classes} character classes")

        # Entropy estimate (bits per char * length)
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
            if entropy < 40:
                issues.append(
                    f"WEAK: {label} password entropy ~{entropy:.0f} bits (<40)"
                )
            elif entropy < 60:
                warnings.append(
                    f"{label} password entropy ~{entropy:.0f} bits (60+ recommended)"
                )
            else:
                passed.append(f"{label} password entropy ~{entropy:.0f} bits")

    if not passwords_to_check:
        warnings.append("No passwords configured")

    # --- Salt quality ---
    if cfg.salt:
        if len(cfg.salt) < 16:
            issues.append(f"Salt is only {len(cfg.salt)} bytes (minimum 16)")
        elif cfg.salt == b"\x00" * len(cfg.salt):
            issues.append("Salt is all zeros")
        else:
            passed.append(f"Salt OK ({len(cfg.salt)} bytes)")
    else:
        warnings.append("No salt configured (random salt will be used per encryption)")

    # --- Config hygiene ---
    if cfg.config_path:
        config_dir = cfg.config_path.parent
        gitignore = config_dir / ".gitignore"
        if gitignore.is_file():
            gitignore_content = gitignore.read_text(encoding="utf-8", errors="replace")
            config_name = cfg.config_path.name
            yaml_in_gitignore = ".pagevault.yaml" in gitignore_content
            if config_name in gitignore_content or yaml_in_gitignore:
                passed.append(f"{config_name} is in .gitignore")
            else:
                issues.append(
                    f"{config_name} is NOT in .gitignore — passwords may be committed"
                )
        else:
            warnings.append("No .gitignore found in config directory")

    # Check environment variable
    if os.environ.get("PAGEVAULT_PASSWORD"):
        warnings.append(
            "PAGEVAULT_PASSWORD is set in environment — "
            "visible to other processes and shell history"
        )

    # --- File integrity (check managed files if available) ---
    managed_files: list[Path] = []
    if cfg.managed and cfg.config_path:
        managed_files = _resolve_managed_html_files(
            cfg.config_path.parent, cfg.managed
        )

    if managed_files:
        checked = 0
        for file_path in managed_files:
            try:
                html = file_path.read_text(encoding="utf-8")
            except OSError:
                warnings.append(f"Cannot read managed file: {file_path.name}")
                continue

            if not has_pagevault_elements(html):
                continue

            soup = _parse_html(html)

            for el in soup.find_all("pagevault", attrs={"data-pv-v4": True}):
                # In v4, content_hash lives inside the encrypted envelope
                # metadata, not as a DOM attribute. Existence of a
                # data-pv-meta script is the marker for an integrity-capable
                # region; validating the hash requires decryption (not done
                # in audit, which is password-free).
                if el.find("script", attrs={"data-pv-meta": True}, recursive=False):
                    checked += 1

        if checked > 0:
            passed.append(f"Found {checked} encrypted region(s) with content hashes")
    else:
        warnings.append("No managed files configured for integrity checks")

    # --- Output results ---
    click.echo("pagevault audit")
    click.echo("=" * 40)

    if issues:
        click.echo(f"\nISSUES ({len(issues)}):")
        for issue in issues:
            click.echo(f"  [!] {issue}")

    if warnings:
        click.echo(f"\nWARNINGS ({len(warnings)}):")
        for warning in warnings:
            click.echo(f"  [?] {warning}")

    if passed:
        click.echo(f"\nPASSED ({len(passed)}):")
        for p in passed:
            click.echo(f"  [+] {p}")

    click.echo()
    if issues:
        click.echo(f"Result: {len(issues)} issue(s) found")
        raise SystemExit(1)
    elif warnings:
        click.echo(f"Result: OK with {len(warnings)} warning(s)")
    else:
        click.echo("Result: All checks passed")
