"""Command-line interface for pagevault."""

import re
from pathlib import Path

import click

from pagevault import __version__
from pagevault.crypto import PagevaultError
from pagevault.parser import (
    _parse_html,
    has_pagevault_elements,
)

from .commands.audit import audit as _audit
from .commands.config import config as _config_group
from .commands.lock import lock as _lock
from .commands.mark import mark as _mark
from .commands.sync import sync as _sync
from .commands.unlock import unlock as _unlock
from .shared import (
    _format_size,
    _print_runtime_info,
    _relative_path,
)


@click.group()
@click.version_option(version=__version__, prog_name="pagevault")
def main():
    """Password-protect content in HTML and encrypt arbitrary files.

    pagevault encrypts <pagevault> regions in HTML files for mixed public/private
    content on static sites, and wraps arbitrary files into encrypted HTML.

    \b
    Quick start:
      pagevault config init               # Create .pagevault.yaml
      pagevault mark index.html           # Tag elements for encryption
      pagevault lock index.html           # Encrypt marked HTML regions
      pagevault lock paper.pdf            # Wrap file as encrypted HTML
      pagevault lock mysite/ --site       # Bundle directory as encrypted site
      pagevault unlock _locked/           # Restore original content
      pagevault sync _locked/ -r          # Re-wrap keys for current users
    """
    pass


main.add_command(_mark, name="mark")
main.add_command(_lock, name="lock")
main.add_command(_unlock, name="unlock")
main.add_command(_sync, name="sync")
main.add_command(_audit, name="audit")
main.add_command(_config_group, name="config")



@main.command()
@click.argument("path", type=click.Path(exists=True))
def info(path):
    """Inspect an encrypted HTML file.

    Shows encryption metadata, viewer info, and runtime details
    without requiring a password.

    \b
    Examples:
      pagevault info encrypted.html
      pagevault info _locked/index.html
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise click.ClickException(f"Not a file: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as e:
        raise click.ClickException(f"Cannot read {file_path}: {e}")

    if not has_pagevault_elements(content):
        raise click.ClickException("File has no pagevault elements")

    soup = _parse_html(content)

    # Check for wrap-level v4 envelope (pv-meta script tag at document level)
    pv_meta_el = soup.find("script", {"id": "pv-meta"})
    if pv_meta_el:
        import json

        from pagevault.crypto import inspect_payload_v4

        try:
            envelope = json.loads(pv_meta_el.string)
        except (json.JSONDecodeError, TypeError) as e:
            raise click.ClickException(f"Invalid pv-meta JSON: {e}") from e

        info_data = inspect_payload_v4(envelope)

        click.echo(f"File: {_relative_path(file_path)}")
        click.echo("Format:         v4 chunked (wrap)")
        click.echo(f"Version:        v{info_data['version']}")
        click.echo(f"Algorithm:      {info_data['algorithm']}")
        click.echo(f"KDF:            {info_data['kdf']}")
        click.echo(f"Iterations:     {info_data['iterations']:,}")
        click.echo(f"Key blobs:      {info_data['key_count']}")
        click.echo(f"Chunk size:     {_format_size(info_data['chunk_size'])}")
        click.echo(f"Chunks:         {info_data['chunk_count']}")
        click.echo(f"Total size:     {_format_size(info_data['total_size'])}")

        if "content_hash" in envelope:
            click.echo(f"Content hash:   {envelope['content_hash']}")

        # Count chunk script tags in a single DOM pass (previously O(N²)
        # via while soup.find). If it disagrees with the envelope, surface
        # the mismatch — that's an integrity signal worth showing.
        chunk_id_re = re.compile(r"^pv-\d+$")
        chunk_tags_found = len(soup.find_all("script", {"id": chunk_id_re}))
        envelope_count = info_data["chunk_count"]
        if chunk_tags_found == envelope_count:
            click.echo(f"Chunk tags:     {chunk_tags_found}")
        else:
            click.echo(
                f"Chunk tags:     {chunk_tags_found} "
                f"(WARNING: envelope says {envelope_count})"
            )

        # Check pagevault element for mode
        pv_el = soup.find("pagevault")
        if pv_el:
            mode = pv_el.get("data-mode", "single")
            click.echo(f"Mode:           {mode}")

        _print_runtime_info(soup)
        click.echo(f"pagevault:       v{__version__}")
        return

    # --- v4 region-encrypted format: envelopes inside <pagevault data-pv-v4> ---
    import json

    from pagevault.crypto import inspect_payload_v4

    elements = soup.find_all("pagevault")
    encrypted_regions = [el for el in elements if el.has_attr("data-pv-v4")]

    if not encrypted_regions:
        raise click.ClickException("No encrypted regions found")

    click.echo(f"File: {_relative_path(file_path)}")
    click.echo(f"Encrypted regions: {len(encrypted_regions)}")
    click.echo()

    for i, el in enumerate(encrypted_regions):
        mode = el.get("data-mode", "single")
        hint = el.get("data-hint", "")
        title = el.get("data-title", "")
        remember = el.get("data-remember", "")

        click.echo(f"--- Region {i + 1} ---")

        meta_script = None
        for child in el.find_all("script", recursive=False):
            if child.has_attr("data-pv-meta"):
                meta_script = child
                break

        if meta_script is None or not meta_script.string:
            click.echo("  Error: missing pv-meta script")
        else:
            try:
                envelope = json.loads(meta_script.string)
                info_data = inspect_payload_v4(envelope)
                click.echo(f"  Version:      v{info_data['version']}")
                click.echo(f"  Algorithm:    {info_data['algorithm']}")
                click.echo(f"  KDF:          {info_data['kdf']}")
                click.echo(f"  Iterations:   {info_data['iterations']:,}")
                click.echo(f"  Key blobs:    {info_data['key_count']}")
                click.echo(f"  Chunk size:   {_format_size(info_data['chunk_size'])}")
                click.echo(f"  Chunks:       {info_data['chunk_count']}")
                click.echo(f"  Total size:   {_format_size(info_data['total_size'])}")
            except (json.JSONDecodeError, PagevaultError) as e:
                click.echo(f"  Error parsing envelope: {e}")

        click.echo(f"  Mode:         {mode}")
        if hint:
            click.echo(f"  Hint:         {hint}")
        if title:
            click.echo(f"  Title:        {title}")
        if remember:
            click.echo(f"  Remember:     {remember}")
        click.echo()

    _print_runtime_info(soup)

    # Check for wrap type
    wrap_el = soup.find("pagevault", {"data-wrap-type": True})
    if wrap_el:
        click.echo(f"Wrap type:       {wrap_el.get('data-wrap-type')}")
        if wrap_el.get("data-filename"):
            click.echo(f"Filename:        {wrap_el.get('data-filename')}")
        if wrap_el.get("data-entry"):
            click.echo(f"Entry point:     {wrap_el.get('data-entry')}")

    click.echo(f"pagevault:       v{__version__}")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-p", "--password", help="Password to verify (prompts if omitted)")
@click.option("-u", "--username", help="Username for multi-user content")
def check(path, password, username):
    """Verify a password against an encrypted file.

    Performs fast key verification (one PBKDF2 + one AES-GCM unwrap).
    Does NOT decrypt content.

    Exit code 0 = password correct, 1 = incorrect.

    \b
    Examples:
      pagevault check encrypted.html -p "test-password"
      pagevault check _locked/file.html -p "pw" -u alice
      pagevault check encrypted.html              # prompts for password
    """
    if not password:
        password = click.prompt("Password", hide_input=True)

    file_path = Path(path)
    if not file_path.is_file():
        raise click.ClickException(f"Not a file: {file_path}")

    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError as e:
        raise click.ClickException(f"Cannot read {file_path}: {e}")

    if not has_pagevault_elements(content):
        raise click.ClickException("File has no pagevault elements")

    soup = _parse_html(content)

    import json

    from pagevault.crypto import verify_password_v4

    # Check wrap-level v4 envelope first (document-level pv-meta script)
    pv_meta_el = soup.find("script", {"id": "pv-meta"})
    envelope = None
    if pv_meta_el:
        try:
            envelope = json.loads(pv_meta_el.string)
        except (json.JSONDecodeError, TypeError) as e:
            raise click.ClickException(f"Invalid pv-meta JSON: {e}") from e
    else:
        # Fall through to region-level v4: find the first <pagevault data-pv-v4>
        # and grab its child <script data-pv-meta>.
        encrypted_el = soup.find("pagevault", attrs={"data-pv-v4": True})
        if not encrypted_el:
            raise click.ClickException("No encrypted regions found")
        meta_script = None
        for child in encrypted_el.find_all("script", recursive=False):
            if child.has_attr("data-pv-meta"):
                meta_script = child
                break
        if meta_script is None or not meta_script.string:
            raise click.ClickException("Missing pv-meta script in region")
        try:
            envelope = json.loads(meta_script.string)
        except json.JSONDecodeError as e:
            raise click.ClickException(f"Invalid region envelope JSON: {e}") from e

    try:
        result = verify_password_v4(envelope, password, username=username)
    except PagevaultError as e:
        raise click.ClickException(str(e)) from e

    if result:
        click.echo("Password correct")
        raise SystemExit(0)
    else:
        click.echo("Password incorrect")
        raise SystemExit(1)


@main.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option(
    "-P",
    "--port",
    default=8765,
    type=int,
    help="Port number (default: 8765)",
)
@click.option(
    "-o",
    "--open",
    "open_browser",
    is_flag=True,
    help="Open browser automatically",
)
def serve(directory, port, open_browser):
    """Serve directory over local HTTP for previewing encrypted files.

    Useful for testing encrypted HTML files that need HTTP (not file://) to work
    correctly with Web Crypto API and blob URLs.

    \b
    Examples:
      pagevault serve                     # Serve current directory on :8765
      pagevault serve _locked/ -P 9000    # Serve _locked/ on port 9000
      pagevault serve _locked/ --open     # Serve and open browser
    """
    import functools
    import http.server
    import webbrowser

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=directory
    )
    try:
        with http.server.HTTPServer(("", port), handler) as httpd:
            url = f"http://localhost:{port}"
            click.echo(f"Serving {directory} at {url}")
            click.echo("Press Ctrl+C to stop.")
            if open_browser:
                webbrowser.open(url)
            httpd.serve_forever()
    except KeyboardInterrupt:
        click.echo("\nStopped.")
    except OSError as e:
        raise click.ClickException(f"Cannot start server: {e}")


if __name__ == "__main__":
    main()
