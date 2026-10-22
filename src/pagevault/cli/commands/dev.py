"""dev command group (developer experience tools)."""

import functools
import http.server
import urllib.parse
import webbrowser
from pathlib import Path

import click


class _PreviewHandler(http.server.SimpleHTTPRequestHandler):
    """Static file handler that never serves hidden paths.

    A project root typically holds ``.pagevault.yaml`` (plaintext
    credentials) and ``.git/``; a preview server has no reason to expose
    either. Covers GET and HEAD, and percent-encoded dots.
    """

    def send_head(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if any(part.startswith(".") for part in path.split("/")):
            self.send_error(404, "File not found")
            return None
        return super().send_head()


def make_handler(directory: Path):
    """Return a request handler class serving ``directory``."""
    return functools.partial(_PreviewHandler, directory=str(directory))


@click.group()
def dev():
    """Developer experience tools.

    \b
    Examples:
      pagevault dev serve                 # Serve current directory on :8765
      pagevault dev serve _locked/ -P 9000
    """
    pass


@dev.command("serve")
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option(
    "-P",
    "--port",
    default=8765,
    type=int,
    help="Port number (default: 8765)",
)
@click.option(
    "--host",
    default="127.0.0.1",
    help="Interface to bind (default: 127.0.0.1; use 0.0.0.0 to expose on the network)",
)
@click.option(
    "-o",
    "--open",
    "open_browser",
    is_flag=True,
    help="Open browser automatically",
)
def serve(directory, port, host, open_browser):
    """Serve directory over local HTTP for previewing encrypted files.

    Useful for testing encrypted HTML files that need HTTP (not file://) to work
    correctly with Web Crypto API and blob URLs.

    \b
    Examples:
      pagevault dev serve                     # Serve current directory on :8765
      pagevault dev serve _locked/ -P 9000    # Serve _locked/ on port 9000
      pagevault dev serve _locked/ --open     # Serve and open browser
    """
    try:
        with http.server.HTTPServer((host, port), make_handler(directory)) as httpd:
            url = f"http://{'localhost' if host in ('127.0.0.1', '') else host}:{port}"
            click.echo(f"Serving {directory} at {url}")
            click.echo("Press Ctrl+C to stop.")
            if open_browser:
                webbrowser.open(url)
            httpd.serve_forever()
    except KeyboardInterrupt:
        click.echo("\nStopped.")
    except OSError as e:
        raise click.ClickException(f"Cannot start server: {e}")
