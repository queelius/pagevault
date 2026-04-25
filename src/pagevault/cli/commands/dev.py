"""dev command group (developer experience tools)."""

import click


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
      pagevault dev serve                     # Serve current directory on :8765
      pagevault dev serve _locked/ -P 9000    # Serve _locked/ on port 9000
      pagevault dev serve _locked/ --open     # Serve and open browser
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
