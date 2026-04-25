"""Command-line interface for pagevault."""

import click

from pagevault import __version__

from .commands.audit import audit as _audit
from .commands.config import config as _config_group
from .commands.dev import dev as _dev_group
from .commands.inspect import inspect as _inspect
from .commands.lock import lock as _lock
from .commands.mark import mark as _mark
from .commands.sync import sync as _sync
from .commands.unlock import unlock as _unlock


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
main.add_command(_dev_group, name="dev")
main.add_command(_inspect, name="inspect")



if __name__ == "__main__":
    main()
