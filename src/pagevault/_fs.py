"""Filesystem helpers shared by every command that writes output."""

import contextlib
import os
import stat
import tempfile
from pathlib import Path


def _default_mode() -> int:
    """Mode a plain open() would give a new file under the current umask."""
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


def atomic_write(
    path: Path,
    data: str | bytes,
    mode: int | None = None,
    follow_symlinks: bool = False,
) -> None:
    """Write ``data`` to ``path`` so it is never seen partially written.

    The data goes to a temporary file in the same directory, which is then
    renamed over ``path``. An interrupted or failed write leaves the old
    file (or no file) in place rather than a truncated one, which matters
    when ``path`` is the only copy (sync, mark) or a deploy directory.
    Text is written as UTF-8. Without ``mode``, the result keeps an existing
    file's mode and a new file gets the usual umask-derived mode, not
    mkstemp's 0600. Pass ``mode`` (e.g. 0o600 for a file holding passwords)
    to set it outright; the data is never readable under a wider mode,
    since the temporary file starts as 0600.

    A symlink at ``path`` is replaced by the new file, so a link planted in
    an output directory cannot redirect the write elsewhere. Pass
    ``follow_symlinks`` to write to the link's target instead, for a file
    the user deliberately linked (a config kept in a dotfiles repo).
    """
    path = Path(os.path.realpath(path) if follow_symlinks else path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except FileNotFoundError:
            mode = _default_mode()

    # A short fixed prefix: deriving it from path.name would push names near
    # the filesystem's length limit (255 bytes) over it.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".pv-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode("utf-8") if isinstance(data, str) else data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
