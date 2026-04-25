"""Generate JSON fixtures for JS tests.

Run this whenever the Python encrypt format changes:
    python tests/js/fixtures/generate_v4_fixture.py
"""

import json
from pathlib import Path

from pagevault.crypto import encrypt_v4

FIXTURES_DIR = Path(__file__).parent


def main():
    data = b"Hello, v4!"
    envelope, chunks = encrypt_v4(
        data,
        password="testpw",
        meta={"kind": "file", "mime": "text/plain"},
    )

    fixture = {
        "envelope": envelope,
        "chunks": chunks,
        "password": "testpw",
        "expected_text": "Hello, v4!",
    }

    (FIXTURES_DIR / "v4_simple.json").write_text(json.dumps(fixture, indent=2))
    print("Generated v4_simple.json")


if __name__ == "__main__":
    main()
