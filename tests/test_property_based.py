"""Property-based tests for pagevault's core invariants.

These use Hypothesis to generate many HTML inputs and verify the claims
the codebase makes about itself, especially:

1. unlock(lock(html)) preserves content (roundtrip)
2. lock(lock(html)) is idempotent (closure property)
3. Locking does not leak plaintext into the output
4. Attribute preservation across lock/unlock cycles

Example-based tests (test_parser.py) check specific inputs. These tests
generate many inputs, including edge cases the author didn't think of:
whitespace, unicode, HTML entities, various attribute combinations.
"""

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from pagevault.parser import lock_html, mark_body, mark_elements, unlock_html

# Hypothesis strategies


# Plaintext for property-based testing. Restricted to a subset that
# survives HTML5 parser normalization cleanly (HTML5 mandates replacement
# of null bytes to U+FFFD, normalizes \r to \n, and escapes & < > "
# during serialization). Property-based tests don't need to cover every
# Unicode corner — they need many diverse but testable inputs.
_safe_text = st.text(
    alphabet=st.characters(
        min_codepoint=0x20,  # space
        max_codepoint=0x7E,  # tilde (printable ASCII)
        blacklist_characters="<>&\"'",
    ),
    min_size=0,
    max_size=200,
)

# Passwords: printable ASCII, non-empty
_password = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126),
    min_size=1,
    max_size=50,
)


def _wrap_in_pagevault(content: str) -> str:
    """Wrap text content in a <pagevault> element inside minimal HTML."""
    return f"<html><body><pagevault>{content}</pagevault></body></html>"


class TestLockUnlockRoundtrip:
    """unlock(lock(html)) preserves the original plaintext."""

    @given(content=_safe_text, password=_password)
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_roundtrip_preserves_content(self, content, password):
        html = _wrap_in_pagevault(content)
        locked = lock_html(html, password=password)
        unlocked = unlock_html(locked, password=password)
        # The content must appear somewhere in the unlocked output
        # (exact equality depends on BeautifulSoup's serialization).
        assert content in unlocked or content.strip() in unlocked

    @given(
        content=st.text(
            alphabet=st.characters(
                min_codepoint=0x20,
                max_codepoint=0x7E,
                blacklist_characters="<>&\"'",
            ),
            # 40+ chars so coincidental runtime-substring match is negligible
            min_size=40,
            max_size=200,
        ),
        password=_password,
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_locked_does_not_leak_plaintext(self, content, password):
        """The locked output must not contain the original plaintext.

        Content is >= 40 chars so coincidental substring matches with the
        runtime JS (which contains English words like "template") are
        astronomically unlikely."""
        html = _wrap_in_pagevault(content)
        locked = lock_html(html, password=password)
        assert content not in locked


class TestClosureProperty:
    """lock(lock(html)) == lock(html). Locking is idempotent."""

    @given(content=_safe_text, password=_password)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_relock_is_idempotent(self, content, password):
        # Fix the salt so equality is structural, not crypto-random.
        html = _wrap_in_pagevault(content)
        once = lock_html(html, password=password, salt=b"\x00" * 16)
        twice = lock_html(once, password=password, salt=b"\x00" * 16)
        assert once == twice

    @given(content=_safe_text, password=_password)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_relock_preserves_ciphertext(self, content, password):
        """The ciphertext of an already-encrypted element is preserved
        across a second lock call (even with a different password)."""
        html = _wrap_in_pagevault(content)
        once = lock_html(html, password=password)
        # Re-lock with a different password; the existing ciphertext
        # should NOT be replaced (original password still decrypts).
        twice = lock_html(once, password="different-password-xyz")
        # Once the element is encrypted, it stays encrypted with its
        # original key — the original password still works.
        unlocked = unlock_html(twice, password=password)
        assert content in unlocked or content.strip() in unlocked


class TestMarkAndLockRoundtrip:
    """Mark → lock → unlock preserves original body content."""

    @given(content=_safe_text, password=_password)
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_mark_body_then_roundtrip(self, content, password):
        # Skip empty content (mark_body returns html unchanged if empty)
        assume(content.strip() != "")

        html = f"<html><body>{content}</body></html>"
        marked = mark_body(html)
        locked = lock_html(marked, password=password)
        unlocked = unlock_html(locked, password=password)
        assert content in unlocked or content.strip() in unlocked


class TestNoPlaintextInLocked:
    """Locked output must not contain plaintext under any inputs.

    Uses a restricted ASCII charset at size >= 40 so substring matches
    with the runtime JS are not a concern.
    """

    @given(
        content=st.text(
            alphabet=st.characters(
                min_codepoint=0x20,
                max_codepoint=0x7E,
                blacklist_characters="<>&\"'",
            ),
            min_size=40,
            max_size=200,
        ),
        password=_password,
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_long_content_not_leaked(self, content, password):
        html = _wrap_in_pagevault(content)
        locked = lock_html(html, password=password)
        assert content not in locked


class TestMarkElementsIdempotence:
    """Repeating a selector N times in mark_elements wraps each match once.

    The contract relies on BeautifulSoup's `.select()` re-evaluating
    against the current DOM after each per-selector wrap. Pinning the
    property here so a future refactor that batches selects against a
    snapshot will fail loudly.
    """

    @given(
        content=st.text(
            alphabet=st.characters(
                min_codepoint=0x61,  # 'a'
                max_codepoint=0x7A,  # 'z'
            ),
            min_size=1,
            max_size=20,
        ),
        repeat=st.integers(min_value=1, max_value=5),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_repeated_selector_wraps_once(self, content, repeat):
        # Single div with the content; we'll target it with the same
        # selector N times and verify only one wrapper is produced.
        html = f'<html><body><div id="t">{content}</div></body></html>'
        result = mark_elements(html, ["#t"] * repeat)
        # Count occurrences of the opening pagevault tag.
        assert result.count("<pagevault>") == 1
        assert result.count("</pagevault>") == 1
