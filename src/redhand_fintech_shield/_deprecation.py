"""One way to deprecate public API: a ``DeprecationWarning`` that says what to use instead."""

from __future__ import annotations

import warnings


def warn_deprecated(what: str, instead: str, *, removal: str = "a future minor release") -> None:
    """Warn that ``what`` is deprecated in favour of ``instead``, blaming the caller."""
    warnings.warn(
        f"{what} is deprecated and will be removed in {removal}; use {instead}",
        DeprecationWarning,
        stacklevel=3,
    )
