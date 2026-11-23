"""Canonical forms for beneficiary identifiers.

The same payee must not be able to appear as several. ``A@Bank`` and ``a@bank`` are one UPI
address, ``GB82 WEST 1234 5698 7654 32`` and ``gb82west12345698765432`` are one IBAN. Without a
canonical form, a payee list check or a per-payee window can be dodged by changing case, spacing
or Unicode form.

Only identifier types that are case-insensitive by specification are case-folded (UPI addresses,
IBANs, IFSC codes). Any other identifier keeps its case: merging two case-distinct ids could make
an unknown payee look like a known one, which would loosen the rule.

This is canonicalisation, not a defence against look-alike characters from other scripts.
"""

from __future__ import annotations

import re
import unicodedata

_IBAN_SHAPE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
# IFSC: four letters, a zero, six alphanumerics; then the account number.
_IFSC_ACCOUNT = re.compile(r"^([A-Za-z]{4}0[A-Za-z0-9]{6})[\s:/-]+(\d{6,18})$")
_VPA = re.compile(r"^[^@\s]+@[^@\s]+$")


def _iban_checksum_ok(iban: str) -> bool:
    """ISO 13616 mod-97 check, so ordinary ids are not mistaken for IBANs."""
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def _canonical_once(raw: str) -> str:
    text = unicodedata.normalize("NFKC", raw)
    cleaned: list[str] = []
    for ch in text:
        if ch.isspace():
            cleaned.append(" ")
        elif unicodedata.category(ch) not in ("Cc", "Cf"):  # drops zero-width and control chars
            cleaned.append(ch)
    text = " ".join("".join(cleaned).split())
    if not text:
        return ""

    compact = text.replace(" ", "").replace("-", "").upper()
    if _IBAN_SHAPE.match(compact) and _iban_checksum_ok(compact):
        return compact
    if (m := _IFSC_ACCOUNT.match(text)) is not None:
        return f"{m.group(1).upper()}:{m.group(2)}"
    if _VPA.match(text):
        return text.casefold()
    return text


def canonical_beneficiary(raw: str) -> str:
    """Return the canonical form of a payee identifier ('' if nothing usable remains).

    The form is a fixed point: cleaning can expose characters that Unicode composition then
    merges (a control character between a letter and its accent, for example), so the steps are
    repeated until the text stops changing. Without that, one visible payee could have two
    canonical spellings, one before and one after a second normalisation.
    """
    text = raw
    for _ in range(6):
        nxt = _canonical_once(text)
        if nxt == text:
            return text
        text = nxt
    return text
