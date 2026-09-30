"""Render the executive and technical reports as self-contained HTML.

The documents are plain HTML with an inline stylesheet so they can be printed
to PDF by a browser, or by the optional ``reportlab`` path in
:mod:`fera.reports.pdf`, without shipping a template engine or a web service.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from . import _esc, _text

#: Inline stylesheet shared by both report types.  Kept small on purpose: a
#: report has to stay readable when printed in black and white.
_STYLE = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
 margin:0;padding:2rem;color:#1c2733;line-height:1.5;background:#fff}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.15rem;margin:2rem 0 .5rem;padding-bottom:.25rem;
 border-bottom:2px solid #e3e8ee}
h3{font-size:1rem;margin:1.25rem 0 .35rem}
.meta{color:#5a6b7d;font-size:.85rem;margin-bottom:1.5rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem}
th,td{border:1px solid #d7dee6;padding:.4rem .6rem;text-align:left;font-size:.9rem;
 vertical-align:top}
th{background:#f4f7fa;font-weight:600}
.score{font-size:2.4rem;font-weight:700;line-height:1}
.band{display:inline-block;padding:.15rem .6rem;border-radius:.75rem;
 font-size:.8rem;font-weight:600;background:#eef2f6}
.band.LOW{background:#e3f4e9;color:#1d6b39}
.band.MODERATE{background:#fdf3dd;color:#8a5d00}
.band.HIGH{background:#fde8e0;color:#96301a}
.band.CRITICAL{background:#fbdcdc;color:#8b1a1a}
.band.NOT_VERIFIABLE,.band.UNAVAILABLE{background:#eceff3;color:#5a6b7d}
.tag{display:inline-block;padding:.1rem .45rem;border-radius:.3rem;font-size:.72rem;
 font-weight:600;letter-spacing:.02em}
.OBSERVED{background:#e3f4e9;color:#1d6b39}
.CONFIGURED{background:#e6eefb;color:#1c4d8b}
.INFERRED{background:#f3e8fb;color:#5b2a86}
.NOT_VERIFIABLE{background:#eceff3;color:#5a6b7d}
.FAIL{background:#fbdcdc;color:#8b1a1a}
.WARNING{background:#fdf3dd;color:#8a5d00}
.PASS{background:#e3f4e9;color:#1d6b39}
.note{background:#f7f9fb;border-left:3px solid #c3ceda;padding:.6rem .8rem;
 margin:.6rem 0;font-size:.88rem}
footer{margin-top:2.5rem;padding-top:.8rem;border-top:1px solid #e3e8ee;
 color:#5a6b7d;font-size:.78rem}
"""


def _row(label: str, value: Any, *, default: str = "not reported") -> str:
    """One label/value table row."""
    return f"<tr><th>{_esc(label)}</th><td>{_esc(_text(value, default))}</td></tr>"


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """A bordered table, or an explicit empty-state message."""
    if not rows:
        return '<p class="note">No items were reported for this section.</p>'
    head = "".join(f"<th>{_esc(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _tag(value: Any) -> str:
    """Render an evidence/finding status as a coloured, non-hidden chip."""
    raw = _text(value, "UNKNOWN")
    return f'<span class="tag {raw}">{raw}</span>'


def _document(title: str, subtitle: str, sections: Sequence[Any], *, generated_at: str) -> str:
    """Wrap rendered sections in the shared page chrome.

    ``sections`` may contain nested lists (the section helpers return one), so
    the body is flattened before it is joined.
    """
    body = "\n".join(str(item) for group in sections for item in (group if isinstance(group, list) else [group]))
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{_esc(title)}</title><style>{_STYLE}</style></head><body>"
        f"<h1>{_esc(title)}</h1><p class=\"meta\">{_esc(subtitle)} &middot; generated {generated_at}</p>"
        f"{body}"
        "<footer>FERA &mdash; every value in this document is reproduced from the canonical "
        "analysis bundle. No claim was re-derived, and no evidence status was upgraded. "
        "A NOT_VERIFIABLE result means the passive capture could not settle the question, "
        "not that the check failed.</footer></body></html>"
    )
