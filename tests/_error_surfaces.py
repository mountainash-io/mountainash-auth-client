"""Test helper: every observable text surface of an exception, chains included."""
from __future__ import annotations

import traceback


def exception_surfaces(error: BaseException) -> str:
    """Join str/repr/args/vars/notes/formatted traceback of ``error`` and its chains."""
    parts: list[str] = []
    seen: set[int] = set()
    stack: list[BaseException] = [error]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        parts += [
            str(current),
            repr(current),
            repr(current.args),
            repr(vars(current)),
            repr(getattr(current, "__notes__", [])),
            "".join(traceback.format_exception(type(current), current, current.__traceback__)),
        ]
        for linked in (current.__cause__, current.__context__):
            if linked is not None:
                stack.append(linked)
    return "\n".join(parts)
