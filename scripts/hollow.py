#!/usr/bin/env python3
"""
hollow.py — Replace all pub fn / fn bodies with todo!() while preserving signatures.

Usage:
    python3 scripts/hollow.py crates/memf-linux/src/process.rs crates/memf-linux/src/thread.rs ...

Only hollows functions that have a body (not trait method declarations ending in `;`).
Helper/private functions are also hollowed since tests may call them indirectly through
the public walker.
"""
import re
import sys
import pathlib


def hollow_file(path: str) -> int:
    """Hollow all fn bodies in file. Returns count of hollowed functions."""
    text = pathlib.Path(path).read_text()
    result = []
    i = 0
    hollowed = 0

    while i < len(text):
        # Find next fn keyword (pub fn, pub unsafe fn, fn, async fn, etc.)
        m = re.search(
            r'\b(pub(?:\([^)]*\))?\s+(?:unsafe\s+)?(?:async\s+)?fn|(?:unsafe\s+)?(?:async\s+)?fn)\s+\w+',
            text[i:]
        )
        if not m:
            result.append(text[i:])
            break

        result.append(text[i : i + m.start()])
        i += m.start()

        # Find the opening brace or semicolon of the function
        # Scan past generics and parameter list to find { or ;
        j = i + len(m.group())
        depth = 0  # track angle-bracket depth for generics
        brace_pos = None
        semi_pos = None

        while j < len(text):
            c = text[j]
            if c == '<':
                depth += 1
            elif c == '>' and depth > 0:
                depth -= 1
            elif depth == 0:
                if c == '{':
                    brace_pos = j
                    break
                elif c == ';':
                    semi_pos = j
                    break
            j += 1

        if semi_pos is not None and (brace_pos is None or semi_pos < brace_pos):
            # Trait method declaration — no body to hollow
            result.append(text[i : semi_pos + 1])
            i = semi_pos + 1
            continue

        if brace_pos is None:
            # No body found — append rest
            result.append(text[i:])
            break

        # Find matching closing brace
        scan = brace_pos + 1
        depth = 1
        while scan < len(text) and depth > 0:
            c = text[scan]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
            scan += 1
        body_end = scan  # one past the closing }

        # Emit: signature up to and including opening brace, then todo!(), then }
        result.append(text[i : brace_pos + 1])
        result.append('\n        todo!()\n    }')
        i = body_end
        hollowed += 1

    pathlib.Path(path).write_text(''.join(result))
    return hollowed


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/hollow.py <file1.rs> [file2.rs ...]")
        sys.exit(1)

    total = 0
    for f in sys.argv[1:]:
        count = hollow_file(f)
        print(f"Hollowed {count:3d} fn bodies: {f}")
        total += count
    print(f"\nTotal: {total} fn bodies replaced with todo!()")
