#!/usr/bin/env python3
"""
add_linenos.py
Adds {linenos=table} to fenced code blocks with more than 10 lines
across all markdown files in the Hugo content directory.
"""

import re
import os

CONTENT_DIR = r"C:\Users\dark\RadiantSec\content"
MIN_LINES = 10

# Matches an opening code fence:
#   group 1 — backticks (3+)
#   group 2 — language identifier (optional)
#   group 3 — existing options e.g. " {hl_lines=...}" (optional)
OPEN_FENCE = re.compile(r'^(`{3,})([\w\-]*)(.*?)$')
CLOSE_FENCE = re.compile(r'^`{3,}\s*$')


def process(content: str) -> tuple[str, int]:
    lines = content.splitlines(keepends=True)
    result = []
    patches = 0
    i = 0

    while i < len(lines):
        raw = lines[i]
        stripped = raw.rstrip('\r\n')
        m = OPEN_FENCE.match(stripped)

        if m:
            fence    = m.group(1)   # e.g. ```
            lang     = m.group(2)   # e.g. python
            opts     = m.group(3)   # e.g.  {hl_lines="1"}  or ""
            eol      = raw[len(stripped):]

            # Locate the closing fence
            j = i + 1
            body = []
            while j < len(lines):
                cl = lines[j].rstrip('\r\n')
                if CLOSE_FENCE.match(cl):
                    break
                body.append(lines[j])
                j += 1

            if len(body) > MIN_LINES and 'linenos' not in opts:
                # Inject linenos=table into the options block
                if opts.strip().startswith('{') and opts.strip().endswith('}'):
                    opts = opts.rstrip('}') + ', linenos=table}'
                else:
                    opts = opts + ' {linenos=table}'
                patches += 1

            result.append(fence + lang + opts + eol)
            result.extend(body)
            if j < len(lines):
                result.append(lines[j])
                i = j + 1
            else:
                i = j
        else:
            result.append(raw)
            i += 1

    return ''.join(result), patches


def main():
    total_files = 0
    total_patches = 0

    for root, _, files in os.walk(CONTENT_DIR):
        for fname in files:
            if not fname.endswith('.md'):
                continue
            fpath = os.path.join(root, fname)
            with open(fpath, 'r', encoding='utf-8') as f:
                original = f.read()

            updated, patches = process(original)

            if patches:
                with open(fpath, 'w', encoding='utf-8') as f:
                    f.write(updated)
                rel = os.path.relpath(fpath, CONTENT_DIR)
                print(f"  [{patches:2d} blocks]  {rel}")
                total_files  += 1
                total_patches += patches

    print(f"\n{total_patches} code blocks updated across {total_files} files.")


if __name__ == '__main__':
    main()
