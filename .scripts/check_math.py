#!/usr/bin/env python3

"""
md_math_lint.py

Rules:
- Inline math MUST be exactly: $` ... `$   (dollar + backticks)
  follwing https://github.blog/changelog/2023-05-08-new-delimiter- \
  syntax-for-inline-mathematical-expressions/
- Block math MUST be fenced as:
    ```math
    ...
    ```
- Everything else is flagged:
  - legacy $...$ / $$...$$
  - \\( ... \\) / \\[ ... \\]
  - mismatched $`...`$ delimiters

Ignores:
- fenced code blocks of any language (``` or ~~~), except ```math which is treated as math-block
- inline code spans using backticks (outside $`...`$)
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

FENCE_RE = re.compile(r"^(\s*)(```+|~~~+)(.*)$")
INLINE_ALLOWED_RE = re.compile(r"(?<!\\)\$`(.+?)`(?<!\\)\$", re.DOTALL)

# Things to forbid
LEGACY_INLINE_DOLLAR_RE = re.compile(r"(?<!\\)\$(?!\$)(.+?)(?<!\\)\$", re.DOTALL)
DISPLAY_DOLLAR_RE = re.compile(r"(?<!\\)\$\$(.+?)(?<!\\)\$\$", re.DOTALL)
PAREN_MATH_RE = re.compile(
    r"(?<!\\)\\\(|(?<!\\)\\\)|(?<!\\)\\\[|(?<!\\)\\\]", re.DOTALL
)

INLINE_CODE_SPAN_RE = re.compile(r"`([^`]|``)*`")  # simple masking


@dataclass(frozen=True)
class Issue:
    path: str
    line: int
    col: int
    kind: str
    excerpt: str


def iter_markdown_files(inputs: list[str]) -> Iterable[Path]:
    for p in inputs:
        path = Path(p)
        if path.is_dir():
            for root, _, files in os.walk(path):
                for name in files:
                    if name.lower().endswith(".md"):
                        yield Path(root) / name
        else:
            yield path


def compute_line_col(text: str, idx: int) -> tuple[int, int]:
    line = text.count("\n", 0, idx) + 1
    last_nl = text.rfind("\n", 0, idx)
    col = (idx + 1) if last_nl < 0 else (idx - last_nl)
    return line, col


def mask_ranges(s: str, ranges: list[tuple[int, int]], fill: str = " ") -> str:
    if not ranges:
        return s
    arr = list(s)
    for a, b in ranges:
        for i in range(max(0, a), min(len(arr), b)):
            arr[i] = fill
    return "".join(arr)


def build_masks(raw: str) -> tuple[str, list[tuple[int, int]], list[tuple[int, int]]]:
    """
    Returns:
      scan_text: raw with non-math fenced blocks masked out (spaces), math fences kept.
      math_block_ranges: (start,end) ranges of ```math fenced blocks (including fences+content)
      non_math_fence_ranges: ranges of other fenced blocks
    """
    lines = raw.splitlines(keepends=True)

    out = []
    math_block_ranges: list[tuple[int, int]] = []
    non_math_fence_ranges: list[tuple[int, int]] = []

    in_fence = False
    fence_char = ""
    fence_len = 0
    is_math = False

    idx = 0
    block_start = 0

    for line in lines:
        m = FENCE_RE.match(line)
        if m:
            token = m.group(2)
            info = m.group(3).strip()

            if not in_fence:
                in_fence = True
                fence_char = token[0]  # ` or ~
                fence_len = len(token)
                is_math = fence_char == "`" and info == "math"
                block_start = idx

                out.append(line)  # keep fence line
            else:
                # close only if same fence char and length>= opener length
                if token[0] == fence_char and len(token) >= fence_len:
                    in_fence = False
                    out.append(line)  # keep closing fence line

                    block_end = idx + len(line)
                    if is_math:
                        math_block_ranges.append((block_start, block_end))
                    else:
                        non_math_fence_ranges.append((block_start, block_end))

                    is_math = False
                    fence_char = ""
                    fence_len = 0
                else:
                    # inside fence content line that happens to look like a fence; treat as content
                    if is_math:
                        out.append(line)
                    else:
                        out.append(
                            " " * (len(line) - (1 if line.endswith("\n") else 0))
                            + ("\n" if line.endswith("\n") else "")
                        )
        else:
            if in_fence:
                if is_math:
                    out.append(line)
                else:
                    out.append(
                        " " * (len(line) - (1 if line.endswith("\n") else 0))
                        + ("\n" if line.endswith("\n") else "")
                    )
            else:
                out.append(line)

        idx += len(line)

    return "".join(out), math_block_ranges, non_math_fence_ranges


def lint_file(path: str, raw: str) -> list[Issue]:
    issues: list[Issue] = []

    scan_text, _, _ = build_masks(raw)

    # Mask allowed inline $`...`$ first
    allowed_ranges = [
        (m.start(), m.end()) for m in INLINE_ALLOWED_RE.finditer(scan_text)
    ]
    tmp = mask_ranges(scan_text, allowed_ranges, fill=" ")

    # Mask inline code spans (outside allowed math)
    code_ranges = [(m.start(), m.end()) for m in INLINE_CODE_SPAN_RE.finditer(tmp)]
    tmp2 = mask_ranges(tmp, code_ranges, fill=" ")

    # 1) Forbid $$...$$ anywhere (outside masked areas)
    for m in DISPLAY_DOLLAR_RE.finditer(tmp2):
        line, col = compute_line_col(raw, m.start())
        excerpt = (
            raw[m.start(): m.end()].splitlines()[0] + " …"
            if "\n" in raw[m.start(): m.end()]
            else raw[m.start(): m.end()]
        )
        issues.append(
            Issue(path, line, col, "forbidden_display_dollars", excerpt.strip())
        )

    # 2) Forbid legacy single-dollar inline math ($...$) not part of allowed $`...`$
    for m in LEGACY_INLINE_DOLLAR_RE.finditer(tmp2):
        line, col = compute_line_col(raw, m.start())
        excerpt = raw[m.start(): m.end()]
        excerpt = excerpt.splitlines()[0] + " …" if "\n" in excerpt else excerpt
        issues.append(
            Issue(path, line, col, "forbidden_inline_dollar", excerpt.strip())
        )

    # 3) Forbid \( \) and \[ \]
    for m in PAREN_MATH_RE.finditer(tmp2):
        line, col = compute_line_col(raw, m.start())
        issues.append(
            Issue(
                path,
                line,
                col,
                "forbidden_backslash_math_delimiter",
                raw[m.start(): m.start() + 2],
            )
        )

    # 4) Detect broken $`...`$ (unbalanced)
    # Strategy: on tmp (where allowed ranges are masked) find remaining '$`' or '`$' tokens.
    broken_scan = tmp  # allowed masked, code not yet masked (fine)
    # mask inline code too to avoid `$` inside code
    broken_scan = mask_ranges(broken_scan, code_ranges, fill=" ")

    opener = re.finditer(r"(?<!\\)\$`", broken_scan)
    closer = re.finditer(r"`(?<!\\)\$", broken_scan)
    open_positions = [m.start() for m in opener]
    close_positions = [m.start() for m in closer]
    if open_positions or close_positions:
        # If any remain, they are unmatched (since matched ones were masked as allowed)
        for pos in open_positions:
            line, col = compute_line_col(raw, pos)
            issues.append(
                Issue(
                    path, line, col, "unmatched_inline_math_opener", raw[pos:pos + 2]
                )
            )
        for pos in close_positions:
            line, col = compute_line_col(raw, pos)
            issues.append(
                Issue(
                    path, line, col, "unmatched_inline_math_closer", raw[pos:pos + 2]
                )
            )

    return issues


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", help="Markdown file(s) or directory(ies)")
    args = ap.parse_args()

    all_issues: list[Issue] = []
    for md in iter_markdown_files(args.paths):
        if not md.exists() or not md.is_file():
            continue
        raw = md.read_text(encoding="utf-8")
        all_issues.extend(lint_file(str(md), raw))

    for i in all_issues:
        print(f"{i.path}:{i.line}:{i.col}: {i.kind}: {i.excerpt}")

    return 1 if all_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
