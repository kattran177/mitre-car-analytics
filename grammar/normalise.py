"""Normalise CAR pseudocode before ANTLR4 parsing.

Handles the known inconsistencies in the corpus:
- Mixed-case booleans (and/AND/or/OR)
- {{pipe}} escape sequences
- Typos (double quotes, bracket notation)
- Missing parentheses in filter where clauses
- Single = used as comparison (should be ==)
- Multiline conditions (join into single logical line)
"""

import re


def normalise(raw: str) -> str:
    """Normalise pseudocode text for parsing. Returns cleaned text."""
    text = raw.strip()

    # Normalise smart/curly quotes to ASCII
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2018", "'").replace("\u2019", "'")

    # Join continuation lines (lines starting with or/and/OR/AND that are part
    # of a multiline condition inside a filter/join)
    text = _join_continuation_lines(text)

    # Normalise {{pipe}} to |
    text = text.replace("{{pipe}}", "|")

    # Normalise boolean operators to lowercase
    text = re.sub(r'\bAND\b', 'and', text)
    text = re.sub(r'\bOR\b', 'or', text)
    text = re.sub(r'\bNOT\b', 'not', text)
    text = re.sub(r'\bIN\b', 'in', text)

    # Normalise non-standard keywords
    text = re.sub(r'\bCONTAINS\b', 'match', text)

    # Fix missing 'where' in filter: "filter X (" → "filter X where ("
    text = re.sub(r'(filter\s+\w+)\s*\(', r'\1 where (', text)

    # Fix single = used as comparison (but not in assignments like var = search)
    text = _fix_comparison_equals(text)

    # Quote unquoted wildcard values AFTER == normalisation:
    # field == *pattern* → field == "*pattern*"
    text = re.sub(r'(==\s*)\*([^"\s*][^"\s]*)\*', r'\1"*\2*"', text)
    text = re.sub(r'(==\s*)\*([^"\s]+)', r'\1"*\2"', text)

    # Fix double-quote typos: parent_exe == "explorer.exe"")
    text = re.sub(r'"\)', '")', text.replace('"")', '")'))

    # Normalise bracket field notation [field] → field
    text = re.sub(r'\[(\w+)\]', r'\1', text)

    # Strip trailing whitespace per line
    text = "\n".join(line.rstrip() for line in text.split("\n"))

    return text


def _join_continuation_lines(text: str) -> str:
    """Join lines that are continuations of a multiline expression.

    A continuation line starts with whitespace followed by a condition fragment
    (or/and, field comparison, closing paren).
    """
    lines = text.split("\n")
    joined = []
    for line in lines:
        stripped = line.strip()
        # Continuation: starts with or/and/OR/AND, or is just a closing paren,
        # or is a condition fragment inside a filter (indented, not a keyword start)
        if joined and stripped and _is_continuation(stripped, joined[-1]):
            joined[-1] = joined[-1].rstrip() + " " + stripped
        else:
            joined.append(line)
    return "\n".join(joined)


def _is_continuation(current: str, previous: str) -> bool:
    """Determine if current line is a continuation of previous."""
    prev_stripped = previous.strip()

    # Line starts with boolean connector
    if re.match(r'^(and|or|AND|OR)\b', current):
        return True

    # Line is just a closing paren (possibly with trailing content)
    if current == ')' or current == '),' or re.match(r'^\)\s*$', current):
        return True

    # Previous line ends with 'and', 'or', or an open paren without close
    if prev_stripped.endswith(('and', 'or', 'AND', 'OR')):
        return True

    # Previous line has unclosed parentheses
    if prev_stripped.count('(') > prev_stripped.count(')'):
        return True

    return False


def _fix_comparison_equals(text: str) -> str:
    """Replace single = with == inside where(...) clauses, but not in assignments.

    Strategy: find all 'where (' regions and fix = within them.
    Also fix = inside filter conditions that lack 'where' keyword (later CAR style).
    """
    lines = text.split("\n")
    result = []

    for line in lines:
        # Don't touch assignment lines (var = search/filter/join/group/from/run/...)
        if re.match(r'^\s*\w+\s*=\s*(search|filter|join|group|from|run)\b', line):
            # But DO fix = inside the where(...) portion of filter lines
            where_idx = line.find('where')
            if where_idx > 0:
                prefix = line[:where_idx]
                suffix = line[where_idx:]
                suffix = _replace_single_equals(suffix)
                line = prefix + suffix
            result.append(line)
        elif re.match(r'^\s*\w+\s*=\s*\w+\s*-\s*\w+', line):
            # Set difference: var = a - b
            result.append(line)
        else:
            # Continuation/condition lines — always fix = to ==
            result.append(_replace_single_equals(line))

    return "\n".join(result)


def _replace_single_equals(text: str) -> str:
    """Replace single = with == in text (but not != or == or <=  or >=)."""
    return re.sub(r'(?<![!=<>])=(?!=)', ' == ', text)


def normalise_file(path: str) -> str:
    """Read and normalise a .pseudo file."""
    with open(path, encoding="utf-8") as f:
        return normalise(f.read())
