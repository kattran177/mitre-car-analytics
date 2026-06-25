"""Normalise CAR pseudocode before ANTLR4 parsing.

Handles the known inconsistencies in the corpus:
- Mixed-case booleans (and/AND/or/OR)
- {{pipe}} escape sequences
- Typos (double quotes, bracket notation)
- Missing parentheses in filter where clauses
- Single = used as comparison (should be ==)
- Multiline conditions (join into single logical line)
- Missing closing parens before 'output'
- Unquoted values (exe=svchost.exe → exe=="svchost.exe")
- Non-standard operators (CONTAINS, includes, does not contain)
- Wildcard data model refs (Process:* → Process:Create)
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

    # Normalise non-standard operators/keywords
    text = re.sub(r'\bCONTAINS\s*\(\s*"?([^")\s]+)"?\s*\)', r'match "\1"', text)
    text = re.sub(r'\bCONTAINS\s*\(\s*([^)]+)\)', r'match "\1"', text)
    text = re.sub(r'\bCONTAINS\b', 'match', text)
    text = re.sub(r'\bincludes\b', 'in', text)
    text = re.sub(r'\bdoes not contain\b', '!=', text)

    # Fix wildcard data model: Process:* → Process:Create
    text = re.sub(r'(\w+):\*', r'\1:Create', text)

    # Fix missing 'where' in filter: "filter X (" → "filter X where ("
    text = re.sub(r'(filter\s+\w+)\s*\(', r'\1 where (', text)

    # Fix filter without parens: "filter X where field..." → "filter X where (field...)"
    text = _fix_filter_without_parens(text)

    # Fix single = used as comparison (but not in assignments)
    text = _fix_comparison_equals(text)

    # Quote unquoted wildcard values AFTER == normalisation:
    # field == *pattern* → field == "*pattern*"
    text = re.sub(r'(==\s*)\*([^"\s*][^"\s]*)\*', r'\1"*\2*"', text)
    text = re.sub(r'(==\s*)\*([^"\s]+)', r'\1"*\2"', text)

    # Quote unquoted bare values: exe==svchost.exe → exe=="svchost.exe"
    text = re.sub(r'(==\s*)([A-Za-z][A-Za-z0-9_.\\:]+\.exe)\b', r'\1"\2"', text)
    text = re.sub(r'(!=\s*)([A-Za-z][A-Za-z0-9_.\\:]+\.exe)\b', r'\1"\2"', text)

    # Fix double-quote typos: parent_exe == "explorer.exe"")
    text = re.sub(r'"\)', '")', text.replace('"")', '")'))

    # Normalise bracket field notation [field] → field
    text = re.sub(r'\[(\w+)\]', r'\1', text)

    # Fix missing closing paren before 'output' keyword
    text = _fix_missing_close_paren(text)

    # Strip trailing whitespace per line
    text = "\n".join(line.rstrip() for line in text.split("\n"))

    return text


def _join_continuation_lines(text: str) -> str:
    """Join lines that are continuations of a multiline expression."""
    lines = text.split("\n")
    joined = []
    for line in lines:
        stripped = line.strip()
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


def _fix_filter_without_parens(text: str) -> str:
    """Fix filters that have 'where' but conditions aren't wrapped in parens.

    Pattern: filter X where command_line == "..." → filter X where (command_line == "...")
    """
    lines = text.split("\n")
    result = []
    for line in lines:
        # Match: filter VAR where FIELD (not followed by open paren)
        m = re.match(r'^(\s*\w+\s*=\s*filter\s+\w+\s+where\s+)(?!\()(.+)$', line)
        if m:
            prefix, condition = m.groups()
            # Wrap condition in parens if not already
            if not condition.strip().startswith('('):
                # Check if condition already ends with )
                if condition.rstrip().endswith(')'):
                    line = prefix + '(' + condition
                else:
                    line = prefix + '(' + condition + ')'
        result.append(line)
    return "\n".join(result)


def _fix_missing_close_paren(text: str) -> str:
    """Insert missing closing paren before 'output' keyword.

    Handles two cases:
    1. 'output' joined mid-line due to continuation joining (most common)
    2. 'output' on its own line after unclosed filter
    """
    # Case 1: 'output' joined mid-line after unclosed filter condition
    # Only match when there are unclosed parens before 'output'
    lines = text.split("\n")
    result = []
    for line in lines:
        # Check if line contains 'output' mid-line with unclosed parens before it
        m = re.search(r'\boutput\s+\w', line)
        if m and not line.strip().startswith('output'):
            before = line[:m.start()]
            after = line[m.start():]
            open_count = before.count('(') - before.count(')')
            if open_count > 0:
                line = before + ')' * open_count + '\n' + after
        result.append(line)

    text = "\n".join(result)

    # Case 2: 'output' on next line after unclosed parens
    lines = text.split("\n")
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('output') and result:
            prev = result[-1]
            open_count = prev.count('(') - prev.count(')')
            if open_count > 0:
                result[-1] = prev + ')' * open_count
        result.append(line)
    return "\n".join(result)


def _fix_comparison_equals(text: str) -> str:
    """Replace single = with == inside where(...) clauses, but not in assignments."""
    lines = text.split("\n")
    result = []

    for line in lines:
        if re.match(r'^\s*\w+\s*=\s*(search|filter|join|group|from|run)\b', line):
            # Fix = inside the where(...) portion of filter lines
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
            result.append(_replace_single_equals(line))

    return "\n".join(result)


def _replace_single_equals(text: str) -> str:
    """Replace single = with == in text (but not != or == or <= or >=)."""
    return re.sub(r'(?<![!=<>])=(?!=)', ' == ', text)


def normalise_file(path: str) -> str:
    """Read and normalise a .pseudo file."""
    with open(path, encoding="utf-8") as f:
        return normalise(f.read())
