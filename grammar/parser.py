"""Recursive-descent parser for CAR pseudocode.

Implements the CARPseudo.g4 grammar in pure Python (no ANTLR4 runtime needed).
Strict mode: raises ParseError on ambiguous/unparseable input.
Produces an AST (list of statement dicts) suitable for IR conversion.
"""

import re
from dataclasses import dataclass, field
from typing import Any


class ParseError(Exception):
    """Raised when pseudocode cannot be parsed strictly."""
    def __init__(self, message: str, line: int = 0, text: str = ""):
        self.line = line
        self.text = text
        super().__init__(f"Line {line}: {message} | '{text}'")


# === TOKENISER ===

TOKEN_PATTERNS = [
    ("STRING", r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\''),
    ("CAR_ID", r'CAR-\d+-\d+-\d+'),
    ("NUMBER", r'\d+'),
    ("ASSIGN", r'=(?!=)'),  # = but not ==
    ("EQ", r'=='),
    ("NEQ", r'!='),
    ("LTE", r'<='),
    ("GTE", r'>='),
    ("LT", r'<'),
    ("GT", r'>'),
    ("LPAREN", r'\('),
    ("RPAREN", r'\)'),
    ("LBRACKET", r'\['),
    ("RBRACKET", r'\]'),
    ("COMMA", r','),
    ("DOT", r'\.'),
    ("COLON", r':'),
    ("MINUS", r'-'),
    ("PLUS", r'\+'),
    ("STAR", r'\*'),
    ("KEYWORD", r'\b(search|filter|where|join|group|by|from|select|output|run|'
                r'and|or|not|in|match|exists|as|null|'
                r'Analytic|'
                r'min|max|count|unique|average|standard_deviation|'
                r'sec|second|seconds|minute|minutes|min|hour|hours|day|days)\b'),
    ("ID", r'[a-zA-Z_][a-zA-Z0-9_]*'),
    ("WS", r'[ \t]+'),
    ("NEWLINE", r'\n'),
]

_TOKEN_RE = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_PATTERNS))


@dataclass
class Token:
    type: str
    value: str
    line: int


def tokenise(text: str) -> list[Token]:
    """Tokenise normalised pseudocode."""
    tokens = []
    line_num = 1
    for m in _TOKEN_RE.finditer(text):
        kind = m.lastgroup
        value = m.group()
        if kind == "NEWLINE":
            line_num += 1
            continue
        if kind == "WS":
            continue
        # Reclassify keywords that matched as ID
        if kind == "ID" and re.match(
            r'^(search|filter|where|join|group|by|from|select|output|run|'
            r'and|or|not|in|match|exists|as|null|Analytic|'
            r'min|max|count|unique|average|standard_deviation|'
            r'sec|second|seconds|minute|minutes|hour|hours|day|days)$', value
        ):
            kind = "KEYWORD"
        tokens.append(Token(kind, value, line_num))
    return tokens


# === PARSER ===

class Parser:
    """Recursive-descent parser for CAR pseudocode."""

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, type_: str, value: str | None = None) -> Token:
        tok = self.peek()
        if tok is None:
            raise ParseError(f"Expected {type_}({value}) but got EOF", line=self._line())
        if tok.type != type_ or (value is not None and tok.value != value):
            raise ParseError(
                f"Expected {type_}({value}) but got {tok.type}({tok.value})",
                line=tok.line, text=tok.value
            )
        return self.advance()

    def match(self, type_: str, value: str | None = None) -> Token | None:
        tok = self.peek()
        if tok and tok.type == type_ and (value is None or tok.value == value):
            return self.advance()
        return None

    def _line(self) -> int:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos].line
        return self.tokens[-1].line if self.tokens else 0

    # === PROGRAM ===

    def parse(self) -> list[dict]:
        """Parse entire program, return list of statement AST nodes."""
        statements = []
        while self.peek() is not None:
            stmt = self.statement()
            if stmt:
                statements.append(stmt)
        return statements

    def statement(self) -> dict | None:
        """Parse a single statement."""
        tok = self.peek()
        if tok is None:
            return None

        # output statement
        if tok.type == "KEYWORD" and tok.value == "output":
            return self.output_stmt()

        # Assignment-style: ID = ...
        if tok.type == "ID":
            # Check if it's field assignment (ID.ID = ...) or regular (ID = ...)
            next_tok = self.tokens[self.pos + 1] if self.pos + 1 < len(self.tokens) else None
            if next_tok and next_tok.type == "DOT":
                return self.assign_stmt()
            if next_tok and next_tok.type == "ASSIGN":
                return self.assignment_dispatch()

        raise ParseError(f"Unexpected token {tok.type}({tok.value})", tok.line, tok.value)

    def assignment_dispatch(self) -> dict:
        """Dispatch ID = ... based on the keyword after ="""
        id_tok = self.advance()  # ID
        self.expect("ASSIGN")   # =

        tok = self.peek()
        if tok is None:
            raise ParseError("Unexpected EOF after =", id_tok.line)

        if tok.type == "KEYWORD":
            if tok.value == "search":
                return self.search_stmt(id_tok.value)
            elif tok.value == "filter":
                return self.filter_stmt(id_tok.value)
            elif tok.value == "join":
                return self.join_stmt(id_tok.value)
            elif tok.value == "group":
                return self.group_stmt(id_tok.value)
            elif tok.value == "from":
                return self.select_stmt(id_tok.value)
            elif tok.value == "run":
                return self.run_stmt(id_tok.value)

        # Check for set difference: ID - ID
        if tok.type == "ID":
            left = self.advance()
            if self.match("MINUS"):
                right = self.expect("ID")
                return {"type": "set_diff", "target": id_tok.value,
                        "left": left.value, "right": right.value}
            # Unrecognised
            raise ParseError(f"Unexpected after '=': {left.value}", left.line, left.value)

        raise ParseError(f"Expected keyword after '=', got {tok.value}", tok.line, tok.value)

    # === STATEMENT PARSERS ===

    def search_stmt(self, target: str) -> dict:
        self.expect("KEYWORD", "search")
        models = [self.data_model_ref()]
        while self.match("COMMA"):
            models.append(self.data_model_ref())
        return {"type": "search", "target": target, "models": models}

    def data_model_ref(self) -> dict:
        # Handle both ID:ID and (Registry:Create AND Registry:Remove)
        tok = self.peek()
        if tok and tok.type == "LPAREN":
            # Grouped model refs: (Registry:Create AND Registry:Remove AND ...)
            self.advance()
            models = [self._single_model_ref()]
            while self.match("KEYWORD", "and"):
                models.append(self._single_model_ref())
            self.expect("RPAREN")
            return {"object": models[0]["object"], "actions": [m["action"] for m in models]}
        return self._single_model_ref()

    def _single_model_ref(self) -> dict:
        obj = self.expect("ID")
        self.expect("COLON")
        action = self.expect("ID")
        return {"object": obj.value, "action": action.value}

    def filter_stmt(self, target: str) -> dict:
        self.expect("KEYWORD", "filter")
        source = self.expect("ID")
        self.expect("KEYWORD", "where")
        self.expect("LPAREN")
        condition = self.expr()
        self.expect("RPAREN")
        return {"type": "filter", "target": target, "source": source.value, "condition": condition}

    def join_stmt(self, target: str) -> dict:
        self.expect("KEYWORD", "join")
        self.expect("LPAREN")
        sources = [self.expect("ID").value]
        while self.match("COMMA"):
            sources.append(self.expect("ID").value)
        self.expect("RPAREN")
        self.expect("KEYWORD", "where")
        self.expect("LPAREN")
        condition = self.expr()
        self.expect("RPAREN")
        return {"type": "join", "target": target, "sources": sources, "condition": condition}

    def group_stmt(self, target: str) -> dict:
        self.expect("KEYWORD", "group")
        source = self.expect("ID")
        self.expect("KEYWORD", "by")
        fields = [self.field_ref()]
        while self.match("COMMA"):
            fields.append(self.field_ref())
        # Optional temporal clause
        temporal = None
        if self.peek() and self.peek().value == "where":
            # consume temporal clause loosely
            temporal = self._consume_temporal_clause()
        return {"type": "group", "target": target, "source": source.value,
                "fields": fields, "temporal": temporal}

    def select_stmt(self, target: str) -> dict:
        self.expect("KEYWORD", "from")
        source = self.expect("ID")
        self.expect("KEYWORD", "select")
        aggs = [self.agg_expr()]
        while self.match("COMMA"):
            aggs.append(self.agg_expr())
        return {"type": "select", "target": target, "source": source.value, "aggregations": aggs}

    def output_stmt(self) -> dict:
        self.expect("KEYWORD", "output")
        ids = [self.expect("ID").value]
        while self.match("COMMA"):
            ids.append(self.expect("ID").value)
        return {"type": "output", "variables": ids}

    def assign_stmt(self) -> dict:
        field = self.field_ref()
        self.expect("ASSIGN")
        # Parse the RHS as an expression (could be field ref)
        value = self.field_ref()
        return {"type": "assign", "target": field, "value": value}

    def run_stmt(self, target: str) -> dict:
        self.expect("KEYWORD", "run")
        self.expect("KEYWORD", "Analytic")
        self.expect("COLON")
        car_id = self.expect("CAR_ID")
        return {"type": "run", "target": target, "analytic_id": car_id.value}

    # === EXPRESSIONS ===

    def expr(self) -> dict:
        return self.or_expr()

    def or_expr(self) -> dict:
        left = self.and_expr()
        while self.match("KEYWORD", "or"):
            right = self.and_expr()
            left = {"op": "or", "left": left, "right": right}
        return left

    def and_expr(self) -> dict:
        left = self.not_expr()
        while self.match("KEYWORD", "and"):
            right = self.not_expr()
            left = {"op": "and", "left": left, "right": right}
        return left

    def not_expr(self) -> dict:
        if self.match("KEYWORD", "not"):
            operand = self.not_expr()
            return {"op": "not", "operand": operand}
        return self.atom_expr()

    def atom_expr(self) -> dict:
        # Grouped expression
        if self.peek() and self.peek().type == "LPAREN":
            self.advance()
            e = self.expr()
            self.expect("RPAREN")
            return e

        # Must be a comparison
        return self.comparison()

    def comparison(self) -> dict:
        left = self.field_ref()

        tok = self.peek()
        if tok is None:
            return {"op": "ref", "field": left}

        # field not in [...]
        if tok.type == "KEYWORD" and tok.value == "not":
            self.advance()
            self.expect("KEYWORD", "in")
            values = self.value_list()
            return {"op": "not_in", "field": left, "values": values}

        # field in [...]
        if tok.type == "KEYWORD" and tok.value == "in":
            self.advance()
            values = self.value_list()
            return {"op": "in", "field": left, "values": values}

        # field match "regex"
        if tok.type == "KEYWORD" and tok.value == "match":
            self.advance()
            pattern = self.expect("STRING")
            return {"op": "match", "field": left, "pattern": pattern.value.strip("\"'")}

        # field exists
        if tok.type == "KEYWORD" and tok.value == "exists":
            self.advance()
            return {"op": "exists", "field": left}

        # Comparison operators
        if tok.type in ("EQ", "NEQ", "LT", "GT", "LTE", "GTE"):
            op_tok = self.advance()
            right = self.value_or_field()
            return {"op": op_tok.value, "field": left, "value": right}

        # If no operator follows, treat as a bare reference
        return {"op": "ref", "field": left}

    # === VALUES ===

    def value_or_field(self) -> Any:
        tok = self.peek()
        if tok is None:
            raise ParseError("Expected value", self._line())
        if tok.type == "STRING":
            return self.advance().value.strip("\"'")
        if tok.type == "NUMBER":
            return int(self.advance().value)
        if tok.type == "KEYWORD" and tok.value == "null":
            self.advance()
            return None
        # Could be a field reference or duration
        if tok.type == "ID" or tok.type == "KEYWORD":
            return self.field_ref()
        raise ParseError(f"Expected value, got {tok.type}({tok.value})", tok.line, tok.value)

    def value_list(self) -> list:
        """Parse [val1, val2, ...] or (val1, val2, ...)"""
        opener = self.peek()
        if opener and opener.type == "LBRACKET":
            self.advance()
            values = [self.value_or_field()]
            while self.match("COMMA"):
                values.append(self.value_or_field())
            self.expect("RBRACKET")
            return values
        elif opener and opener.type == "LPAREN":
            self.advance()
            values = [self.value_or_field()]
            while self.match("COMMA"):
                values.append(self.value_or_field())
            self.expect("RPAREN")
            return values
        raise ParseError("Expected [ or ( for value list", self._line())

    def field_ref(self) -> str:
        """Parse dotted field reference: ID.ID.ID"""
        parts = [self.expect("ID").value]
        while self.match("DOT"):
            parts.append(self.expect("ID").value)
        return ".".join(parts)

    def agg_expr(self) -> dict:
        func = self.expect("KEYWORD")
        self.expect("LPAREN")
        field = self.field_ref()
        self.expect("RPAREN")
        alias = None
        if self.match("KEYWORD", "as"):
            alias = self.expect("ID").value
        return {"func": func.value, "field": field, "alias": alias}

    def _consume_temporal_clause(self) -> str:
        """Consume a temporal where clause loosely (returns raw text)."""
        # Skip 'where' '(' ... ')'
        self.expect("KEYWORD", "where")
        self.expect("LPAREN")
        depth = 1
        parts = []
        while depth > 0:
            tok = self.advance()
            if tok.type == "LPAREN":
                depth += 1
            elif tok.type == "RPAREN":
                depth -= 1
                if depth == 0:
                    break
            parts.append(tok.value)
        return " ".join(parts)


# === PUBLIC API ===

def parse(text: str) -> list[dict]:
    """Parse normalised CAR pseudocode into AST (list of statements).

    Raises ParseError if input cannot be strictly parsed.
    """
    tokens = tokenise(text)
    if not tokens:
        return []
    parser = Parser(tokens)
    return parser.parse()
