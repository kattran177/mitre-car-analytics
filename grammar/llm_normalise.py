"""LLM-assisted normalisation for pseudocode that fails deterministic parsing.

When the grammar parser rejects input, this module asks the LLM to rewrite it
into a form that conforms to the grammar, then re-parses deterministically.
This quantifies exactly where LLMs are needed in the pipeline.
"""

from grammar.normalise import normalise
from grammar.parser import parse, ParseError

# Compact prompt — gives the LLM the grammar rules and asks it to rewrite
NORMALISE_PROMPT = """Rewrite this CAR pseudocode to match the strict grammar below. 
Do NOT translate to Splunk. Just fix the pseudocode syntax.

## Grammar Rules (MUST follow exactly):
- Statements: search, filter, join, group, output
- search: `variable = search Model:Action`
- filter: `variable = filter source where (conditions)`
  - Conditions MUST be wrapped in parentheses after 'where'
  - Use == for equality, != for inequality
  - Strings MUST be quoted: "value"
  - Wildcards inside quotes: "*pattern*"
  - Boolean: and, or, not (lowercase)
  - Valid operators: ==, !=, match "pattern", in ["a", "b"], not in ["a", "b"]
- output: `output variable_name`
- Each statement on its own line
- Every filter MUST have matching parentheses

## Parse Error:
{error}

## Original Pseudocode:
```
{pseudocode}
```

## Rewrite Rules:
- Keep the SAME logic/intent
- Fix syntax only (parens, quotes, operators)
- Replace non-standard operators: CONTAINS("x") → match "*x*"
- Replace 'includes' → in [...]  
- Replace 'does not contain' → not in [...]
- Quote all string values
- Ensure every filter has: filter VAR where (condition)
- If the pseudocode is bare conditions (no search/filter), wrap as:
  events = search Event:Log
  filtered = filter events where (original_conditions)
  output filtered

Return ONLY the corrected pseudocode. No explanation, no markdown fences.
"""


def llm_normalise(client, model: str, pseudocode: str, error: str) -> str | None:
    """Ask the LLM to rewrite unparseable pseudocode into grammar-compliant form.

    Args:
        client: Anthropic client
        model: Model name
        pseudocode: Raw pseudocode that failed to parse
        error: The ParseError message

    Returns:
        Normalised pseudocode string, or None if LLM output also fails to parse.
    """
    prompt = NORMALISE_PROMPT.format(error=error, pseudocode=pseudocode)

    response = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    rewritten = response.content[0].text.strip()

    # Strip markdown fences if present
    if rewritten.startswith("```"):
        lines = rewritten.split("\n")
        rewritten = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

    return rewritten


def normalise_and_parse(client, model: str, pseudocode: str, max_attempts: int = 2) -> tuple[list[dict] | None, dict]:
    """Attempt to parse pseudocode, falling back to LLM normalisation if needed.

    Returns:
        (ast, metadata) where ast is the parse result (or None on failure),
        and metadata tracks what happened.
    """
    meta = {"method": "deterministic", "attempts": 0, "llm_used": False}

    # First: try deterministic normalisation + parse
    try:
        normalised = normalise(pseudocode)
        ast = parse(normalised)
        return ast, meta
    except ParseError as e:
        initial_error = str(e)

    # Second: LLM-assisted normalisation
    meta["method"] = "llm_assisted"
    meta["llm_used"] = True
    meta["initial_error"] = initial_error

    for attempt in range(max_attempts):
        meta["attempts"] = attempt + 1
        try:
            rewritten = llm_normalise(client, model, pseudocode, initial_error)
            if rewritten is None:
                continue
            # Apply deterministic normalisation to LLM output, then parse
            normalised = normalise(rewritten)
            ast = parse(normalised)
            meta["rewritten"] = rewritten
            return ast, meta
        except ParseError as e:
            initial_error = str(e)  # Use new error for next attempt
            meta["last_error"] = str(e)

    return None, meta


def batch_normalise(client, model: str, failures: dict[str, str]) -> dict:
    """Process a batch of failed pseudocode blocks through LLM normalisation.

    Args:
        client: Anthropic client
        model: Model name
        failures: {car_id: pseudocode} for analytics that failed deterministic parse

    Returns:
        Results dict with per-analytic outcomes and summary stats.
    """
    results = {}
    stats = {"total": len(failures), "fixed": 0, "still_failing": 0}

    for car_id, pseudocode in failures.items():
        ast, meta = normalise_and_parse(client, model, pseudocode)
        results[car_id] = {
            "success": ast is not None,
            "meta": meta,
            "ast": ast,
        }
        if ast is not None:
            stats["fixed"] += 1
        else:
            stats["still_failing"] += 1

    stats["fix_rate"] = round(stats["fixed"] / max(stats["total"], 1) * 100, 1)
    return {"results": results, "stats": stats}
