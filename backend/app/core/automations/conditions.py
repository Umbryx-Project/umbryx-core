from __future__ import annotations

import re
from typing import Any

_TEMPLATE_RE = re.compile(r"\{\{([^}]+)\}\}")


def resolve_value(template: Any, context: dict) -> Any:
    """Resolve {{variable}} placeholders in a value.

    Supports nested dotted access: {{event.data.severity}}
    If the entire string is a single template, returns the raw resolved
    value (preserving type). Otherwise, substitutes within the string.
    """
    if isinstance(template, str):
        full = _TEMPLATE_RE.fullmatch(template.strip())
        if full:
            return _resolve_path(full.group(1).strip(), context)

        def _sub(m: re.Match) -> str:
            v = _resolve_path(m.group(1).strip(), context)
            return str(v) if v is not None else ""

        return _TEMPLATE_RE.sub(_sub, template)

    if isinstance(template, dict):
        return {k: resolve_value(v, context) for k, v in template.items()}

    if isinstance(template, list):
        return [resolve_value(v, context) for v in template]

    return template


def _resolve_path(path: str, context: dict) -> Any:
    parts = path.split(".")
    current: Any = context
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if current is None:
            return None
    return current


_VALID_OPS = {
    "eq",
    "ne",
    "gt",
    "lt",
    "gte",
    "lte",
    "contains",
    "not_contains",
    "in",
    "not_in",
    "starts_with",
    "ends_with",
    "matches",
    "is_empty",
    "is_not_empty",
    "is_null",
    "is_not_null",
}


def _apply_operator(left: Any, op: str, right: Any) -> bool:
    if op == "is_null":
        return left is None
    if op == "is_not_null":
        return left is not None
    if op == "is_empty":
        return left is None or left == "" or left == [] or left == {}
    if op == "is_not_empty":
        return not (left is None or left == "" or left == [] or left == {})

    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "gt":
        try:
            return float(left) > float(right)
        except (TypeError, ValueError):
            return False
    if op == "lt":
        try:
            return float(left) < float(right)
        except (TypeError, ValueError):
            return False
    if op == "gte":
        try:
            return float(left) >= float(right)
        except (TypeError, ValueError):
            return False
    if op == "lte":
        try:
            return float(left) <= float(right)
        except (TypeError, ValueError):
            return False
    if op == "contains":
        if isinstance(left, str):
            return str(right) in left
        if isinstance(left, (list, dict)):
            return right in left
        return False
    if op == "not_contains":
        if isinstance(left, str):
            return str(right) not in left
        if isinstance(left, (list, dict)):
            return right not in left
        return True
    if op == "in":
        if isinstance(right, (list, tuple, set)):
            return left in right
        if isinstance(right, str):
            return str(left) in right
        return False
    if op == "not_in":
        if isinstance(right, (list, tuple, set)):
            return left not in right
        if isinstance(right, str):
            return str(left) not in right
        return True
    if op == "starts_with":
        return isinstance(left, str) and left.startswith(str(right))
    if op == "ends_with":
        return isinstance(left, str) and left.endswith(str(right))
    if op == "matches":
        try:
            return bool(re.search(str(right), str(left)))
        except re.error:
            return False
    return False


def _eval_rule(rule: dict, context: dict) -> bool:
    if "op" in rule:
        group = rule
        return _eval_group(group, context)

    field = rule.get("field", "")
    op = rule.get("operator", "eq")
    value = rule.get("value")

    if op not in _VALID_OPS:
        return False

    left = resolve_value(field, context)
    right = resolve_value(value, context) if isinstance(value, str) else value

    return _apply_operator(left, op, right)


def _eval_group(group: dict, context: dict) -> bool:
    op = group.get("op", "AND").upper()
    rules = group.get("rules", [])

    if not rules:
        return True

    if op == "AND":
        return all(_eval_rule(r, context) for r in rules)
    if op == "OR":
        return any(_eval_rule(r, context) for r in rules)
    if op == "NOT":
        return not any(_eval_rule(r, context) for r in rules)

    return False


def evaluate_conditions(conditions: list[dict] | None, context: dict) -> bool:
    """Evaluate a list of condition groups (implicit AND between groups).

    Each group is {"op": "AND|OR|NOT", "rules": [...]}.
    Each rule is {"field": "...", "operator": "...", "value": ...}.
    """
    if not conditions:
        return True

    return all(_eval_group(g, context) for g in conditions)
