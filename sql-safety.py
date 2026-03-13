"""
PreToolUse hook: Block dangerous SQL operations before they execute.

Intercepts Bash commands and MCP database tool calls, matching against
configurable patterns for destructive SQL operations (DROP TABLE, TRUNCATE,
DELETE/UPDATE without WHERE, etc.). Blocks with a clear explanation and
asks the user to confirm if the operation is intentional.

Usage:
    Hook type: PreToolUse
    Matcher: Bash (and optionally your MCP database tool names)

Configuration:
    Place a config.json next to this script to customize patterns,
    trigger keywords, safe overrides, and MCP tool matching.
"""

import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

DEFAULT_CONFIG = {
    "trigger_keywords": ["mysql", "psql", "sqlite3", "mongosh", ".sql"],
    "mcp_tool_patterns": ["mysql", "sql", "database", "db"],
    "dangerous_patterns": [
        {"pattern": r"\bDROP\s+TABLE\b", "label": "DROP TABLE"},
        {"pattern": r"\bDROP\s+DATABASE\b", "label": "DROP DATABASE"},
        {"pattern": r"\bTRUNCATE\b", "label": "TRUNCATE"},
        {"pattern": r"\bDELETE\s+FROM\s+\S+\s*;", "label": "DELETE without WHERE clause"},
        {"pattern": r"\bDELETE\s+FROM\s+\S+\s*$", "label": "DELETE without WHERE clause"},
        {
            "pattern": r"\bUPDATE\s+\S+\s+SET\s+(?!.*\bWHERE\b).*[;$]",
            "label": "UPDATE without WHERE clause",
        },
        {
            "pattern": r"\bALTER\s+TABLE\s+\S+\s+DROP\s+COLUMN\b",
            "label": "ALTER TABLE DROP COLUMN",
        },
    ],
    "safe_overrides": [
        r"DROP\s+TABLE\s+IF\s+EXISTS.*CREATE\s+TABLE",
        r"DROP\s+TEMPORARY\s+TABLE",
    ],
}


def load_config():
    """Load configuration from config.json, falling back to defaults."""
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            # Merge: user keys override defaults, missing keys use defaults
            merged = dict(DEFAULT_CONFIG)
            merged.update(user_config)
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    return dict(DEFAULT_CONFIG)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def is_database_bash_command(command, trigger_keywords):
    """Check if a bash command involves a database CLI or SQL file."""
    cmd_lower = command.lower()
    return any(keyword.lower() in cmd_lower for keyword in trigger_keywords)


def is_mcp_database_tool(tool_name, mcp_patterns):
    """Check if an MCP tool name matches database-related patterns."""
    name_lower = tool_name.lower()
    return any(pat.lower() in name_lower for pat in mcp_patterns)


def matches_safe_override(text, safe_overrides):
    """Return True if the text matches any safe override pattern."""
    for pattern in safe_overrides:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            return True
    return False


def find_dangerous_pattern(text, dangerous_patterns):
    """Return the first matching dangerous pattern label, or None."""
    for entry in dangerous_patterns:
        pattern = entry.get("pattern", "")
        label = entry.get("label", "Unknown dangerous operation")
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            return label
    return None


def extract_sql_text(tool_name, tool_input):
    """Extract the SQL-relevant text from the tool input.

    For Bash tools, this is the command string.
    For MCP tools, this checks common parameter names for SQL content.
    """
    if tool_name == "Bash":
        return tool_input.get("command", "")

    # MCP database tools -- check common parameter names for SQL content
    sql_param_names = ["query", "sql", "statement", "command", "queries", "input"]
    for param_name in sql_param_names:
        value = tool_input.get(param_name, "")
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, list):
            return " ; ".join(str(v) for v in value)

    # Fallback: serialize all string values and check them
    text_parts = []
    for key, value in tool_input.items():
        if isinstance(value, str):
            text_parts.append(value)
    return " ".join(text_parts)


# ---------------------------------------------------------------------------
# Main hook logic
# ---------------------------------------------------------------------------


def main():
    # Parse hook input from stdin
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # Malformed input -- don't block, just exit
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    config = load_config()

    trigger_keywords = config.get("trigger_keywords", [])
    mcp_patterns = config.get("mcp_tool_patterns", [])
    dangerous_patterns = config.get("dangerous_patterns", [])
    safe_overrides = config.get("safe_overrides", [])

    # Determine if this tool call is database-related
    is_bash = tool_name == "Bash"
    is_mcp_db = is_mcp_database_tool(tool_name, mcp_patterns)

    if is_bash:
        command = tool_input.get("command", "")
        if not is_database_bash_command(command, trigger_keywords):
            # Not a database command -- allow
            sys.exit(0)

    if not is_bash and not is_mcp_db:
        # Not a tool we care about -- allow
        sys.exit(0)

    # Extract the SQL text to analyze
    sql_text = extract_sql_text(tool_name, tool_input)
    if not sql_text:
        sys.exit(0)

    # Check safe overrides first (e.g., DROP IF EXISTS + CREATE)
    if matches_safe_override(sql_text, safe_overrides):
        sys.exit(0)

    # Check for dangerous patterns
    label = find_dangerous_pattern(sql_text, dangerous_patterns)
    if label:
        preview = sql_text[:200]
        result = {
            "decision": "block",
            "reason": (
                f"SQL SAFETY: Blocked dangerous operation: {label}\n"
                f"Command: {preview}\n\n"
                f"If this is intentional, ask the user to confirm."
            ),
        }
        json.dump(result, sys.stdout)
        sys.exit(0)

    # No dangerous patterns found -- allow
    sys.exit(0)


if __name__ == "__main__":
    main()
