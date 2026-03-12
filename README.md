# SQL Safety Guard for Claude Code

**Block destructive database operations before they execute.**

A [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) for Claude Code that intercepts bash commands and MCP tool calls, catching dangerous SQL operations like `DROP TABLE`, `TRUNCATE`, and `DELETE` without `WHERE` before they reach your database. Fully configurable. Zero dependencies.

## The Problem

Claude Code can execute arbitrary bash commands, including database CLI tools. A single misguided `DROP TABLE` or `DELETE FROM users;` and your data is gone. There is no undo.

## The Solution

This hook inspects every `Bash` tool call (and optionally MCP database tool calls) for destructive SQL patterns. When it finds one, it **blocks execution** with a clear explanation and asks the user to confirm. It never blocks silently -- you always see exactly what was caught and why.

## What It Blocks

| Pattern | Example |
|---------|---------|
| `DROP TABLE` | `DROP TABLE users;` |
| `DROP DATABASE` | `DROP DATABASE production;` |
| `TRUNCATE` | `TRUNCATE TABLE logs;` |
| `DELETE` without `WHERE` | `DELETE FROM users;` |
| `UPDATE` without `WHERE` | `UPDATE users SET role = 'admin';` |
| `ALTER TABLE ... DROP COLUMN` | `ALTER TABLE users DROP COLUMN email;` |

## What It Allows

These common safe patterns pass through without blocking:

- **Migration pattern**: `DROP TABLE IF EXISTS ... CREATE TABLE` (drop-and-recreate)
- **Temp tables**: `DROP TEMPORARY TABLE` (session-scoped, no data loss)
- **Filtered operations**: `DELETE FROM users WHERE id = 5;` (has a WHERE clause)
- **Normal queries**: `SELECT`, `INSERT`, `CREATE TABLE`, etc.

## Installation

### 1. Copy the files

```bash
# Clone or copy sql-safety.py and config.json to a permanent location
mkdir -p ~/.claude/hooks
cp sql-safety.py config.json ~/.claude/hooks/
```

### 2. Register the hook

Add to your `.claude/settings.json` (user-level) or `.claude/settings.json` in your project root (project-level):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python ~/.claude/hooks/sql-safety.py"
          }
        ]
      }
    ]
  }
}
```

To also guard MCP database tools, add additional matchers:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python ~/.claude/hooks/sql-safety.py"
          }
        ]
      },
      {
        "matcher": "mcp__mysql",
        "hooks": [
          {
            "type": "command",
            "command": "python ~/.claude/hooks/sql-safety.py"
          }
        ]
      }
    ]
  }
}
```

### 3. Verify it works

Ask Claude Code to run a destructive command:

```
> Run this: mysql -u root -e "DROP TABLE users;"
```

You should see the hook block the command with a clear explanation.

## Configuration

Edit `config.json` (placed next to `sql-safety.py`) to customize behavior:

### Trigger Keywords

Controls which bash commands are inspected. A command is only checked if it contains at least one of these keywords (case-insensitive):

```json
{
  "trigger_keywords": ["mysql", "psql", "sqlite3", "mongosh", ".sql"]
}
```

Add your database CLI tool if it is not listed (e.g., `"clickhouse-client"`, `"cqlsh"`, `"cockroach"`).

### Dangerous Patterns

Each entry has a regex `pattern` and a human-readable `label`:

```json
{
  "dangerous_patterns": [
    {
      "pattern": "\\bDROP\\s+TABLE\\b",
      "label": "DROP TABLE"
    }
  ]
}
```

#### Adding a custom pattern

To block `GRANT ALL PRIVILEGES`:

```json
{
  "pattern": "\\bGRANT\\s+ALL\\s+PRIVILEGES\\b",
  "label": "GRANT ALL PRIVILEGES"
}
```

Add it to the `dangerous_patterns` array in `config.json`.

### Safe Overrides

Patterns that bypass dangerous pattern detection. Checked first -- if any safe override matches, the command is allowed without checking dangerous patterns:

```json
{
  "safe_overrides": [
    "DROP\\s+TABLE\\s+IF\\s+EXISTS.*CREATE\\s+TABLE",
    "DROP\\s+TEMPORARY\\s+TABLE"
  ]
}
```

#### Adding a custom safe override

If your workflow uses `DROP SCHEMA IF EXISTS ... CREATE SCHEMA` as a migration pattern:

```json
"DROP\\s+SCHEMA\\s+IF\\s+EXISTS.*CREATE\\s+SCHEMA"
```

### MCP Tool Patterns

Controls which MCP tool names are treated as database tools. If the tool name contains any of these substrings (case-insensitive), its parameters are inspected for dangerous SQL:

```json
{
  "mcp_tool_patterns": ["mysql", "sql", "database", "db"]
}
```

## How It Works

```
Claude Code calls Bash("mysql -e 'DROP TABLE users;'")
         |
         v
  [PreToolUse hook fires]
         |
         v
  Is "mysql" or ".sql" in the command?  --NO-->  Allow
         |
        YES
         |
         v
  Does it match a safe override?  --YES-->  Allow
         |
        NO
         |
         v
  Does it match a dangerous pattern?  --NO-->  Allow
         |
        YES
         |
         v
  BLOCK with explanation
```

For MCP tools, the flow is similar but checks the tool name against `mcp_tool_patterns` instead of trigger keywords, and inspects common SQL parameter names (`query`, `sql`, `statement`, etc.).

## Handling False Positives

If the hook blocks a command you know is safe:

1. **Add a safe override** to `config.json` for the pattern
2. **Narrow the trigger keywords** if a non-database command is being caught
3. **Confirm when prompted** -- the block message tells the user to confirm if intentional

The hook is designed to be conservative: it is better to block once and ask than to let a destructive operation through.

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## Example Settings File

See `settings.json.example` for a ready-to-use Claude Code settings snippet.

## License

MIT License. See [LICENSE](LICENSE).

---

Built by [VoxCore84](https://github.com/VoxCore84)
