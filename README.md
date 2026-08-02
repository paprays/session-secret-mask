# auto-secret-mask

A Pi extension that masks API keys and secrets in your session — user input, tool calls, and tool output — so real secrets never reach the model or the stored session history.

## How it works

Two independent masking layers:

1. **Pattern recognition** — detects common secret prefixes (`sk-…`, `ghp_…`, `AKIA…`, Slack `xox…`, Google `ya29…`) and replaces them with `$API_KEY_N` placeholders.
2. **Strong matching** — loads real values from env files listed in `~/.pi/agent/secrets.json` and replaces any exact occurrence in input / tool output with `[REDACTED: $NAME]`.

Before a tool executes, `$NAME` is substituted back to the real value. The session history only ever stores the placeholder.

## Install

```bash
pi install git:github.com/paprays/session-secret-mask
```

## Configuration

Create `~/.pi/agent/secrets.json`:

```json
{
  "envFiles": ["~/.zshenv", "~/.env"]
}
```

Import every variable (system vars like `PATH`, `HOME`, etc. are auto-filtered):

```json
{
  "envFiles": {
    "~/.zshenv": ["GH_TOKEN"]
  }
}
```

Whitelist — import only the named variables.

Env files are parsed as `KEY=value` lines, supporting `export` prefixes, quotes, and `#` comments.

## License

MIT
