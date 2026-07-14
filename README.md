# lazaretto-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an agent **verify a
skill, tool, or package before it installs it**. It is a thin client for the
[Lazaretto](https://lazaretto.dev) API — it ships no detection logic and does
nothing but make two HTTPS requests, so it is easy to audit.

## Tools

- **`known_bad_lookup`** — free, no key. Is a sha256 content hash a known-bad
  artifact? (Exact-hash match against an indicator store refreshed daily.)
- **`scan_artifact`** — fetches a target (npm package, GitHub repo, ClawHub
  skill, raw URL, or inline text) without running it and returns a deterministic
  verdict (`malicious` / `flagged` / `clear` / `error`) with evidence. A full
  scan is paid: set `LAZARETTO_API_KEY` (prepaid credits) or pay via x402.

Reports are signals with evidence, not a warranty. `clear` means no known-bad
match and no rule fired — not a statement about risk.

## Install

```bash
npx lazaretto-mcp
```

## Configure (Claude Desktop / Cursor / any MCP client)

```json
{
  "mcpServers": {
    "lazaretto": {
      "command": "npx",
      "args": ["-y", "lazaretto-mcp"],
      "env": {
        "LAZARETTO_API_KEY": "lz_...    (optional — buy credits at https://lazaretto.dev/#pricing)"
      }
    }
  }
}
```

`LAZARETTO_BASE_URL` overrides the API host (default `https://lazaretto.dev`).

## License

MIT. The Lazaretto service and its detection engine are separate and proprietary.
