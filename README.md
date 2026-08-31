# lazaretto-mcp

[![Lazaretto on the x402 List](https://x402-list.com/badge/lazaretto.svg?data=uptime)](https://x402-list.com/services/lazaretto)

Know what a package does before you install it.

An [MCP](https://modelcontextprotocol.io) server for Lazaretto: deterministic
pre-install verification for npm packages, AI agent skills and MCP tools. The
free lockfile check matches every exactly pinned dependency against OSV and
OpenSSF malicious-package advisories with no account. A paid scan adds
behavioral analysis with file-and-line evidence.

This package is a thin front end for the [Lazaretto](https://lazaretto.dev)
API. It ships no detection logic and does nothing but make HTTPS requests, so
it is easy to audit.

## Try it in one line, nothing installed

Check every exactly pinned dependency in your project against published
malicious-package advisories. No account, no key, no install:

```bash
curl -s https://lazaretto.dev/check --data-binary @package-lock.json
```

Works with `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` or
`pnpm-lock.yaml`. We keep no copy of your lockfile.

## Tools

### `check_lockfile` (free, no API key)

Checks every exactly-pinned dependency in your lockfile against published
malicious-package advisories. Reads `package-lock.json`, `yarn.lock`, or
`pnpm-lock.yaml` from the working directory, so the agent never has to paste a
lockfile through its context. One call covers the whole tree.

An empty `malicious` list is an all-clear only when `unverified` is also empty.


- **`known_bad_lookup`**: free, no key. Is a sha256 content hash a known-bad
  artifact? Exact-hash match against an indicator store refreshed daily.
- **`verify_attestation`**: free, no key. A scan verdict ships with a signed
  attestation (compact JWS). Hand this tool one that another agent, a README, or
  a lockfile gave you: it confirms the signature is Lazaretto's, returns the
  attested claims, and flags `contradicted` if a once-`clear` subject is now
  known-bad, so a verdict can be trusted without re-scanning or re-paying. Still
  confirm the artifact you will run matches `claims.sub`.
- **`scan_artifact`**: fetches a target (npm or PyPI package, GitHub repo,
  ClawHub skill, raw URL, or inline text) without running it and returns a
  deterministic verdict (`malicious`, `flagged`, `clear`, `error`) with
  evidence. A full scan needs prepaid credits (set an `X-API-Key` header). Buy
  them at https://lazaretto.dev/#pricing.
- **`check_mcp_tools`**: paid. For a server that runs over stdio, which is most
  of them, nothing can connect to it from outside, so there is no endpoint to
  check. Your client already read its tool list at startup though: paste that
  JSON and we analyze the same text with the same rules, contacting no server at
  all.
- **`scan_mcp_server`**: paid. Point it at an MCP endpoint before you connect to
  it. It asks the server to introduce itself and list its tools, then analyzes
  the text that server hands an agent: tool names, descriptions, parameter
  schemas, and its instructions. That text is documentation a model obeys, so it
  is an instruction channel the server controls. Catches tool poisoning (hidden
  directives to read `~/.ssh/id_rsa` or an agent config file), parameters whose
  purpose is to carry secrets or your conversation out, and standing orders
  about another server's tools. Evidence names the exact tool. It calls only
  `initialize` and `tools/list`, never the server's own tools.

Reports are signals with evidence, not a warranty. `clear` means no known-bad
match and no rule fired. It is not a statement about risk.

## Use it (hosted, zero install)

The server is hosted at `https://lazaretto.dev/mcp`. Add it to any MCP client
that supports remote (Streamable HTTP) servers. Nothing to install, no local
process.

```json
{
  "mcpServers": {
    "lazaretto": {
      "url": "https://lazaretto.dev/mcp",
      "headers": {
        "X-API-Key": "your-prepaid-key (optional; known_bad_lookup is free)"
      }
    }
  }
}
```

`check_lockfile`, `known_bad_lookup`, and `verify_attestation` work with no key.
`scan_artifact`, `scan_mcp_server` and `check_mcp_tools` need credits: buy a bundle at https://lazaretto.dev/#pricing (an
agent can also do this itself over x402 at
`POST https://lazaretto.dev/v1/credits/topup`).

## Self-host the stdio server (optional)

If you would rather run it locally over stdio instead of the hosted URL:

```bash
git clone https://github.com/jamesdfinance-dev/lazaretto-mcp
cd lazaretto-mcp && npm install
LAZARETTO_API_KEY=your-key node index.mjs
```

`LAZARETTO_BASE_URL` overrides the API host (default `https://lazaretto.dev`).

## License

MIT. The Lazaretto service and its detection engine are separate and proprietary.
