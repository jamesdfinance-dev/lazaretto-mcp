# lazaretto-mcp

[![Lazaretto on the x402 List](https://x402-list.com/badge/lazaretto.svg?data=uptime)](https://x402-list.com/services/lazaretto)
[![Lazaretto on Wellknown](https://wellknown.network/agents/lazaretto/badge.svg)](https://wellknown.network/agents/lazaretto)

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
- **`find_attestation`**: free, no key. Has anyone already attested this
  artifact? Give a package identity like `chalk@5.6.1`, an MCP server URL, or a
  sha256 content hash, and get the signed verdict if one exists, with its age,
  whether it was made under an older rules version, and `contradicted` if the
  subject is now known-bad. A miss means no attestation is on record for this
  subject. It is not a verdict either way.
- **`verify_attestation`**: free, no key. A scan verdict ships with a signed
  attestation (compact JWS). Hand this tool one that another agent, a README, or
  a lockfile gave you: it confirms the signature is Lazaretto's, returns the
  attested claims, and flags `contradicted` if a once-`clear` subject is now
  known-bad, so a verdict can be trusted without re-scanning or re-paying. Still
  confirm the artifact you will run matches `claims.sub`.
- **`scan_artifact`**: fetches a target (npm or PyPI package, GitHub repo,
  ClawHub skill, raw URL, or inline text) without running it and returns a
  deterministic verdict (`malicious`, `flagged`, `clear`, `error`) with
  evidence. A full scan needs prepaid credits: the `X-API-Key` header on the
  hosted server, or `LAZARETTO_API_KEY` for the stdio package. Buy them at
  https://lazaretto.dev/buy.
- **`scan_lockfile_deep`**: paid, one credit per package that returns a
  verdict. The behavioral counterpart to `check_lockfile`: reads the code of
  every exactly pinned dependency, up to 25 per call, instead of only matching
  names and versions. Trust `complete_coverage`: `false` means something was
  capped, errored or only partly read, so the run is not a clean bill of health
  for the tree. Calling again with the same lockfile rescans, and bills again,
  the same first packages. The result lists every package it left in
  `not_scanned.packages`, as `name@version` strings. To continue a run, pass
  those as `packages` instead of the lockfile:
  - Hosted server (`https://lazaretto.dev/mcp`): pass `not_scanned.packages`
    back as `packages`, the whole list. It scans the first 25 and lists the
    rest in `not_scanned.packages` again.
  - stdio package: `packages` takes up to 25 per call, so work through
    `not_scanned.packages` 25 at a time. The tool adds `next_call` to the
    result, and `next_call.packages` holds the first 25 of that list.
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
        "X-API-Key": "your-prepaid-key (optional; the free tools need no key)"
      }
    }
  }
}
```

`check_lockfile`, `known_bad_lookup`, `find_attestation` and
`verify_attestation` work with no key. `scan_artifact`, `scan_lockfile_deep`,
`scan_mcp_server` and `check_mcp_tools` need credits: buy a pack by card at
https://lazaretto.dev/buy (an agent with a wallet can also buy credits itself
over x402 at `POST https://lazaretto.dev/v1/credits/topup`).

## Self-host the stdio server (optional)

If you would rather run it locally over stdio instead of the hosted URL, the
npm package is `lazaretto-mcp`:

```json
{
  "mcpServers": {
    "lazaretto": {
      "command": "npx",
      "args": ["-y", "lazaretto-mcp"],
      "env": {
        "LAZARETTO_API_KEY": "your-prepaid-key (optional; the free tools need no key)"
      }
    }
  }
}
```

Or from a clone:

```bash
git clone https://github.com/jamesdfinance-dev/lazaretto-mcp
cd lazaretto-mcp && npm ci
LAZARETTO_API_KEY=your-key node index.mjs
```

The stdio package pays only with prepaid credits on `LAZARETTO_API_KEY`. It
has no x402 client of its own, so a paywall result carries no x402 payment
challenge: per-call x402 payment must be made by the agent's own HTTP client
against `https://lazaretto.dev/v1/scan`, not through this package.
`LAZARETTO_BASE_URL` overrides the API host (default `https://lazaretto.dev`).

## License

MIT. The Lazaretto service and its detection engine are separate and proprietary.
