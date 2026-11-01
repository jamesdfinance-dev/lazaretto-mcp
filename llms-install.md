# Installing lazaretto-mcp (for a coding agent)

You are setting up the Lazaretto MCP server for a developer. Everything you need
is in this file. Follow it top to bottom and do not ask the developer anything
you can decide yourself.

Lazaretto checks npm packages, AI agent skills and MCP tools before they are
installed or connected. Four tools are free with no account on the stdio
package, six on the hosted server, which adds `get_free_key` and
`find_mcp_servers`. Four more are
metered against a key.

## Step 1: pick a transport

**Default to the hosted server at `https://lazaretto.dev/mcp`.** Nothing to
install, and it has two extra free tools: `find_mcp_servers`, which finds a
server for a job in the official MCP registry, and `get_free_key`, which mints
a free key without leaving the session.

Choose the stdio package instead if either is true:

- the client cannot connect to remote (Streamable HTTP) MCP servers, or
- the developer wants `check_lockfile` to read the lockfile off disk, so a large
  dependency tree never passes through the model context.

The stdio package needs Node 20 or newer. Check with `node --version` before
choosing it.

## Step 2: write the config

Use the block for the client you are in. `YOUR_KEY` is optional everywhere: with
no key the free tools work (four on stdio, five on the hosted server) and the
metered ones return a message instead of doing anything. If the developer has not given you a key, leave the key field out
entirely rather than writing a placeholder into their config.

### Claude Code

Hosted:

```bash
claude mcp add --transport http lazaretto https://lazaretto.dev/mcp
```

Hosted with a key:

```bash
claude mcp add --transport http lazaretto https://lazaretto.dev/mcp \
  --header "X-API-Key: YOUR_KEY"
```

stdio:

```bash
claude mcp add lazaretto --env LAZARETTO_API_KEY=YOUR_KEY -- npx -y lazaretto-mcp
```

To check the config into the repo instead, write `.mcp.json` at the repo root:

```json
{
  "mcpServers": {
    "lazaretto": {
      "type": "http",
      "url": "https://lazaretto.dev/mcp"
    }
  }
}
```

Prefer `claude mcp add` unless the developer asked for a config checked into the
repo. A project-scoped `.mcp.json` server has to be approved once by a person
before it loads: until then `claude mcp list` says `Pending approval (run claude
to approve)` and no Lazaretto tools exist. Do not keep retrying. Tell the
developer to run `claude` and approve it, or switch to `claude mcp add`.

Verify with `claude mcp list`. The `lazaretto` row should say `Connected`.

### Cursor

Write `~/.cursor/mcp.json` for every project, or `.cursor/mcp.json` for this one.
Merge into the existing `mcpServers` object, do not overwrite the file.

Hosted:

```json
{
  "mcpServers": {
    "lazaretto": {
      "url": "https://lazaretto.dev/mcp",
      "headers": { "X-API-Key": "YOUR_KEY" }
    }
  }
}
```

stdio:

```json
{
  "mcpServers": {
    "lazaretto": {
      "command": "npx",
      "args": ["-y", "lazaretto-mcp"],
      "env": { "LAZARETTO_API_KEY": "YOUR_KEY" }
    }
  }
}
```

Cursor reloads on save. Tell the developer to look under Settings, MCP for
`lazaretto` and its tool list.

### Cline

Write `cline_mcp_settings.json` (MCP Servers panel, then Configure MCP Servers).
Merge into the existing `mcpServers` object. Keep `"type": "streamableHttp"`:
without it Cline uses the legacy SSE transport, which this server does not
offer, and the connection fails.

```json
{
  "mcpServers": {
    "lazaretto": {
      "type": "streamableHttp",
      "url": "https://lazaretto.dev/mcp",
      "headers": { "X-API-Key": "YOUR_KEY" },
      "disabled": false,
      "autoApprove": ["check_lockfile", "known_bad_lookup", "find_attestation", "verify_attestation"]
    }
  }
}
```

Auto-approve only those four. They are the free ones. Never auto-approve a
metered tool: it spends the developer's credits without them seeing the call.

For stdio, replace `url` and `headers` with `command`, `args` and `env` exactly
as in the Cursor stdio block, keeping `disabled` and `autoApprove`.

### Any other MCP client

Hosted:

```json
{
  "mcpServers": {
    "lazaretto": {
      "url": "https://lazaretto.dev/mcp",
      "headers": { "X-API-Key": "YOUR_KEY" }
    }
  }
}
```

stdio:

```json
{
  "mcpServers": {
    "lazaretto": {
      "command": "npx",
      "args": ["-y", "lazaretto-mcp"],
      "env": { "LAZARETTO_API_KEY": "YOUR_KEY" }
    }
  }
}
```

## Step 3: the environment variable

The stdio package reads two, both optional:

| Variable | What it does |
| --- | --- |
| `LAZARETTO_API_KEY` | A key holding credits, sent as `X-API-Key`. Only the metered tools use it. |
| `LAZARETTO_BASE_URL` | Overrides the API host. Default `https://lazaretto.dev`. Leave it unset. |

The hosted server has no environment variables. Its key travels in the
`X-API-Key` header instead.

Never write a real key into a file that is tracked by git. If the client
supports it, reference an environment variable the developer sets in their shell.

## Step 4: make the first call

Restart or reload the client so it picks up the config, then call:

```
check_lockfile
```

with no arguments if you are on stdio, or with the project lockfile text as
`lockfile` if you are on the hosted server. A result with one known-malware
version in the tree looks like this. `source` is present only on stdio, naming
the file it read:

```json
{
  "source": "package-lock.json",
  "checked": 2,
  "format": "package-lock",
  "malicious": [
    { "name": "debug", "version": "4.4.2", "ids": ["MAL-2025-46974"], "advisory_url": "https://osv.dev/vulnerability/MAL-2025-46974" }
  ],
  "unverified": [],
  "truncated": false,
  "skipped": { "count": 0, "reason": "..." },
  "note": "1 pinned package version is listed as malware. Remove or upgrade before installing.",
  "disclaimer": "..."
}
```

`skipped` is an object, not a list.

If there is no lockfile in the project, call `known_bad_lookup` with
`sha256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
instead. That is the hash of the empty file, so a miss is the expected answer and
it still proves the connection works.

Report the result to the developer. Say which transport you configured, which
file you wrote, and whether a key is in place.

## What costs money

Free, no key, no account:

- `check_lockfile`
- `known_bad_lookup`
- `find_attestation`
- `verify_attestation`
- `get_free_key` (hosted server only)
- `find_mcp_servers` (hosted server only)

Metered, one credit per verdict and nothing on an error:

- `scan_artifact`
- `scan_lockfile_deep` (one credit per package, up to 25 per call)
- `scan_mcp_server`
- `check_mcp_tools`

If the developer wants the metered tools and has no key, do this rather than
sending them to a payment page:

- Hosted: call `get_free_key` and store what it returns. It is shown once.
- stdio: run `curl -sX POST https://lazaretto.dev/v1/trial` and use the key it
  returns.

Either gives a small daily allowance that refills each day. Credit packs are at
https://lazaretto.dev/buy, and an agent with a wallet can buy credits itself over
x402 at `POST https://lazaretto.dev/v1/credits/topup`.

## Payment, stated exactly

The stdio package pays one way only: prepaid credits on `LAZARETTO_API_KEY`. It
carries no x402 client. A paywalled result from it has no x402 payment challenge
in it, so there is no way to make it pay per call. Per-call x402 payment has to
come from your own HTTP client against `https://lazaretto.dev/v1/scan`, not
through this package. The hosted endpoint works the same way: `X-API-Key` spends
prepaid credits.

Do not tell the developer this package can pay as it goes. It cannot.

## Reading a result

- `malicious` empty is an all-clear only when `unverified` is also empty AND
  `truncated` is `false`. Anything in `unverified` was not checked. Never report
  it as clean.
- `truncated: true` means the lockfile ran past the per-request package limit and
  everything past it went into NEITHER list. Those packages were never looked at,
  and `checked` counts only the ones that were. Check the rest (once per
  workspace, or by passing the remaining tree) before you tell the developer the
  dependencies are clean.
- On `find_attestation`, `found: false` with `answer: "identity_check"` means
  nobody has attested the subject and you are being handed a free identity check
  against published advisories instead: unsigned, about the identity rather than
  the code, and not a verdict. `identity_check.listed_as_malware: true` is
  returned as an error result on both transports and means the version is
  published as malware. `null` there means the corpus could not be consulted:
  unchecked, never clear.
- On `scan_lockfile_deep`, `complete_coverage: false` means something was capped,
  errored or was only partly read, so the run is not a clean bill of health for
  the tree. The packages it skipped are listed in `not_scanned.packages`, as
  `name@version` strings, and passing those back as `packages` continues the run.
- A rate-limit message or a transport failure is not an all-clear. Wait and call
  again.
- `clear` means no known-bad match and no rule fired. It is not a statement about
  risk. These are signals with evidence, not a warranty.

## If it does not work

| Symptom | Fix |
| --- | --- |
| No Lazaretto tools in the client | Reload or restart the client. Confirm the JSON parses and `lazaretto` is inside `mcpServers`. |
| stdio server will not start | Run `npx -y lazaretto-mcp` in a terminal. It should start and wait on stdin with no output. If not, check `node --version` is 20 or newer. |
| Every metered tool says it needs credits | The key is missing or was not accepted. The env var is exactly `LAZARETTO_API_KEY`, the header exactly `X-API-Key`. |
| `check_lockfile` cannot read a lockfile | It reads only `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml`, relative to the working directory. Pass `path` for a monorepo, for example `apps/web/pnpm-lock.yaml`. |
| Rate limited | The free check allows a small number per minute per IP. Wait and call again. |

Source and issues: https://github.com/jamesdfinance-dev/lazaretto-mcp
