# lazaretto-mcp

[![Lazaretto on the x402 List](https://x402-list.com/badge/lazaretto.svg?data=uptime)](https://x402-list.com/services/lazaretto)
[![Lazaretto on Wellknown](https://wellknown.network/agents/lazaretto/badge.svg)](https://wellknown.network/agents/lazaretto)

Know what a package does before you install it.

## Quick start

No account and no key. In Claude Code:

```bash
claude mcp add --transport http lazaretto "https://lazaretto.dev/mcp?ref=npm"
```

Then, in a project with a lockfile, ask your agent for the free check:

> Use the lazaretto `check_lockfile` tool to check this project's dependencies.

In any other client, add `https://lazaretto.dev/mcp?ref=npm` as a remote MCP
server. If your client only runs local servers, make `npx -y lazaretto-mcp` the
command, which needs Node 20 or newer. [Set it up](#set-it-up) has the exact steps
for Cursor, Gemini CLI and Cline, and [lazaretto.dev/add](https://lazaretto.dev/add)
covers more clients.

`ref=npm` only tells us this page is where you found it. Leave it off and nothing
changes.

## What it is

An [MCP](https://modelcontextprotocol.io) server for Lazaretto: deterministic
pre-install verification for npm packages, AI agent skills and MCP tools. The
free lockfile check matches every exactly pinned dependency against OSV and
OpenSSF malicious-package advisories, with no account. A metered scan adds
behavioral analysis with file-and-line evidence.

This package is a thin front end for the [Lazaretto](https://lazaretto.ai)
API. It ships no detection logic and does nothing but make HTTPS requests, so
it is short enough to read end to end. Each request names this package in its
`User-Agent` header, so we can tell how much use comes through it.

Setting this up as an agent, with no other context? Read
[llms-install.md](llms-install.md) instead. It is the same information as a
straight-line procedure.

## Two ways to run it

| | Hosted (recommended) | stdio package |
| --- | --- | --- |
| Endpoint | `https://lazaretto.dev/mcp?ref=npm` | `npx -y lazaretto-mcp` |
| Install | nothing | Node 20 or newer |
| Key goes in | the `X-API-Key` header | the `LAZARETTO_API_KEY` env var |
| Get a free key in-session | yes, the `get_free_key` tool | no, `curl` the trial endpoint |
| Find a server for a job | yes, the `find_mcp_servers` tool | no |
| Reads your lockfile off disk | no, you pass the text | yes, from the working directory |
| Needs a client that speaks Streamable HTTP | yes | no |

Eight tools are on both. Their arguments match except for these:

| Tool | stdio package | Hosted |
| --- | --- | --- |
| `check_lockfile`, `scan_lockfile_deep` | also take `path`, a lockfile on disk | no `path` |
| `scan_artifact` | `target_type` | `type`, plus `name` for inline content |

The stdio package refuses an argument a tool does not take, and says what it does
take.

The hosted server adds two free tools:
`find_mcp_servers`, which finds a server for a job in the official MCP registry,
and `get_free_key`, which mints a free developer key in the session. Pick the hosted one
unless your client has no remote-server support, or you want `check_lockfile` to
read the lockfile off disk so a large tree never passes through the model
context.

## Set it up

### Claude Code

Hosted, one command:

```bash
claude mcp add --transport http lazaretto "https://lazaretto.dev/mcp?ref=npm"
```

With a key for the metered tools:

```bash
claude mcp add --transport http lazaretto "https://lazaretto.dev/mcp?ref=npm" \
  --header "X-API-Key: YOUR_KEY"
```

stdio instead:

```bash
claude mcp add lazaretto --env LAZARETTO_API_KEY=YOUR_KEY -- npx -y lazaretto-mcp
```

Drop `--env LAZARETTO_API_KEY=YOUR_KEY` if you only want the free tools.

To check it in for the whole team, put this in `.mcp.json` at the repo root
instead of running the command:

```json
{
  "mcpServers": {
    "lazaretto": {
      "type": "http",
      "url": "https://lazaretto.dev/mcp?ref=npm"
    }
  }
}
```

One catch with `.mcp.json`: a project-scoped server needs a person to approve it
once. Until they do, `claude mcp list` says `Pending approval (run claude to
approve)` and the tools are not there. The `claude mcp add` commands above take
effect immediately, with nothing to approve, so use those if you want it working
in this session.

Confirm with `claude mcp list`. The entry should say `Connected`.

### Cursor

One click, free tools: [Add to Cursor](https://cursor.com/install-mcp?name=lazaretto&config=eyJ1cmwiOiJodHRwczovL2xhemFyZXR0by5kZXYvbWNwP3JlZj1ucG0ifQ%3D%3D). To add a key, or to set it up by hand,
edit `~/.cursor/mcp.json` for every project, or `.cursor/mcp.json` for one:

```json
{
  "mcpServers": {
    "lazaretto": {
      "url": "https://lazaretto.dev/mcp?ref=npm",
      "headers": {
        "X-API-Key": "YOUR_KEY"
      }
    }
  }
}
```

Drop the `headers` block if you only want the free tools. For stdio, replace
`url` and `headers` with:

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

Cursor reloads the file on save. Settings, MCP should list `lazaretto` with its
tools.

### Gemini CLI

Install it as an extension. This adds the hosted server with its free tools and
a short GEMINI.md telling the agent when to check:

```sh
gemini extensions install https://github.com/jamesdfinance-dev/lazaretto-mcp
```

The metered tools need a key, which the extension does not send. For those, add
the server directly instead:

```sh
gemini mcp add -s user --transport http --header "X-API-Key: YOUR_KEY" lazaretto "https://lazaretto.dev/mcp?ref=npm"
```

Use the key itself, not `$LAZARETTO_API_KEY`: Gemini CLI redacts environment
variables whose names contain KEY or TOKEN.

Google moved individual accounts from Gemini CLI to Antigravity CLI on June 18,
2026. Gemini CLI still serves paid API keys and Code Assist Standard or Enterprise.
We have not tested Antigravity CLI. [lazaretto.dev/add](https://lazaretto.dev/add)
has its steps.

### Cline

Open the MCP Servers panel, then Configure MCP Servers, which opens
`cline_mcp_settings.json`. Add the block below, keeping `"type": "streamableHttp"`:
without it Cline falls back to the legacy SSE transport, which this server does
not offer.

```json
{
  "mcpServers": {
    "lazaretto": {
      "type": "streamableHttp",
      "url": "https://lazaretto.dev/mcp?ref=npm",
      "headers": { "X-API-Key": "YOUR_KEY" },
      "disabled": false,
      "autoApprove": ["check_lockfile", "known_bad_lookup", "find_attestation", "verify_attestation"]
    }
  }
}
```

`autoApprove` lists only free tools on purpose, so nothing that spends
credits runs without you seeing it. The hosted server has two more free tools,
`find_mcp_servers` and `get_free_key`. They are left out so that a search or a new
key is something you see happen. Drop the `headers` block if you only want the free tools. For stdio, swap `url` and `headers` for `command`, `args` and
`env` exactly as in the Cursor example above.

### Any other MCP client

Remote (Streamable HTTP):

```json
{
  "mcpServers": {
    "lazaretto": {
      "url": "https://lazaretto.dev/mcp?ref=npm",
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

Both key fields are optional. Without one, the free tools work (four on the
stdio package, six on the hosted server, which adds `get_free_key` and
`find_mcp_servers`) and the
four metered ones return a message telling you how to get credits.

## The first call to try

From a project that has a lockfile, ask your agent:

> Use the lazaretto `check_lockfile` tool to check this project's dependencies.

On the stdio server, call it with no arguments: it finds `package-lock.json`,
`npm-shrinkwrap.json`, `yarn.lock` or `pnpm-lock.yaml` in the working directory
by itself. The hosted server cannot read your disk, so pass the lockfile text as
`lockfile`. On either server, pass a list of `"name@version"` strings as
`packages` to ask about specific versions, or when a whole tree would not fit in
context. Give one or the other, never both.

A result with one known-malware version in the tree looks like this (the stdio
server adds `source`, naming the file it read; the hosted one has no `source`
because it never touched your disk):

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

An empty `malicious` list is a real all-clear only when `unverified` is also
empty and `truncated` is `false`. Anything under `unverified` was not checked
and must not be reported as clean.

`truncated: true` is the case with no list to read. A lockfile longer than the
per-request package limit is clipped, and the packages past the limit land in
neither `malicious` nor `unverified`: they were never looked at, and `checked`
counts only the ones that were. Check it once per workspace, or pass the rest of
the tree, before calling the dependencies clean.

`skipped` is an object, not a list: it counts entries with no published registry
identity and says why they have none.

No lockfile handy? `known_bad_lookup` needs nothing but a hash:

```
known_bad_lookup with sha256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

That is the hash of the empty file, so a miss is the expected answer. It proves
the connection works.

You can also check the service without an MCP client at all:

```bash
curl -s https://lazaretto.dev/check --data-binary @package-lock.json
```

We keep no copy of your lockfile.

## Free and metered

Free, no key, no account:

- `check_lockfile`
- `known_bad_lookup`
- `find_attestation`
- `verify_attestation`

Free, hosted server only:

- `find_mcp_servers`, which finds remote servers in the official MCP registry
  for a job ("postgres", "send slack messages"), each with its endpoint, tools,
  the command to add it, and our latest read (we re-read each server about every
  two weeks). Servers we flagged or could not reach are left out.
- `get_free_key`, which mints a developer key with a small daily allowance that
  refills each day. No payment, no account, no card. It is shown once, so store
  it. Throttled to one key per source per window.

Metered, needs credits on a key:

- `scan_artifact` (one credit per artifact)
- `scan_lockfile_deep` (one credit per package that returns a verdict)
- `scan_mcp_server` (one credit)
- `check_mcp_tools` (one credit)

One credit is consumed per verdict and nothing on an error. Three ways to get
credits:

1. Free developer key: call `get_free_key` on the hosted server, or
   `curl -sX POST https://lazaretto.dev/v1/trial` for the stdio package.
2. Buy a pack at https://lazaretto.dev/buy.
3. An agent holding a wallet can buy credits itself over x402 at
   `POST https://lazaretto.dev/v1/credits/topup`.

Without credits a metered tool changes nothing and spends nothing. It returns a
message saying how to get a key.

## How payment works, exactly

The stdio package pays one way only: prepaid credits on `LAZARETTO_API_KEY`. It
has no x402 client inside it. A paywalled result from this package therefore
carries no x402 payment challenge for your agent to answer, and there is no way
to make it pay per call. If you want per-call x402 payment, your own HTTP
client has to make it against `https://lazaretto.dev/v1/scan` directly, not
through this package.

The hosted endpoint is the same: the `X-API-Key` header spends prepaid credits.

## Tools

### `check_lockfile` (free)

Checks every exactly pinned dependency in your lockfile against published
malicious-package advisories. One call covers the whole tree. Only exact
versions can be answered: a range like `^5.0.0` has no definitive answer,
because a compromised release usually sits between clean ones. Entries with no
published registry identity (`file:`, `link:`, `workspace:`, git) are counted
under `skipped` rather than dropped.

Give `packages`, a list of `name@version` strings, to ask about specific versions
instead. A result with anything under `malicious` comes back marked as an error, so
an agent acts on it rather than summarising it.

An empty `malicious` list is an all-clear only when `unverified` is also empty
and `truncated` is `false`. A `truncated` result dropped everything past the
per-request package limit into neither list, so those packages are unchecked
rather than clean: split the tree and check the rest.

### `known_bad_lookup` (free)

Is a sha256 content hash a known-bad artifact? Exact-hash match against an
indicator store refreshed daily.

### `find_attestation` (free)

Has anyone already attested this artifact? Give a package identity like
`chalk@5.6.1`, an MCP server URL, or a sha256 content hash, and get the signed
verdict if one exists, with its age, whether it was made under an older rules
version, and `contradicted` if the subject is now known-bad. A miss means no
attestation is on record for this subject. It is not a verdict either way.

When nobody has attested an npm package identity, the answer falls back to a
free identity check against published advisories: `answer: "identity_check"`
with an `identity_check` object, and `found` still `false`, because an identity
check is unsigned, looks at the identity rather than the code, and absence from
the corpus is not a verdict. Both transports mark
`identity_check.listed_as_malware: true` as an error result, so a known-malware
version cannot be summarised as "nothing found".

### `verify_attestation` (free)

A scan verdict ships with a signed attestation (compact JWS). Hand this tool one
that another agent, a README, or a lockfile gave you: it confirms the signature
is Lazaretto's, returns the attested claims, and flags `contradicted` if a
once-`clear` subject is now known-bad, so a verdict can be used without
re-scanning or paying again. Still confirm the artifact you will run matches
`claims.sub`.

### `get_free_key` (free, hosted server only)

Mints a developer key for the metered tools without leaving the session. No
payment, no account, no card. The key holds a small daily allowance that refills
every day. Present it as the `X-API-Key` header on the connection, or hand it to
whoever configures the client. It is shown once and cannot be recovered, so store
it before doing anything else. Calling again shortly after is refused rather than
minting a second key. The stdio package has no such tool: use
`curl -sX POST https://lazaretto.dev/v1/trial` instead.

### `scan_artifact` (metered)

Fetches a target (npm or PyPI package, GitHub repo, ClawHub skill, raw URL, or
inline text) without running it and returns a deterministic verdict
(`malicious`, `flagged`, `clear`, `error`) with the file, line and evidence
behind each finding.

### `scan_lockfile_deep` (metered)

The behavioral counterpart to `check_lockfile`: reads the code of every exactly
pinned dependency, up to 25 per call, instead of matching names and versions
only. Trust `complete_coverage`. `false` means something was capped, errored or
was only partly read, so the run is not a clean bill of health for the tree.

Calling again with the same lockfile rescans, and bills again, the same first
packages. The result lists what it left in `not_scanned.packages`, as
`name@version` strings. To continue a run, pass those as `packages` instead of
the lockfile:

- Hosted server: pass the whole `not_scanned.packages` list back as `packages`.
  It scans the first 25 and lists the rest in `not_scanned.packages` again.
- stdio package: `packages` takes up to 25 per call, so work through
  `not_scanned.packages` 25 at a time. The tool adds `next_call` to the result,
  and `next_call.packages` holds the first 25 of that list.

### `check_mcp_tools` (metered)

For a server that runs over stdio, which is most of them, nothing can connect to
it from outside, so there is no endpoint to check. Your client already read its
tool list at startup though: paste that JSON and we analyze the same text with
the same rules, contacting no server at all.

### `scan_mcp_server` (metered)

Point it at an MCP endpoint before you connect to it. It asks the server to
introduce itself and list its tools, then analyzes the text that server hands an
agent: tool names, descriptions, parameter schemas, and its instructions. That
text is documentation a model obeys, so it is an instruction channel the server
controls. Catches tool poisoning (hidden directives to read `~/.ssh/id_rsa` or
an agent config file), parameters whose purpose is to carry secrets or your
conversation out, and standing orders about another server's tools. Evidence
names the exact tool. It calls only `initialize` and `tools/list`, never the
server's own tools.

## Reading a result

Reports are signals with evidence, not a warranty. `clear` means no known-bad
match and no rule fired. It is not a statement about risk.

## Environment variables (stdio only)

| Variable | Required | What it does |
| --- | --- | --- |
| `LAZARETTO_API_KEY` | no | A key holding prepaid credits, sent as `X-API-Key`. Only the metered tools use it. |
| `LAZARETTO_BASE_URL` | no | Overrides the API host. Default `https://lazaretto.dev`. |

## When it does not work

- **The client shows no tools.** For stdio, run `npx -y lazaretto-mcp` in a
  terminal. It should print a short note saying it is an MCP server, then wait.
  If npx cannot find it, check `node --version` is 20 or newer.
- **Every metered tool says it needs credits.** The key is missing or was not
  accepted. Check the env var name is exactly `LAZARETTO_API_KEY`, or the header
  is exactly `X-API-Key`.
- **`check_lockfile` says it could not read a lockfile.** It only reads
  `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml`,
  relative to the working directory. Pass `path` explicitly for a monorepo, for
  example `apps/web/pnpm-lock.yaml`.
- **A rate-limit message.** The free check allows a small number per minute per
  IP. Wait and call it again. Do not read the failure as an all-clear.

## Run it from a clone (optional)

```bash
git clone https://github.com/jamesdfinance-dev/lazaretto-mcp
cd lazaretto-mcp && npm ci
read -rs LAZARETTO_API_KEY && export LAZARETTO_API_KEY
node index.mjs
```

## License

MIT. The Lazaretto service and its detection engine are separate and proprietary.
