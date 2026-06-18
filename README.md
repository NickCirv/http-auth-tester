<div align="center">

# http-auth-tester

**Test HTTP auth endpoints from the CLI — Basic, Bearer, API key, Digest, and all at once**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue?labelColor=0B0A09)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?labelColor=0B0A09)](package.json)
[![Node >=18](https://img.shields.io/badge/node-%3E%3D18-green?labelColor=0B0A09)](package.json)

</div>

## Install

```bash
npx github:NickCirv/http-auth-tester --help
```

## Usage

```bash
# Test bearer token auth
TOKEN=mytoken npx github:NickCirv/http-auth-tester bearer https://api.example.com/me

# Try every auth method and see which ones pass
TOKEN=t BASIC_USER=u BASIC_PASS=p API_KEY=k \
  npx github:NickCirv/http-auth-tester all https://api.example.com/me --json
```

| Flag | Description |
|------|-------------|
| `--token <t>` | Bearer token (or env `TOKEN`) |
| `--user / --pass` | Basic / Digest credentials (or env `BASIC_USER` / `BASIC_PASS`) |
| `--key <k>` | API key value (or env `API_KEY`) |
| `--header <name>` | Header name for `apikey` command (default: `X-API-Key`) |
| `--param <name>` | Query param name for `query` command (default: `api_key`) |
| `--expect <code>` | Expected HTTP status (default: `200`) |
| `--method <verb>` | HTTP method (default: `GET`) |
| `--body <json>` | Request body for POST/PUT |
| `--timeout <ms>` | Request timeout in ms (default: `10000`) |
| `--verbose` | Print request + response headers (auth values always redacted) |
| `--json` | Output results as JSON |

## What it does

Sends a real HTTP request using the specified auth method and reports whether the response status matches `--expect`. The `all` command tries every method in sequence and shows which ones succeed — useful for auditing an endpoint you don't control.

Auth credentials are always shown as `[REDACTED]` in verbose output; they are never logged or echoed. Env vars take priority over CLI flags to keep secrets out of shell history.

Exit code `0` = status matched, `1` = mismatch, network error, or missing credentials.

---
<sub>Zero dependencies · Node >=18 · MIT · by <a href="https://github.com/NickCirv">NickCirv</a></sub>
