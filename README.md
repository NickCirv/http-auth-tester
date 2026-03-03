# http-auth-tester

Test HTTP authentication endpoints from the command line. Supports Basic, Bearer, API key (header), API key (query param), and Digest auth. Zero external dependencies — built-in Node.js modules only.

```
hat bearer https://api.example.com/me --token mytoken
hat all    https://api.example.com/me
```

## Install

**npx (no install required):**
```bash
npx http-auth-tester bearer https://api.example.com/me --token mytoken
```

**Global install:**
```bash
npm install -g http-auth-tester
hat --help
```

**Clone and run locally:**
```bash
git clone https://github.com/NickCirv/http-auth-tester.git
cd http-auth-tester
node index.js --help
```

## Requirements

- Node.js >= 18
- Zero npm dependencies

## Usage

```
http-auth-tester <command> <url> [options]
hat <command> <url> [options]
```

### Commands

| Command | Description |
|---------|-------------|
| `basic <url>` | Test HTTP Basic auth |
| `bearer <url>` | Test Bearer token auth |
| `apikey <url>` | Test API key in request header |
| `query <url>` | Test API key in query string |
| `digest <url>` | Test HTTP Digest auth |
| `all <url>` | Try all methods, report which succeed |

### Credentials

Env vars take priority over CLI flags. Never hardcode secrets.

| Env var | Flag | Auth type |
|---------|------|-----------|
| `BASIC_USER` | `--user <u>` | Basic, Digest |
| `BASIC_PASS` | `--pass <p>` | Basic, Digest |
| `TOKEN` | `--token <t>` | Bearer |
| `API_KEY` | `--key <k>` | API key (header/query) |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--header <name>` | `X-API-Key` | Header name for apikey command |
| `--param <name>` | `api_key` | Query param name for query command |
| `--expect <code>` | `200` | Expected HTTP status code |
| `--method <verb>` | `GET` | HTTP method |
| `--body <json>` | — | Request body for POST/PUT |
| `--timeout <ms>` | `10000` | Request timeout |
| `--verbose` | — | Show request/response headers (redacted) |
| `--json` | — | Output as JSON |
| `--version` | — | Print version |
| `--help` | — | Show help |

## Examples

### Basic auth

```bash
# Credentials via env (recommended)
BASIC_USER=admin BASIC_PASS=secret hat basic https://api.example.com/me

# Credentials via flags
hat basic https://api.example.com/me --user admin --pass secret

# Expect 401 (test that unauthenticated is rejected)
hat basic https://api.example.com/me --expect 401

# With verbose header output
BASIC_USER=admin BASIC_PASS=secret hat basic https://api.example.com/me --verbose
```

### Bearer token

```bash
TOKEN=eyJhbGciOiJIUzI1NiJ9... hat bearer https://api.example.com/me

hat bearer https://api.example.com/me --token mytoken --json
```

### API key in header

```bash
API_KEY=my-secret-key hat apikey https://api.example.com/me

# Custom header name
hat apikey https://api.example.com/me --header Authorization --key "ApiKey mykey"
```

### API key in query string

```bash
API_KEY=my-secret-key hat query https://api.example.com/search

# Custom param name
hat query https://api.example.com/search --param access_token --key mykey
```

### Digest auth

```bash
BASIC_USER=admin BASIC_PASS=secret hat digest https://api.example.com/me
```

### Test all methods

```bash
TOKEN=mytoken BASIC_USER=user BASIC_PASS=pass API_KEY=key hat all https://api.example.com/me

# JSON output
TOKEN=mytoken hat all https://api.example.com/me --json
```

### POST with body

```bash
TOKEN=mytoken hat bearer https://api.example.com/users \
  --method POST \
  --body '{"name":"Alice","email":"alice@example.com"}' \
  --expect 201
```

### Timeout and scripting

```bash
# Fail fast
hat bearer https://api.example.com/me --timeout 3000

# Use exit code in scripts
if hat bearer https://api.example.com/health --expect 200; then
  echo "Auth OK"
else
  echo "Auth failed"
fi
```

## Output

Color-coded results in terminal:

- **Green ✔** — status matches `--expect`
- **Red ✘** — status mismatch or 4xx/5xx
- **Yellow ~** — unexpected redirect or other

Auth values are always shown as `[REDACTED]` in verbose output. Raw credential values are never logged.

### JSON mode

```bash
hat bearer https://httpbin.org/bearer --json
```

```json
{
  "command": "bearer",
  "url": "https://httpbin.org/bearer",
  "status": 200,
  "expected": 200,
  "ok": true,
  "body": "..."
}
```

`all` command JSON:

```json
{
  "none":   { "status": 401, "ok": false },
  "basic":  { "status": 401, "ok": false },
  "bearer": { "status": 200, "ok": true },
  "apikey": { "status": 401, "ok": false },
  "query":  { "status": 401, "ok": false },
  "digest": { "status": 401, "ok": false }
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Response status matches `--expect` |
| `1` | Status mismatch, network error, or missing credentials |

## Security

- Zero external dependencies — no supply chain risk
- Credentials never logged or echoed, always `[REDACTED]` in output
- `Authorization`, `X-API-Key`, `Cookie` headers redacted in verbose mode
- Env var credentials take priority over CLI flags to avoid secrets in shell history
- Uses Node.js built-in `https`/`http` — no third-party HTTP clients

## License

MIT
