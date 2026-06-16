# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Structure

Two separate Go modules coexist:

- **Root** (`go.mod`) — v1 legacy app, maintained only for critical bug fixes.
- **`v2/`** (`v2/go.mod`) — active rewrite, module `github.com/dhojayev/traderepublic-portfolio-downloader/v2`.

All new development happens in `v2/`. The root module will eventually be retired.

## Commands

### v2 (active)

```bash
# Run the downloader
go run ./v2/cmd/websocket-downloader/main.go [flags]

# Build
go build -o websocket-downloader ./v2/cmd/websocket-downloader

# Test
cd v2 && go test -v ./...

# Lint
cd v2 && golangci-lint run ./...

# Regenerate REST client from openapi-rest.yaml + mocks
cd v2 && make generate
```

### Root (v1)

```bash
go test -v ./...
golangci-lint run ./...
make generate     # regenerates REST client, mocks, and example data
make init         # re-runs Wire (dependency injection wiring)
make reset        # wipes .session, .refresh, responses/, documents/, transactions.csv
```

## websocket-downloader flags

| Flag | Default | Description |
|---|---|---|
| `--debug` | false | Debug logging |
| `--max-items=N` | 0 (all) | Limit transactions processed |
| `--timeout=N` | 60 | Timeout in seconds |
| `--export-csv` | false | Export parsed data to `debug/transactions.csv` |
| `--offline` | false | Use existing `debug/` files, skip network |
| `--auth-only` | false | Reset auth file and reauthenticate |
| `--init-auth` | false | Start login and exit (approve in the app, then run again) |
| `--last-3-months` | false | Filter to last 3 months |
| `--from-date=YYYY-MM-DD` | — | Filter from a specific date |

Env vars (also loadable via a `.env` file, loaded automatically):
- `TR_PHONE_NUMBER`, `TR_PIN` — credentials.
- `TR_WAF_TOKEN` — AWS WAF anti-bot token required on auth endpoints. If unset, the app auto-generates one with a headless browser (needs Chrome installed). Get one manually with `go run ./cmd/waf-token`.

## v2 Architecture

```
v2/
├── cmd/websocket-downloader/main.go   # Main entrypoint (active)
├── cmd/portfolio-downloader/          # Older v2 entrypoint (less active)
├── cmd/waf-token/                     # Prints a fresh AWS WAF token (headless browser)
├── internal/
│   ├── const.go                       # API URLs, file paths, .auth filename, TR headers (app version, device info)
│   ├── console/                       # Interactive prompts: phone, PIN; cross-platform password read
│   ├── waf/                           # chromedp headless-browser AWS WAF token generator
│   └── traderepublic/api/
│       ├── client.go                  # REST client: Login (v2), PollLoginStatus, RefreshSession; injects TR + WAF headers
│       ├── auth/                      # FileCredentialsService (./.auth), Token, ExtractTokenFromCookies
│       ├── restclient/openapi_gen.go  # oapi-codegen output (login path hand-patched to /api/v2)
│       └── websocketclient/           # gorilla/websocket client; SetSessionToken for live refresh
└── openapi-rest.yaml                  # Trade Republic REST API spec (still encodes the old v1 login paths)
```

Requires Google Chrome installed for WAF token auto-generation (`internal/waf` drives it via chromedp).

### WebSocket protocol

The Trade Republic WebSocket uses a custom text protocol:
- Connect: `connect 31 {"locale":"de",...}`
- Subscribe: `sub <id> {"type":"timelineTransactions",...}`
- Response: `<id> A <json>` (data), `<id> C` (continue/more pages), `<id> E` (error)
- Timeline transactions paginate via a cursor in `cursors.after`; use `SubscribeToTimelineTransactionsWithCursor` for subsequent pages.

### Auth flow (app-approval, app version 15.x)

TR web login moved to `/api/v2` and is **approved in the mobile app** (push), not via SMS OTP.
All auth endpoints require an `X-aws-waf-token` header (+ `aws-waf-token` cookie) and the
`X-TR-Platform` / `X-TR-App-Version` / `X-TR-Device-Info` headers (see `api.applyCommonHeaders`).

1. Check `./.auth` for a cached session token; reuse if present.
2. Ensure a WAF token: use `TR_WAF_TOKEN` or generate one via `internal/waf` (headless Chrome).
3. `POST /api/v2/auth/web/login` (phone + PIN) → `processId`. `TOO_MANY_REQUESTS` is retried with backoff.
4. Poll `GET /api/v2/auth/web/login/processes/{processId}` until `status == "CONFIRMED"` (user taps approve in the app).
5. Extract `tr_session` / `tr_refresh` from the response cookies → store to `./.auth`.

Session tokens expire in ~5 min. A background refresher (`startSessionRefresher`) calls
`GET /api/v1/auth/web/session` with the `tr_refresh` cookie every `SessionRefreshInterval` (120 s)
and pushes the new token into the WebSocket client via `SetSessionToken`, so large portfolios
(runs > 5 min) keep authenticating instead of dropping the tail.

Note: `RestAPIBaseURI` must keep its trailing slash — oapi-codegen resolves operation paths
relatively, and without it RFC 3986 resolution drops the `/v1` segment.

### Debug output

Raw and formatted JSON are written to:
- `./debug/transactions/` — paginated transaction lists + individual transaction files
- `./debug/details/` — per-transaction detail responses (keyed by UUID)

`--offline` mode reads from these directories without any network calls, useful for iterating on CSV parsing logic.

### Code generation

- REST client: `oapi-codegen` from `openapi-rest.yaml` → `v2/internal/traderepublic/api/restclient/openapi_gen.go`
- Mocks: `go.uber.org/mock/mockgen` via `//go:generate` directives → `*_mock.go` files
- DI wiring (v1 only): `google/wire`
