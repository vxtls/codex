# Configuration

For basic configuration instructions, see [this documentation](https://developers.openai.com/codex/config-basic).

For advanced configuration instructions, see [this documentation](https://developers.openai.com/codex/config-advanced).

For a full configuration reference, see [this documentation](https://developers.openai.com/codex/config-reference).

## Strict DoH Networking

Codex requires strict DoH configuration for Codex-owned outbound networking
(HTTP/HTTPS/SSE/WS/WSS and explicit DNS checks).

Codex uses these strict DoH servers by default:

```toml
[networking]
doh_servers = [
  "https://1.1.1.1/dns-query",
  "https://1.0.0.1/dns-query",
  "https://8.8.8.8/resolve",
]
```

Add a `[networking]` section in `~/.codex/config.toml` to override the defaults
or enable request logging:

```toml
[networking]
doh_servers = [
  "https://1.1.1.1/dns-query",
  "https://1.0.0.1/dns-query",
  "https://8.8.8.8/resolve",
]
request_log_path = "/absolute/path/to/network-requests.jsonl"
```

Rules:

- If `[networking]` is omitted, Codex falls back to the built-in DoH servers above.
- If `networking.doh_servers` is set, it must be non-empty.
- DoH server URLs must be valid `http`/`https` URLs.
- DoH server hosts must be IP literals (for strict no-system-DNS bootstrap).
- If configuration is invalid, config loading fails at startup.
- There is no fallback to system DNS.
- `request_log_path` is optional. When set, Codex appends JSONL metadata
  records with: `ts`, `transport`, `method`, `url`, `status`,
  `duration_ms`, `error`.

## Lifecycle hooks

Admins can set top-level `allow_managed_hooks_only = true` in
`requirements.toml` to ignore user, project, and session hook configs while
still allowing managed hooks from requirements and managed config layers. This
setting is only supported in `requirements.toml`; putting it in `config.toml`
does not enable managed-hooks-only mode.
