# Logging & Observability

Every HTTP request on both listeners produces one structured log record, and
every typed error produces exactly one — so an operator can follow both what
happened and why it failed.

## Choosing a level

Three sources can set the log level. They are resolved in this order, highest
priority first:

| Priority | Source | Example |
| --- | --- | --- |
| 1 | `RUST_LOG` environment variable | `RUST_LOG=info,foundry_verifier=debug` |
| 2 | `--log-level` CLI flag | `foundry --log-level debug serve --config config.yaml` |
| 3 | `logging.level` in the config file | see below |
| 4 | built-in default | `info` |

The same ladder applies to the output format (`--log-format` /
`logging.format`, no environment tier) and to payload logging
(`--log-sensitive` / `logging.sensitive_payloads`).

```bash
# Everything at info, but verbose verification internals
RUST_LOG=info,foundry_verifier=debug foundry serve --config config.yaml

# JSON output for a log shipper
foundry --log-format json serve --config config.yaml
```

> **A silent log usually means a typo, not a bug.** `RUST_LOG` accepts any
> target name, so a misspelled level such as `RUST_LOG=infoo` builds a valid
> filter that matches nothing — and the process then logs nothing at all, with
> no warning. Only a *syntactically* invalid directive is reported and downgraded
> to `info`.

## Configuration file

All three settings can live in `config.yaml`. The whole section is optional; a
config without it behaves exactly as before.

```yaml
logging:
  level: info                  # any EnvFilter directive
  format: human                # human | json
  sensitive_payloads: false    # DEV/TEST ONLY — see the warning below
```

## `sensitive_payloads` — development only

> **Do not enable this in production.** With `sensitive_payloads: true` (or
> `--log-sensitive`), `debug` and `trace` records may include raw JWEs,
> `vp_token` values, decrypted response payloads, disclosed claim values, and
> the presentation request as sent to the wallet — that is, holder personal
> data. The process prints a `WARN` on startup whenever the flag is on.
