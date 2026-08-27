# DC API Expected Origins

Over the Digital Credentials API transport, OpenID4VP requires a wallet to bind
an SD-JWT VC's KB-JWT `aud` to the **browsing-context Origin** of the page that
called `navigator.credentials.get()`, prefixed with `origin:` — *not* to the
verifier's `x509_hash` Client Identifier, which is what every other transport
uses. The browser attests that Origin to the wallet; the server cannot derive it
(RFC 6454), so it has to be told:

```yaml
verifier:
  dc_api_expected_origins: ["https://verifier-site.example"]
```

List one entry per site expected to invoke this verifier over the DC API. A
single trailing slash is normalised away, so `https://x.example` and
`https://x.example/` both match.

> **Set this whenever you drive a DC API presentation from the admin console.**
> `/console` is served **only by the admin listener**, so the Origin the wallet
> is handed is the *admin* origin — `http://127.0.0.1:9000` by default, or
> whatever hostname a reverse proxy exposes that listener on. Left unset,
> foundry falls back to a single origin derived from
> `server.wallet_facing.public_base_url`, which is a **different** Origin
> whenever the two listeners differ in host *or* port — which is the default
> (`:9000` vs `:8443`) and stays true behind a proxy that gives them separate
> hostnames. The fallback exists only for the single-origin case where the DC
> API caller and the wallet-facing listener genuinely share an Origin.

The symptom when this is wrong is an otherwise well-formed presentation failing
at HTTP 400 with:

```text
verification failed: holder key binding verification failed: KB-JWT audience
mismatch: presented "origin:https://console-host.example", expected one of
["origin:https://verifier-site.example"]
```

The message names both sides of the comparison, so the fix is usually readable
straight off the log line: the *presented* value is the Origin the browser
attested to the wallet, and the *expected* list is this config key (or, when it
is unset, the `public_base_url`-derived fallback). Add the presented Origin to
`dc_api_expected_origins` if it is one you intend to serve.

> **`dc_api_expected_origins` is mandatory for `transport: "dc_api_signed"`.**
> A signed request carries `expected_origins` (OpenID4VP 1.0 L2442), which the
> wallet compares against the invoking Origin to detect replay. foundry rejects
> a signed DC API request with HTTP 400 when the list is empty rather than
> guessing an Origin from `public_base_url` — signing an assertion about which
> Origins are legitimate is not something a default can do safely. The unsigned
> `dc_api` transport is unaffected and still falls back.

To confirm the wallet's side independently, CMWallet logs it as
`GetCredentialActivity: origin <value>`, readable via `adb logcat`.
