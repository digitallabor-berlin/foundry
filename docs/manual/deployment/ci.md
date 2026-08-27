# CI: automated build & push

`.github/workflows/docker-publish.yml` builds and pushes
`containers.digitallabor.dev/foundry/foundry` on a GitHub-hosted
`ubuntu-latest` runner — genuinely amd64, not emulated, which is exactly why
this exists (see the segfault discussion above). It runs `cargo fmt --check` +
`cargo clippy --workspace --all-targets -- -D warnings` + `cargo nextest run
--workspace` first and only builds/pushes if those pass — mirroring the
workspace-wide gates this repo requires before any change is considered done
(see the root `AGENTS.md`).

| Trigger | Tags produced |
| --- | --- |
| push to `main` | `:latest`, `:sha-<short-sha>` |
| push tag `vX.Y.Z` | `:vX.Y.Z`, `:X.Y`, `:X`, `:sha-<short-sha>` |
| manual (`workflow_dispatch`) | whatever the current ref would produce |

It intentionally does **not** use `docker/setup-qemu-action` — adding it back
would reintroduce the segfault this workflow exists to avoid; if you ever need
multi-arch (`linux/amd64,linux/arm64`) images, that requires the
`tonistiigi/xx`-based cross-compilation rewrite discussed above, not QEMU.

**One-time repo setup** — two secrets under *Settings → Secrets and
variables → Actions*, matching the credentials already in
`~/dev/dl-infra-k8s/foundry/regcred.yaml` for `containers.digitallabor.dev`:

| Secret | Value |
| --- | --- |
| `REGISTRY_USERNAME` | the registry username (`capmin`) |
| `REGISTRY_PASSWORD` | the registry password |
