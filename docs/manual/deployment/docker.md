# Docker

A multi-stage `Dockerfile` at the repo root builds and packages the `foundry` server binary. The builder stage uses `rust:1.97-slim-bookworm` (matching `rust-toolchain.toml`) with `pkg-config`/`libssl-dev` installed, since `josekit` depends on a dynamically linked `openssl-sys`. The runtime stage is `debian:bookworm-slim` with `ca-certificates`/`libssl3` and runs as a non-root `foundry` user.

## Building the image

```bash
docker build -t foundry:latest .
```

(Podman works as a drop-in replacement: `podman build -t foundry:latest .`)

**Building for a different target architecture (e.g. deploying to an amd64
cluster from an Apple Silicon / arm64 machine):** a plain `docker build` always
targets the *host's* architecture and gives no warning when that doesn't match
where the image will run — the mismatch only surfaces at container start as an
`exec format error` (or an equivalent silent failure, depending on the runtime).
The naive fix is to force the target platform with `buildx`:

```bash
docker buildx build --platform linux/amd64 -t foundry:latest --load .
```

**This reliably segfaults `rustc` on Apple Silicon.** `--platform linux/amd64`
does not cross-compile — it runs the *entire* amd64 toolchain, including
`rustc`/LLVM, under QEMU's user-mode CPU emulation, and rustc crashes under
that emulation on M-series Macs (`rustc -vV` or even a bare `rustc` invocation
segfaults, signal 11, before any of your code is even touched). This is a
currently open upstream issue — see
[rust-lang/rust#147026](https://github.com/rust-lang/rust/issues/147026) and
[rust-lang/rustup#3902](https://github.com/rust-lang/rustup/issues/3902) — not
something wrong with this Dockerfile or your Docker setup, and there is no
reliable QEMU flag that fixes it.

Two real ways around it:

1. **Build on a native amd64 host** (a cloud VM, a GitHub Actions `ubuntu-latest`
   runner, etc.) instead of emulating locally. No Dockerfile or command changes
   needed — just run the same `docker build`/`docker buildx build --platform
   linux/amd64 --push .` on an amd64 machine, where it's a native build rather
   than an emulated one. `.github/workflows/docker-publish.yml` already does
   exactly this on every push/tag — see [CI](ci.md) below
   — so in practice you shouldn't need to build+push manually at all.
2. **True cross-compilation**, if you need to keep building on Apple Silicon.
   This means rustc runs *natively* (arm64) and targets amd64 without ever
   executing amd64 machine code, so QEMU emulation of the compiler itself is
   avoided entirely. The standard tool for this in a Dockerfile is
   [`tonistiigi/xx`](https://github.com/tonistiigi/xx) (its `xx-cargo` wrapper
   handles the target triple, C toolchain and `pkg-config` setup, which matters
   here since `josekit` needs `openssl-sys` to link dynamically against the
   *target* architecture's `libssl-dev`, not the host's). This is a real
   rewrite of the builder stage of this Dockerfile — it hasn't been done here
   yet; happy to do it on request, but it needs validating against an actual
   `docker buildx` environment before trusting it in CI.

Once you have a genuinely `amd64` image (built either way), verify it before
pushing:

```bash
docker inspect foundry:latest --format '{{.Architecture}}'   # must print: amd64
```

## Running the image

The image expects `config.yaml`, the key material, and trust anchors it references to be bind-mounted rather than baked in (they're config-driven via paths relative to the config file, and already gitignored). The default entrypoint runs `foundry`, with `CMD` set to `serve --config /app/config.yaml`:

```bash
docker run --rm \
  -v $PWD/config.yaml:/app/config.yaml \
  -v $PWD/keys:/app/keys \
  -v $PWD/trust:/app/trust \
  -v $PWD/foundry.db:/app/foundry.db \
  -p 8443:8443 -p 9000:9000 \
  foundry:latest
```

The wallet-facing (`8443`) and admin (`9000`) listeners are both plain HTTP inside the container — TLS is expected to be terminated externally (e.g. a reverse proxy), same as when running the binary directly.

Other CLI subcommands work the same way by overriding the default command, e.g. to run `quickstart` against a mounted output directory:

```bash
docker run --rm -v $PWD/dev:/app/dev foundry:latest quickstart --dir /app/dev --out-config /app/dev/config.yaml
```

*Note: the image runs as a fixed non-root user (uid 999). If a bind-mounted host directory isn't writable by that uid, pass `--user "$(id -u):$(id -g)"` to run as your own user instead.*

---
