# Design — MkDocs Manual for Foundry

**Date:** 2026-08-27
**Status:** Approved (design). Implementation plan pending.
**Scope:** Introduce an MkDocs documentation site at `docs/manual/`, migrate the
bulk of `README.md` into it, publish to GitHub Pages, and gate the result on a
strict build.

---

## 1. Problem

`README.md` is **1,431 lines** across 16 `##` sections. It is simultaneously the
repository's landing page, its operator manual, its protocol-extension
reference, its logging reference, and its contributor guide. Consequences:

- Content is nested up to **five heading levels** deep (`h2:16, h3:17, h4:10,
  h5:3`). The Admin Test Console alone is 178 lines at depth four.
- Ordering is accidental — Docker precedes "Running the Project".
- Seven of the sixteen top-level sections document OpenID4VCI feature flags as
  flat siblings with no organizing principle.
- There is no single place to see what `config.yaml` accepts; config snippets
  are scattered across eight sections.
- No mechanism validates that a documented cross-reference still resolves.

## 2. Decisions

Decisions taken during brainstorming, with the alternatives that were rejected.

| # | Decision | Rejected alternative |
| --- | --- | --- |
| D1 | Publish to **GitHub Pages** *and* run `mkdocs build --strict` as a CI gate on every push/PR | Local-only; CI-check-only without publishing |
| D2 | `docs_dir: docs` — the **whole `docs/` tree** is the site, with `docs/manual/` as one subtree | `docs_dir: docs/manual` (manual only), which would leave the conformance report unpublished |
| D3 | **Exclude** `docs/superpowers/**` and `docs/specs/**` from the built site | Publishing the vendored spec texts and internal process artifacts |
| D4 | README becomes a **~150-line landing page** retaining architecture, prerequisites, and quickstart | Pure ~40-line pointer; ~300-line "operator essentials" |
| D5 | Nav is **audience-first** (Getting Started / Deployment / Operating / Issuance / Verification / Development / Reference) | Mirroring README order; protocol-first grouping |
| D6 | Content moves **verbatim**; prose improvements are separate later commits | Migrate-and-improve in one pass |
| D7 | Artifact-based Pages deploy (`upload-pages-artifact` + `deploy-pages`) | `mkdocs gh-deploy` pushing a `gh-pages` branch |
| D8 | A **Rust test** enforces the absolute-URL rule for links into excluded trees | A CI-only grep step |

Repository facts that constrain the design: repo is **public**, Apache-2.0,
`github.com/digitallabor-berlin/foundry`, default branch `main`. Site URL will
be `https://digitallabor-berlin.github.io/foundry/`.

## 3. Verified Technical Facts

Verified against MkDocs source and changelogs on 2026-08-27, then **confirmed
empirically** by building this repository's actual `docs/` tree with the
proposed `exclude_docs` and `validation` settings. Versions in use locally and
pinned for CI: **mkdocs 1.6.1**, **mkdocs-material 9.7.7**
(`pymdown-extensions 11.0.2`, transitively).

The probe's output is the evidence behind §7.1's failure-mode table. Its
findings, verbatim:

- `../../AGENTS.md` produced `WARNING - ... the target '../AGENTS.md' is not
  found among documentation files`, and `mkdocs build --strict` **exited
  non-zero**. Hard failure confirmed.
- Six links into `specs/` and `superpowers/` produced
  `INFO - ... which is excluded from the built site`. They stayed at INFO even
  with every `validation.links` key raised to `warn`. **Unpromotable**,
  confirming that only a repository test can enforce this (D8).
- The bare directory link `../specs/` took a **different** code path:
  `unrecognized relative link '../specs/', it was left as is`. Unlike the six
  above, this one **is** promotable — `validation.links.unrecognized_links:
  warn` turned it into a WARNING. Added to the config accordingly.
- `docs/.venv` (117 MB, present during the probe) was **not** copied into
  `site/`; the built site was 2.8 MB. MkDocs's implicit `.*` exclusion survives
  an explicit `exclude_docs` override. The venv has since been relocated to the
  repository root, so this is no longer load-bearing — but it establishes that
  `exclude_docs` does not clobber the implicit defaults.

| Fact | Verdict |
| --- | --- |
| `exclude_docs` introduced in MkDocs 1.5; gitignore pattern semantics; multi-line YAML string | Confirmed |
| **A link pointing at an `exclude_docs`-excluded file does NOT fail `--strict`** | Confirmed — `structure/pages.py` caps it via `warning_level = min(logging.INFO, validation.links.not_found)`, emitting `"contains a link to 'X' which is excluded from the built site"` at INFO. `--strict` aborts only at ≥WARNING. **No config key promotes this.** |
| Anchor fragments are **not** validated at warning level by default (`validation.links.anchors` defaults to `info`) | Confirmed |
| `validation` accepts `warn` / `info` / `ignore`; `absolute_links` also accepts `relative_to_docs` (1.6+) | Confirmed |
| A link to a file **outside** `docs_dir` (e.g. `../../AGENTS.md`) *does* fail `--strict` as `links.not_found` | Confirmed |
| `not_in_nav` keeps a file built and only suppresses the omitted-files message; `exclude_docs` takes precedence over it | Confirmed |
| Theme feature strings `navigation.instant`, `navigation.sections`, `navigation.expand`, `toc.follow`, `search.suggest`, `content.code.copy` | Confirmed |
| Both `gh-deploy` and the artifact-pair are current; action majors `configure-pages@v6`, `upload-pages-artifact@v5`, `deploy-pages@v5` | Confirmed (choice is judgement, see D7) |
| No upstream-prescribed pinning practice for a Python-free repo | Uncertain — pinned `requirements-docs.txt` chosen as lowest ceremony |

**The second row is load-bearing.** It is why D8 exists: the tool that was
expected to enforce spec-citation integrity cannot, so a repository test does.

## 4. Page Tree

`docs_dir: docs`, so the paths below are site paths. Right-hand column gives the
source line range in `README.md` at commit `c974dfc`.

```text
docs/
  index.md                                  site landing        <- README 1-20
  manual/
    getting-started/
      installation.md                       prereqs + building  <- 21-49
      quickstart.md                         run + validate cfg  <- 173-194
    deployment/
      docker.md                             build + run image   <- 50-111, 143-168
      ci.md                                 automated build     <- 112-142
    operating/
      http-server.md                        serving + endpoints <- 195-224
      openapi.md                            OpenAPI / Swagger   <- 225-246
      admin-api.md                          offer + DPC example <- 247-334
      test-console.md                       admin console       <- 335-408, 464-512
      keys-and-certificates.md              cert CLI            <- 513-543
      logging.md                            levels + cfg + flag <- 1111-1158, 1231-1238
      following-a-request.md                request tracing     <- 1159-1230
    issuance/
      credential-types.md                   types + claims      <- 1045-1110
      wallet-attestation.md                 ABCA + PoP          <- 544-641
      android-keystore-attestation.md                           <- 642-696
      dpop.md                               DPoP + nonces       <- 697-787
      credential-encryption.md              req/resp JWE        <- 884-941
      encrypted-pre-auth-code.md                                <- 942-992
      by-reference-offers.md                                    <- 993-1044
      paso-transaction-data.md                                  <- 788-883
    verification/
      dc-api-origins.md                     expected_origins    <- 409-463
      request-diagnostics.md                as-sent to wallet   <- 1239-1278
    development/
      testing.md                            the gate            <- 1296-1343
      conformance-suite.md                  ignored gaps        <- 1344-1428
      end-to-end.md                         subprocess suite    <- 1279-1295
    reference/
      configuration.md                      NEW - key index
      log-fields.md                         NEW - extracted table
      specs.md                              NEW - spec index
  conformance/
    openid4vc-conformance.md                unchanged, in place
```

**29 pages total** — 27 under `docs/manual/`, plus `docs/index.md` and the
existing conformance report. Every README line from 7 to 1428 lands in exactly
one page.

**Lines 1429–1432 (`## License`) are the sole exception**: the licence notice
stays in the README only. It is landing-page content, three lines long, and its
link target (`LICENSE`) sits outside `docs_dir`.

### 4.1 Merges

Four merges exist to avoid stub pages:

- **Prerequisites (7 lines) folds into `installation.md`** — seven lines is not a page.
- **"Running the HTTP Server" (8 lines) folds into `http-server.md`** alongside Exposed Endpoints.
- **`sensitive_payloads` (8 lines) folds into `logging.md`.**
- **Docker's "Building the image" and "Running the image" rejoin as `docker.md`**, with "CI: automated build & push" split out to `ci.md` — it documents GitHub Actions, not Docker usage.

### 4.2 The three new pages

These **assemble existing material**; they do not introduce new claims about
behaviour. Each fixes a specific defect:

- **`reference/configuration.md`** — an index of `config.yaml` keys, each
  linking to the feature page that explains it. Today those snippets are spread
  across eight sections with no index.
- **`reference/log-fields.md`** — `AGENTS.md` §4.5 declares log field names
  "operator-facing API" and `instrumentation_hygiene.rs` asserts they stay
  documented. This gives that contract a stable URL instead of burying it in a
  162-line prose section.
- **`reference/specs.md`** — restates the §4.4 governing-documents table with
  absolute GitHub links, since `docs/specs/` is excluded from the build (D3).

### 4.3 An asymmetry left visible on purpose

`verification/` has **two** pages against `issuance/`'s **eight**. That reflects
the README accurately: the only verifier-side operator content is the DC API
origins discussion (currently buried inside the console section) and the
request diagnostics (buried inside Logging). This migration does not invent
verifier documentation. The lopsided nav makes the gap legible, which is the
intended outcome.

### 4.4 README duplication policy

D4 keeps architecture, prerequisites, and quickstart in the README, which means
they exist in two places. This is deliberate and bounded:

- **Duplicated (35 lines, all stable):** workspace architecture table (changes
  only when a crate is added), prerequisites, quickstart.
- **NOT duplicated:** the endpoint table. It is the drift-prone one — 22 lines
  that change whenever a route changes, which per `AGENTS.md` §6 already
  requires touching `openapi.json`. It lives only in
  `manual/operating/http-server.md`; the README links to it.

The manual is the **single source of truth**. README content is limited to what
is either trivially stable or required for the landing-page role.

## 5. Tooling and Configuration

### 5.1 `requirements-docs.txt` (repository root)

```text
mkdocs==1.6.1
mkdocs-material==9.7.7
```

Placed at the root, **not** inside `docs/` — with `docs_dir: docs`, anything in
that tree would be copied into `site/` as a static asset.

**Local environment (already provisioned).** A `uv`-managed virtualenv exists at
the repository root, `.venv/`, holding exactly these two pins. Activate before
any mkdocs command:

```bash
source .venv/bin/activate
```

`uv` writes a self-excluding `.gitignore` (`*`) inside the venv, so it is
invisible to git — `git ls-files --others --exclude-standard` reports zero
untracked files. Add `/.venv` to `.gitignore` regardless, so a plain
`python -m venv .venv` cannot later be committed.

> The venv originally lived at `docs/.venv`, i.e. **inside `docs_dir`**. The §3
> probe showed MkDocs excluded it anyway, but it has been relocated to the root.
> Do not create a virtualenv under `docs/`.

**Why a `requirements-docs.txt` rather than `pyproject.toml` + `uv.lock`:** a
`pyproject.toml` at the root of a Cargo workspace competes with `Cargo.toml` for
the reader's idea of "the" manifest, for two direct dependencies with no
first-party Python code. A plain pinned requirements file is installable by both
`pip install -r` and `uv pip install -r`, so it serves the local uv workflow and
GitHub Actions from one file. Revisit if the docs build ever grows plugins.

### 5.2 `mkdocs.yml` (repository root)

```yaml
site_name: Foundry
site_description: EUDI Wallet OpenID4VCI Issuer and OpenID4VP Verifier
site_url: https://digitallabor-berlin.github.io/foundry/
repo_url: https://github.com/digitallabor-berlin/foundry
repo_name: digitallabor-berlin/foundry
edit_uri: edit/main/docs/

docs_dir: docs
site_dir: site

exclude_docs: |
  /superpowers/
  /specs/

validation:
  links:
    not_found: warn
    anchors: warn              # default is info - raised deliberately
    absolute_links: warn       # catches accidental /rooted links
    unrecognized_links: warn   # default is info - catches bare dir links
  nav:
    omitted_files: warn        # a new page missing from nav fails CI
    not_found: warn

theme:
  name: material
  features:
    - navigation.instant
    - navigation.sections
    - navigation.expand
    - toc.follow
    - search.suggest
    - content.code.copy

markdown_extensions:
  - admonition
  - tables
  - toc: {permalink: true}
  - pymdownx.details
  - pymdownx.superfences
  - pymdownx.tabbed: {alternate_style: true}

nav:
  - Home: index.md
  - Getting Started:
      - Installation: manual/getting-started/installation.md
      - Quickstart: manual/getting-started/quickstart.md
  - Deployment:
      - Docker: manual/deployment/docker.md
      - CI Build & Push: manual/deployment/ci.md
  - Operating:
      - HTTP Server & Endpoints: manual/operating/http-server.md
      - OpenAPI & Swagger UI: manual/operating/openapi.md
      - Admin API: manual/operating/admin-api.md
      - Admin Test Console: manual/operating/test-console.md
      - Keys & Certificates: manual/operating/keys-and-certificates.md
      - Logging: manual/operating/logging.md
      - Following a Request: manual/operating/following-a-request.md
  - Issuance (OpenID4VCI):
      - Credential Types & Claims: manual/issuance/credential-types.md
      - Wallet Attestation & ABCA: manual/issuance/wallet-attestation.md
      - Android Keystore Attestation: manual/issuance/android-keystore-attestation.md
      - DPoP: manual/issuance/dpop.md
      - Request & Response Encryption: manual/issuance/credential-encryption.md
      - Encrypted Pre-Authorized Code: manual/issuance/encrypted-pre-auth-code.md
      - By-Reference Offers: manual/issuance/by-reference-offers.md
      - PaSO Transaction Data: manual/issuance/paso-transaction-data.md
  - Verification (OpenID4VP):
      - DC API Expected Origins: manual/verification/dc-api-origins.md
      - Request Diagnostics: manual/verification/request-diagnostics.md
  - Development:
      - Testing: manual/development/testing.md
      - Conformance Suite: manual/development/conformance-suite.md
      - End-to-End Suite: manual/development/end-to-end.md
  - Reference:
      - Configuration: manual/reference/configuration.md
      - Log Fields: manual/reference/log-fields.md
      - Specifications: manual/reference/specs.md
      - Conformance Report: conformance/openid4vc-conformance.md
```

Three settings do real work rather than decoration:

- **`anchors: warn`** — the migration's largest risk is that splitting one
  1,431-line page into 29 breaks fragment references. At the default `info`,
  `--strict` would sail straight past the breakage most likely to occur.
- **`nav.omitted_files: warn`** — makes "added a page, forgot the nav" a build
  failure. With 29 pages this will happen.
- **`unrecognized_links: warn`** — proven by the §3 probe to convert the bare
  `../specs/` directory link from a silent INFO into a build failure. This is
  one of the eight broken conformance links moved out of the "only a test can
  catch it" bucket at zero cost.
- **`edit_uri`** — every page gets an edit link to GitHub, which is how a public
  docs site stays maintained.

`/site` and `/.venv` are added to `.gitignore`. The artifact-based deploy means
there is no `gh-pages` branch to track.

### 5.3 `crates/foundry/tests/docs_hygiene.rs`

Walks `docs/index.md`, `docs/manual/**/*.md`, and `docs/conformance/*.md`; fails
on any relative link into `specs/` or `superpowers/` (at any `../` depth),
naming the absolute-URL form to use instead. Approximately 40 lines, no new
dependency.

Rationale: MkDocs cannot catch this (§3), the repository already enforces
documentation contracts this way (`instrumentation_hygiene.rs`,
`conformance_report.rs`), and unlike a CI-only grep it fails on the developer's
machine inside the §5.1 gate before a push.

## 6. CI and Deployment

New workflow `.github/workflows/docs.yml`, separate from `docker-publish.yml`
because the triggers differ: docs are validated on **pull requests**, where
broken links are cheap to fix; the image builds only on `main` and tags.

**Job `build`** — triggers: `push` to `main`, `pull_request`, `workflow_dispatch`.

```text
actions/checkout@v7                 (matches docker-publish.yml)
actions/setup-python@v6   cache: pip
pip install -r requirements-docs.txt
mkdocs build --strict
actions/upload-pages-artifact@v5    (only when ref == main)
  with: {path: site}                # NOT the action's `_site` default
```

`path: site` is mandatory and easy to miss — `upload-pages-artifact` defaults to
`_site`, while `mkdocs.yml` sets `site_dir: site`. Omitting it produces a green
build that deploys nothing.

`actions/configure-pages` is **deliberately not used.** Its purpose is to inject
a computed base URL, and `site_url` is set explicitly in `mkdocs.yml`; adding it
would create two competing sources for the same value.

**Job `deploy`** — `needs: build`, `if: github.ref == 'refs/heads/main'`.

```text
permissions: {contents: read, pages: write, id-token: write}
environment: github-pages
actions/deploy-pages@v5
```

D7's reasoning: no `gh-pages` branch in a repository whose history is otherwise
all source; `contents: read` instead of `contents: write`, so the docs job can
never write to the repository; and the artifact is built once then deployed,
rather than built-and-pushed in one step where a failure leaves the branch
half-updated.

**Deliberately not done:** adding the docs build to `docker-publish.yml`'s
`test` job. That job installs OpenSSL, resolves the Rust toolchain, and warms a
`rust-cache`; a Python docs build has no business sharing it, and coupling them
means a docs typo blocks an image release.

## 7. Link Migration

Three classes, each with a distinct failure mode.

### 7.1 Class 1 — the conformance document becomes a page

`docs/conformance/openid4vc-conformance.md` (829 lines) holds 8 relative links,
all of which break:

| Target | Count | Failure mode (empirically confirmed, §3) |
| --- | --- | --- |
| `../../AGENTS.md` | 1 | **Hard fail** — outside `docs_dir`; `links.not_found: warn`; `--strict` aborts |
| `../specs/` (bare directory) | 1 | **Hard fail once `unrecognized_links: warn` is set** — a different code path from the rows below, and promotable |
| `../specs/*.md` | 5 | **Silent rot** — excluded tree, INFO only, *unpromotable*. Caught by `docs_hygiene.rs` alone |
| `../superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md` | 1 | **Silent rot** — same |

All 8 become absolute
`https://github.com/digitallabor-berlin/foundry/blob/main/...` URLs, which are
correct both on GitHub and in the built site.

> `crates/foundry/tests/conformance_report.rs` is a mechanical consistency guard
> over this exact file (`const REPORT_REL: &str =
> "docs/conformance/openid4vc-conformance.md"`). The file must **not** move, and
> every link edit must keep that test green.

### 7.2 Class 2 — README intra-page anchors

All 9 currently resolve. After the split each `](#section)` becomes a manual
URL — mostly *relative* links between manual pages, which `--strict` does
validate, and with `anchors: warn` so does every fragment.

### 7.3 Class 3 — inbound references from outside `docs/`

Ten references name the README. A mechanical migration leaves these stale, and
**two are in Rust source**, which a markdown-only sweep would miss.

| Location | Current text | Repoint to |
| --- | --- | --- |
| `AGENTS.md:13` | "see `README.md` — this file does not restate it" | `docs/index.md` |
| `AGENTS.md:238` | field rename -> "update `README.md` too" | `reference/log-fields.md` |
| `AGENTS.md:243` | "Logging & Observability section of `README.md`" | `operating/logging.md` |
| `crates/foundry/AGENTS.md:14` | "Build/run/CLI usage is documented in `README.md`" | see resolution rule below |
| `crates/foundry-issuer/AGENTS.md:110` | "root `README.md`; enforced by..." | see resolution rule below |
| `crates/foundry-verifier/AGENTS.md:79` | `README.md` | see resolution rule below |
| `.github/workflows/docker-publish.yml:11` | "see `README.md` #Docker for upstream issue links" | `deployment/docker.md` |
| `crates/foundry/src/logging.rs:211` | "...in the README should be relaxed accordingly" | manual page (**Rust source**) |
| `crates/foundry/tests/instrumentation_hygiene.rs:124` | "update README.md and the spec too" | `reference/log-fields.md` (**Rust source**) |
| `crates/foundry/tests/e2e_full_flow.rs:113` | "mirrors how `README.md`..." | manual page (**Rust source**) |

**Resolution rule for the non-specific targets.** Three rows above name the
README without naming a section. The implementer must read the surrounding
sentence, determine which README section it was referring to, and repoint at the
manual page that §4 assigns that section to. Do not guess from the table alone —
the spec deliberately records "unresolved" rather than a plausible wrong target.

**Deliberately not touched:**

- `crates/foundry-mdoc/AGENTS.md:29,96` and
  `crates/foundry-mdoc/tests/fixtures/README.md` refer to a *different* README
  (test fixtures) — unrelated.
- `docs/superpowers/plans/*` cite README line numbers as historical record.
  Rewriting completed plans would falsify that record.

### 7.4 A new `AGENTS.md` rule, not just repointing

`AGENTS.md` §8 "Maintaining These Files" has no rule for the manual. Without
one, the next feature documents itself in the README and undoes this migration
by increments. Add:

> **Documented behaviour change** -> update the relevant `docs/manual/` page,
> and for a new page also `mkdocs.yml`'s `nav`.

And note that §4.5's log-field rule and §6's OpenAPI rule now point at manual
pages rather than README sections.

## 8. Execution

### 8.1 Governing constraint: move, do not rewrite

Prose moves **verbatim**. The only permitted edits during migration:

1. Heading levels shifted so each page starts at `#`.
2. Links rewritten per §7.
3. A one-line intro where a page's first heading would otherwise lack context.

Nothing else. No tightening, no reordering, no incidental improvements.

The reason is reviewability: a commit that relocates 1,400 lines *and* rewrites
them is unreviewable, because a reviewer cannot distinguish an intentional
clarification from a dropped clause. Kept verbatim, the diff is mechanically
checkable. Prose improvements are a **separate later commit** against a stable
structure.

This must be stated in **every subagent dispatch** — "improve the docs while
moving them" is exactly what a helpful implementer does unprompted.

### 8.2 Sequencing — copy first, delete last

| # | Step | Notes |
| --- | --- | --- |
| 1 | **Scaffold** — `mkdocs.yml`, `requirements-docs.txt`, `.github/workflows/docs.yml`, `.gitignore` += `/site` and `/.venv`, `docs/index.md`, valid empty nav | Establishes the gate before there is anything to break |
| 2 | **Migrate content, one nav group per commit** (7 commits) | README left **intact**; content duplicated in the interim. Each commit ends with `mkdocs build --strict` |
| 3 | **Conformance doc link rewrite** — the 8 links | `conformance_report.rs` kept green |
| 4 | **README truncation** to the ~150-line landing page | First destructive step; everything deleted already exists in the manual and has been strict-built |
| 5 | **Cross-reference repointing** — the 10 inbound refs incl. 2 in Rust source | |
| 6 | **`AGENTS.md` §8 rule + §4.5/§6 repointing** | The durability step |
| 7 | **`docs_hygiene.rs`** | Keeps excluded-tree links from rotting silently |

Approximately 11 commits on branch `docs/mkdocs-manual`.

### 8.3 Verification

- **Structural:** `source .venv/bin/activate && mkdocs build --strict` after
  every commit. The activation step is mandatory — mkdocs is not on the global
  `PATH`.
- **Workspace gate (`AGENTS.md` §5.1):** `cargo fmt` ->
  `cargo nextest run --workspace --no-fail-fast --status-level fail` ->
  `cargo clippy --workspace --all-targets -- -D warnings`. Not optional for a
  docs change: steps 3, 5, and 7 touch Rust files and a file guarded by
  `conformance_report.rs`.
- **E2E (§5.2):** `cargo nextest run -p foundry --test e2e_full_flow
  --run-ignored ignored-only`, once before the PR.
- **Completeness:** a **throwaway** migration-check script comparing README at
  the pre-migration commit against the manual — for each section body, assert
  its distinctive text appears in exactly one manual page. Run at step 4, then
  deleted. This *proves* nothing was dropped rather than asserting it.

### 8.4 Definition of done

1. `mkdocs build --strict` clean.
2. §5.1 gate green; §5.2 E2E green once.
3. Every README line 7-1428 traceable to exactly one manual page; 1429-1432
   (`## License`) deliberately retained in the README only.
4. No stale README reference outside `docs/superpowers/plans/`.
5. `mkdocs serve` — nav navigable, no orphan pages, human review.
6. Pages deploy succeeds.

### 8.5 Roles (`AGENTS.md` §7)

| Step | Agent | Why |
| --- | --- | --- |
| 2 (content commits) | `mechanical-implementer` | Transcription against a complete spec |
| 1, 3, 5, 6, 7 | `integration-implementer` | Spans config, Rust, and CI |
| Final branch review | `final-reviewer` | Per §7; also runs §5.2 |

## 9. Open Items for the Repository Owner

These cannot be done from the codebase:

1. **Settings -> Pages -> Source = "GitHub Actions"** — required once before the
   first deploy. The workflow cannot set this itself.
2. **Whether the docs build becomes a required status check** — a dangling link
   would then block a code PR. Consistent with the intent of the strict gate,
   but a workflow-friction call.

## 10. Explicit Non-Goals

- **No prose rewriting** during migration (§8.1).
- **No verifier documentation invented** to balance the nav (§4.3).
- **`docs/specs/` is not restructured or moved** — it stays where `AGENTS.md`
  §4.4 says it is, merely excluded from the built site.
- **No API-reference generation** from Rust doc comments. The existing
  `openapi.json` / `openapi-wallet.json` and Swagger UI already cover the HTTP
  surface; adding `cargo doc` integration is a separate project.
- **Completed superpowers plans are not rewritten** (§7.3).
