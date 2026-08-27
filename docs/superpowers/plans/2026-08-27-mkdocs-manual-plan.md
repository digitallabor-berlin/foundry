# MkDocs Manual Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the bulk of `README.md` (1,431 lines) into an MkDocs site under
`docs/manual/`, published to GitHub Pages, with a strict build that fails CI on
broken cross-references.

**Architecture:** `docs_dir` is the whole `docs/` tree; `docs/superpowers/` and
`docs/specs/` are excluded from the build. The manual is 27 pages under
`docs/manual/`, plus `docs/index.md` and the existing conformance report — 29
nav entries. Content moves **verbatim**; the README is reduced to a ~150-line
landing page. `mkdocs build --strict` runs on every push and PR; `main`
additionally deploys to Pages via the artifact actions.

**Tech Stack:** mkdocs 1.6.1, mkdocs-material 9.7.7 (pinned in
`requirements-docs.txt`, already installed in the repo-root `uv` venv). Rust
1.97.1 / cargo-nextest for the two Rust-touching tasks.

**Spec:** [`docs/superpowers/specs/2026-08-27-mkdocs-manual-design.md`](../specs/2026-08-27-mkdocs-manual-design.md)

---

## Global Constraints

These apply to **every** task. Read them before starting any task.

1. **Content moves VERBATIM.** The only permitted edits to migrated prose are:
   (a) heading levels decremented so each page starts at `#`, (b) the specific
   link rewrites this plan names, (c) nothing else. **No rewording, no
   tightening, no reordering, no "while I'm here" improvements.** If you think a
   sentence is wrong, leave it and say so in your report. Spec §8.1.
2. **The test runner is `cargo nextest run`, never `cargo test`.** Root
   `AGENTS.md` §5.
3. **The gate is the whole workspace, every time** — there is no cheaper tier
   and no affected-crate subset:

   ```bash
   cargo fmt
   cargo nextest run --workspace --no-fail-fast --status-level fail
   cargo clippy --workspace --all-targets -- -D warnings
   ```

   Run it before marking any task complete. Quote the nextest summary line as
   evidence. `AGENTS.md` §5.1 and §5.3.
4. **mkdocs requires venv activation.** It is not on the global `PATH`:

   ```bash
   source .venv/bin/activate
   ```

5. **`mkdocs build --strict` must pass at the end of every task.** With
   `nav.omitted_files: warn` set, a page that exists but is missing from
   `mkdocs.yml`'s `nav` is a build failure — so **every task that creates pages
   must add them to `nav` in the same commit.**
6. **The absolute-URL base** for links into excluded trees or outside
   `docs_dir`:

   ```text
   https://github.com/digitallabor-berlin/foundry/blob/main/
   ```

   Referred to below as `GH_BASE`. Write it out in full in the files; the
   abbreviation is for this plan only.
7. **`README.md` stays untouched until Task 9.** Every line range in this plan
   is against `README.md` as of commit `41fd1b4` (unchanged since). Do not edit
   or reflow it while extracting from it.
8. **Never use `.unwrap()` / `.expect()` / `panic!()` outside `#[cfg(test)]`
   code.** `AGENTS.md` §4.1. Relevant to Task 12.

### Why this plan cites line ranges instead of pasting content

This is a verbatim relocation of 1,400 lines. Re-typing them into the plan would
create a third copy that can drift from the README, and would introduce
transcription risk in exactly the material we are trying to move without
alteration. Instead each page gets an **exact extraction command** whose output
is byte-identical to the source, plus the **exact list of links to change in that
page**. That is more precise than a pasted copy, not less.

---

## File Structure

**Created:**

| Path | Responsibility |
| --- | --- |
| `mkdocs.yml` | Site config: `docs_dir`, exclusions, validation levels, theme, nav |
| `requirements-docs.txt` | Pinned mkdocs + material for CI and local installs |
| `.github/workflows/docs.yml` | Strict build on push/PR; Pages deploy on `main` |
| `docs/index.md` | Site landing page (overview + workspace architecture) |
| `docs/manual/getting-started/*.md` | 2 pages — installation, quickstart |
| `docs/manual/deployment/*.md` | 2 pages — docker, ci |
| `docs/manual/operating/*.md` | 7 pages — server, openapi, admin api, console, keys, logging, request tracing |
| `docs/manual/issuance/*.md` | 8 pages — OpenID4VCI feature documentation |
| `docs/manual/verification/*.md` | 2 pages — DC API origins, request diagnostics |
| `docs/manual/development/*.md` | 3 pages — testing, conformance suite, e2e |
| `docs/manual/reference/*.md` | 3 pages — configuration index, log fields, spec index |
| `crates/foundry/tests/docs_hygiene.rs` | Enforces absolute-URL rule that mkdocs cannot |

**Modified:**

| Path | Change |
| --- | --- |
| `README.md` | Truncated to ~150-line landing page (Task 9) |
| `.gitignore` | `+/site`, `+/.venv` (Task 1) |
| `docs/conformance/openid4vc-conformance.md` | 8 links → absolute URLs (Task 1) |
| `AGENTS.md` | 3 README refs repointed; new §8 rule (Tasks 10, 11) |
| `crates/foundry/AGENTS.md` | 1 README ref (Task 10) |
| `crates/foundry-issuer/AGENTS.md` | 1 README ref (Task 10) |
| `crates/foundry-verifier/AGENTS.md` | 1 README ref (Task 10) |
| `.github/workflows/docker-publish.yml` | 1 README ref in a comment (Task 10) |
| `crates/foundry/src/logging.rs` | 1 README ref in a comment (Task 10) |
| `crates/foundry/tests/instrumentation_hygiene.rs` | 1 README ref in assert message (Task 10) |
| `crates/foundry/tests/e2e_full_flow.rs` | 1 README ref in doc comment (Task 10) |

---

## Deviation from the spec's sequencing — read this

Spec §8.2 orders the conformance link rewrite as step 3, after content
migration. **This plan moves it into Task 1**, because the scaffold cannot be
strict-green without it:

`docs/conformance/openid4vc-conformance.md` already exists inside `docs_dir`.
With `nav.omitted_files: warn` it must appear in `nav` from the first commit, and
once it is a built page its `../../AGENTS.md` link is a hard `--strict` failure
(empirically confirmed — see spec §3). So "make a strict-green site out of what
already exists" is one indivisible unit of work. Everything else in §8.2 is
unchanged.

---

## The canonical extraction recipe

Every content task uses this. `SRC_START`/`SRC_END` are 1-based inclusive
`README.md` line numbers.

```bash
# 1. Extract the exact range, verbatim.
sed -n "${SRC_START},${SRC_END}p" README.md > "$TARGET"

# 2. Decrement every heading by one level: '## X' -> '# X', '### X' -> '## X'.
#    Verified safe: no heading of level 2+ exists inside any code fence in
#    README.md, so this cannot corrupt a fenced '# comment' line (single '#'
#    is not matched).
sed -i '' -E 's/^##/#/' "$TARGET"

# 3. Confirm the page now starts at a single '#'.
head -1 "$TARGET"

# 4. Audit every link the page contains, so none is missed.
grep -nE '\]\([^)]*\)' "$TARGET" || echo "(no links in this page)"
```

For a page assembled from **two** ranges, extract both and concatenate in the
order given, then run steps 2–4 once on the result.

**After every task:**

```bash
source .venv/bin/activate
mkdocs build --strict
```

---

## Task 1: Scaffold a strict-green site

**Files:**

- Create: `mkdocs.yml`
- Create: `requirements-docs.txt`
- Create: `.github/workflows/docs.yml`
- Create: `docs/index.md`
- Modify: `.gitignore`
- Modify: `docs/conformance/openid4vc-conformance.md` (8 links)

**Interfaces:**

- Produces: `mkdocs.yml` with a `nav:` containing exactly two entries (`Home`,
  `Conformance Report`). Tasks 2–8 each **append** their group to this `nav`.
- Produces: `GH_BASE` link convention, used by Tasks 4, 5, 7, 8, 10, 12.

- [ ] **Step 1: Create `requirements-docs.txt`**

```text
mkdocs==1.6.1
mkdocs-material==9.7.7
```

- [ ] **Step 2: Verify the local venv already satisfies those pins**

```bash
source .venv/bin/activate
python -c "
import importlib.metadata as m
for p in ('mkdocs','mkdocs-material'): print(f'{p}=={m.version(p)}')
"
```

Expected, exactly:

```text
mkdocs==1.6.1
mkdocs-material==9.7.7
```

If it differs, stop and report — do not silently re-pin.

- [ ] **Step 3: Append to `.gitignore`**

Add these two lines at the end of the existing file (do not reorder or remove
anything already there):

```text
/site
/.venv
```

- [ ] **Step 4: Create `mkdocs.yml`**

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
    anchors: warn
    absolute_links: warn
    unrecognized_links: warn
  nav:
    omitted_files: warn
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
  - toc:
      permalink: true
  - pymdownx.details
  - pymdownx.superfences
  - pymdownx.tabbed:
      alternate_style: true

nav:
  - Home: index.md
  - Reference:
      - Conformance Report: conformance/openid4vc-conformance.md
```

- [ ] **Step 5: Create `docs/index.md` from README lines 1–20**

```bash
sed -n '1,20p' README.md > docs/index.md
```

Do **not** decrement headings here — line 1 is already a single `#` (`# Foundry`).
Then decrement only the `## Workspace Architecture` heading:

```bash
sed -i '' -E 's/^## Workspace Architecture/## Workspace Architecture/' docs/index.md
```

That is a no-op by design: `docs/index.md` keeps `# Foundry` as its `h1` and
`## Workspace Architecture` as an `h2`. Verify:

```bash
grep -nE '^#{1,3} ' docs/index.md
```

Expected: `1:# Foundry` and one `## Workspace Architecture`.

- [ ] **Step 6: Append a nav signpost to `docs/index.md`**

This is new content (permitted — it is not migrated prose). Append:

```markdown
## Where to go next

- **[Getting Started](manual/getting-started/installation.md)** — prerequisites, building, and a running server.
- **[Deployment](manual/deployment/docker.md)** — Docker images and CI.
- **[Operating](manual/operating/http-server.md)** — endpoints, admin API, test console, keys, logging.
- **[Issuance (OpenID4VCI)](manual/issuance/credential-types.md)** — credential types and protocol extensions.
- **[Verification (OpenID4VP)](manual/verification/dc-api-origins.md)** — DC API origins and request diagnostics.
- **[Development](manual/development/testing.md)** — the test gate and conformance suite.
- **[Reference](manual/reference/configuration.md)** — configuration keys, log fields, specifications.
```

⚠️ Those targets do not exist yet, so `--strict` will fail on them until Task 8.
**Therefore: comment this block out in Task 1** by wrapping it in an HTML
comment, and uncomment it in Task 8 Step 5. Write it now so it is not forgotten:

```markdown
<!-- Uncommented in Task 8 once all target pages exist.
## Where to go next
... (the list above)
-->
```

- [ ] **Step 7: Rewrite the 8 links in the conformance report**

Find them first:

```bash
grep -nE '\]\((\.\./|\.\./\.\./)' docs/conformance/openid4vc-conformance.md
```

Expected: 8 matches. Rewrite each to an absolute URL. The mapping is exact:

| Current target | New target |
| --- | --- |
| `../../AGENTS.md` | `https://github.com/digitallabor-berlin/foundry/blob/main/AGENTS.md` |
| `../specs/` | `https://github.com/digitallabor-berlin/foundry/tree/main/docs/specs/` |
| `../specs/openid-4-verifiable-credential-issuance-1_0.md` | `https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/openid-4-verifiable-credential-issuance-1_0.md` |
| `../specs/openid-4-verifiable-presentations-1_0.md` | `https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/openid-4-verifiable-presentations-1_0.md` |
| `../specs/openid4vc-high-assurance-interoperability-profile-1_0.md` | `https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/openid4vc-high-assurance-interoperability-profile-1_0.md` |
| `../specs/iso-18013-5-device-auth.md` | `https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/iso-18013-5-device-auth.md` |
| `../specs/emvco-dpc-schema-framework.md` | `https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/emvco-dpc-schema-framework.md` |
| `../superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md` | `https://github.com/digitallabor-berlin/foundry/blob/main/docs/superpowers/specs/2026-08-13-emvco-dpc-display-metadata-design.md` |

Note the **`tree/main`** (not `blob/main`) for the bare directory link — a
directory URL with `blob` 404s on GitHub.

Change **only the link targets**. Leave all link text and all surrounding prose
exactly as it is.

- [ ] **Step 8: Verify the conformance guard test still passes**

```bash
cargo nextest run -p foundry --test conformance_report --no-fail-fast
```

Expected: all tests pass. This test mechanically parses that document; if it
fails, a link edit damaged structure it depends on. Fix before continuing.

- [ ] **Step 9: Create the docs workflow `.github/workflows/docs.yml`**

```yaml
name: Docs build & deploy

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch: {}

concurrency:
  group: docs-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  build:
    name: mkdocs build --strict
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-python@v6
        with:
          python-version: "3.x"
          cache: pip

      - name: Install docs dependencies
        run: pip install -r requirements-docs.txt

      # --strict turns every WARNING into a build failure. The validation
      # block in mkdocs.yml deliberately raises anchors and unrecognized_links
      # from their `info` defaults, so fragment references and bare directory
      # links fail here rather than rotting silently.
      - name: Build
        run: mkdocs build --strict

      # path: site is mandatory — this action defaults to `_site`, while
      # mkdocs.yml sets `site_dir: site`. Omitting it deploys nothing.
      - name: Upload Pages artifact
        if: github.ref == 'refs/heads/main'
        uses: actions/upload-pages-artifact@v5
        with:
          path: site

  deploy:
    name: Deploy to GitHub Pages
    needs: build
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@v5
```

- [ ] **Step 10: Run the strict build**

```bash
source .venv/bin/activate
mkdocs build --strict
```

Expected: exit 0, no WARNING lines. If `../../AGENTS.md` or `../specs/` still
warn, Step 7 is incomplete.

- [ ] **Step 11: Run the full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: nextest reports all tests passed. Quote the summary line.

- [ ] **Step 12: Commit**

```bash
git add mkdocs.yml requirements-docs.txt .gitignore docs/index.md \
        .github/workflows/docs.yml docs/conformance/openid4vc-conformance.md
git commit -m "docs: scaffold mkdocs site with strict build and Pages deploy

docs_dir is the whole docs/ tree; superpowers/ and specs/ are excluded.
validation raises anchors and unrecognized_links from their info defaults
so fragment and bare-directory links fail the build instead of rotting.

Rewrites the conformance report's 8 relative links to absolute GitHub
URLs. This lands here rather than later because the report already sits
in docs_dir: with nav.omitted_files: warn it must be in nav from the
first commit, and once built its ../../AGENTS.md link is a hard --strict
failure."
```

---

## Task 2: Getting Started group

**Files:**

- Create: `docs/manual/getting-started/installation.md`
- Create: `docs/manual/getting-started/quickstart.md`
- Modify: `mkdocs.yml` (nav)

**Interfaces:**

- Consumes: `mkdocs.yml` `nav` from Task 1.
- Produces: `manual/getting-started/installation.md` and
  `manual/getting-started/quickstart.md` as link targets for Task 9's README and
  Task 1's signpost list.

- [ ] **Step 1: Extract `installation.md` (README 21–49)**

```bash
mkdir -p docs/manual/getting-started
sed -n '21,49p' README.md > docs/manual/getting-started/installation.md
sed -i '' -E 's/^##/#/' docs/manual/getting-started/installation.md
head -1 docs/manual/getting-started/installation.md
```

Expected first line: `# Prerequisites`.

This page holds two former `##` sections (Prerequisites, Building the Project),
so after the decrement it has two `#` headings. Fix that — a page needs one
`h1`. Replace the first line with a page title and demote both:

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("docs/manual/getting-started/installation.md")
lines = p.read_text().split("\n")
out = ["# Installation", ""]
for line in lines:
    out.append("#" + line if line.startswith("# ") else line)
p.write_text("\n".join(out))
PY
grep -nE '^#{1,3} ' docs/manual/getting-started/installation.md
```

Expected: `1:# Installation`, then `## Prerequisites`, then
`## Building the Project`.

- [ ] **Step 2: Audit links in `installation.md`**

```bash
grep -nE '\]\([^)]*\)' docs/manual/getting-started/installation.md || echo "(none)"
```

Expected: the two upstream Rust issue URLs and the `xx` repo URL if present in
range, all absolute `https://` — leave them alone. No relative links expected.
If a relative link appears, stop and report.

- [ ] **Step 3: Extract `quickstart.md` (README 169–194)**

⚠️ The range starts at **169**, not 173. Lines 169–172 are the
`## Running the Project` heading and its intro paragraph. An earlier draft of
this plan started at 173 and would have silently dropped them — the only
content-loss bug found during plan review. Do not "correct" 169 back to 173.

```bash
sed -n '169,194p' README.md > docs/manual/getting-started/quickstart.md
sed -i '' -E 's/^##/#/' docs/manual/getting-started/quickstart.md
grep -nE '^#{1,3} ' docs/manual/getting-started/quickstart.md
```

Expected, exactly:

```text
1:# Running the Project
...:## 1. Quickstart (Development Setup)
...:## 2. Validating Configuration
```

**No title prepend is needed** — line 169's `## Running the Project` becomes the
page's single `#`. That is strictly better than inventing a title, and is why
the range starts at 169.

- [ ] **Step 4: Fix the one anchor link in `quickstart.md`**

README line 183 contains a link to `#credential-types--claim-configuration`
(still within the 169–194 range).
Rewrite it:

```text
](#credential-types--claim-configuration)
```

becomes

```text
](../issuance/credential-types.md)
```

Leave the link **text** unchanged.

- [ ] **Step 5: Add both pages to `mkdocs.yml` nav**

Insert **above** the existing `- Reference:` entry:

```yaml
  - Getting Started:
      - Installation: manual/getting-started/installation.md
      - Running the Project: manual/getting-started/quickstart.md
```

The nav label is "Running the Project" to match the page's `h1`; the filename
stays `quickstart.md` because Tasks 5, 9, and 10 reference that path.

- [ ] **Step 6: Strict build**

```bash
source .venv/bin/activate
mkdocs build --strict
```

Expected: exit 0. A failure naming `../issuance/credential-types.md` means
Step 4 ran before that page exists — that link must point at a page created in
Task 5, so **temporarily** leave README line 183's link as plain text (strip the
link, keep the words) and restore it in Task 5 Step 9. Record which you did in
your report.

- [ ] **Step 7: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 8: Commit**

```bash
git add docs/manual/getting-started mkdocs.yml
git commit -m "docs: migrate Getting Started group to the manual

Verbatim move of README lines 21-49 and 173-194. Headings decremented and
a page title added; prose unchanged."
```

---

## Task 3: Deployment group

**Files:**

- Create: `docs/manual/deployment/docker.md`
- Create: `docs/manual/deployment/ci.md`
- Modify: `mkdocs.yml` (nav)

**Interfaces:**

- Produces: `manual/deployment/docker.md` — link target for Task 10's
  `docker-publish.yml` comment repoint.
- Produces: `manual/deployment/ci.md` — target of `docker.md`'s one anchor link.

- [ ] **Step 1: Extract `docker.md` (README 50–111 then 143–168)**

Two ranges, concatenated in that order. Range 112–142 (the CI section) is
deliberately skipped — it becomes `ci.md`.

```bash
mkdir -p docs/manual/deployment
{ sed -n '50,111p' README.md; echo; sed -n '143,168p' README.md; } \
  > docs/manual/deployment/docker.md
sed -i '' -E 's/^##/#/' docs/manual/deployment/docker.md
grep -nE '^#{1,3} ' docs/manual/deployment/docker.md
```

Expected: `# Docker`, then `## Building the image`, then `## Running the image`.
That is already a valid single-`h1` page — no title prepend needed.

- [ ] **Step 2: Fix the one anchor link in `docker.md`**

README line 91 links to `#ci-automated-build--push`. Rewrite:

```text
](#ci-automated-build--push)
```

becomes

```text
](ci.md)
```

- [ ] **Step 3: Extract `ci.md` (README 112–142)**

```bash
sed -n '112,142p' README.md > docs/manual/deployment/ci.md
sed -i '' -E 's/^##/#/' docs/manual/deployment/ci.md
head -1 docs/manual/deployment/ci.md
```

Expected first line: `# CI: automated build & push`.

- [ ] **Step 4: Audit links in both pages**

```bash
grep -nE '\]\([^)]*\)' docs/manual/deployment/*.md
```

Every remaining link should be an absolute `https://` URL (the two rust-lang
issue links and the `tonistiigi/xx` link) or `ci.md`. Anything relative that is
not `ci.md` — stop and report.

- [ ] **Step 5: Add to `mkdocs.yml` nav, after Getting Started**

```yaml
  - Deployment:
      - Docker: manual/deployment/docker.md
      - CI Build & Push: manual/deployment/ci.md
```

- [ ] **Step 6: Strict build**

```bash
source .venv/bin/activate
mkdocs build --strict
```

- [ ] **Step 7: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 8: Commit**

```bash
git add docs/manual/deployment mkdocs.yml
git commit -m "docs: migrate Deployment group to the manual

Verbatim move of README lines 50-111 and 143-168 into docker.md, and
112-142 into ci.md. The CI section is split out because it documents
GitHub Actions rather than Docker usage."
```

---

## Task 4: Operating group

The largest task: 7 pages, and the page holding 6 of the 10 anchor links.

**Files:**

- Create: `docs/manual/operating/http-server.md`
- Create: `docs/manual/operating/openapi.md`
- Create: `docs/manual/operating/admin-api.md`
- Create: `docs/manual/operating/test-console.md`
- Create: `docs/manual/operating/keys-and-certificates.md`
- Create: `docs/manual/operating/logging.md`
- Create: `docs/manual/operating/following-a-request.md`
- Modify: `mkdocs.yml` (nav)

**Interfaces:**

- Produces: `manual/operating/http-server.md` (holds the endpoint table — the
  README will link to it in Task 9), `manual/operating/logging.md` (target of
  `AGENTS.md` §4.5 repoint in Task 11), and
  `manual/operating/test-console.md`.

- [ ] **Step 1: Extract all seven pages**

```bash
mkdir -p docs/manual/operating
sed -n '195,224p' README.md > docs/manual/operating/http-server.md
sed -n '225,246p' README.md > docs/manual/operating/openapi.md
sed -n '247,334p' README.md > docs/manual/operating/admin-api.md
{ sed -n '335,408p' README.md; echo; sed -n '464,512p' README.md; } \
  > docs/manual/operating/test-console.md
sed -n '513,543p' README.md > docs/manual/operating/keys-and-certificates.md
{ sed -n '1111,1158p' README.md; echo; sed -n '1231,1238p' README.md; } \
  > docs/manual/operating/logging.md
sed -n '1159,1230p' README.md > docs/manual/operating/following-a-request.md

for f in docs/manual/operating/*.md; do sed -i '' -E 's/^##/#/' "$f"; done
grep -nE '^# ' docs/manual/operating/*.md
```

Note `test-console.md` skips README 409–463 — that range is the DC API Expected
Origins subsection and becomes `verification/dc-api-origins.md` in Task 6.

- [ ] **Step 2: Give each page exactly one `h1`**

Several pages start at a former `###` or `####` and now have no `#`. Prepend
titles where `head -1` is not already a single `#`:

| File | Required first line |
| --- | --- |
| `http-server.md` | `# HTTP Server & Endpoints` |
| `openapi.md` | `# API Documentation (OpenAPI / Swagger UI)` |
| `admin-api.md` | `# Admin API` |
| `test-console.md` | `# Admin Test Console` |
| `keys-and-certificates.md` | `# Key & Certificate Management CLI` |
| `logging.md` | `# Logging & Observability` |
| `following-a-request.md` | `# Following a Request` |

Use this, which prepends only when the file does not already open with a single
`#` heading, and demotes a duplicate if one results:

```bash
python3 - <<'PY'
from pathlib import Path
titles = {
    "http-server.md": "HTTP Server & Endpoints",
    "openapi.md": "API Documentation (OpenAPI / Swagger UI)",
    "admin-api.md": "Admin API",
    "test-console.md": "Admin Test Console",
    "keys-and-certificates.md": "Key & Certificate Management CLI",
    "logging.md": "Logging & Observability",
    "following-a-request.md": "Following a Request",
}
base = Path("docs/manual/operating")
for name, title in titles.items():
    p = base / name
    text = p.read_text()
    lines = text.split("\n")
    h1s = [i for i, l in enumerate(lines) if l.startswith("# ")]
    if len(h1s) == 1 and h1s[0] == 0:
        continue                      # already correct
    lines = ["#" + l if l.startswith("# ") else l for l in lines]
    p.write_text(f"# {title}\n\n" + "\n".join(lines))
for name in titles:
    p = base / name
    print(name, "->", [l for l in p.read_text().split("\n") if l.startswith("# ")])
PY
```

Verify each page prints exactly one `#` heading.

- [ ] **Step 3: Rewrite the 6 anchor links in `http-server.md`**

These come from README lines 209, 210, 211, 219, 221, 223:

| Anchor in source | New target |
| --- | --- |
| `#by-reference-credential-offers` | `../issuance/by-reference-offers.md` |
| `#abca-challenge-retrieval-post-challenge` | `../issuance/wallet-attestation.md#abca-challenge-retrieval-post-challenge` |
| `#paso-transaction-data-metadata` (both occurrences) | `../issuance/paso-transaction-data.md` |
| `#api-documentation-openapi--swagger-ui` | `openapi.md` |
| `#admin-test-console` | `test-console.md` |

⚠️ Four of these point at pages created in **Task 5**, which runs after this
one. `--strict` will fail. **Do this instead:** in this task, rewrite only the
two same-group links (`openapi.md`, `test-console.md`), and leave the four
cross-group anchors as-is. They will still be `#...` fragments that do not
resolve — so `anchors: warn` fails the build.

To keep this task strict-green, **strip those four links to plain text** (keep
the words, drop the `[...](...)` wrapper) and record it. **Task 5 Step 10
restores them** as proper relative links. This is the only place in the plan
where a link is temporarily removed, and it exists because the nav validation is
deliberately strict.

- [ ] **Step 4: Rewrite the 2 anchor links in `test-console.md`**

From README lines 391 and 510:

| Anchor | New target | Exists after |
| --- | --- | --- |
| `#dc-api-expected-origins` | `../verification/dc-api-origins.md` | Task 6 |
| `#end-to-end-test-real-subprocess-issue--verify--revoke--re-verify` | `../development/end-to-end.md` | Task 7 |

Both targets are future pages. Apply the same treatment as Step 3: strip to
plain text now, restored in **Task 6 Step 5** and **Task 7 Step 6**
respectively.

- [ ] **Step 5: Rewrite the 1 file link in `admin-api.md`**

README line 332 links to `docs/specs/emvco-dpc-schema-framework.md`. That tree
is excluded from the build, so it becomes absolute:

```text
](docs/specs/emvco-dpc-schema-framework.md)
```

becomes

```text
](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/emvco-dpc-schema-framework.md)
```

- [ ] **Step 6: Audit every link in the group**

```bash
grep -nE '\]\([^)]*\)' docs/manual/operating/*.md
```

Every result must be one of: an absolute `https://` URL, `openapi.md`,
`test-console.md`. Any remaining `#`-fragment or `../` path — stop and report.

- [ ] **Step 7: Add to `mkdocs.yml` nav, after Deployment**

```yaml
  - Operating:
      - HTTP Server & Endpoints: manual/operating/http-server.md
      - OpenAPI & Swagger UI: manual/operating/openapi.md
      - Admin API: manual/operating/admin-api.md
      - Admin Test Console: manual/operating/test-console.md
      - Keys & Certificates: manual/operating/keys-and-certificates.md
      - Logging: manual/operating/logging.md
      - Following a Request: manual/operating/following-a-request.md
```

- [ ] **Step 8: Strict build**

```bash
source .venv/bin/activate
mkdocs build --strict
```

- [ ] **Step 9: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 10: Commit**

```bash
git add docs/manual/operating mkdocs.yml
git commit -m "docs: migrate Operating group to the manual

Verbatim move of README lines 195-246, 247-334, 335-408 + 464-512,
513-543, 1111-1158 + 1231-1238, and 1159-1230. Six forward references to
pages that do not exist yet are temporarily plain text; Tasks 5-7 restore
them as relative links."
```

---

## Task 5: Issuance group

**Files:**

- Create: `docs/manual/issuance/credential-types.md`
- Create: `docs/manual/issuance/wallet-attestation.md`
- Create: `docs/manual/issuance/android-keystore-attestation.md`
- Create: `docs/manual/issuance/dpop.md`
- Create: `docs/manual/issuance/credential-encryption.md`
- Create: `docs/manual/issuance/encrypted-pre-auth-code.md`
- Create: `docs/manual/issuance/by-reference-offers.md`
- Create: `docs/manual/issuance/paso-transaction-data.md`
- Modify: `docs/manual/operating/http-server.md` (restore 4 links)
- Modify: `docs/manual/getting-started/quickstart.md` (restore 1 link, if stripped)
- Modify: `mkdocs.yml` (nav)

**Interfaces:**

- Consumes: the stripped-link markers left by Task 2 Step 6 and Task 4 Step 3.
- Produces: `manual/issuance/wallet-attestation.md` containing the heading
  `## ABCA Challenge Retrieval (POST /challenge)`, whose generated anchor is
  `#abca-challenge-retrieval-post-challenge`. Task 4's restored deep link
  depends on that exact slug.

- [ ] **Step 1: Extract all eight pages**

```bash
mkdir -p docs/manual/issuance
sed -n '1045,1110p' README.md > docs/manual/issuance/credential-types.md
sed -n '544,641p'   README.md > docs/manual/issuance/wallet-attestation.md
sed -n '642,696p'   README.md > docs/manual/issuance/android-keystore-attestation.md
sed -n '697,787p'   README.md > docs/manual/issuance/dpop.md
sed -n '884,941p'   README.md > docs/manual/issuance/credential-encryption.md
sed -n '942,992p'   README.md > docs/manual/issuance/encrypted-pre-auth-code.md
sed -n '993,1044p'  README.md > docs/manual/issuance/by-reference-offers.md
sed -n '788,883p'   README.md > docs/manual/issuance/paso-transaction-data.md

for f in docs/manual/issuance/*.md; do sed -i '' -E 's/^##/#/' "$f"; done
grep -cE '^# ' docs/manual/issuance/*.md
```

Every file should report exactly `1` — each range starts at a former `##`, which
becomes the page's single `#`. If any reports `0` or `2+`, prepend or demote as
in Task 4 Step 2 and report which.

- [ ] **Step 2: Confirm the ABCA anchor slug**

```bash
grep -n 'ABCA Challenge Retrieval' docs/manual/issuance/wallet-attestation.md
```

Expected: a `## ABCA Challenge Retrieval (\`POST /challenge\`)` heading. MkDocs
slugifies that to `abca-challenge-retrieval-post-challenge`. Task 4's restored
link uses that slug; if the heading text differs, use the actual slug and note
the deviation.

- [ ] **Step 3: Rewrite the 2 spec links in `paso-transaction-data.md`**

From README lines 793–794:

```text
](docs/specs/paso-core.md)
```

becomes

```text
](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/paso-core.md)
```

and

```text
](docs/specs/paso-proof-metadata.md)
```

becomes

```text
](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/paso-proof-metadata.md)
```

- [ ] **Step 4: Rewrite the 2 spec links in `credential-types.md`**

From README lines 1087 and 1107:

```text
](docs/specs/emvco-dpc-schema-framework.md)
```

becomes

```text
](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/emvco-dpc-schema-framework.md)
```

and

```text
](docs/specs/eu-age-verification-annex-a-av-profile.md)
```

becomes

```text
](https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/eu-age-verification-annex-a-av-profile.md)
```

- [ ] **Step 5: Audit links across the group**

```bash
grep -nE '\]\([^)]*\)' docs/manual/issuance/*.md
```

Every result must be an absolute `https://` URL. There should be **no**
relative links and no `#` fragments in this group. Stop and report otherwise.

- [ ] **Step 6: Add to `mkdocs.yml` nav, after Operating**

```yaml
  - Issuance (OpenID4VCI):
      - Credential Types & Claims: manual/issuance/credential-types.md
      - Wallet Attestation & ABCA: manual/issuance/wallet-attestation.md
      - Android Keystore Attestation: manual/issuance/android-keystore-attestation.md
      - DPoP: manual/issuance/dpop.md
      - Request & Response Encryption: manual/issuance/credential-encryption.md
      - Encrypted Pre-Authorized Code: manual/issuance/encrypted-pre-auth-code.md
      - By-Reference Offers: manual/issuance/by-reference-offers.md
      - PaSO Transaction Data: manual/issuance/paso-transaction-data.md
```

- [ ] **Step 7: Strict build (pages only, before restoring links)**

```bash
source .venv/bin/activate
mkdocs build --strict
```

Expected: exit 0.

- [ ] **Step 8: Restore the 4 stripped links in `http-server.md`**

Re-wrap the plain-text spans Task 4 Step 3 left behind:

| Link text to re-wrap | Target |
| --- | --- |
| the by-reference-offers reference | `../issuance/by-reference-offers.md` |
| the ABCA challenge reference | `../issuance/wallet-attestation.md#abca-challenge-retrieval-post-challenge` |
| both PaSO transaction-data references | `../issuance/paso-transaction-data.md` |

Recover the original link text from the source:

```bash
sed -n '209,211p;223p' README.md
```

- [ ] **Step 9: Restore the link in `quickstart.md` if Task 2 stripped it**

```bash
sed -n '183p' README.md
```

Re-wrap that link text with target `../issuance/credential-types.md`.

- [ ] **Step 10: Strict build again, with links restored**

```bash
mkdocs build --strict
```

Expected: exit 0. A failure naming
`wallet-attestation.md#abca-challenge-retrieval-post-challenge` means the slug
in Step 2 differs — use the real one.

- [ ] **Step 11: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 12: Commit**

```bash
git add docs/manual/issuance docs/manual/operating/http-server.md \
        docs/manual/getting-started/quickstart.md mkdocs.yml
git commit -m "docs: migrate Issuance (OpenID4VCI) group to the manual

Verbatim move of README lines 544-641, 642-696, 697-787, 788-883,
884-941, 942-992, 993-1044, 1045-1110. Spec citations become absolute
GitHub URLs because docs/specs/ is excluded from the built site and
mkdocs only logs such links at INFO. Restores the forward references
Task 4 left as plain text."
```

---

## Task 6: Verification group

**Files:**

- Create: `docs/manual/verification/dc-api-origins.md`
- Create: `docs/manual/verification/request-diagnostics.md`
- Modify: `docs/manual/operating/test-console.md` (restore 1 link)
- Modify: `mkdocs.yml` (nav)

**Interfaces:**

- Produces: `manual/verification/dc-api-origins.md` — target of
  `test-console.md`'s restored link.

- [ ] **Step 1: Extract both pages**

```bash
mkdir -p docs/manual/verification
sed -n '409,463p'   README.md > docs/manual/verification/dc-api-origins.md
sed -n '1239,1278p' README.md > docs/manual/verification/request-diagnostics.md
for f in docs/manual/verification/*.md; do sed -i '' -E 's/^##/#/' "$f"; done
head -1 docs/manual/verification/dc-api-origins.md
head -1 docs/manual/verification/request-diagnostics.md
```

`dc-api-origins.md` starts from a former `#####` heading, so after the decrement
its first heading is `####`. Prepend a title and promote the block:

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("docs/manual/verification/dc-api-origins.md")
lines = p.read_text().split("\n")
# Former ##### -> #### after the global decrement; promote all headings by two
# more levels so the page's own top heading is h2 under a new h1.
out = []
for l in lines:
    if l.startswith("#### "):
        out.append("## " + l[5:])
    elif l.startswith("##### "):
        out.append("### " + l[6:])
    else:
        out.append(l)
p.write_text("# DC API Expected Origins\n\n" + "\n".join(out))
print([l for l in p.read_text().split("\n") if l.startswith("#")][:6])
PY
```

`request-diagnostics.md` starts from a former `###`, now `##`. Prepend:

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("docs/manual/verification/request-diagnostics.md")
p.write_text("# Presentation Request Diagnostics\n\n" + p.read_text())
PY
```

- [ ] **Step 2: Audit links**

```bash
grep -nE '\]\([^)]*\)' docs/manual/verification/*.md || echo "(none)"
```

Any relative link or `#` fragment — stop and report.

- [ ] **Step 3: Add to `mkdocs.yml` nav, after Issuance**

```yaml
  - Verification (OpenID4VP):
      - DC API Expected Origins: manual/verification/dc-api-origins.md
      - Request Diagnostics: manual/verification/request-diagnostics.md
```

- [ ] **Step 4: Strict build**

```bash
source .venv/bin/activate
mkdocs build --strict
```

- [ ] **Step 5: Restore the DC API link in `test-console.md`**

Recover the original text:

```bash
sed -n '390,391p' README.md
```

Re-wrap it with target `../verification/dc-api-origins.md`.

- [ ] **Step 6: Strict build again**

```bash
mkdocs build --strict
```

- [ ] **Step 7: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 8: Commit**

```bash
git add docs/manual/verification docs/manual/operating/test-console.md mkdocs.yml
git commit -m "docs: migrate Verification (OpenID4VP) group to the manual

Verbatim move of README lines 409-463 and 1239-1278. This group has two
pages against Issuance's eight, accurately reflecting how little
verifier-side operator documentation the README contains. The asymmetry
is left visible rather than papered over."
```

---

## Task 7: Development group

**Files:**

- Create: `docs/manual/development/testing.md`
- Create: `docs/manual/development/conformance-suite.md`
- Create: `docs/manual/development/end-to-end.md`
- Modify: `docs/manual/operating/test-console.md` (restore 1 link)
- Modify: `mkdocs.yml` (nav)

**Interfaces:**

- Produces: `manual/development/end-to-end.md` — target of `test-console.md`'s
  second restored link, and of Task 10's `e2e_full_flow.rs` repoint.

- [ ] **Step 1: Extract all three pages**

```bash
mkdir -p docs/manual/development
sed -n '1296,1343p' README.md > docs/manual/development/testing.md
sed -n '1344,1428p' README.md > docs/manual/development/conformance-suite.md
sed -n '1279,1295p' README.md > docs/manual/development/end-to-end.md
for f in docs/manual/development/*.md; do sed -i '' -E 's/^##/#/' "$f"; done
grep -cE '^# ' docs/manual/development/*.md
```

`testing.md` and `end-to-end.md` each start at a former `##` → one `#`. Good.
`conformance-suite.md` starts at a former `###` → `##`; prepend a title:

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("docs/manual/development/conformance-suite.md")
p.write_text("# Conformance Test Suite\n\n" + p.read_text())
PY
```

- [ ] **Step 2: Rewrite the 3 links in `conformance-suite.md`**

From README lines 1347, 1348, 1425:

| Current target | New target |
| --- | --- |
| `docs/specs/` | `https://github.com/digitallabor-berlin/foundry/tree/main/docs/specs/` |
| `docs/conformance/openid4vc-conformance.md` | `../../conformance/openid4vc-conformance.md` |
| `AGENTS.md` | `https://github.com/digitallabor-berlin/foundry/blob/main/AGENTS.md` |

Note the middle one is a **relative site link**, not an absolute URL — the
conformance report *is* a built page, so linking to it relatively keeps
navigation inside the site and gets validated by `--strict`. Verify the depth:
from `docs/manual/development/` up two levels reaches `docs/`, then
`conformance/…`.

- [ ] **Step 3: Audit links**

```bash
grep -nE '\]\([^)]*\)' docs/manual/development/*.md
```

Expected: absolute `https://` URLs plus the one
`../../conformance/openid4vc-conformance.md`, plus the `nexte.st` link if in
range.

- [ ] **Step 4: Add to `mkdocs.yml` nav, after Verification**

```yaml
  - Development:
      - Testing: manual/development/testing.md
      - Conformance Suite: manual/development/conformance-suite.md
      - End-to-End Suite: manual/development/end-to-end.md
```

- [ ] **Step 5: Strict build**

```bash
source .venv/bin/activate
mkdocs build --strict
```

A failure on `../../conformance/openid4vc-conformance.md` means the relative
depth is wrong — count directories again.

- [ ] **Step 6: Restore the end-to-end link in `test-console.md`**

```bash
sed -n '510p' README.md
```

Re-wrap that link text with target `../development/end-to-end.md`.

- [ ] **Step 7: Strict build again**

```bash
mkdocs build --strict
```

- [ ] **Step 8: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 9: Commit**

```bash
git add docs/manual/development docs/manual/operating/test-console.md mkdocs.yml
git commit -m "docs: migrate Development group to the manual

Verbatim move of README lines 1279-1295, 1296-1343, 1344-1428. The
conformance report is linked relatively because it is a built page;
docs/specs/ and AGENTS.md are absolute because they are not."
```

---

## Task 8: Reference group

The only task that **writes new prose**. Everything here assembles material that
already exists elsewhere; it must not make any new claim about behaviour.

**Files:**

- Create: `docs/manual/reference/configuration.md`
- Create: `docs/manual/reference/log-fields.md`
- Create: `docs/manual/reference/specs.md`
- Modify: `docs/index.md` (uncomment the signpost list)
- Modify: `mkdocs.yml` (nav)

**Interfaces:**

- Produces: `manual/reference/log-fields.md` — target of `AGENTS.md` §4.5 and
  `instrumentation_hygiene.rs` repoints in Tasks 10 and 11.

- [ ] **Step 1: Build the configuration key index**

First, gather every config key documented anywhere in the README:

```bash
grep -nE '^\s{0,4}[a-z_]+:' README.md | grep -vE '^\s*#' | head -60
awk '/^```yaml/,/^```$/' README.md | grep -E '^\s*[a-z_]+:' | sort -u
```

Then write `docs/manual/reference/configuration.md` as a table with one row per
key: the key path, a one-line description **copied from the README's own prose**
for that key, and a link to the manual page that documents it. Structure:

```markdown
# Configuration Reference

`config.yaml` keys, and where each is explained in full. This page is an index —
the behavioural documentation lives on the linked pages.

## Issuer

| Key | Documented in |
| --- | --- |
| `issuer.…` | [Credential Types & Claims](../issuance/credential-types.md) |

## Verifier

| Key | Documented in |
| --- | --- |
| `verifier.dc_api_expected_origins` | [DC API Expected Origins](../verification/dc-api-origins.md) |
| `verifier.dc_api_accept_legacy_web_origin_audience` | [DC API Expected Origins](../verification/dc-api-origins.md) |

## Logging

| Key | Documented in |
| --- | --- |
| `logging.sensitive_payloads` | [Logging](../operating/logging.md) |
```

**Do not invent keys.** Every row must correspond to a key that appears in a
README yaml block. If a key's owning page is ambiguous, link the page whose
source range contained that yaml block.

- [ ] **Step 2: Build the log-fields reference**

The authoritative list is in root `AGENTS.md` §4.5 and asserted by
`crates/foundry/tests/instrumentation_hygiene.rs`. Read both:

```bash
grep -n 'request_id' AGENTS.md
sed -n '105,130p' crates/foundry/tests/instrumentation_hygiene.rs
```

Write `docs/manual/reference/log-fields.md` listing the fields those two sources
agree on — `request_id`, `tx_id`, `route`, `method`, `listener`, `http.status`,
`latency_ms`, `error.kind`, `error.detail`, plus the per-credential verification
fields `credential`, `credential_type`, `format`, `check`, `passed`, `checks`,
`checks_passed`, and the verdict fields `credentials_requested`,
`credentials_answered`, `credentials_failed`.

Include this note verbatim, because it is the reason the page exists:

```markdown
> These names are operator-facing API. Renaming one is a breaking change for
> anyone consuming the logs, and `crates/foundry/tests/instrumentation_hygiene.rs`
> asserts that each is still emitted somewhere in the source tree.
```

Link onward to [Logging](../operating/logging.md) and
[Following a Request](../operating/following-a-request.md).

- [ ] **Step 3: Build the specifications index**

Restate root `AGENTS.md` §4.4's governing-documents table with **absolute**
GitHub URLs, since `docs/specs/` is excluded from the site:

```bash
sed -n '/^| Spec file/,/^$/p' AGENTS.md
```

Write `docs/manual/reference/specs.md` with one row per pinned document: its
filename linked to
`https://github.com/digitallabor-berlin/foundry/blob/main/docs/specs/<file>`,
and the "Governs" text. For the two reference **stubs** (EMVCo DPC, ISO 18013-5)
and the vendor profile (Google Wallet), carry over §4.4's caveat that a stub is
not the specification and a vendor profile never overrides a standards-track
MUST. Do not restate spec content itself.

- [ ] **Step 4: Add to `mkdocs.yml` nav**

Replace the existing `- Reference:` block from Task 1 with the full version:

```yaml
  - Reference:
      - Configuration: manual/reference/configuration.md
      - Log Fields: manual/reference/log-fields.md
      - Specifications: manual/reference/specs.md
      - Conformance Report: conformance/openid4vc-conformance.md
```

- [ ] **Step 5: Uncomment the signpost list in `docs/index.md`**

Remove the `<!--` / `-->` wrapper Task 1 Step 6 added. All seven targets now
exist.

- [ ] **Step 6: Strict build**

```bash
source .venv/bin/activate
mkdocs build --strict
```

Expected: exit 0. This is the first build with all 29 nav entries present.

- [ ] **Step 7: Verify nav completeness**

```bash
grep -cE '\.md$' mkdocs.yml
find docs -name '*.md' -not -path 'docs/specs/*' -not -path 'docs/superpowers/*' | wc -l
```

Both must be **29**. A mismatch means a page is missing from nav (which
`--strict` would have caught) or an extra file exists in `docs/`.

- [ ] **Step 8: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 9: Commit**

```bash
git add docs/manual/reference docs/index.md mkdocs.yml
git commit -m "docs: add the Reference group and complete the nav

Three assembled pages: a config key index (the README scattered these
across eight sections), the operator-facing log field list that
AGENTS.md 4.5 declares API and instrumentation_hygiene.rs asserts, and a
spec index with absolute URLs since docs/specs/ is excluded from the
build. All 29 nav entries now present."
```

---

## Task 9: Truncate the README

The first destructive step. Everything removed here already exists in the
manual and has passed a strict build.

**Files:**

- Modify: `README.md` (1,431 lines → ~150)
- Create (temporary): `/tmp/migration-check.py` — deleted in Step 5

**Interfaces:**

- Consumes: every page created in Tasks 2–8.

- [ ] **Step 1: Snapshot the pre-truncation README**

```bash
git show HEAD:README.md > /tmp/README.before.md
wc -l /tmp/README.before.md
```

Expected: 1431.

- [ ] **Step 2: Write the completeness checker**

This proves nothing was dropped, rather than asserting it. It takes each
migrated README section, picks its longest prose lines as fingerprints, and
requires each to appear in exactly one manual page.

```python
#!/usr/bin/env python3
"""Verify every migrated README section landed in exactly one manual page."""
import re
import sys
from pathlib import Path

BEFORE = Path("/tmp/README.before.md")
DOCS = Path("docs")

# (start, end, expected_page) — the mapping from the plan's File Structure.
RANGES = [
    (21, 49, "manual/getting-started/installation.md"),
    (169, 194, "manual/getting-started/quickstart.md"),
    (50, 111, "manual/deployment/docker.md"),
    (143, 168, "manual/deployment/docker.md"),
    (112, 142, "manual/deployment/ci.md"),
    (195, 224, "manual/operating/http-server.md"),
    (225, 246, "manual/operating/openapi.md"),
    (247, 334, "manual/operating/admin-api.md"),
    (335, 408, "manual/operating/test-console.md"),
    (464, 512, "manual/operating/test-console.md"),
    (513, 543, "manual/operating/keys-and-certificates.md"),
    (1111, 1158, "manual/operating/logging.md"),
    (1231, 1238, "manual/operating/logging.md"),
    (1159, 1230, "manual/operating/following-a-request.md"),
    (1045, 1110, "manual/issuance/credential-types.md"),
    (544, 641, "manual/issuance/wallet-attestation.md"),
    (642, 696, "manual/issuance/android-keystore-attestation.md"),
    (697, 787, "manual/issuance/dpop.md"),
    (884, 941, "manual/issuance/credential-encryption.md"),
    (942, 992, "manual/issuance/encrypted-pre-auth-code.md"),
    (993, 1044, "manual/issuance/by-reference-offers.md"),
    (788, 883, "manual/issuance/paso-transaction-data.md"),
    (409, 463, "manual/verification/dc-api-origins.md"),
    (1239, 1278, "manual/verification/request-diagnostics.md"),
    (1296, 1343, "manual/development/testing.md"),
    (1344, 1428, "manual/development/conformance-suite.md"),
    (1279, 1295, "manual/development/end-to-end.md"),
]

lines = BEFORE.read_text().split("\n")
pages = {p: p.read_text() for p in DOCS.rglob("manual/**/*.md")}
pages_by_rel = {str(p.relative_to(DOCS)): t for p, t in pages.items()}

def fingerprints(block):
    """Longest prose lines: no headings, no fences, no links, >=50 chars."""
    out = []
    fenced = False
    for line in block:
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced or line.startswith("#") or not line.strip():
            continue
        s = line.strip()
        if len(s) >= 50 and "](" not in s:
            out.append(s)
    out.sort(key=len, reverse=True)
    return out[:3]

failures = []
checked = 0
for start, end, expected in RANGES:
    block = lines[start - 1 : end]
    fps = fingerprints(block)
    if not fps:
        print(f"NOTE  {start}-{end} -> {expected}: no prose fingerprint "
              f"(code-only range), skipped")
        continue
    target = pages_by_rel.get(expected)
    if target is None:
        failures.append(f"MISSING PAGE {expected} for lines {start}-{end}")
        continue
    for fp in fps:
        checked += 1
        hits = [rel for rel, text in pages_by_rel.items() if fp in text]
        if expected not in hits:
            failures.append(
                f"LOST  lines {start}-{end}: fingerprint not in {expected}\n"
                f"      {fp[:90]!r}\n      found in: {hits or 'NOWHERE'}"
            )
        elif len(hits) > 1:
            failures.append(
                f"DUPED lines {start}-{end}: fingerprint in {len(hits)} pages\n"
                f"      {fp[:90]!r}\n      {hits}"
            )

print(f"\nchecked {checked} fingerprints across {len(RANGES)} ranges")
if failures:
    print(f"\n{len(failures)} FAILURE(S):\n")
    print("\n".join(failures))
    sys.exit(1)
print("OK: every migrated range is present in exactly its expected page")
```

Save as `/tmp/migration-check.py`.

- [ ] **Step 3: Run the checker BEFORE truncating**

```bash
python3 /tmp/migration-check.py
```

Expected: `OK: every migrated range is present in exactly its expected page`.

**If it reports LOST or DUPED, stop.** Do not truncate the README. Fix the
migration first — this is the only safety net between here and permanent loss.

- [ ] **Step 4: Write the new README**

Keep exactly these six blocks, in this order:

- **(a)** Lines 1–6 verbatim (title + description).
- **(b)** `## Workspace Architecture` — lines 7–20 verbatim.
- **(c)** `## Prerequisites` — lines 21–27 verbatim.
- **(d)** `## Quickstart` — a fresh `## Quickstart` heading, then README lines
  174–186 verbatim as its body. (Line 173 is `### 1. Quickstart (Development
  Setup)`; the README keeps the body under a `##` instead of nesting.)
- **(e)** A new `## Documentation` section (new prose, permitted) — content below.
- **(f)** `## License` — lines 1429–1432 verbatim.

Block **(e)**:

```markdown
## Documentation

Full documentation: **<https://digitallabor-berlin.github.io/foundry/>**

| Topic | |
| --- | --- |
| Installation and building | [Getting Started](docs/manual/getting-started/installation.md) |
| Docker images and CI | [Deployment](docs/manual/deployment/docker.md) |
| Endpoints, admin API, test console, keys, logging | [Operating](docs/manual/operating/http-server.md) |
| Credential types, attestation, DPoP, encryption, PaSO | [Issuance](docs/manual/issuance/credential-types.md) |
| DC API origins, request diagnostics | [Verification](docs/manual/verification/dc-api-origins.md) |
| Test gate, conformance suite | [Development](docs/manual/development/testing.md) |
| Configuration keys, log fields, specifications | [Reference](docs/manual/reference/configuration.md) |
| Clause-by-clause conformance verdicts | [Conformance report](docs/conformance/openid4vc-conformance.md) |

Contributor guidelines and the normative invariants live in
[`AGENTS.md`](AGENTS.md).
```

**Do not** carry over the endpoint table (README 203–224) — spec §4.4 keeps it
only in `manual/operating/http-server.md`.

- [ ] **Step 5: Verify the result and clean up**

```bash
wc -l README.md
grep -cE '^## ' README.md
rm /tmp/migration-check.py
```

Expected: roughly 120–160 lines and 5 `##` sections (Workspace Architecture,
Prerequisites, Quickstart, Documentation, License).

- [ ] **Step 6: Check the README's own links resolve**

```bash
grep -oE '\]\(([^)h][^)]*)\)' README.md | sed 's/^](//;s/)$//' | while read -r t; do
  [ -e "$t" ] && echo "OK   $t" || echo "DEAD $t"
done
```

Every line must say `OK`. These are GitHub-relative paths, not site paths, so
they resolve against the repo root.

- [ ] **Step 7: Strict build**

```bash
source .venv/bin/activate
mkdocs build --strict
```

The README is outside `docs_dir` so this is unaffected — run it anyway to
confirm nothing regressed.

- [ ] **Step 8: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 9: Commit**

```bash
git add README.md
git commit -m "docs: reduce README to a landing page

1431 lines -> ~150. Keeps title, workspace architecture, prerequisites,
quickstart, and license; everything else now lives in the manual, which
is the single source of truth.

The endpoint table is deliberately NOT retained: it changes whenever a
route changes and duplicating it invites drift. Architecture,
prerequisites, and quickstart are duplicated on purpose because they are
stable and serve the landing-page role.

Verified with a throwaway fingerprint checker that every migrated line
range appears in exactly one manual page before deleting anything."
```

---

## Task 10: Repoint the inbound README references

Seven files, ten references. Two are in Rust source, which a markdown-only sweep
would miss.

**Files:**

- Modify: `AGENTS.md` (3 refs — lines 13, 238, 243)
- Modify: `crates/foundry/AGENTS.md` (line 14)
- Modify: `crates/foundry-issuer/AGENTS.md` (line 110)
- Modify: `crates/foundry-verifier/AGENTS.md` (line 79)
- Modify: `.github/workflows/docker-publish.yml` (line 11)
- Modify: `crates/foundry/src/logging.rs` (line 211)
- Modify: `crates/foundry/tests/instrumentation_hygiene.rs` (line 124)
- Modify: `crates/foundry/tests/e2e_full_flow.rs` (line 113)

- [ ] **Step 1: Locate all ten**

```bash
grep -rn 'README' AGENTS.md crates/foundry/AGENTS.md \
  crates/foundry-issuer/AGENTS.md crates/foundry-verifier/AGENTS.md \
  .github/workflows/docker-publish.yml crates/foundry/src/logging.rs \
  crates/foundry/tests/instrumentation_hygiene.rs \
  crates/foundry/tests/e2e_full_flow.rs
```

Expected: 10 matches.

⚠️ **Do not** touch `crates/foundry-mdoc/AGENTS.md` or
`crates/foundry-mdoc/tests/fixtures/README.md` — those refer to a *different*
README (test fixtures), and are out of scope.

⚠️ **Do not** touch anything under `docs/superpowers/plans/` — those cite README
line numbers as historical record, and rewriting a completed plan falsifies it.

- [ ] **Step 2: The three unambiguous repoints**

| File:line | New target |
| --- | --- |
| `AGENTS.md:13` | `docs/index.md` |
| `AGENTS.md:238` | `docs/manual/reference/log-fields.md` |
| `AGENTS.md:243` | `docs/manual/operating/logging.md` |

For `AGENTS.md:13`, the sentence says build/run/CLI usage is documented in the
README and "this file does not restate it". Point it at the manual instead:

```markdown
see **[the manual](docs/index.md)** — this file does not restate it.
```

- [ ] **Step 3: The four references needing resolution**

For each of `crates/foundry/AGENTS.md:14`,
`crates/foundry-issuer/AGENTS.md:110`, `crates/foundry-verifier/AGENTS.md:79`,
and `.github/workflows/docker-publish.yml:11`:

1. Read the **surrounding sentence** to see which README section it meant.
2. Look that section up in this plan's File Structure table to get its manual
   page.
3. Repoint at that page, using a repo-relative path (these files are read on
   GitHub, not in the site).

`docker-publish.yml:11` is already determined — its comment says
"see README.md #Docker for the upstream issue links", so it becomes
`docs/manual/deployment/docker.md`.

**Do not guess** for the other three. If the surrounding sentence does not make
the section clear, report it as unresolved rather than picking a plausible page.

- [ ] **Step 4: The three Rust-source references**

These are comments and an assertion message, not code paths — but they are still
`cargo fmt` / `clippy` territory, so re-run the gate after.

| File:line | Current | Change to |
| --- | --- | --- |
| `crates/foundry/src/logging.rs:211` | "…in the README should be relaxed accordingly" | "…in `docs/manual/operating/logging.md` should be relaxed accordingly" |
| `crates/foundry/tests/instrumentation_hygiene.rs:124` | "update README.md and the spec too — operators grep these" | "update `docs/manual/reference/log-fields.md` and the spec too — operators grep these" |
| `crates/foundry/tests/e2e_full_flow.rs:113` | "mirrors how `README.md` …" | "mirrors how `docs/manual/getting-started/quickstart.md` …" |

Keep each line within the file's existing comment wrapping. Do not reflow
neighbouring lines.

- [ ] **Step 5: Verify no stale references remain**

```bash
grep -rn 'README' --include='*.md' --include='*.rs' --include='*.yml' . \
  | grep -v '^./target' \
  | grep -v '^./docs/superpowers/' \
  | grep -v 'foundry-mdoc' \
  | grep -v '^./.worktrees/'
```

Expected: only the README's own self-references (if any) and nothing pointing at
migrated sections.

- [ ] **Step 6: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

`instrumentation_hygiene.rs` must still pass — you changed its message, not its
assertion.

- [ ] **Step 7: Commit**

```bash
git add AGENTS.md crates/foundry/AGENTS.md crates/foundry-issuer/AGENTS.md \
        crates/foundry-verifier/AGENTS.md .github/workflows/docker-publish.yml \
        crates/foundry/src/logging.rs \
        crates/foundry/tests/instrumentation_hygiene.rs \
        crates/foundry/tests/e2e_full_flow.rs
git commit -m "docs: repoint inbound README references at the manual

Ten references across seven files, three of them in Rust source where a
markdown-only sweep would have missed them. Deliberately excludes
foundry-mdoc's fixture README (a different file) and the superpowers
plans (historical record)."
```

---

## Task 11: Make the migration durable in AGENTS.md

Without this, the next feature documents itself in the README and undoes the
migration by increments.

**Files:**

- Modify: `AGENTS.md` (§8 new rule; §4.5 and §6 notes)

- [ ] **Step 1: Add the §8 maintenance rule**

In `AGENTS.md` §8 "Maintaining These Files", add a bullet alongside the existing
ones:

```markdown
- **Documented behaviour change** → update the relevant `docs/manual/` page. A
  **new page** additionally requires a `nav:` entry in `mkdocs.yml` —
  `validation.nav.omitted_files: warn` makes a page missing from the nav a build
  failure. `README.md` is a landing page, not a manual: do not add feature
  documentation to it.
```

- [ ] **Step 2: Note the docs gate in §5**

Add to §5.1, after the existing gate block. The outer fence below is four
tildes so the inner ` ```bash ` block survives copy-paste — write the inner
block into `AGENTS.md` as a normal triple-backtick fence.

~~~~markdown
Documentation changes under `docs/` additionally require:

```bash
source .venv/bin/activate
mkdocs build --strict
```

`--strict` fails on broken links and unresolved heading anchors. Note that a
link into `docs/specs/` or `docs/superpowers/` is **not** caught — those trees
are excluded from the build, and mkdocs logs such links at INFO only. Use
absolute `https://github.com/digitallabor-berlin/foundry/blob/main/…` URLs for
them; `crates/foundry/tests/docs_hygiene.rs` enforces this.
~~~~

- [ ] **Step 3: Update §4.5's log-field sentence**

The line currently reads "…update `README.md` too". It should name the manual
page:

```markdown
  watching the logs; update `docs/manual/reference/log-fields.md` too.
```

And the section's closing pointer, currently "the 'Logging & Observability'
section of `README.md`", becomes
`docs/manual/operating/logging.md`.

- [ ] **Step 4: Update §6's OpenAPI rule**

§6 requires endpoint changes to be reflected in the OpenAPI specs. Add that the
endpoint table moved:

```markdown
The operator-facing endpoint table lives in
`docs/manual/operating/http-server.md` (it is deliberately not duplicated in
`README.md`). An endpoint change updates that page as well as `openapi.json` /
`openapi-wallet.json`.
```

- [ ] **Step 5: Verify the AGENTS.md links resolve**

```bash
grep -oE '\]\(([^)h][^)]*)\)' AGENTS.md | sed 's/^](//;s/)$//' \
  | sed 's/#.*//' | grep -v '^$' | while read -r t; do
  [ -e "$t" ] && echo "OK   $t" || echo "DEAD $t"
done
```

Every line must say `OK`.

- [ ] **Step 6: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add AGENTS.md
git commit -m "docs: add manual maintenance rules to AGENTS.md

Section 8 gains a rule that a documented behaviour change updates the
manual page and, for a new page, mkdocs.yml's nav. Section 5 documents
the strict docs build and the one class of link it cannot catch. Sections
4.5 and 6 now name manual pages instead of README sections."
```

---

## Task 12: The docs hygiene test

Enforces the one rule mkdocs provably cannot: links into excluded trees log at
INFO and never fail `--strict` (spec §3, confirmed empirically).

**Files:**

- Create: `crates/foundry/tests/docs_hygiene.rs`

- [ ] **Step 1: Write the failing test**

```rust
//! Enforces the absolute-URL rule for documentation links that MkDocs cannot
//! check. `docs/specs/` and `docs/superpowers/` are excluded from the built
//! site via `exclude_docs`. MkDocs handles a link pointing INTO an excluded
//! tree by capping the log level — `warning_level = min(logging.INFO,
//! validation.links.not_found)` — so it emits INFO and `--strict` does not
//! abort. No config key promotes it. Confirmed empirically; see
//! `docs/superpowers/specs/2026-08-27-mkdocs-manual-design.md` §3.
//!
//! Consequence: such a link renders as a dead href in the published site with
//! CI green. Since root `AGENTS.md` §4.4 makes spec citation normative, this
//! test is the enforcement mechanism.

use std::fs;
use std::path::{Path, PathBuf};

/// Repository root, derived from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root must exist")
}

/// Every markdown file that MkDocs builds into a page.
fn built_pages(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("docs")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // The two trees excluded from the built site, plus dotdirs
                // (MkDocs excludes `.*` implicitly) and the local venv.
                if name == "specs" || name == "superpowers" || name.starts_with('.')
                {
                    continue;
                }
                stack.push(path);
            } else if name.ends_with(".md") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn built_pages_do_not_link_into_excluded_trees() {
    let root = repo_root();
    let pages = built_pages(&root);
    assert!(
        !pages.is_empty(),
        "found no built markdown pages under docs/ — the walk is broken"
    );

    let mut offences = Vec::new();
    for page in &pages {
        let text = fs::read_to_string(page).expect("page must be readable");
        let rel = page.strip_prefix(&root).unwrap_or(page).display();
        for (lineno, line) in text.lines().enumerate() {
            for target in link_targets(line) {
                if target.starts_with("http://") || target.starts_with("https://")
                {
                    continue;
                }
                let normalised = target.trim_start_matches("./");
                let hits_excluded = normalised
                    .split('/')
                    .any(|seg| seg == "specs" || seg == "superpowers");
                if hits_excluded {
                    offences.push(format!(
                        "{rel}:{}: relative link `{target}` points into a tree \
                         excluded from the built site. MkDocs logs this at INFO \
                         only, so --strict will not catch it. Use an absolute \
                         URL: https://github.com/digitallabor-berlin/foundry/\
                         blob/main/docs/{normalised}",
                        lineno + 1
                    ));
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "{} documentation link(s) into excluded trees:\n{}",
        offences.len(),
        offences.join("\n")
    );
}

/// Extract each markdown inline-link target from one line.
fn link_targets(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b']' && bytes[i + 1] == b'(' {
            if let Some(end) = line[i + 2..].find(')') {
                let target = &line[i + 2..i + 2 + end];
                // Ignore pure fragments — those are validated by
                // `validation.links.anchors: warn` in mkdocs.yml.
                if !target.starts_with('#') && !target.is_empty() {
                    out.push(target.to_string());
                }
                i = i + 2 + end;
                continue;
            }
        }
        i += 1;
    }
    out
}
```

- [ ] **Step 2: Prove the test can fail**

Temporarily add a bad link to a built page:

```bash
echo '' >> docs/manual/reference/specs.md
echo 'BAD: [spec](../../specs/paso-core.md)' >> docs/manual/reference/specs.md
cargo nextest run -p foundry --test docs_hygiene --no-fail-fast
```

Expected: **FAIL**, naming `docs/manual/reference/specs.md` and the line number.
A test that cannot fail proves nothing — do not skip this step.

- [ ] **Step 3: Remove the deliberate breakage**

```bash
git checkout docs/manual/reference/specs.md
cargo nextest run -p foundry --test docs_hygiene --no-fail-fast
```

Expected: PASS.

- [ ] **Step 4: Confirm mkdocs would NOT have caught it**

This documents *why* the test exists. Re-add the bad link, run the strict
build, and confirm it passes anyway:

```bash
echo 'BAD: [spec](../../specs/paso-core.md)' >> docs/manual/reference/specs.md
source .venv/bin/activate
mkdocs build --strict && echo "CONFIRMED: --strict passed despite the dead link"
git checkout docs/manual/reference/specs.md
```

Expected: the strict build **passes**, printing the confirmation. If it fails
instead, mkdocs behaviour has changed — report it, because the spec's §3
rationale would then be stale.

- [ ] **Step 5: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 6: Update the tests AGENTS.md index**

`crates/foundry/tests/AGENTS.md` carries a table of what each test file covers.
Add a row for `docs_hygiene.rs`: it enforces that built documentation pages link
into `docs/specs/` and `docs/superpowers/` only by absolute URL, because MkDocs
logs such links at INFO and `--strict` cannot catch them.

- [ ] **Step 7: Commit**

```bash
git add crates/foundry/tests/docs_hygiene.rs crates/foundry/tests/AGENTS.md
git commit -m "test: enforce absolute URLs for links into excluded doc trees

MkDocs caps the log level for a link pointing at an exclude_docs-excluded
file to INFO, so --strict cannot catch it and no config key promotes it.
Verified both directions: this test fails on a planted bad link, and
mkdocs build --strict passes on the same link."
```

---

## Task 13: Final verification and handoff

**Files:** none modified.

- [ ] **Step 1: Full gate**

```bash
cargo fmt
cargo nextest run --workspace --no-fail-fast --status-level fail
cargo clippy --workspace --all-targets -- -D warnings
```

- [ ] **Step 2: The E2E suite** (`AGENTS.md` §5.2 — before PR, not per task)

```bash
cargo nextest run -p foundry --test e2e_full_flow --run-ignored ignored-only
```

- [ ] **Step 3: Strict build and nav completeness**

```bash
source .venv/bin/activate
mkdocs build --strict
grep -cE '\.md$' mkdocs.yml     # expect 29
```

- [ ] **Step 4: Serve and review by eye**

```bash
mkdocs serve
```

Open <http://127.0.0.1:8000/>. Check: every nav group expands; no page is
blank; no page has two `h1`s; the Home signposts all work; the conformance
report renders its tables.

- [ ] **Step 5: Confirm no content was lost, one last time**

```bash
git show <TASK-9-PARENT-COMMIT>:README.md | wc -l   # expect 1431
wc -l README.md                                     # expect ~120-160
```

- [ ] **Step 6: Report the two owner actions**

Neither can be done from the codebase — surface both explicitly:

1. **Settings → Pages → Source = "GitHub Actions"**, required once before the
   first deploy succeeds.
2. **Decide whether the docs build becomes a required status check.**

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: §4 page tree → Tasks 2–8;
§4.1 merges → the concatenated ranges in Tasks 3, 4; §4.2 new pages → Task 8;
§4.4 duplication policy → Task 9 Step 4; §5.1 requirements → Task 1 Steps 1–2;
§5.2 mkdocs.yml → Task 1 Step 4; §5.3 hygiene test → Task 12; §6 CI → Task 1
Step 9; §7.1 conformance links → Task 1 Step 7; §7.2 anchors → Tasks 2, 4, 5, 6,
7; §7.3 inbound refs → Task 10; §7.4 AGENTS.md rule → Task 11; §8.1 verbatim
rule → Global Constraint 1; §8.3 verification → Task 9 Step 2 and Task 13; §8.4
done criteria → Task 13.

**Deviation recorded:** the conformance link rewrite moves from spec §8.2 step 3
into Task 1, because `nav.omitted_files: warn` plus an existing page in
`docs_dir` makes it inseparable from the scaffold. Documented above under
"Deviation from the spec's sequencing".

**Known rough edge:** the forward-reference problem. Six links point at pages
created in later tasks, and strict nav validation will not tolerate a dangling
target. The plan handles this by temporarily stripping those six links to plain
text and restoring them in the task that creates the target (Task 4 Step 3 →
Task 5 Step 8; Task 4 Step 4 → Task 6 Step 5 and Task 7 Step 6; Task 2 Step 4 →
Task 5 Step 9). Each restore step names the README line to recover the original
text from. This is the alternative to creating 29 stub pages in Task 1, which
would have made every intermediate commit build a site full of empty pages.

**Placeholder scan.** No "TBD", "TODO", "implement later", or "similar to Task
N" remains. Every code step carries the actual content. Two steps deliberately
delegate judgement rather than prescribe it, and both say so explicitly: Task 8
Steps 1–3 (assembling the reference pages from sources named by command) and
Task 10 Step 3 (four references whose target section must be read from context).
In both cases the instruction is to report rather than guess.

**Type and name consistency.** Checked across tasks: the 29 nav paths in Tasks
1–8 match the File Structure table and the `RANGES` list in Task 9's checker;
`docs_hygiene.rs`'s three helpers (`repo_root`, `built_pages`, `link_targets`)
are defined once, in Task 12, and referenced nowhere else; the
anchor slug `abca-challenge-retrieval-post-challenge` is produced in Task 5
Step 2 and consumed in Task 5 Step 8 with a verification step between them.

**Line-range accounting — verified mechanically, and it caught a bug.** The 27
ranges in Task 9's `RANGES` list were checked for gaps and overlaps by sorting
them and walking the boundaries. The first pass reported
`GAP: 169..172` — the `## Running the Project` heading and its intro paragraph,
which no page claimed. Left unfixed, Task 9 would have deleted four lines that
existed nowhere else, while every per-task strict build stayed green and the
fingerprint checker never looked at them (a range absent from `RANGES` is not
checked). `quickstart.md` now starts at 169, and the re-run reports no gap and
no overlap across 21–1428.

Two ranges are excluded by design: 1–20 goes to `docs/index.md`, which is not a
manual page and so is not in the checker, and 1429–1432 (`## License`) stays in
the README. Ranges 409–463 and 464–512 belong to two different pages, which is
why `test-console.md` and `dc-api-origins.md` are built from non-contiguous
slices — that is intentional, not an overlap.

**Lesson recorded for the executor:** the fingerprint checker in Task 9 can only
verify ranges that appear in `RANGES`. It cannot detect a range nobody listed.
The gap-and-overlap walk above is the check that catches *that* class of error,
and it should be re-run if any range in this plan is edited.

**One residual risk the plan cannot remove.** Task 9 deletes 1,280 lines of
README. The fingerprint checker in Step 3 is the guard, and it runs *before* the
deletion with an explicit "if it fails, stop" instruction. But a fingerprint is
a sample, not a proof of byte-equality: a range whose prose lines are all under
50 characters, or which is entirely code, is reported as `NOTE ... skipped`
rather than verified. Task 9's reviewer should read those NOTE lines and
spot-check those ranges by hand. The plan flags this rather than implying the
checker is exhaustive.
