# Development guide

Development documentation for [WireGuard for Decky](../README.md).
Run the commands below from the repository root.

## Build

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and Git.
uv downloads Python 3.13 and installs the pinned Node.js 22/npm and development
tools in the repository's `.venv`; no system Node.js installation is needed:

```sh
uv sync --locked
uv run --locked npm ci
uv run --locked npm test
uv run --locked npm run package
```

The installable archive is `out/decky-wireguard-0.1.0.zip`. Its single top-level
`decky-wireguard` directory contains the backend, plugin metadata, compiled
`dist/index.js`, the README, and four allowlisted Markdown guides in `docs/`.
It also contains the project license and third-party license texts and notices.
No third-party Python packages or runtime npm installation are needed. The
bundled `py_modules/nm_keyfile.py` uses `ctypes` with the system's `libnm` for
offline advanced-property conversion. Profile editing requires NetworkManager
1.44+ for revision-checked writes. Secret-bearing writes go directly over the
configured Unix system bus; keyfiles for `nmcli --offline` travel only by pipe.
Profile reads also use D-Bus directly. `nmcli` and `busctl` are still used
for status and readiness. File import runs `py_modules/read_conf.py` with
`/usr/bin/python3` under the account identified by Decky's `DECKY_USER`.
See [Install](../README.md#install) to install it.

For frontend development, use `uv run --locked npm run watch`;
`uv run --locked npm run typecheck` checks the UI.
The build uses Decky's official Rollup tooling and externalizes React and
`@decky/ui`, provided by the loader. TypeScript is pinned to 5.9 because the
current Decky Rollup plugin requires its JavaScript compiler API, which is not
available in TypeScript 7.

The official build tooling currently has transitive npm advisories in its
development dependencies, including `glob`, `minimatch`, and `deepmerge`.
These packages are not shipped in the plugin archive; avoid building untrusted
source trees. `npm audit --omit=dev` reports no runtime dependency advisories
for the committed lockfile at creation time.

## Branches and releases

Two long-lived branches produce two kinds of release. Every push to them runs
`.github/workflows/release.yml`: the [checks](#ci) must pass before the ZIP is
built, verified, and published on the
[GitHub Releases page](https://github.com/Polgonite/decky-wireguard/releases).

| Branch | Release | Version | Marked as |
| --- | --- | --- | --- |
| `main` | Stable | `package.json` as is, such as `0.2.0` | Latest release |
| `dev` | Development build | `0.2.0-dev.<run>.<attempt>.sha<commit>` | **Pre-release**, never latest |

Work happens on `dev`, which the maintainer can push to directly. `main` only
accepts pull requests from `dev`, so each merge into `main` publishes a stable
release, see [Release procedure](#release-procedure). Both branches are
protected by GitHub rulesets, see [Branch protection](#branch-protection).

### Versioning rules

- `package.json` is the only source of the plugin version (the `pyproject.toml`
  version is a placeholder for the tooling environment). It holds the version
  that will be released next, as plain `MAJOR.MINOR.PATCH`.
- Each stable release is exactly one step above the latest stable tag
  `vMAJOR.MINOR.PATCH`: the next patch, minor, or major version. Choose
  **patch** for fixes only, **minor** for new features or changed behavior,
  and **major** for breaking changes, such as dropping a supported SteamOS or
  Decky Loader version or settings that do not carry over. While the version
  is `0.x`, breaking changes may use a minor step. The first stable release
  uses the `package.json` version as is.
- `npm run bump -- patch|minor|major` sets `package.json` and
  `package-lock.json` to that next version, based on the stable tags on
  `origin`. `tools/release_version.py` implements these rules for both the
  helper and the workflow, which fails for an older, already released, or
  skipped version.
- Development builds append `-dev.<run>.<attempt>.sha<commit>` (the workflow
  run ID, attempt number, and short commit SHA) in the packaged `package.json`
  and ZIP filename. Source versions are not committed back, and reruns create
  distinct releases instead of overwriting assets. Right after a stable
  release, `dev` still holds the released version; its development builds then
  use the next patch version, so they keep sorting above the latest stable
  release until the next bump.
- SemVer 2.0 precedence applies: `0.2.0-dev.…` is older than `0.2.0`, and
  development builds order by run ID, attempt, then commit.
- A stable release is always rebuilt and published from the merged commit on
  `main`. Never turn a development build into a stable release by editing it
  or removing its pre-release flag; the updater also ignores a non-prerelease
  whose version has a pre-release suffix.

### Update channels

The updater selects the highest eligible version, not the latest publication
date, and never installs a version that is not newer than the installed one.

- By default only the latest stable release is considered. It is found through
  GitHub's `releases/latest`, so many development builds cannot hide it.
- With **Development updates** enabled (advanced settings), the newest 100
  releases are also considered, together with the latest stable release. A
  stable release outranks the development builds of the same version.
- Installations of a development build follow the same rules. Without the
  opt-in they only move to a stable release that is newer than their own.
- Automatic checks (**Check for updates automatically**, off by default) use
  the same rules and only show a notification.
- A missing SHA-256 digest, an invalid asset URL, a network error, or an installed
  version that is not valid SemVer ends the check with a visible error. The
  updater does not fall back to another build.

### Release procedure

1. On `dev`, choose the [version step](#versioning-rules) and bump:
   `uv run --locked npm run bump -- minor`. Commit `package.json` and
   `package-lock.json`, then push `dev`. Skip this step for the first stable
   release, which uses the current version.
2. Open a pull request from `dev` into `main`. Its **Checks** run shows which
   release merging publishes, such as "Stable release v0.2.0 is a minor
   release after v0.1.0". It fails for an invalid version or a pull request
   from any branch other than `dev`.
3. Review and merge it with a merge commit, the only method allowed on
   `main`, which keeps `dev` and `main` histories related. As the only code
   owner, the maintainer merges through the admin bypass for the approval;
   passing checks stay required.
4. The resulting push to `main` runs the checks again, then builds the ZIP
   from the merged commit, publishes `v<version>` as the latest release with
   notes generated since the previous stable tag, and verifies the published
   release: the tag points to the merged commit, the release is neither a
   draft nor a pre-release, its notes name the commit, its only asset is
   byte-identical to the verified ZIP, and GitHub reports it as the latest
   release.

If anything fails before publication, nothing is published; fix it on `dev`
and open a new pull request, since the version is still unreleased. If the
verification after publication fails, inspect the release before anyone
installs it. Delete a broken release together with its tag only if it was
never installed; otherwise fix forward with the next patch version.

### CI

Both CI jobs use Ubuntu 24.04 runners to avoid automatic OS migrations.
The checkout and setup actions use Node.js 24 internally; the project still
builds with Node.js 22.

The **Checks** job runs for every pull request and every push to `main` or
`dev`, in the same locked uv environment as local development. It runs all
pre-commit hooks on all files (Ruff, ESLint, TypeScript, the backend and
frontend tests including offline NetworkManager conversion, and
actionlint/ShellCheck), validates the release version for the target branch,
then builds the ZIP and checks it with `tools/verify_package.py`. Its token is
read-only and not persisted, so pull requests, including those from forks,
cannot publish anything. Superseded pull request runs are canceled.

The publication job runs only for pushes and depends on the checks
(`needs: checks`). If the checks fail or are canceled, it is skipped and
nothing is published. It rebuilds the ZIP, repeats the archive verification,
and is the only job with `contents: write`. Runs on the same branch are
serialized by a concurrency group, and a running publication is never
canceled. GitHub keeps only the newest waiting run per group, so pushes in
quick succession can skip the build of an intermediate commit.

The workflow uses the automatic `GITHUB_TOKEN`; no additional secret is
required. Repository or organization policies must allow GitHub Actions to
create releases.

### Branch protection

Three repository rulesets (Settings → Rules) protect the branches:

- **Protect main (stable releases)** and **Protect dev (development builds)**
  require pull requests with one approval from a code owner
  (`.github/CODEOWNERS` names the maintainer), dismiss stale approvals, and
  block force pushes and deletion. `main` only allows merge commits. The
  repository admin can bypass them: always on `dev`, so direct pushes work,
  but only through a pull request on `main`, so merging a `dev` pull request
  into `main` is possible without a second reviewer while direct pushes to
  `main` are rejected.
- **Require checks on main** requires a successful **Checks** status from
  GitHub Actions before anything merges into `main`. It has no bypass, not
  even for the admin. `dev` has no required status check because direct
  pushes have none yet; the publication job's dependency on the checks still
  keeps failing development builds from being published.

If the **Checks** job is renamed, update the required status check, otherwise
merges into `main` stay blocked.

## Development environment and pre-commit

From the repository root, create the uv venv, install npm dependencies, and
install the Git pre-commit hook:

```sh
uv sync --locked
uv run --locked npm ci
uv run --locked pre-commit install
uv run --locked pre-commit run --all-files
uv run --locked npm run package
```

The hooks lint Python with Ruff, lint JavaScript/TypeScript with ESLint, check
frontend types, run backend tests, and validate Actions workflows (including
embedded shell) with actionlint/ShellCheck. Python is selected by
`.python-version`; `pyproject.toml` pins Node.js, pre-commit, Ruff, actionlint, and
ShellCheck, and `uv.lock` locks their dependencies. Node.js, actionlint, and
ShellCheck are supplied through Python wrapper packages. Local and CI commands
use `--locked` so dependency changes require an explicit `uv lock`.

The hooks invoke tools through `uv run --locked`, so they work without activating
the venv, provided uv and Git are on your `PATH`. For an interactive shell with
plain `npm`, `python3`, and `pre-commit` commands, activate it:

```sh
source .venv/bin/activate
```

VS Code retains the ESLint and Ruff extension recommendations in
`.vscode/extensions.json`. Launch it from the activated shell so extensions can
find the venv's Node.js and Python tools.

### Committing from the terminal

After the setup above, run these commands from the repository root:

```sh
git status --short
git diff
git add README.md src/index.tsx # Replace with the files you intend to commit.
git diff --cached --check
git diff --cached
```

Commit normally; the installed hook uses the uv environment and your existing
Git identity:

```sh
git commit -m "Describe the change"
git status --short
git --no-pager log --oneline -1
```

If Git cannot resolve your identity, configure it first. If a hook
fails, fix the reported issue and retry without bypassing hooks. If a hook
rewrites files, review and stage those changes before retrying. An empty final
status means the working tree is clean.

## Testing

Run the backend and frontend tests with:

```sh
uv run --locked npm test
```

Backend tests mock live NetworkManager and `wg` operations. When `nmcli` is
installed they also exercise real offline profile conversion without accessing
host network connections.
`npm test` also exercises the frontend readiness monitor with mocked Steam APIs,
including online/offline login, unfinished initialization, API errors, and unloading.
Real Steam Deck/Decky integration must be checked on the device.
