# Contributing to Farrier

Thanks for helping. Bug reports, docs fixes, connector requests and code are all welcome, and you don't need to
know Python, Next.js or certificates to start: this guide takes you from nothing to a merged pull request.

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems are never reported in
public: follow the [security policy](SECURITY.md).

**New here?** Pick an issue labelled
[`good first issue`](https://github.com/gagankarthik/farrier/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22),
leave a comment that you're taking it, and follow the steps below.

## What's in the repository

Farrier is three programs in one repository. You only need the tools for the part you change.

| Folder | What it is | Written in | You need |
|---|---|---|---|
| `farrier/` and `tests/` | The **engine**: scans, renews and deploys certificates; serves the API | Python | Python 3.11+ |
| `web/` | The **dashboard** people use, and its sign-in | TypeScript, Next.js (React) | Node.js 22.18+ |
| `site/` | The **website and docs** at [farrier-erc1.vercel.app](https://farrier-erc1.vercel.app) | TypeScript, Next.js, MDX | Node.js 22.18+ |
| `deploy/` | Docker Compose, Helm chart, Terraform | YAML, HCL | nothing to run locally |
| `functions/` | Cloud functions that react to Farrier's events | Python | Python 3.11+ |

## 1. Install the tools (once)

- **Git**: [git-scm.com/downloads](https://git-scm.com/downloads). Check with `git --version`.
- **Python 3.11 or newer**: [python.org/downloads](https://www.python.org/downloads/). Check with
  `python --version` (on macOS and Linux it may be `python3`; use that wherever this guide says `python`).
- **Node.js 22.18 or newer** (only for `web/` or `site/`): [nodejs.org](https://nodejs.org) (the LTS
  version). It includes `npm`. Check with `node --version`.

Docker, Terraform and Helm are **not** needed: CI checks those parts for you.

**Windows:** the commands below work in Git Bash, which comes with Git. In PowerShell, activate the virtual
environment with `.venv\Scripts\Activate.ps1` and set variables with `$env:NAME="value"; command` instead of
`NAME=value command`.

## 2. Get the code

1. Click **Fork** at the top of [the repository](https://github.com/gagankarthik/farrier) to make your own copy.
2. Clone your fork and add the original as `upstream`, so you can pull in other people's changes later:

   ```bash
   git clone https://github.com/<your-username>/farrier.git
   cd farrier
   git remote add upstream https://github.com/gagankarthik/farrier.git
   ```

3. Make a branch for your change. Never work on `main`:

   ```bash
   git checkout -b fix-leave-dashboard-link
   ```

## 3. Set up the engine (Python)

A virtual environment keeps Farrier's packages separate from the rest of your computer.

```bash
python -m venv .venv
source .venv/bin/activate           # Windows Git Bash: source .venv/Scripts/activate
pip install -e ".[dev]"             # installs Farrier in editable mode, plus pytest
pip install ruff                    # the linter
```

`-e` means "editable": your code changes take effect without reinstalling. Run `source .venv/bin/activate`
again in every new terminal.

Check it works:

```bash
farrier --version                   # farrier 0.1.0
python -m pytest -q                 # runs every engine test; takes about a minute
```

You should see something like `276 passed, 3 skipped`. The skipped tests need a Let's Encrypt test server
that CI starts for you.

## 4. Set up the dashboard and website (Node.js)

Each app installs its own packages. Only do the one you're changing.

```bash
cd web                              # or: cd site
npm ci                              # installs exactly the versions in package-lock.json
cd ..
```

## 5. Run Farrier on your machine

Two terminals, both in the `farrier` folder:

```bash
# terminal 1: the engine, with 41 simulated TLS endpoints
source .venv/bin/activate
farrier demo
```

```bash
# terminal 2: the dashboard
cd web
FARRIER_API_URL=http://127.0.0.1:8740 npm run dev
```

Open http://localhost:3000. Changes you save in `web/src` appear in the browser straight away.

To see the dashboard without the engine, run `npm run dev` in `web/` with no `FARRIER_API_URL`: it uses
simulated data. To work on the website, run `npm run dev -- -p 3100` in `site/` and open http://localhost:3100.

## 6. Check your change

Run the same checks CI runs, for the parts you changed. A pull request can't be merged until they pass.

| You changed | Run |
|---|---|
| `farrier/` or `tests/` | `python -m pytest -q` and `ruff check farrier functions --select F` |
| `functions/` | `python -m pytest -q functions` |
| `web/` | in `web/`: `npm run lint`, `npx tsc --noEmit`, `npm test`, `npm run build` |
| `site/` | in `site/`: `npm run typecheck`, `npm run lint`, `npm run build` |
| `deploy/helm/` | `pip install pyyaml jsonschema` then `python deploy/helm/farrier/ci/check.py` |

What they mean: `pytest` and `npm test` run the tests, `ruff`, `npm run lint` and `tsc` catch mistakes without
running anything, and `build` proves the app still compiles.

**Add a test** for a bug fix (one that fails before your fix and passes after) and for new behaviour. Engine
tests live in `tests/`, named `test_<area>.py`; look at a neighbouring test and copy its shape. Dashboard tests
are `*.test.mjs` files next to the code they test.

## 7. Open a pull request

1. Commit with a message that says what the change does, in the imperative:

   ```bash
   git add <the files you changed>
   git commit -m "Send Leave dashboard to the docs instead of looping back"
   ```

   Add a short body after a blank line when the reason isn't obvious.

2. If you changed what users see or do, add one line to `CHANGELOG.md` under **Unreleased**.
3. Push your branch to your fork, then open the pull request on GitHub (it shows a **Compare & pull request**
   button):

   ```bash
   git push -u origin fix-leave-dashboard-link
   ```

4. Fill in the template: what changed, why, and how you tested it. Link the issue with `Fixes #123` so it closes
   when the pull request merges.
5. CI runs on your pull request. If a check fails, click **Details** to see why, fix it, commit and push again:
   the pull request updates by itself.
6. A maintainer reviews it. Answer comments by pushing more commits; there's no need to open a new pull request.

To catch up with changes others merged while you worked:

```bash
git fetch upstream
git rebase upstream/main
git push --force-with-lease
```

## Ground rules

- One change per pull request. Small pull requests get reviewed faster.
- Never commit secrets, keys, `.env` files or a data folder. In examples, credentials are `env:NAME` or
  `file:/path` references, never values.
- Connector and DNS provider changes: say whether you tried them on a real device or account, or only against
  the mocks in the tests.
- The dashboard and the website each keep a copy of a few shared files (marked
  `// Shared with site/: keep in step.`). Change both copies together.
- Not sure about an approach? Ask on the issue or in
  [Discussions](https://github.com/gagankarthik/farrier/discussions) before writing a lot of code.

## For maintainers

### Versioning

Farrier follows [Semantic Versioning](https://semver.org/). The version is in `farrier/__init__.py`,
`web/package.json` and `site/package.json`, and they must match. Pushing a `v*` tag runs the release workflow,
which checks that, then publishes the signed, multi-arch images `ghcr.io/gagankarthik/farrier` and
`farrier-web`.

### The website

`site/` is exported as plain files (`npm run build` writes `site/out/`) and hosted on Vercel: a project with
Root Directory `site`, framework Next.js. Every push to `main` that changes `site/` deploys it. Optional
variables: `NEXT_PUBLIC_SITE_URL` (the public address; detected on Vercel), `NEXT_PUBLIC_DEMO_URL` (a hosted
demo, if one exists) and `NEXT_PUBLIC_BASE_PATH` (only when served under a sub-path).

Installs never include the website: the Docker image is the dashboard only, and its documentation links follow
`FARRIER_DOCS_URL`, defaulting to the public docs.

## License

Contributions are released under the [MIT License](LICENSE), the same as the project.
