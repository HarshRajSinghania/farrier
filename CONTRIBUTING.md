# Contributing to Farrier

Thanks for helping. Bug reports, connector requests, docs fixes and code are all welcome.
By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- **Bugs and features:** open an [issue](https://github.com/gagankarthik/farrier/issues/new/choose) first,
  so we can agree on the approach before you write code.
- **Questions and ideas:** use [Discussions](https://github.com/gagankarthik/farrier/discussions).
- **Security problems:** never in public. Follow the [security policy](SECURITY.md).

## Set up

```bash
git clone https://github.com/gagankarthik/farrier.git && cd farrier
pip install -e ".[dev]"            # Python 3.11 or newer
farrier demo                       # 41 local TLS endpoints, API on :8740

cd web && npm install              # Node.js 20 or newer
FARRIER_API_URL=http://127.0.0.1:8740 npm run dev   # site, docs and dashboard on :3000
```

## Checks

Run the same checks CI runs before you open a pull request:

```bash
python -m pytest -q                               # engine
cd web && npm run lint && npx tsc --noEmit && npm run build && npm test
```

CI also runs the ACME client against Pebble, Let's Encrypt's test server (`tests/test_pebble.py`).

## Pull requests

- Keep each pull request to one change, and add or update tests for it.
- New behaviour that users see needs a line in `CHANGELOG.md` under **Unreleased**.
- Never commit secrets, keys or a data directory. Credentials in examples are `env:` or `file:` references.
- Connector and DNS provider changes: say whether you ran them against a real device or account,
  or only against the mocks.
- Write commit messages in the imperative ("Add Citrix ADC connector"), with a short body when the
  reason isn't obvious.

## Versioning

Farrier follows [Semantic Versioning](https://semver.org/). Maintainers cut releases as described
at the top of [CHANGELOG.md](CHANGELOG.md).

## The public website

The landing page and docs are `site/`, a separate Next.js app exported as plain files (`npm run build` in
`site/` writes `site/out/`). It is hosted on Vercel: a project with Root Directory `site` and framework
Next.js; no other settings are needed. Optional environment variables:

| Variable | Value |
|---|---|
| `NEXT_PUBLIC_SITE_URL` | the public address for metadata, the sitemap and robots.txt (on Vercel the production domain is detected) |
| `NEXT_PUBLIC_DEMO_URL` | the live demo's address; unset, "Live demo" links to the install guide's "Try it" |
| `NEXT_PUBLIC_BASE_PATH` | only if the site is served under a sub-path, e.g. `/farrier` |

`out/` is plain HTML, CSS and JavaScript, so any static host (Cloudflare Pages, S3 and CloudFront, GitHub
Pages) works too.

The live demo is `web/` (the dashboard) deployed with no `FARRIER_API_URL`: with no engine behind it, it runs
on simulated data. Installs never include the website: the Docker image is the dashboard only, where `/`
opens `/dashboard`. Its documentation links follow `FARRIER_DOCS_URL` (per install, at runtime), else
`NEXT_PUBLIC_DOCS_URL` set when the image is built, else the docs' source on GitHub.

## License

Contributions are released under the [MIT License](LICENSE), the same as the project.
