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

The landing page, docs and live demo are the same `web/` app in site mode, with no engine behind it: the demo
runs on simulated data. Host it on a platform with a global CDN (Vercel, Cloudflare or Netlify) with:

| Setting | Value |
|---|---|
| Root directory | `web` |
| Build command | `npm run build` |
| `NEXT_PUBLIC_SITE_URL` | the public address, e.g. `https://farrier.dev` (on Vercel it is detected) |
| `FARRIER_API_URL` | not set: the demo stays simulated |

Installs never serve this site: the Docker image runs in app mode, where `/` opens the dashboard.

## License

Contributions are released under the [MIT License](LICENSE), the same as the project.
