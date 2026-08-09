# Contributing to Verdix

Verdix is an AGPL-3.0 AI triage co-pilot for Suricata. Contributions are welcome:
bug fixes, enrichment sources, prompt improvements, docs, and corpus tooling.

## Local development

```bash
git clone https://github.com/verdixsec/verdix.git
cd verdix
python -m venv .venv && source .venv/bin/activate   # Python 3.11+
pip install -r requirements.txt
```

This installs the runtime and test dependencies. The linter and type checker are not
pinned in `requirements.txt`; add them with `pip install ruff mypy`.

To run the full stack (app plus the Gemma/Ollama container), follow
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). Do not duplicate those steps here.

### Building the app image locally

`geoip/*.mmdb` is gitignored, so a clean clone cannot `docker build` the app image until
you fetch the GeoIP databases once:

```bash
python scripts/fetch_geoip.py
docker build -t verdix-app:local .
```

CI runs the same script in the `build-app` job, so there's no separate fetch logic to
keep in sync.

## Before opening a PR

Run these locally and make sure they pass:

```bash
pytest
ruff check .
mypy src/
```

The evaluation harness ships under `eval/` and runs against your own labeled corpus.
The public repository does not include the labeled corpus (`eval/data/` is excluded), so
point the harness at a corpus you assemble yourself. If your change touches the prompt,
the LLM client, or scoring, run the harness against your corpus and confirm the verdict
metrics hold before you open the PR.

These checks are local discipline. CI currently runs only the secret scan, so a green
pull request still depends on you running the suite yourself.

## Conventions

- Branch off `main` with a short-lived feature branch. Use a prefix: `feat/`, `fix/`,
  `chore/`, or `docs/`.
- Write [Conventional Commits](https://www.conventionalcommits.org): `fix: correct RDAP
  timeout handling`.
- Keep PRs small and focused. One change per branch is easier to review and revert.
- Merge to `main` only when the tests and the eval harness pass.

## License

Contributions are accepted under [AGPL-3.0](LICENSE).
