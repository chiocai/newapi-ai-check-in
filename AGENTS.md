# Repository Guidelines

## Project Structure & Module Organization
The repository is a Python automation project centered on `main.py` for standard New-API check-ins and `checkin_996/main.py` for the 996 flow. Shared business logic lives in `checkin.py`, authentication helpers in `sign_in_with_github.py` and `sign_in_with_linuxdo.py`, and reusable utilities in `utils/`.

Keep docs in `docs/`, example screenshots in `assets/`, and GitHub Actions workflows in `.github/workflows/`. Place isolated unit tests in `tests/`; provider-specific or end-to-end regression scripts currently use root-level `test_*.py` files.

## Build, Test, and Development Commands
- `uv sync --dev` — install runtime and development dependencies from `pyproject.toml` and `uv.lock`.
- `uv run camoufox fetch` — download the Camoufox browser required by browser-based sign-in flows.
- `uv run python -u main.py` — run the primary multi-account check-in entrypoint locally.
- `uv run python -u checkin_996/main.py` — run the separate 996 provider flow.
- `uv run pytest tests/` — run focused unit tests.
- `uv run pytest test_b4u_topup.py` — run a targeted regression test file.
- `uv run ruff check .` / `uv run ruff format .` — lint and format the codebase.

## Coding Style & Naming Conventions
Target Python 3.11+. Follow `ruff` settings in `pyproject.toml`: tabs for indentation, single quotes, and a 120-character line limit. Use `snake_case` for modules, functions, and test files; reserve `PascalCase` for classes such as `CheckIn`. Keep provider-specific branches small and move reusable HTTP, browser, or notification logic into `utils/`.

## Testing Guidelines
Use `pytest` with `pytest-mock` and `pytest-cov` when extending coverage. Name new tests `test_<feature>.py`, and keep test functions descriptive, for example `test_retry_on_401_session_expiry`. No hard coverage gate is configured, so add at least one focused test for each bug fix or provider feature and run the smallest relevant test set before opening a PR.

## Commit & Pull Request Guidelines
Recent history follows Conventional Commit prefixes with concise Chinese summaries, for example `feat: 支持...`, `fix: 修复...`, and `refactor: 精简...`. Keep commits scoped to one change. PRs should describe the provider or flow touched, list new secrets or env vars, link the related issue, and include logs or screenshots when behavior changes are visible in GitHub Actions.

## Security & Configuration Tips
Never commit real account cookies, tokens, OTP links, or `.env` data. Store runtime data in GitHub Environment secrets such as `ACCOUNTS`, `PROVIDERS`, and `PROXY`. When changing login or notification flows, verify that logs do not leak sensitive headers, session values, or webhook URLs.
