# Contributing

Thanks for helping small charities run better! Contributions of all kinds are welcome: bug reports, translations, docs, and code.

## Getting started
1. Fork the repo and clone it.
2. Copy `config.example.php` to `config.php` (never commit it).
3. Run locally with PHP's built-in server: `php -S localhost:8000`
4. Open `http://localhost:8000` — an admin account is created on first run (see README).

## Guidelines
- Never commit real beneficiary/donor data, API keys, or passwords.
- Keep the app dependency-free (PHP + SQLite, no build step) so it runs on shared hosting.
- Persian (RTL) UI is the primary language; keep UI strings in Persian.
- Open an issue first for large changes.

## Good first issues
- Translate the documentation to English/Arabic
- Add automated tests for `api.php`
- Split the frontend into smaller modules
