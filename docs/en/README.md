# Mehr Javid — English documentation

Mehr Javid is a lightweight, Persian-language (RTL) web application for running a small medical charity: beneficiary case management, accounting, donor tracking and an admin panel. It is a single-page frontend (`index.html`) talking to a single-file PHP + SQLite backend (`api.php`). There is no build step and no external dependency, so it runs on ordinary shared hosting (cPanel / LiteSpeed).

> The UI is in Persian by design. This page documents setup, architecture and the API for developers and administrators who do not read Persian.

## Requirements

- PHP 8.1+ with the `pdo_sqlite` extension
- A writable `data/` directory (created automatically; git-ignored)
- Optional: a Najva account (SMS/OTP) and a ZarinPal merchant ID (online donations)

## Quick start (local)

```bash
cp config.example.php config.php   # never commit config.php
php -S localhost:8000
```

Open `http://localhost:8000`. On first run an admin account is created:

- username: `admin`
- password: `admin_initial_password` from `config.php`, or an auto-generated one written to `data/INITIAL_ADMIN_PASSWORD.txt`
- you are forced to change it at first login; delete the file afterwards.

## Configuration (`config.php`)

| Key | Purpose |
|---|---|
| `najva_api_key` | Najva SMS API key (OTP login, notifications) |
| `najva_sender_line` | Approved SMS sender line |
| `zarinpal_merchant_id` | ZarinPal merchant ID (optional; enables online donations) |
| `admin_initial_password` | Initial admin password; leave empty to auto-generate |

## Architecture

- `index.html` — the whole UI (HTML/CSS/JS), RTL, responsive, light/dark themes.
- `api.php` — one entry point; the client sends an `action` and the server dispatches it. Tables are created/migrated automatically on first request, using SQLite in `data/`.
- Sessions with CSRF tokens (issued by the `bootstrap` action), rate limiting, an idle session timeout, an audit log, and password hashing with `password_hash`.

### Roles

| Role | Access |
|---|---|
| guest | public donation stats, registration, login |
| user | registers and tracks their own beneficiary cases, messages, notifications |
| admin: `reviewer` | reviews and updates cases |
| admin: `super_admin` | everything, including accounting, admin management, settings, backups |

## API overview

All calls go through `api.php` with an `action`. Main groups:

| Group | Actions (prefix) |
|---|---|
| Session / auth | `bootstrap`, `otp_request`, `otp_verify`, `user_register`, `user_login`, `user_logout`, `admin_login`, `admin_login_totp_verify`, `admin_logout`, `admin_change_password` |
| Cases (submissions) | `submission_create`, `submission_update`, `submission_delete`, `submission_list_mine`, `submission_list_all`, `submission_search`, `submission_set_status`, `submission_set_priority`, `submission_timeline_get`, `submission_asset` |
| Accounting | `accounting_transaction_*`, `accounting_category_*`, `accounting_bank_account_*`, `accounting_transfer_create`, `accounting_summary`, `budget_set`, `budget_vs_actual`, `financial_summary`, `financial_review` |
| Donors & donations | `donor_create`, `donor_update`, `donor_list`, `donor_detail`, `donor_merge`, `donation_request_payment`, `donation_verify`, `donation_public_stats`, `payment_record`, `payment_list` |
| Accommodation | `accommodation_room_list`, `accommodation_assign_room`, `accommodation_checkout` |
| Messaging | `message_send`, `message_list`, `notification_list`, `notification_mark_read` |
| Administration | `admin_create`, `admin_list`, `admin_delete`, `admin_set_role`, `settings_get`, `settings_update`, `audit_log_list`, `admin_backup_download`, `dashboard_stats` |
| Surveys | `survey_submit`, `survey_status`, `survey_stats` |

(See `api.php` for exact parameters; the list above reflects the current dispatcher.)

## Deployment checklist

1. Upload `index.html`, `api.php` and `config.php` (with your own keys).
2. Make sure `data/` is writable and **not** web-accessible (deny it in your server config).
3. Serve over HTTPS.
4. Log in as `admin`, change the password, delete `data/INITIAL_ADMIN_PASSWORD.txt`.
5. Schedule regular backups (`admin_backup_download`, or copy the SQLite file from `data/`).

## Privacy

This repository contains no real beneficiary or donor data. Keep it that way: never commit `config.php`, `data/` or any `*.sqlite` file. Security reports: see [SECURITY.md](../../SECURITY.md).

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md). Helpful next steps: automated tests for `api.php`, splitting the frontend into modules, Arabic documentation.
