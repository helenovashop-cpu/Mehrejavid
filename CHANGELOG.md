# Changelog

## Unreleased
- Docs: multi-charity setup guide (`docs/en/multi-charity-setup.md`)
- Tests: online donation endpoints (amount/phone validation, public stats, gateway-callback failure and replay paths) in `tests/donation_test.php`; run in CI
- Tests: patient registration and SMS OTP verification, patient financial requests and admin profile edits (`tests/registration_test.php`); run in CI
- Secrets moved to `config.php` (git-ignored); random initial admin password
- Added MIT license, contributing guide, security policy
- Added CI lint workflow and issue/PR templates
- Added roadmap
- Added English documentation (`docs/en/README.md`)
- Added automated API smoke tests (`php tests/smoke_test.php`) covering CSRF, role checks, admin login and login rate-limiting; run in CI
- Fixed: `accounting_category_create`, `accounting_bank_account_create` and `donor_create` returned the audit-log row id instead of the new record's id
- Tests: accounting flow (categories, accounts, transactions, summary/balances) and admin password change
- Tests: document review statuses (admin-only, notification on correction, access control) and the admin donor list
- Tests: donor create/update/detail/merge (donations move to the kept donor)
- Hardening: `donor_create` now validates the phone number format like `donor_update` does
- Tests: internal account transfers (balances move, income/expense totals unchanged, deleting one leg removes both)
- Tests: transaction list filters, edit and delete (with CSRF/404 checks), monthly budgets vs. actual spend, audit-log entries and admin database backup
- Tests: admin account management (create/validate/promote/delete, self-demotion and self-delete guards), settings validation, and reviewer-vs-super_admin permission boundaries
- Tests: case lifecycle (manual creation, search, status validation, priority flag, timeline, deletion cleanup)
- Tests: per-case message thread and notification feed (patient/admin messaging, guest and cross-patient isolation, mark-as-read) in `tests/messaging_test.php`
- Tests: editing and deleting accounting categories and bank accounts (CSRF/guest/404 checks, in-use delete guard, audit log) in `tests/accounting_admin_test.php`
- Tests: accommodation rooms (admin-only access, assign/checkout validation, one active guest per room, patient notification) in `tests/accommodation_test.php`
- Tests: admin two-factor authentication (setup, two-step login, wrong/malformed codes, clock-drift window, disable with password, audit log, TOTP rate limit) in `tests/two_factor_test.php`, using an independent RFC 6238 generator
- Added `tools/demo_seed.php`: local demo instance pre-filled with fake data

## 0.1.0
- Initial public release
