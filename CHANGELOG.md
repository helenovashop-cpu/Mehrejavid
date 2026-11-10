# Changelog

## Unreleased
- Secrets moved to `config.php` (git-ignored); random initial admin password
- Added MIT license, contributing guide, security policy
- Added CI lint workflow and issue/PR templates
- Added roadmap
- Added English documentation (`docs/en/README.md`)
- Added automated API smoke tests (`php tests/smoke_test.php`) covering CSRF, role checks, admin login and login rate-limiting; run in CI
- Fixed: `accounting_category_create`, `accounting_bank_account_create` and `donor_create` returned the audit-log row id instead of the new record's id
- Tests: accounting flow (categories, accounts, transactions, summary/balances) and admin password change
- Tests: donor create/update/detail/merge (donations move to the kept donor)
- Hardening: `donor_create` now validates the phone number format like `donor_update` does
- Tests: internal account transfers (balances move, income/expense totals unchanged, deleting one leg removes both)
- Tests: transaction list filters, edit and delete (with CSRF/404 checks), monthly budgets vs. actual spend, audit-log entries and admin database backup
- Tests: case lifecycle (manual creation, search, status validation, priority flag, timeline, deletion cleanup)

## 0.1.0
- Initial public release
