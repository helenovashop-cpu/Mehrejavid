# Setting up Mehr Javid for another charity

Mehr Javid is built for one charity, but nothing stops another small Persian-speaking charity from running its own copy. **One installation serves one charity**: every deployment has its own `config.php` and its own SQLite database in `data/`. There is no multi-tenant mode, so run one copy per organisation (for example one hosting account or sub-domain each).

This guide lists what you can change from the admin panel, what is still hard-coded and needs a small edit, and what to prepare with your SMS and payment providers. Where something is hard-coded, line numbers are deliberately not given; search for the quoted text instead.

## 1. Install a fresh copy

Follow the Deployment checklist in [README.md](README.md). Use a new, empty `data/` directory; never copy another charity's database. After first login (`admin`), change the password and delete `data/INITIAL_ADMIN_PASSWORD.txt`.

## 2. What you can change in the admin panel

Log in as a `super_admin` and open **Settings**. These values are stored in the database (`settings` table) and apply without touching code:

| Setting | Effect |
|---|---|
| `org_name` | Organisation name; at the moment only the privacy-policy page uses it (see section 3 for the other places) |
| `org_reg_number`, `org_address`, `org_phone` | Contact/registration details |
| `org_instagram`, `org_whatsapp` | Social links |
| `brand_color` | Primary colour of the interface |
| `default_theme` | `light` or `dark` |
| `session_timeout_minutes` | Idle session timeout |
| `notify_sms_*` | Switch individual SMS notifications on or off |
| `stale_case_days` | After how many days a case is flagged as stale |
| `specialties` | The list of medical specialties offered on the request form (JSON list of `value` / `label`) |

Accounting categories and bank accounts are also managed in the panel (accounting section), so you can rename or delete the defaults.

## 3. What is still hard-coded

These items still carry the original charity's name or data. Search for the text shown and replace it with your own:

1. **Page metadata in `index.html`**: `<title>`, the `description` / `keywords` / `author` meta tags, the Open Graph and Twitter tags, the `canonical` link and the JSON-LD block near the top (it contains the organisation name and URL).
2. **Logo**: the `LOGO_DATA_URL` constant in `index.html` is a base64 `data:` URL. Replace it with your own logo (keep it small, a few tens of KB).
3. **Name and texts in `index.html`**: the header brand name, the page-title suffix, the footer, the logo `alt` text, the About page, the donation page sub-title, the donor/accounting report headings and the printed donation receipt (including its signature line) all contain the original charity's name as plain text. Replace it with your own and rewrite the About text to describe your activity.
4. **Seeded bank accounts in `api.php`**: on a brand-new database four accounts are created (search for the loop that inserts into `accounting_bank_accounts`). Replace the names before the first request, or rename them afterwards in the admin panel.
5. **Default `org_name`** in `SETTINGS_DEFAULTS` in `api.php`.
6. **SMS wording** in `api.php`: the thank-you message after an online donation contains the organisation name.

Tip: after editing, run `grep -n "مهر جاوید" index.html api.php` and make sure nothing you did not intend to keep is left.

## 4. SMS (Najva)

Iranian SMS providers do not allow free-text messages on a shared service line; every message has to use a pre-approved template (pattern). You need three templates in your Najva panel and must put their exact names into `api.php`:

| Constant | Used for |
|---|---|
| `NAJVA_LOGIN_TEMPLATE` | One-time login / registration code |
| `NAJVA_STATUS_TEMPLATE` | Case status change notifications |
| `NAJVA_DONATION_TEMPLATE` | Thank-you after a donation |

Suggested texts are in the comment above those constants in `api.php`. The status and donation templates use a single `%token20` slot (up to 20 characters, 8 spaces), which is why the app sends short status labels. Wait for approval before relying on a template; until then those SMS messages will fail (the app keeps working, errors go to the PHP error log). Put `najva_api_key` and `najva_sender_line` in `config.php`.

## 5. Online donations (ZarinPal)

1. Get a merchant ID from ZarinPal and set `zarinpal_merchant_id` in `config.php`.
2. `ZARINPAL_SANDBOX` in `api.php` is `true` by default, which sends payments to ZarinPal's sandbox. Test the full flow, then set it to `false` to go live.
3. Serve the site over HTTPS; the gateway redirects the donor back to your own domain.

## 6. Before you go live

- Keep `config.php`, `data/` and any `*.sqlite` file out of version control and out of the web root's public listing (the app writes a deny-all `.htaccess` into `data/`, but also deny it in your server configuration).
- Create a separate admin account per staff member (`admin_create`) and use `reviewer` for people who only need to review cases; enable two-factor authentication for every `super_admin`.
- Schedule regular backups (admin backup download, or copy the SQLite file).
- Run the demo (`php tools/demo_seed.php`) locally first to explore the panel with invented data.
- Check how personal and medical data of beneficiaries must be handled under the rules that apply to your organisation. This software does not make that decision for you.

## Help wanted

Making the organisation name, logo, bank accounts and SMS template names fully configurable (so no source edits are needed) is on the [roadmap](../../ROADMAP.md). Pull requests are welcome; see [CONTRIBUTING.md](../../CONTRIBUTING.md).
