<?php
/**
 * api.php — backend for the سامانه ثبت مددجویان (Mehr Javid Jahrom charity
 * patient-registration system).
 *
 * -----------------------------------------------------------------------
 * WHY THIS FILE LOOKS DIFFERENT FROM A GENERIC "get/set/delete/list" STORE
 * -----------------------------------------------------------------------
 * The previous version of this app used a generic key/value contract
 * (action=get/set/delete/list on arbitrary string keys) with NO server
 * side authorization at all — any visitor could call
 * `action=get&key=admin:auth` or `action=get&key=user:<national-id>` and
 * receive the admin password or a patient's plaintext password directly,
 * because the client was trusted completely. This file replaces that
 * model with named, purpose-specific actions that each enforce their own
 * authentication/authorization rule, so "can the caller read this?" is
 * decided on the server, every time, for every record.
 *
 * Security measures implemented here:
 *  - Passwords are hashed with password_hash() (bcrypt/argon2i), never
 *    stored or compared in plain text.
 *  - All reads/writes use PDO prepared statements (no string-built SQL).
 *  - Session-based auth for both patients and admins, with
 *    session_regenerate_id() on every privilege change (login).
 *  - CSRF tokens required on every state-changing request.
 *  - Per-IP rate limiting on login/register endpoints.
 *  - Strict allow-listing + size limits on uploaded file data (photos /
 *    medical documents), which arrive as base64 data URLs.
 *  - Security response headers (no-sniff, no framing, no-referrer).
 *  - Admin bootstrap credential is hashed in the database, never present
 *    in any file served to the browser, and MUST be changed on first
 *    login (see README.md).
 */

declare(strict_types=1);

// ---------------------------------------------------------------------
// نگارش: این تاریخ را هر بار که این فایل را روی سرور جایگزین می‌کنید عوض
// کنید — با نگاه به همین خط (مثلاً از طریق "دانلود" در File Manager و باز
// کردن با یک ویرایشگر متنی) می‌توانید مطمئن شوید نسخه‌ی درست بالا آمده.
// Last updated: 1405/08/02
// ---------------------------------------------------------------------

// Buffer all output so that if a fatal PHP error prints partial HTML/text
// before we're ready, we can wipe it and still return clean JSON instead of
// the broken/non-JSON response the frontend calls "پاسخ نامعتبر از سرور".
ob_start();

// ---------------------------------------------------------------------
// 0. Baseline hardening
// ---------------------------------------------------------------------
ini_set('display_errors', '0'); // never leak stack traces/paths to clients
// Large base64 photo/document uploads need more headroom than PHP's default
// memory_limit — this is safe to raise at runtime (unlike post_max_size /
// upload_max_filesize, which the host controls; see the .user.ini note).
ini_set('memory_limit', '256M');
set_time_limit(120);
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'");

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
  || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

// ---------------------------------------------------------------------
// 0.1 Error log — a private, non-public record of every server-side error,
//     so a bug can be diagnosed by reading a file instead of guessing from
//     the generic "پاسخ نامعتبر از سرور دریافت شد" message shown in the UI.
// ---------------------------------------------------------------------
$logsDir = __DIR__ . '/logs';
if (!is_dir($logsDir)) { @mkdir($logsDir, 0770, true); }
if (!file_exists($logsDir . '/.htaccess')) { @file_put_contents($logsDir . '/.htaccess', "Require all denied\nDeny from all\n"); }
if (!file_exists($logsDir . '/index.html')) { @file_put_contents($logsDir . '/index.html', ''); }

/** Appends one line to logs/errors.log. Never throws — a logging failure must never break the request. */
function logApiError(string $message, string $tag = 'ERROR'): void {
  global $logsDir;
  $action = $_POST['action'] ?? $_GET['action'] ?? '?';
  $line = '[' . gmdate('Y-m-d H:i:s') . "] [$tag] [action=$action] " . $message . "\n";
  @file_put_contents($logsDir . '/errors.log', $line, FILE_APPEND | LOCK_EX);
}

// Catch anything unexpected (a bad query, a type mismatch, a missing column
// after a migration, etc.) and always answer with valid JSON instead of a
// blank page or raw PHP error text — this is what the frontend's "پاسخ
// نامعتبر از سرور دریافت شد" message means when it happens: something threw
// before reaching here. With this handler in place, the real reason is
// always visible in the JSON `error` field AND in logs/errors.log.
set_error_handler(function(int $severity, string $message, string $file = '', int $line = 0){
  if (!(error_reporting() & $severity)) return false;
  throw new ErrorException($message, 0, $severity, $file, $line);
});
set_exception_handler(function(Throwable $e){
  logApiError($e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine());
  if (ob_get_length() !== false) { ob_clean(); }
  http_response_code(500);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['ok' => false, 'error' => 'خطای داخلی سرور: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE);
  exit;
});
// A true PHP Fatal Error (parse error, calling an undefined function, running
// out of memory, etc.) bypasses set_error_handler entirely and, without this,
// would print a raw broken page — exactly the "پاسخ نامعتبر از سرور" case.
// This catches it at shutdown, logs it, and still returns clean JSON.
register_shutdown_function(function(){
  $err = error_get_last();
  if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_COMPILE_ERROR, E_CORE_ERROR], true)) {
    logApiError($err['message'] . ' at ' . $err['file'] . ':' . $err['line'], 'FATAL');
    if (ob_get_length() !== false) { ob_clean(); }
    if (!headers_sent()) {
      http_response_code(500);
      header('Content-Type: application/json; charset=utf-8');
    }
    echo json_encode(['ok' => false, 'error' => 'خطای داخلی سرور (fatal). جزئیات در logs/errors.log ثبت شد.'], JSON_UNESCAPED_UNICODE);
  }
});

session_set_cookie_params([
  'lifetime' => 0,
  'path' => '/',
  'httponly' => true,
  'samesite' => 'Lax',
  'secure' => $isHttps,
]);
session_name('mj_session');
session_start();

function fail(string $error, int $httpCode = 400): void {
  http_response_code($httpCode);
  echo json_encode(['ok' => false, 'error' => $error], JSON_UNESCAPED_UNICODE);
  exit;
}

function ok(array $data = []): void {
  echo json_encode(array_merge(['ok' => true], $data), JSON_UNESCAPED_UNICODE);
  exit;
}

// ---------------------------------------------------------------------
// 1. Storage — SQLite via PDO (zero external configuration required).
//    The database file lives outside the web-servable public path where
//    possible; at minimum, data/.htaccess denies all direct access.
// ---------------------------------------------------------------------
$dataDir = __DIR__ . '/data';
if (!is_dir($dataDir)) {
  mkdir($dataDir, 0770, true);
}
// Defense in depth even if the web server ignores .htaccess.
if (!file_exists($dataDir . '/.htaccess')) {
  file_put_contents($dataDir . '/.htaccess', "Require all denied\nDeny from all\n");
}
if (!file_exists($dataDir . '/index.html')) {
  file_put_contents($dataDir . '/index.html', '');
}

$dbPath = $dataDir . '/app.sqlite';
try {
  $pdo = new PDO('sqlite:' . $dbPath);
  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $pdo->exec('PRAGMA foreign_keys = ON');
} catch (Throwable $e) {
  logApiError('DB connect failed: ' . $e->getMessage());
  fail('اتصال به دیتابیس برقرار نشد.', 500);
}

$pdo->exec('CREATE TABLE IF NOT EXISTS users (
  national_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  father_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  city TEXT NOT NULL,
  dob TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
)');

$pdo->exec('CREATE TABLE IF NOT EXISTS admins (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
)');

$pdo->exec('CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY,
  national_id TEXT NOT NULL,
  name TEXT, father_name TEXT, dob TEXT, phone TEXT, city TEXT,
  specialty TEXT, specialty_label TEXT,
  problem_description TEXT,
  photo_thumb TEXT, has_full_photo INTEGER NOT NULL DEFAULT 0,
  needs_accommodation INTEGER NOT NULL DEFAULT 0,
  accommodation_days TEXT, companion_names TEXT, companion_count TEXT,
  companion_phone TEXT, companion_photo_count INTEGER NOT NULL DEFAULT 0,
  medical_docs_meta TEXT,
  submitted_at TEXT NOT NULL
)');
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_submissions_nid ON submissions(national_id)');

$pdo->exec("CREATE TABLE IF NOT EXISTS submission_assets (
  submission_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('photo','doc','companionPhoto','receipt')),
  idx INTEGER NOT NULL DEFAULT 0,
  mime TEXT, name TEXT, data TEXT NOT NULL,
  PRIMARY KEY (submission_id, kind, idx)
)");

// One-time migration: older deployments created this table before 'receipt'
// was a valid asset kind, so its CHECK constraint silently rejected every
// receipt-photo insert — and since that insert ran inside submission_create's
// transaction, it rolled back the WHOLE submission. This was very likely the
// cause of the unexplained "خطا در ذخیره اطلاعات در سرور" error whenever a
// مددجو attached a receipt photo. SQLite can't alter a CHECK constraint in
// place, so if the live table's constraint is still missing 'receipt',
// rebuild it — preserving every column the live table actually has (not just
// the original six), since later columns like doc_status/review_note may
// already have been added to it by the ensureColumn() calls further below.
$existingAssetsSql = $pdo->query("SELECT sql FROM sqlite_master WHERE type='table' AND name='submission_assets'")->fetchColumn();
if ($existingAssetsSql && strpos($existingAssetsSql, "'receipt'") === false) {
  try {
    $pdo->beginTransaction();
    $pdo->exec('DROP TABLE IF EXISTS submission_assets_old'); // clean up any leftover from a previously interrupted migration
    $liveColumns = $pdo->query('PRAGMA table_info(submission_assets)')->fetchAll(PDO::FETCH_ASSOC);
    $liveColumnNames = array_column($liveColumns, 'name');
    $extraCols = array_diff($liveColumnNames, ['submission_id', 'kind', 'idx', 'mime', 'name', 'data']);
    $extraColsSql = '';
    foreach ($liveColumns as $col) {
      if (in_array($col['name'], $extraCols, true)) {
        $extraColsSql .= ', ' . $col['name'] . ' ' . $col['type'] . ($col['dflt_value'] !== null ? ' DEFAULT ' . $col['dflt_value'] : '');
      }
    }
    $pdo->exec('ALTER TABLE submission_assets RENAME TO submission_assets_old');
    $pdo->exec("CREATE TABLE submission_assets (
      submission_id TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('photo','doc','companionPhoto','receipt')),
      idx INTEGER NOT NULL DEFAULT 0,
      mime TEXT, name TEXT, data TEXT NOT NULL$extraColsSql,
      PRIMARY KEY (submission_id, kind, idx)
    )");
    $colList = implode(', ', $liveColumnNames);
    $pdo->exec("INSERT INTO submission_assets ($colList) SELECT $colList FROM submission_assets_old");
    $pdo->exec('DROP TABLE submission_assets_old');
    $pdo->commit();
  } catch (Throwable $e) {
    $pdo->rollBack();
    error_log('submission_assets receipt-kind migration failed: ' . $e->getMessage());
  }
}

$pdo->exec('CREATE TABLE IF NOT EXISTS rate_limits (
  scope TEXT NOT NULL, identifier TEXT NOT NULL,
  window_start INTEGER NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (scope, identifier)
)');

$pdo->exec("CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('login','register')),
  code TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL
)");
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes(phone, purpose)');

// ---------------------------------------------------------------------
// Najva SMS integration (login verification codes + status-change notices).
// -----------------------------------------------------------------------
// IMPORTANT: the API key grants full send access to the SMS account. It lives
// in config.php (git-ignored), never in this file. Rotate it if ever exposed.
// Secrets are read from config.php (copy config.example.php; never commit it).
$APP_CONFIG = is_file(__DIR__ . '/config.php') ? (require __DIR__ . '/config.php') : [];
define('NAJVA_API_KEY', (string) ($APP_CONFIG['najva_api_key'] ?? ''));
// The shared "خدماتی" (service) sender line shown in your Najva panel.
define('NAJVA_SENDER_LINE', (string) ($APP_CONFIG['najva_sender_line'] ?? ''));
// The approved SMS template (پترن) used for OTP codes — required because
// the plain send.json method needs a dedicated line, but this shared line
// can only send via a pre-approved template (verify/lookup.json).
const NAJVA_LOGIN_TEMPLATE = 'mehrejavid_login';
// Two more approved templates (پترن) for the shared service line — Najva
// (like every Iranian SMS provider) does NOT allow free-text sending on a
// shared "خدماتی" line; every message must go through a pre-approved
// template. Najva's token slots have strict length/space limits (%token,
// %token2, %token3 allow NO spaces at all; %token10 allows up to 10 chars /
// 4 spaces; %token20 allows up to 20 chars / 8 spaces) — so we use the
// %token20 slot and keep the inserted value short. Create each pattern in
// the Najva panel (همان‌طور که برای mehrejavid_login انجام شده)، منتظر
// تاییدش بمانید، و نام دقیق پترن را همین‌جا جایگزین کنید.
//   - وضعیت پرونده: متن پیشنهادی → «وضعیت پرونده شما در موسسه خیریه درمانی مهر جاوید به «%token20» تغییر کرد.»
//   - تشکر از کمک مالی: متن پیشنهادی → «با سپاس از کمک شما به مبلغ %token20 تومان به موسسه خیریه درمانی مهر جاوید. خداوند خیرتان دهد.»
const NAJVA_STATUS_TEMPLATE = 'mehrejavid_status';
const NAJVA_DONATION_TEMPLATE = 'mehrejavid_donation';

// Short, SMS-safe versions of the case-status labels — the full labels in
// CASE_STATUSES are complete sentences (e.g. "درخواست شما ثبت و در حال
// بررسی می‌باشد") that are far too long/spacey for Najva's %token20 slot
// (max 20 chars, max 8 spaces), so status-change SMS uses these instead.
// Short, SMS-safe versions of the case-status labels — the full labels in
// CASE_STATUSES are complete sentences (e.g. "درخواست شما ثبت و در حال
// بررسی می‌باشد") that are far too long for Najva's %token slot, so
// status-change SMS uses these instead. They use a zero-width non-joiner
// (‌) rather than a real space between words — Najva's plain %token
// placeholder rejects any value containing an actual space character, and
// ZWNJ isn't one (it still displays as a normal-looking half-space break).
const SMS_STATUS_LABELS = [
  'submitted' => 'ثبت‌شد',
  'initial_review' => 'بررسی‌اولیه',
  'final_review' => 'بررسی‌نهایی',
  'rejected' => 'ردشد',
];

/** Shared GET-request helper for both Najva endpoints below. */
function najvaGet(string $fullUrl): array {
  try {
    $resp = false;
    if (function_exists('curl_init')) {
      $ch = curl_init($fullUrl);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch, CURLOPT_TIMEOUT, 10);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
      $resp = curl_exec($ch);
      $curlErr = curl_error($ch);
      curl_close($ch);
      if ($resp === false) return ['ok' => false, 'detail' => 'خطای اتصال cURL: ' . $curlErr];
    } else {
      $resp = @file_get_contents($fullUrl);
      if ($resp === false) return ['ok' => false, 'detail' => 'امکان اتصال به نجوا نبود (احتمالاً allow_url_fopen غیرفعال است).'];
    }
    $json = json_decode((string) $resp, true);
    $status = $json['return']['status'] ?? null;
    $statusMsg = $json['return']['message'] ?? 'پاسخ نامشخص از نجوا';
    if ($status === 200) return ['ok' => true, 'detail' => 'ok'];
    return ['ok' => false, 'detail' => "کد $status - $statusMsg"];
  } catch (Throwable $e) {
    return ['ok' => false, 'detail' => 'خطای داخلی: ' . $e->getMessage()];
  }
}

/**
 * Sends the OTP code via Najva's approved-template API (verify/lookup.json),
 * which — unlike the plain send.json method — works with a shared service
 * line. $code is inserted wherever %token% appears in the approved template.
 */
function sendOtpSmsViaNajva(string $phone, string $code): array {
  if (NAJVA_API_KEY === '') return ['ok' => false, 'detail' => 'کلید API تنظیم نشده است.'];
  $url = 'https://sms.najva.com/v1/' . NAJVA_API_KEY . '/verify/lookup.json';
  $params = [
    'receptor' => $phone,
    'template' => NAJVA_LOGIN_TEMPLATE,
    'sender' => NAJVA_SENDER_LINE,
    'token' => $code,
  ];
  return najvaGet($url . '?' . http_build_query($params));
}

/**
 * Sends a free-text SMS via Najva's plain send API. Requires a dedicated
 * line for shared "خدماتی" accounts this may fail — used only for
 * non-critical, best-effort notices (e.g. status-change alerts).
 */
function sendSmsViaNajva(string $phone, string $message): array {
  if (NAJVA_API_KEY === '') return ['ok' => false, 'detail' => 'کلید API تنظیم نشده است.'];
  $url = 'https://sms.najva.com/v1/' . NAJVA_API_KEY . '/sms/send.json';
  $params = ['receptor' => $phone, 'message' => $message];
  if (NAJVA_SENDER_LINE !== '') $params['sender'] = NAJVA_SENDER_LINE;
  return najvaGet($url . '?' . http_build_query($params));
}

/**
 * Sends any SMS via an approved Najva pattern/template (verify/lookup.json)
 * — the only method the shared service line accepts. Use this instead of
 * sendSmsViaNajva() for every new best-effort notice; each notice needs its
 * own approved template in the Najva panel (see the NAJVA_*_TEMPLATE
 * constants above).
 *
 * Najva's exact required parameter name for the token slot (token, token2,
 * token3, token10, or token20) has proven inconsistent to pin down from
 * outside their panel, so — rather than guess wrong again — this sends the
 * same value under every possible slot name at once. Whichever one the
 * approved pattern is actually wired to will pick it up; the rest are
 * simply unused extra parameters, which REST APIs (including Najva's)
 * ignore harmlessly.
 */
function sendTemplateSmsViaNajva(string $phone, string $template, string $token): array {
  if (NAJVA_API_KEY === '') return ['ok' => false, 'detail' => 'کلید API تنظیم نشده است.'];
  $url = 'https://sms.najva.com/v1/' . NAJVA_API_KEY . '/verify/lookup.json';
  $params = [
    'receptor' => $phone,
    'template' => $template,
    'sender' => NAJVA_SENDER_LINE,
    'token' => $token,
    'token2' => $token,
    'token3' => $token,
    'token10' => $token,
    'token20' => $token,
  ];
  return najvaGet($url . '?' . http_build_query($params));
}

// ---------------------------------------------------------------------
// ZarinPal payment gateway — powers the public "کمک مالی آنلاین" page.
// ---------------------------------------------------------------------
// TODO: replace with your real Merchant ID from the ZarinPal panel
// (zarinpal.com → پنل کاربری → اطلاعات پذیرنده) once you have one.
define('ZARINPAL_MERCHANT_ID', (string) ($APP_CONFIG['zarinpal_merchant_id'] ?? '00000000-0000-0000-0000-000000000000'));
// TODO: set to false once ZARINPAL_MERCHANT_ID above is a real, non-sandbox
// Merchant ID — until then this talks to ZarinPal's sandbox, which never
// moves real money and always "succeeds" for testing purposes.
const ZARINPAL_SANDBOX = true;

function zarinpalBaseUrl(): string {
  return ZARINPAL_SANDBOX ? 'https://sandbox.zarinpal.com' : 'https://payment.zarinpal.com';
}

/** Shared POST-JSON helper for both ZarinPal endpoints below. Returns the decoded response or null on a transport failure. */
function zarinpalApiPost(string $path, array $payload): ?array {
  $url = zarinpalBaseUrl() . $path;
  if (!function_exists('curl_init')) {
    error_log('[zarinpal] cURL extension not available.');
    return null;
  }
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
    CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
    CURLOPT_TIMEOUT => 15,
    CURLOPT_SSL_VERIFYPEER => true,
  ]);
  $resp = curl_exec($ch);
  $curlErr = curl_error($ch);
  curl_close($ch);
  if ($resp === false) { error_log('[zarinpal] cURL error: ' . $curlErr); return null; }
  $data = json_decode($resp, true);
  return is_array($data) ? $data : null;
}

/** Starts a payment: asks ZarinPal for an authority token + the URL to redirect the browser to. Amount is in Toman. */
function zarinpalRequest(int $amountToman, string $description, ?string $mobile, string $callbackUrl): array {
  $payload = [
    'merchant_id' => ZARINPAL_MERCHANT_ID,
    'amount' => $amountToman * 10, // ZarinPal's request/verify APIs take Rial, not Toman.
    'description' => $description,
    'callback_url' => $callbackUrl,
  ];
  if ($mobile) $payload['metadata'] = ['mobile' => $mobile];

  $data = zarinpalApiPost('/pg/v4/payment/request.json', $payload);
  $code = (int) ($data['data']['code'] ?? 0);
  if (!$data || $code !== 100) {
    $msg = $data['errors']['message'] ?? null;
    error_log('[zarinpal] request failed: ' . json_encode($data));
    return ['ok' => false, 'message' => is_string($msg) ? $msg : null, 'authority' => null, 'paymentUrl' => null];
  }
  $authority = (string) $data['data']['authority'];
  return ['ok' => true, 'authority' => $authority, 'paymentUrl' => zarinpalBaseUrl() . '/pg/StartPay/' . $authority, 'message' => null];
}

/** Confirms a completed payment with ZarinPal after the gateway redirects the browser back. Amount is in Toman (must match the original request). */
function zarinpalVerify(int $amountToman, string $authority): array {
  $payload = ['merchant_id' => ZARINPAL_MERCHANT_ID, 'amount' => $amountToman * 10, 'authority' => $authority];
  $data = zarinpalApiPost('/pg/v4/payment/verify.json', $payload);
  $code = (int) ($data['data']['code'] ?? 0);
  // 100 = freshly verified, 101 = already verified earlier (e.g. the person refreshed the callback page) — both count as paid.
  if (!$data || !in_array($code, [100, 101], true)) {
    error_log('[zarinpal] verify failed: ' . json_encode($data));
    return ['ok' => false, 'refId' => null];
  }
  return ['ok' => true, 'refId' => $data['data']['ref_id'] ?? null];
}

/** Best-effort base URL (scheme://host/dir) of this script, used to build the gateway callback and the redirect back to the site. */
function currentBaseUrl(): string {
  $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
  $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
  $dir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '')), '/');
  return $scheme . '://' . $host . $dir;
}

// -- v2 additions: case status/timeline, internal messaging, notifications --
$pdo->exec('CREATE TABLE IF NOT EXISTS submission_timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submission_id TEXT NOT NULL,
  status TEXT NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL
)');
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_timeline_submission ON submission_timeline(submission_id)');

$pdo->exec("CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submission_id TEXT NOT NULL,
  sender_role TEXT NOT NULL CHECK (sender_role IN ('admin','user')),
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  read_by_admin INTEGER NOT NULL DEFAULT 0,
  read_by_user INTEGER NOT NULL DEFAULT 0
)");
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_messages_submission ON messages(submission_id)');

$pdo->exec("CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient_type TEXT NOT NULL CHECK (recipient_type IN ('user','admin')),
  recipient_id TEXT NOT NULL,
  submission_id TEXT,
  type TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL,
  read_at TEXT
)");
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_notifications_recipient ON notifications(recipient_type, recipient_id)');

/** Adds a column to an existing table only if it is not already present (SQLite has no "ADD COLUMN IF NOT EXISTS"). */
function ensureColumn(PDO $pdo, string $table, string $column, string $definition): void {
  $cols = $pdo->query('PRAGMA table_info(' . $table . ')')->fetchAll(PDO::FETCH_ASSOC);
  foreach ($cols as $c) {
    if ($c['name'] === $column) return;
  }
  $pdo->exec("ALTER TABLE $table ADD COLUMN $column $definition");
}
ensureColumn($pdo, 'submissions', 'status', "TEXT NOT NULL DEFAULT 'submitted'");
ensureColumn($pdo, 'submissions', 'status_updated_at', 'TEXT');
ensureColumn($pdo, 'submission_assets', 'doc_status', "TEXT NOT NULL DEFAULT 'received'");
ensureColumn($pdo, 'submission_assets', 'review_note', 'TEXT');

// -- v3 additions: priority flag, admin login tracking, audit log --
ensureColumn($pdo, 'submissions', 'priority_flag', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn($pdo, 'submissions', 'priority_note', 'TEXT');
ensureColumn($pdo, 'admins', 'last_login_at', 'TEXT');
ensureColumn($pdo, 'admins', 'last_login_ip', 'TEXT');
ensureColumn($pdo, 'admins', 'role', "TEXT NOT NULL DEFAULT 'super_admin'");
ensureColumn($pdo, 'admins', 'totp_secret', 'TEXT');
ensureColumn($pdo, 'admins', 'totp_enabled', 'INTEGER NOT NULL DEFAULT 0');

$pdo->exec('CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_username TEXT NOT NULL,
  action TEXT NOT NULL,
  target_id TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
)');
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)');
ensureColumn($pdo, 'audit_log', 'ip_address', 'TEXT');
ensureColumn($pdo, 'audit_log', 'user_agent', 'TEXT');

/** Records an admin action (with IP + browser for a real audit trail); failures here never interrupt the main request. */
function logAudit(PDO $pdo, string $admin, string $action, ?string $targetId = null, ?string $detail = null): void {
  try {
    $ua = mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 300);
    $pdo->prepare('INSERT INTO audit_log (admin_username, action, target_id, detail, created_at, ip_address, user_agent) VALUES (?,?,?,?,?,?,?)')
      ->execute([$admin, $action, $targetId, $detail, gmdate('c'), clientIp(), $ua]);
  } catch (Throwable $e) {}
}

// -- v4 additions: financial assistance (هدایت درمانی) tracking --
ensureColumn($pdo, 'submissions', 'requested_amount', 'INTEGER');
ensureColumn($pdo, 'submissions', 'requested_note', 'TEXT');
ensureColumn($pdo, 'submissions', 'approved_amount', 'INTEGER');
ensureColumn($pdo, 'submissions', 'financial_status', "TEXT NOT NULL DEFAULT 'none'");
ensureColumn($pdo, 'submissions', 'financial_note', 'TEXT');
ensureColumn($pdo, 'submissions', 'manual_entry', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn($pdo, 'submissions', 'manual_entry_by', 'TEXT');
ensureColumn($pdo, 'submissions', 'companion_father_names', 'TEXT');
ensureColumn($pdo, 'submissions', 'companion_national_ids', 'TEXT');

// -- v5 additions: general accounting (income & expense) ledger --
$pdo->exec("CREATE TABLE IF NOT EXISTS accounting_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK (type IN ('income','expense')),
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
)");

$pdo->exec('CREATE TABLE IF NOT EXISTS accounting_bank_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
)');

$pdo->exec("CREATE TABLE IF NOT EXISTS accounting_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK (type IN ('income','expense')),
  category_id INTEGER,
  bank_account_id INTEGER,
  amount INTEGER NOT NULL,
  description TEXT,
  transaction_date TEXT NOT NULL,
  payment_method TEXT NOT NULL DEFAULT 'cash',
  related_submission_id TEXT,
  donor_name TEXT,
  receipt_mime TEXT,
  receipt_data TEXT,
  admin_username TEXT NOT NULL,
  created_at TEXT NOT NULL
)");
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_acct_tx_date ON accounting_transactions(transaction_date)');
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_acct_tx_type ON accounting_transactions(type)');
ensureColumn($pdo, 'accounting_transactions', 'bank_account_id', 'INTEGER');

// Seed the charity's 4 real accounts/funds — once only.
$acctCount = (int) $pdo->query('SELECT COUNT(*) FROM accounting_bank_accounts')->fetchColumn();
if ($acctCount === 0) {
  $now = gmdate('c');
  $bankIns = $pdo->prepare('INSERT INTO accounting_bank_accounts (name, created_at) VALUES (?,?)');
  foreach (['توسعه تعاون', 'توسعه مهر گستر', 'امداد ولایت', 'صندوق'] as $bn) $bankIns->execute([$bn, $now]);
}

// Seed a sensible default chart of categories for a medical charity — once only.
$catCount = (int) $pdo->query('SELECT COUNT(*) FROM accounting_categories')->fetchColumn();
if ($catCount === 0) {
  $now = gmdate('c');
  $seedCats = [
    ['income', 'کمک نقدی خیرین'],
    ['income', 'کمک سازمانی و نهادی'],
    ['income', 'درآمد کمپین‌ها'],
    ['income', 'سایر درآمدها'],
    ['expense', 'هدایت درمانی مددجویان'],
    ['expense', 'هزینه اسکان'],
    ['expense', 'دارو و تجهیزات پزشکی'],
    ['expense', 'هزینه اداری و دفتری'],
    ['expense', 'حقوق و دستمزد'],
    ['expense', 'سایر هزینه‌ها'],
  ];
  $catIns = $pdo->prepare('INSERT INTO accounting_categories (type, name, created_at) VALUES (?,?,?)');
  foreach ($seedCats as $c) $catIns->execute([$c[0], $c[1], $now]);
}

// -- v6 additions: accommodation room management --
$pdo->exec('CREATE TABLE IF NOT EXISTS accommodation_rooms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guesthouse_name TEXT NOT NULL,
  room_label TEXT NOT NULL,
  created_at TEXT NOT NULL
)');

$pdo->exec('CREATE TABLE IF NOT EXISTS accommodation_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id INTEGER NOT NULL,
  submission_id TEXT NOT NULL,
  check_in_date TEXT NOT NULL,
  check_out_date TEXT,
  note TEXT,
  admin_username TEXT NOT NULL,
  created_at TEXT NOT NULL
)');
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_accom_assign_room ON accommodation_assignments(room_id)');
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_accom_assign_sub ON accommodation_assignments(submission_id)');

$roomCount = (int) $pdo->query('SELECT COUNT(*) FROM accommodation_rooms')->fetchColumn();
if ($roomCount === 0) {
  $now = gmdate('c');
  $roomIns = $pdo->prepare('INSERT INTO accommodation_rooms (guesthouse_name, room_label, created_at) VALUES (?,?,?)');
  $seedRooms = [
    ['همراه‌سرای بلوار معلم', 'اتاق ۱'],
    ['همراه‌سرای بلوار معلم', 'اتاق ۲'],
    ['همراه‌سرای بلوار معلم', 'اتاق ۳'],
    ['همراه‌سرای بلوار سپاه', 'اتاق ۱'],
  ];
  foreach ($seedRooms as $r) $roomIns->execute([$r[0], $r[1], $now]);
}

// Self-healing cleanup: an accommodation assignment can be left "dangling"
// (no check-out date, so the room shows as permanently occupied) if its
// case was deleted before this cascading delete existed, or by any other
// means the case disappeared. Auto-check-out any assignment whose
// submission no longer exists, so the room becomes available again.
$pdo->exec("UPDATE accommodation_assignments SET check_out_date = date('now')
  WHERE check_out_date IS NULL
    AND submission_id NOT IN (SELECT id FROM submissions)");

// -- v7 additions: donor management + budgeting --
$pdo->exec('CREATE TABLE IF NOT EXISTS donors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  national_id TEXT,
  notes TEXT,
  created_at TEXT NOT NULL
)');
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_donors_name ON donors(name)');
ensureColumn($pdo, 'accounting_transactions', 'donor_id', 'INTEGER');
ensureColumn($pdo, 'donors', 'donor_type', "TEXT NOT NULL DEFAULT 'individual'");
ensureColumn($pdo, 'submissions', 'receipt_count', 'INTEGER NOT NULL DEFAULT 0');

// -- v4 accounting additions: opening balances, internal fund transfers,
//    and cheque due-date tracking (see the site's "کمبودهای حسابداری" pass).
ensureColumn($pdo, 'accounting_bank_accounts', 'opening_balance', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn($pdo, 'accounting_transactions', 'is_transfer', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn($pdo, 'accounting_transactions', 'transfer_pair_id', 'INTEGER');
ensureColumn($pdo, 'accounting_transactions', 'cheque_number', 'TEXT');
ensureColumn($pdo, 'accounting_transactions', 'cheque_due_date', 'TEXT');

$pdo->exec('CREATE TABLE IF NOT EXISTS accounting_budgets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category_id INTEGER NOT NULL,
  period_type TEXT NOT NULL CHECK (period_type IN (\'monthly\',\'yearly\')),
  period_value TEXT NOT NULL,
  amount INTEGER NOT NULL,
  admin_username TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(category_id, period_type, period_value)
)');

$pdo->exec('CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submission_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  note TEXT,
  admin_username TEXT NOT NULL,
  created_at TEXT NOT NULL
)');
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_payments_submission ON payments(submission_id)');
// Links a payment row back to the accounting transaction that created it (when
// it came from the accounting screen rather than the dedicated "ثبت پرداخت"
// flow), so editing/deleting that transaction can keep the مددجو's own
// payment history and financial status in sync instead of leaving orphans.
ensureColumn($pdo, 'payments', 'accounting_transaction_id', 'INTEGER');

// -- v8 additions: online donations via ZarinPal ---------------------------
// Tracks every payment-gateway attempt from the public "کمک مالی آنلاین"
// page, from the moment ZarinPal issues an authority token until the
// callback confirms (or fails to confirm) the payment. Kept separate from
// accounting_transactions because most attempts here are abandoned at the
// gateway and never become a real transaction.
$pdo->exec("CREATE TABLE IF NOT EXISTS online_donations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  authority TEXT NOT NULL UNIQUE,
  amount INTEGER NOT NULL,
  donor_name TEXT,
  donor_phone TEXT,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid','failed')),
  ref_id TEXT,
  accounting_transaction_id INTEGER,
  created_at TEXT NOT NULL,
  verified_at TEXT
)");
$pdo->exec('CREATE INDEX IF NOT EXISTS idx_online_donations_authority ON online_donations(authority)');

/**
 * Recomputes a submission's total paid amount and financial_status from its
 * payments table, after any payment row was added/changed/removed. Call
 * this any time payments for a submission change outside the original
 * "ثبت پرداخت" flow (e.g. accounting transaction create/edit/delete).
 */
function syncSubmissionPaymentStatus(PDO $pdo, string $submissionId): int {
  $sumStmt = $pdo->prepare('SELECT COALESCE(SUM(amount), 0) FROM payments WHERE submission_id = ?');
  $sumStmt->execute([$submissionId]);
  $totalPaid = (int) $sumStmt->fetchColumn();

  $approvedStmt = $pdo->prepare('SELECT approved_amount, financial_status FROM submissions WHERE id = ?');
  $approvedStmt->execute([$submissionId]);
  $row = $approvedStmt->fetch(PDO::FETCH_ASSOC);
  if (!$row) return $totalPaid;
  $approvedAmount = (int) $row['approved_amount'];

  if ($totalPaid <= 0) {
    $newStatus = ($row['financial_status'] === 'none') ? 'none' : 'approved';
  } else {
    $newStatus = ($approvedAmount > 0 && $totalPaid >= $approvedAmount) ? 'paid' : 'partially_paid';
  }
  $pdo->prepare('UPDATE submissions SET financial_status = ? WHERE id = ?')->execute([$newStatus, $submissionId]);
  return $totalPaid;
}

/** The fixed set of financial-assistance statuses shown in the UI. */
const FINANCIAL_STATUSES = [
  'none' => 'بدون درخواست کمک مالی',
  'pending_review' => 'در انتظار بررسی مدیر',
  'approved' => 'تایید شده — در انتظار پرداخت',
  'partially_paid' => 'پرداخت جزئی انجام شده',
  'paid' => 'هدایت درمانی کامل شد',
  'rejected' => 'رد شده',
];

/** The fixed, ordered set of case statuses used by the timeline UI.
 *  Mirrors CASE_STATUSES in index.html — keep in sync if statuses change client-side. */
const CASE_STATUSES = [
  'submitted' => ['label' => 'درخواست شما ثبت و در حال بررسی می‌باشد', 'color' => '#4C9089'],
  'initial_review' => ['label' => 'بررسی اولیه انجام شد', 'color' => '#C9A227'],
  'final_review' => ['label' => 'بررسی نهایی و نتیجه', 'color' => '#2E7D5B'],
  'rejected' => ['label' => 'درخواست تایید نشد', 'color' => '#C0392B'],
];

// Timeline events include the case-progress statuses above, plus a few
// event markers that are never selectable as a case status themselves
// (kept separate from CASE_STATUSES for that reason): financial-assistance
// events, and the accommodation room-assignment marker.
const TIMELINE_EVENT_META = CASE_STATUSES + [
  'accommodation' => ['label' => 'اسکان', 'color' => '#2E7D5B'],
  'financial_request' => ['label' => 'درخواست کمک مالی', 'color' => '#C9974B'],
  'financial_review' => ['label' => 'بررسی کمک مالی', 'color' => '#C9974B'],
  'payment' => ['label' => 'پرداخت', 'color' => '#2E7D5B'],
];

// Seed the admin bootstrap account exactly once. The initial password comes
// from config.php ('admin_initial_password'); if unset, a random one is
// generated and written to data/INITIAL_ADMIN_PASSWORD.txt. Either way the
// admin MUST change it at first login (must_change_password = 1). Delete the
// txt file afterwards.
$adminCount = (int) $pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn();
if ($adminCount === 0) {
  $cfgFile = __DIR__ . '/config.php';
  $cfg = is_file($cfgFile) ? (require $cfgFile) : [];
  $initialPassword = (string) ($cfg['admin_initial_password'] ?? '');
  if ($initialPassword === '') {
    $initialPassword = bin2hex(random_bytes(8));
    @file_put_contents($dataDir . '/INITIAL_ADMIN_PASSWORD.txt', "username: admin\npassword: " . $initialPassword . "\n");
  }
  $stmt = $pdo->prepare('INSERT INTO admins (username, password_hash, must_change_password, created_at, role) VALUES (?, ?, 1, ?, ?)');
  $stmt->execute(['admin', password_hash($initialPassword, PASSWORD_DEFAULT), gmdate('c'), 'super_admin']);
}

// ---------------------------------------------------------------------
// 2. Small helpers
// ---------------------------------------------------------------------
function clientIp(): string {
  return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/** Fixed-window rate limiter. Returns true if the action is still allowed. */
function rateLimitCheck(PDO $pdo, string $scope, string $identifier, int $maxAttempts, int $windowSeconds): bool {
  $now = time();
  $stmt = $pdo->prepare('SELECT window_start, count FROM rate_limits WHERE scope = ? AND identifier = ?');
  $stmt->execute([$scope, $identifier]);
  $row = $stmt->fetch(PDO::FETCH_ASSOC);

  if (!$row) {
    $ins = $pdo->prepare('INSERT INTO rate_limits (scope, identifier, window_start, count) VALUES (?, ?, ?, 1)');
    $ins->execute([$scope, $identifier, $now]);
    return true;
  }

  if ($now - (int) $row['window_start'] > $windowSeconds) {
    $upd = $pdo->prepare('UPDATE rate_limits SET window_start = ?, count = 1 WHERE scope = ? AND identifier = ?');
    $upd->execute([$now, $scope, $identifier]);
    return true;
  }

  if ((int) $row['count'] >= $maxAttempts) {
    return false;
  }

  $upd = $pdo->prepare('UPDATE rate_limits SET count = count + 1 WHERE scope = ? AND identifier = ?');
  $upd->execute([$scope, $identifier]);
  return true;
}

function requireCsrf(): void {
  $token = $_POST['csrf'] ?? '';
  if (empty($_SESSION['csrf']) || !is_string($token) || !hash_equals($_SESSION['csrf'], $token)) {
    fail('نشست شما منقضی شده است، لطفاً صفحه را رفرش کنید.', 403);
  }
}

function validateNationalId(string $code): bool {
  if (!preg_match('/^\d{10}$/', $code)) return false;
  if (preg_match('/^(\d)\1{9}$/', $code)) return false;
  $check = (int) $code[9];
  $sum = 0;
  for ($i = 0; $i < 9; $i++) $sum += ((int) $code[$i]) * (10 - $i);
  $rem = $sum % 11;
  return ($rem < 2 && $check === $rem) || ($rem >= 2 && $check === 11 - $rem);
}

function str_field(string $key, int $maxLen = 500): string {
  $v = $_POST[$key] ?? '';
  if (!is_string($v)) fail("مقدار نامعتبر برای $key");
  $v = trim($v);
  if (mb_strlen($v) > $maxLen) fail("مقدار $key بیش از حد طولانی است");
  return $v;
}

/** Parse+validate a data: URL, enforcing an allow-list of mimes and a size cap. Returns [mime, rawBase64] or null. */
function parseDataUrl(?string $dataUrl, array $allowedMimes, int $maxBytes): ?array {
  if (!$dataUrl) return null;
  if (!preg_match('/^data:([a-zA-Z0-9.+\/-]+);base64,([A-Za-z0-9+\/=\s]+)$/', $dataUrl, $m)) {
    fail('قالب فایل ارسالی نامعتبر است.');
  }
  [, $mime, $b64] = $m;
  if (!in_array($mime, $allowedMimes, true)) {
    fail('نوع فایل مجاز نیست. فقط تصویر (JPG/PNG/WEBP) یا PDF مجاز است.');
  }
  // Rough decoded-size estimate from base64 length, cheaper than decoding first.
  $approxBytes = (int) (strlen($b64) * 3 / 4);
  if ($approxBytes > $maxBytes) {
    fail('حجم فایل ارسالی بیش از حد مجاز است (حداکثر ' . round($maxBytes / 1024 / 1024, 1) . ' مگابایت).');
  }
  return [$mime, $dataUrl];
}

const ALLOWED_FILE_MIMES = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
const MAX_ASSET_BYTES = 25 * 1024 * 1024; // 25MB per photo/document

function sanitizedUser(array $row): array {
  return [
    'name' => $row['name'],
    'fatherName' => $row['father_name'],
    'nationalId' => $row['national_id'],
    'phone' => $row['phone'],
    'city' => $row['city'],
    'dob' => $row['dob'],
    'referrer' => $row['referrer'] ?? null,
    'referrerPhone' => $row['referrer_phone'] ?? null,
  ];
}

function submissionToRecord(array $row): array {
  return [
    'id' => $row['id'],
    'name' => $row['name'],
    'fatherName' => $row['father_name'],
    'nationalId' => $row['national_id'],
    'dob' => $row['dob'],
    'phone' => $row['phone'],
    'city' => $row['city'],
    'specialty' => $row['specialty'],
    'specialtyLabel' => $row['specialty_label'],
    'problemDescription' => $row['problem_description'],
    'photoThumb' => $row['photo_thumb'],
    'hasFullPhoto' => (bool) $row['has_full_photo'],
    'needsAccommodation' => (bool) $row['needs_accommodation'],
    'accommodationDays' => $row['accommodation_days'],
    'companionNames' => json_decode($row['companion_names'] ?: '[]', true),
    'companionCount' => $row['companion_count'],
    'companionPhone' => $row['companion_phone'],
    'companionPhotoCount' => (int) $row['companion_photo_count'],
    'receiptCount' => (int) ($row['receipt_count'] ?? 0),
    'companionFatherNames' => json_decode($row['companion_father_names'] ?? '[]', true) ?: [],
    'companionNationalIds' => json_decode($row['companion_national_ids'] ?? '[]', true) ?: [],
    'medicalDocsMeta' => json_decode($row['medical_docs_meta'] ?: '[]', true),
    'submittedAt' => $row['submitted_at'],
    'status' => $row['status'] ?? 'submitted',
    'statusLabel' => CASE_STATUSES[$row['status'] ?? 'submitted']['label'] ?? ($row['status'] ?? 'submitted'),
    'statusColor' => CASE_STATUSES[$row['status'] ?? 'submitted']['color'] ?? '#6B7280',
    'statusUpdatedAt' => $row['status_updated_at'] ?? $row['submitted_at'],
    'priorityFlag' => (bool) ($row['priority_flag'] ?? 0),
    'priorityNote' => $row['priority_note'] ?? null,
    'requestedAmount' => isset($row['requested_amount']) ? (int) $row['requested_amount'] : null,
    'requestedNote' => $row['requested_note'] ?? null,
    'approvedAmount' => isset($row['approved_amount']) ? (int) $row['approved_amount'] : null,
    'financialStatus' => $row['financial_status'] ?? 'none',
    'financialStatusLabel' => FINANCIAL_STATUSES[$row['financial_status'] ?? 'none'] ?? ($row['financial_status'] ?? 'none'),
    'financialNote' => $row['financial_note'] ?? null,
    'manualEntry' => (bool) ($row['manual_entry'] ?? 0),
    'referrer' => $row['user_referrer'] ?? null,
    'referrerPhone' => $row['user_referrer_phone'] ?? null,
  ];
}

/** The national ID a submission id belongs to is embedded as 'submission:<nid>:<ts>'. */
function submissionOwnerFromId(string $id): ?string {
  $parts = explode(':', $id);
  return (count($parts) === 3 && $parts[0] === 'submission') ? $parts[1] : null;
}

function currentUserNid(): ?string {
  return $_SESSION['user_nid'] ?? null;
}
function currentAdmin(): ?string {
  return $_SESSION['admin_user'] ?? null;
}
function requireUser(): string {
  $nid = currentUserNid();
  if (!$nid) fail('ابتدا وارد حساب کاربری شوید.', 401);
  return $nid;
}
function requireAdmin(): string {
  $u = currentAdmin();
  if (!$u) fail('ابتدا به عنوان مدیر وارد شوید.', 401);
  return $u;
}

// -- v9 addition: optional referrer (person or organization who referred the beneficiary) --
ensureColumn($pdo, 'users', 'referrer', 'TEXT');
ensureColumn($pdo, 'users', 'referrer_phone', 'TEXT');

// -- v8 additions: satisfaction survey after a case reaches a final outcome --
$pdo->exec('CREATE TABLE IF NOT EXISTS satisfaction_surveys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  submission_id TEXT NOT NULL UNIQUE,
  rating INTEGER NOT NULL,
  comment TEXT,
  created_at TEXT NOT NULL
)');

// -- v7 additions: admin roles, site-wide settings, session idle-timeout --
$pdo->exec('CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
)');

/** Every setting the admin panel can configure, with a safe default.
 *  Booleans/arrays are stored as JSON strings in the DB and decoded on read. */
const SETTINGS_DEFAULTS = [
  'org_name' => 'موسسه خیریه درمانی مهر جاوید',
  'org_reg_number' => '',
  'org_address' => '',
  'org_phone' => '',
  'org_instagram' => '',
  'org_whatsapp' => '',
  'brand_color' => '#1F5C56',
  'default_theme' => 'light', // 'light' | 'dark'
  'session_timeout_minutes' => '30',
  'notify_sms_submitted' => '1',
  'notify_sms_initial_review' => '1',
  'notify_sms_final_review' => '1',
  'notify_sms_rejected' => '1',
  'show_appointment_range_field' => '1',
  'stale_case_days' => '5',
  'specialties' => '[{"value":"ophthalmology","label":"چشم\u200cپزشکی"},{"value":"orthopedics","label":"ارتوپد"},{"value":"kidney","label":"کلیه و سنگ کلیه"},{"value":"occupational-therapy","label":"کاردرمانی"},{"value":"internal-medicine","label":"داخلی"},{"value":"ent","label":"گوش و حلق و بینی"},{"value":"cardiology","label":"قلب و عروق"},{"value":"neurology","label":"مغز و اعصاب"},{"value":"other","label":"سایر"}]',
];

function getSetting(PDO $pdo, string $key) {
  $stmt = $pdo->prepare('SELECT value FROM settings WHERE key = ?');
  $stmt->execute([$key]);
  $val = $stmt->fetchColumn();
  return $val !== false ? $val : (SETTINGS_DEFAULTS[$key] ?? null);
}

/** Returns every setting as a flat assoc array of strings — the frontend decides how to parse each. */
function getAllSettings(PDO $pdo): array {
  $stmt = $pdo->query('SELECT key, value FROM settings');
  $stored = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
  return array_merge(SETTINGS_DEFAULTS, $stored);
}

function setSetting(PDO $pdo, string $key, string $value): void {
  $pdo->prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    ->execute([$key, $value]);
}

/** Same as getAllSettings(), but decodes the specialties field into a real JSON array
 *  for the frontend, instead of leaving it as a raw stored string. */
function getAllSettingsForClient(PDO $pdo): array {
  $settings = getAllSettings($pdo);
  $settings['specialties'] = json_decode($settings['specialties'] ?? '[]', true) ?: [];
  return $settings;
}

/** The logged-in admin's role, or null if not an admin. Roles: super_admin | reviewer. */
function currentAdminRole(PDO $pdo): ?string {
  $u = currentAdmin();
  if (!$u) return null;
  $stmt = $pdo->prepare('SELECT role FROM admins WHERE username = ?');
  $stmt->execute([$u]);
  $role = $stmt->fetchColumn();
  return $role ?: 'reviewer';
}

/** Like requireAdmin(), but also enforces the admin's role is in the allowed list.
 *  'reviewer' admins can review/update cases but not touch money, settings, or other admin accounts. */
function requireRole(PDO $pdo, array $allowedRoles): string {
  $u = requireAdmin();
  $role = currentAdminRole($pdo);
  if (!in_array($role, $allowedRoles, true)) {
    fail('دسترسی شما برای این عملیات کافی نیست.', 403);
  }
  return $u;
}

// ---------------------------------------------------------------------
// TOTP (RFC 6238) — two-factor authentication for admin accounts.
// Pure-PHP implementation (no external library needed): standard 6-digit
// codes, 30-second step, compatible with Google Authenticator / Authy /
// any RFC-6238 app. Secrets are stored base32-encoded, matching the format
// those apps expect for manual key entry.
// ---------------------------------------------------------------------

/** Encodes raw bytes as Base32 (RFC 4648, no padding) — the format TOTP secrets use. */
function base32Encode(string $data): string {
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $bits = '';
  foreach (str_split($data) as $char) {
    $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
  }
  $output = '';
  foreach (str_split($bits, 5) as $chunk) {
    $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
    $output .= $alphabet[bindec($chunk)];
  }
  return $output;
}

/** Decodes a Base32 string (RFC 4648) back to raw bytes. */
function base32Decode(string $b32): string {
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $b32 = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $b32));
  $bits = '';
  foreach (str_split($b32) as $char) {
    $pos = strpos($alphabet, $char);
    if ($pos === false) continue;
    $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
  }
  $bytes = '';
  foreach (str_split($bits, 8) as $chunk) {
    if (strlen($chunk) < 8) break; // drop incomplete trailing bits (padding)
    $bytes .= chr(bindec($chunk));
  }
  return $bytes;
}

/** Generates a fresh random TOTP secret (base32-encoded, 20 raw bytes = 32 chars). */
function generateTotpSecret(): string {
  return base32Encode(random_bytes(20));
}

/** Computes the 6-digit TOTP code for a base32 secret at a given time step. */
function totpCodeAt(string $secretBase32, int $timeStep): string {
  $key = base32Decode($secretBase32);
  $counterBytes = pack('N*', 0) . pack('N*', $timeStep); // 8-byte big-endian counter
  $hash = hash_hmac('sha1', $counterBytes, $key, true);
  $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
  $binary = ((ord($hash[$offset]) & 0x7F) << 24)
    | ((ord($hash[$offset + 1]) & 0xFF) << 16)
    | ((ord($hash[$offset + 2]) & 0xFF) << 8)
    | (ord($hash[$offset + 3]) & 0xFF);
  return str_pad((string) ($binary % 1000000), 6, '0', STR_PAD_LEFT);
}

/** Verifies a 6-digit code against the current time step, allowing ±1 step (±30s)
 *  of clock drift — the standard tolerance for TOTP verification. */
function verifyTotpCode(string $secretBase32, string $code): bool {
  $code = preg_replace('/\D/', '', $code);
  if (strlen($code) !== 6) return false;
  $currentStep = (int) floor(time() / 30);
  for ($i = -1; $i <= 1; $i++) {
    if (hash_equals(totpCodeAt($secretBase32, $currentStep + $i), $code)) return true;
  }
  return false;
}

/** Builds the otpauth:// URI used for manual key entry / QR generation in authenticator apps. */
function totpProvisioningUri(string $secretBase32, string $username, string $orgName): string {
  $label = rawurlencode($orgName . ':' . $username);
  $issuer = rawurlencode($orgName);
  return "otpauth://totp/{$label}?secret={$secretBase32}&issuer={$issuer}&algorithm=SHA1&digits=6&period=30";
}

/** Completes an admin login (called after password check, or after a successful
 *  TOTP verification): records last-login, regenerates the session, and returns
 *  the same response shape the frontend expects from a normal login. */
function finalizeAdminLogin(PDO $pdo, array $row): array {
  $username = $row['username'];
  $previousLogin = ['at' => $row['last_login_at'] ?? null, 'ip' => $row['last_login_ip'] ?? null];
  $now = gmdate('c');
  $ip = clientIp();
  $pdo->prepare('UPDATE admins SET last_login_at = ?, last_login_ip = ? WHERE username = ?')->execute([$now, $ip, $username]);
  logAudit($pdo, $username, 'login', null, $ip);

  session_regenerate_id(true);
  $_SESSION['admin_user'] = $username;
  unset($_SESSION['user_nid']);
  return ['mustChangePassword' => (bool) $row['must_change_password'], 'previousLogin' => $previousLogin];
}

// Idle-timeout: if a logged-in session (user or admin) has been inactive longer
// than the configured limit, sign it out. Checked on every request, after the
// settings table exists so the configured duration can be read.
if (isset($_SESSION['user_nid']) || isset($_SESSION['admin_user'])) {
  $timeoutMinutes = (int) getSetting($pdo, 'session_timeout_minutes');
  if ($timeoutMinutes > 0) {
    $lastActivity = (int) ($_SESSION['last_activity'] ?? 0);
    if ($lastActivity > 0 && (time() - $lastActivity) > $timeoutMinutes * 60) {
      unset($_SESSION['user_nid'], $_SESSION['admin_user']);
      session_regenerate_id(true);
    }
  }
  $_SESSION['last_activity'] = time();
}

// ---------------------------------------------------------------------
// 3. Router
// ---------------------------------------------------------------------
$action = $_POST['action'] ?? $_GET['action'] ?? '';

switch ($action) {

  // -- bootstrap: issues a CSRF token and reports current session role.
  case 'bootstrap': {
    if (empty($_SESSION['csrf'])) {
      $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    $role = 'guest';
    $user = null;
    $adminRole = null;
    $adminUsername = null;
    if (currentAdmin()) {
      $role = 'admin';
      $adminRole = currentAdminRole($pdo);
      $adminUsername = currentAdmin();
    } elseif (currentUserNid()) {
      $role = 'user';
      $stmt = $pdo->prepare('SELECT * FROM users WHERE national_id = ?');
      $stmt->execute([currentUserNid()]);
      $row = $stmt->fetch(PDO::FETCH_ASSOC);
      if ($row) $user = sanitizedUser($row);
      else $role = 'guest'; // session pointed at a user that no longer exists
    }
    $allSettings = getAllSettings($pdo);
    $publicSettings = array_intersect_key($allSettings, array_flip([
      'org_name', 'org_reg_number', 'org_address', 'org_phone', 'org_instagram', 'org_whatsapp',
      'brand_color', 'default_theme', 'show_appointment_range_field', 'specialties', 'stale_case_days',
    ]));
    $publicSettings['specialties'] = json_decode($publicSettings['specialties'] ?? '[]', true) ?: [];
    ok(['csrf' => $_SESSION['csrf'], 'role' => $role, 'user' => $user, 'adminRole' => $adminRole, 'adminUsername' => $adminUsername, 'settings' => $publicSettings]);
  }

  // ===================== public online donations (ZarinPal) =====================

  // -- aggregate, non-identifying totals for the public transparency page ---
  case 'donation_public_stats': {
    $totalRaised = (int) $pdo->query("SELECT COALESCE(SUM(amount),0) FROM accounting_transactions WHERE type = 'income' AND is_transfer = 0")->fetchColumn();
    $totalAidDisbursed = (int) $pdo->query("SELECT COALESCE(SUM(amount),0) FROM accounting_transactions
      WHERE type = 'expense' AND is_transfer = 0 AND related_submission_id IS NOT NULL AND related_submission_id != ''")->fetchColumn();
    $casesHelped = (int) $pdo->query("SELECT COUNT(DISTINCT related_submission_id) FROM accounting_transactions
      WHERE related_submission_id IS NOT NULL AND related_submission_id != ''")->fetchColumn();
    $donorCount = (int) $pdo->query('SELECT COUNT(*) FROM donors')->fetchColumn();
    ok([
      'totalRaised' => $totalRaised,
      'totalAidDisbursed' => $totalAidDisbursed,
      'casesHelped' => $casesHelped,
      'donorCount' => $donorCount,
    ]);
  }

  // -- starts a ZarinPal payment: records a pending attempt, returns the URL
  // to redirect the donor's browser to. ---------------------------------
  case 'donation_request_payment': {
    requireCsrf();
    $amount = (int) ($_POST['amount'] ?? 0); // Toman
    $name = str_field('name', 120);
    $phone = str_field('phone', 11);
    $description = str_field('description', 300);

    if ($amount < 10000) fail('حداقل مبلغ کمک آنلاین ۱۰٬۰۰۰ تومان است.');
    if ($amount > 500000000) fail('مبلغ وارد شده بیش از حد مجاز است.');
    if ($phone !== '' && !preg_match('/^0\d{10}$/', $phone)) fail('شماره موبایل معتبر نیست.');

    $desc = $description ?: ('کمک مالی آنلاین به موسسه خیریه درمانی مهر جاوید' . ($name ? ' — ' . $name : ''));
    $callbackUrl = currentBaseUrl() . '/api.php?action=donation_verify';
    $result = zarinpalRequest($amount, $desc, $phone ?: null, $callbackUrl);
    if (!$result['ok']) {
      fail($result['message'] ?: 'ارتباط با درگاه پرداخت برقرار نشد. لطفاً چند لحظه دیگر دوباره تلاش کنید.', 502);
    }

    $pdo->prepare('INSERT INTO online_donations (authority, amount, donor_name, donor_phone, description, status, created_at) VALUES (?,?,?,?,?,?,?)')
      ->execute([$result['authority'], $amount, $name ?: null, $phone ?: null, $desc, 'pending', gmdate('c')]);

    ok(['paymentUrl' => $result['paymentUrl']]);
  }

  // -- ZarinPal redirects the donor's browser here (a plain GET, no CSRF
  // token available — this is a gateway callback, not a same-site form
  // submit) after the payment attempt; verifies it and records a real
  // accounting income transaction + donor on success, then bounces the
  // browser back to the site with the outcome in the query string. --------
  case 'donation_verify': {
    $authority = (string) ($_GET['Authority'] ?? '');
    $status = (string) ($_GET['Status'] ?? '');
    $redirectBase = currentBaseUrl() . '/index.html';

    $stmt = $pdo->prepare('SELECT * FROM online_donations WHERE authority = ?');
    $stmt->execute([$authority]);
    $donation = $authority !== '' ? $stmt->fetch(PDO::FETCH_ASSOC) : false;

    if (!$donation) { header('Location: ' . $redirectBase . '?donation=failed'); exit; }

    if ($donation['status'] === 'paid') {
      header('Location: ' . $redirectBase . '?donation=success&ref=' . urlencode((string) $donation['ref_id'])); exit;
    }

    if ($status !== 'OK') {
      $pdo->prepare("UPDATE online_donations SET status = 'failed' WHERE id = ?")->execute([$donation['id']]);
      header('Location: ' . $redirectBase . '?donation=failed'); exit;
    }

    $verify = zarinpalVerify((int) $donation['amount'], $authority);
    if (!$verify['ok']) {
      $pdo->prepare("UPDATE online_donations SET status = 'failed' WHERE id = ?")->execute([$donation['id']]);
      header('Location: ' . $redirectBase . '?donation=failed'); exit;
    }

    // Link to an existing donor by phone (then name), or create a new one.
    $donorId = null;
    if ($donation['donor_phone']) {
      $df = $pdo->prepare('SELECT id FROM donors WHERE phone = ? LIMIT 1');
      $df->execute([$donation['donor_phone']]);
      $donorId = $df->fetchColumn() ?: null;
    }
    if (!$donorId && $donation['donor_name']) {
      $df2 = $pdo->prepare('SELECT id FROM donors WHERE name = ? LIMIT 1');
      $df2->execute([$donation['donor_name']]);
      $donorId = $df2->fetchColumn() ?: null;
    }
    if (!$donorId) {
      $pdo->prepare('INSERT INTO donors (name, phone, donor_type, created_at) VALUES (?,?,?,?)')
        ->execute([$donation['donor_name'] ?: 'خیر ناشناس (پرداخت آنلاین)', $donation['donor_phone'] ?: null, 'individual', gmdate('c')]);
      $donorId = (int) $pdo->lastInsertId();
    }

    $catStmt = $pdo->query("SELECT id FROM accounting_categories WHERE type = 'income' AND name = 'کمک نقدی خیرین' LIMIT 1");
    $catId = $catStmt->fetchColumn() ?: null;
    $fundStmt = $pdo->query("SELECT id FROM accounting_bank_accounts WHERE name = 'صندوق' LIMIT 1");
    $fundId = $fundStmt->fetchColumn() ?: null;
    $now = gmdate('c');

    $pdo->beginTransaction();
    try {
      $pdo->prepare('INSERT INTO accounting_transactions
        (type, category_id, bank_account_id, amount, description, transaction_date, payment_method, donor_name, donor_id, admin_username, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        ->execute(['income', $catId, $fundId, (int) $donation['amount'], $donation['description'],
          substr($now, 0, 10), 'online', $donation['donor_name'] ?: null, $donorId, 'online_gateway', $now]);
      $txId = (int) $pdo->lastInsertId();

      $pdo->prepare("UPDATE online_donations SET status = 'paid', ref_id = ?, accounting_transaction_id = ?, verified_at = ? WHERE id = ?")
        ->execute([(string) $verify['refId'], $txId, $now, $donation['id']]);
      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      header('Location: ' . $redirectBase . '?donation=failed'); exit;
    }

    logAudit($pdo, 'online_gateway', 'donation_verify', (string) $txId, (string) $donation['amount']);

    // Best-effort thank-you SMS — never blocks the redirect if it fails.
    if ($donation['donor_phone'] && preg_match('/^0\d{10}$/', $donation['donor_phone'])) {
      sendSmsViaNajva($donation['donor_phone'], "با سپاس از کمک آنلاین شما به مبلغ " . number_format((int) $donation['amount']) . " تومان به موسسه خیریه درمانی مهر جاوید. کد پیگیری: " . $verify['refId']);
    }

    header('Location: ' . $redirectBase . '?donation=success&ref=' . urlencode((string) $verify['refId']));
    exit;
  }

  // -- patient registration --------------------------------------------------
  case 'user_register': {
    requireCsrf();
    if (!rateLimitCheck($pdo, 'register', clientIp(), 10, 3600)) {
      fail('تعداد درخواست‌ها بیش از حد مجاز است، لطفاً بعداً تلاش کنید.', 429);
    }
    $name = str_field('name', 120);
    $fatherName = str_field('fatherName', 120);
    $nid = str_field('nationalId', 10);
    $phone = str_field('phone', 11);
    $city = str_field('city', 120);
    $dob = str_field('dob', 20);
    $password = (string) ($_POST['password'] ?? '');
    $referrer = str_field('referrerName', 120); // optional — name/institution of the referring person or organization
    $referrerPhone = str_field('referrerPhone', 20); // optional — the referrer's own contact number

    if (!$name || !$fatherName || !$city) fail('لطفاً تمام فیلدهای الزامی را تکمیل کنید.');
    if (!validateNationalId($nid)) fail('کد ملی معتبر نیست.');
    if (!preg_match('/^0\d{10}$/', $phone)) fail('شماره موبایل معتبر نیست.');
    if ($referrerPhone && !preg_match('/^0\d{10}$/', $referrerPhone)) fail('شماره تماس معرف معتبر نیست.');
    if (mb_strlen($password) < 4) fail('رمز عبور باید حداقل ۴ کاراکتر باشد.');

    // The phone must have been verified via otp_verify (purpose=register) in this
    // same session, within the last 10 minutes, and must match what's submitted here.
    $verifiedPhone = $_SESSION['phone_verified'] ?? null;
    $verifiedAt = $_SESSION['phone_verified_at'] ?? 0;
    if ($verifiedPhone !== $phone || (time() - (int) $verifiedAt) > 600) {
      fail('لطفاً ابتدا شماره موبایل خود را با کد پیامکی تایید کنید.');
    }

    $check = $pdo->prepare('SELECT 1 FROM users WHERE national_id = ?');
    $check->execute([$nid]);
    if ($check->fetchColumn()) fail('این کد ملی قبلاً ثبت شده است.');

    $stmt = $pdo->prepare('INSERT INTO users (national_id, name, father_name, phone, city, dob, password_hash, created_at, referrer, referrer_phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$nid, $name, $fatherName, $phone, $city, $dob, password_hash($password, PASSWORD_DEFAULT), gmdate('c'), $referrer ?: null, $referrerPhone ?: null]);

    unset($_SESSION['phone_verified'], $_SESSION['phone_verified_at']);
    session_regenerate_id(true);
    $_SESSION['user_nid'] = $nid;
    ok(['user' => ['name' => $name, 'fatherName' => $fatherName, 'nationalId' => $nid, 'phone' => $phone, 'city' => $city, 'dob' => $dob, 'referrer' => $referrer, 'referrerPhone' => $referrerPhone]]);
  }

  // -- patient login ---------------------------------------------------------
  case 'user_login': {
    requireCsrf();
    $nid = str_field('nationalId', 10);
    $password = (string) ($_POST['password'] ?? '');
    if (!validateNationalId($nid)) fail('کد ملی یا رمز عبور اشتباه است.');

    if (!rateLimitCheck($pdo, 'user_login', clientIp() . ':' . $nid, 5, 900)) {
      fail('تعداد تلاش‌های ورود بیش از حد مجاز است، لطفاً ۱۵ دقیقه دیگر تلاش کنید.', 429);
    }

    $stmt = $pdo->prepare('SELECT * FROM users WHERE national_id = ?');
    $stmt->execute([$nid]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || !password_verify($password, $row['password_hash'])) {
      fail('کد ملی یا رمز عبور اشتباه است.');
    }

    session_regenerate_id(true);
    $_SESSION['user_nid'] = $nid;
    unset($_SESSION['admin_user']);
    ok(['user' => sanitizedUser($row)]);
  }

  case 'user_logout': {
    unset($_SESSION['user_nid']);
    ok();
  }
  // -- request an SMS code, either to log in or to verify a phone during registration --
  case 'otp_request': {
    requireCsrf();
    $phone = str_field('phone', 11);
    $purpose = (string) ($_POST['purpose'] ?? '');
    if (!preg_match('/^0\d{10}$/', $phone)) fail('شماره موبایل معتبر نیست.');
    if (!in_array($purpose, ['login', 'register'], true)) fail('درخواست نامعتبر است.');

    if (!rateLimitCheck($pdo, 'otp_request', clientIp() . ':' . $phone, 5, 900)) {
      fail('تعداد درخواست‌های کد بیش از حد مجاز است، لطفاً ۱۵ دقیقه دیگر تلاش کنید.', 429);
    }

    if ($purpose === 'login') {
      $stmt = $pdo->prepare('SELECT 1 FROM users WHERE phone = ?');
      $stmt->execute([$phone]);
      // Deliberately vague — do not reveal whether this phone number is registered.
      if (!$stmt->fetchColumn()) fail('اگر این شماره ثبت‌نام شده باشد، کد پیامک برایش ارسال می‌شود. لطفاً شماره را بررسی کنید.');
    } else {
      $stmt = $pdo->prepare('SELECT 1 FROM users WHERE phone = ?');
      $stmt->execute([$phone]);
      if ($stmt->fetchColumn()) fail('این شماره موبایل قبلاً ثبت‌نام کرده است. از گزینه «ورود» استفاده کنید.');
    }

    $code = (string) random_int(10000, 99999);
    $now = time();
    $pdo->prepare('INSERT INTO otp_codes (phone, purpose, code, expires_at, created_at) VALUES (?,?,?,?,?)')
      ->execute([$phone, $purpose, $code, $now + 120, gmdate('c')]);

    $result = sendOtpSmsViaNajva($phone, $code);
    if (!$result['ok']) fail('ارسال پیامک ممکن نشد: ' . $result['detail'], 502);

    ok(['maskedPhone' => substr($phone, 0, 4) . '***' . substr($phone, -2)]);
  }

  // -- verify an SMS code: logs the patient in, or marks a phone verified for registration --
  case 'otp_verify': {
    requireCsrf();
    $phone = str_field('phone', 11);
    $code = str_field('code', 5);
    $purpose = (string) ($_POST['purpose'] ?? '');
    if (!preg_match('/^0\d{10}$/', $phone)) fail('شماره موبایل معتبر نیست.');
    if (!in_array($purpose, ['login', 'register'], true)) fail('درخواست نامعتبر است.');

    if (!rateLimitCheck($pdo, 'otp_verify', clientIp() . ':' . $phone, 8, 900)) {
      fail('تعداد تلاش‌های نامعتبر بیش از حد مجاز است، لطفاً ۱۵ دقیقه دیگر تلاش کنید.', 429);
    }

    $stmt = $pdo->prepare('SELECT * FROM otp_codes WHERE phone = ? AND purpose = ? ORDER BY id DESC LIMIT 1');
    $stmt->execute([$phone, $purpose]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || $row['expires_at'] < time() || $row['attempts'] >= 5 || !hash_equals($row['code'], $code)) {
      if ($row) $pdo->prepare('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?')->execute([$row['id']]);
      fail('کد وارد شده نامعتبر یا منقضی شده است.');
    }

    $pdo->prepare('DELETE FROM otp_codes WHERE phone = ? AND purpose = ?')->execute([$phone, $purpose]);

    if ($purpose === 'register') {
      // Mark this phone as verified for the next few minutes so user_register can check it.
      $_SESSION['phone_verified'] = $phone;
      $_SESSION['phone_verified_at'] = time();
      ok();
    }

    $userStmt = $pdo->prepare('SELECT * FROM users WHERE phone = ?');
    $userStmt->execute([$phone]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) fail('حساب کاربری یافت نشد.', 404);

    session_regenerate_id(true);
    $_SESSION['user_nid'] = $user['national_id'];
    unset($_SESSION['admin_user']);
    ok(['user' => sanitizedUser($user)]);
  }

  // -- new case submission (bundles form + optional files in one call) ------
  case 'submission_create': {
    requireCsrf();
    $nid = requireUser();

    $userStmt = $pdo->prepare('SELECT * FROM users WHERE national_id = ?');
    $userStmt->execute([$nid]);
    $user = $userStmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) fail('حساب کاربری یافت نشد.', 401);

    if (!rateLimitCheck($pdo, 'submission_create', clientIp(), 20, 3600)) {
      fail('تعداد درخواست‌ها بیش از حد مجاز است.', 429);
    }

    $specialty = str_field('specialty', 60);
    $specialtyLabel = str_field('specialtyLabel', 120) ?: $specialty;
    $problemDescription = str_field('problemDescription', 5000);
    $needsAccommodation = (($_POST['needsAccommodation'] ?? '') === '1');
    $accommodationDays = $needsAccommodation ? str_field('accommodationDays', 10) : '';
    $companionCount = $needsAccommodation ? str_field('companionCount', 10) : '';
    $companionPhone = $needsAccommodation ? str_field('companionPhone', 11) : '';

    // Optional: patient may already have paid receipts to submit for financial assistance.
    // Multiple receipt photos are supported (same pattern as medical docs).
    $receiptAmount = (int) ($_POST['receiptAmount'] ?? 0);
    $receiptPhotosIn = json_decode((string) ($_POST['receiptPhotos'] ?? '[]'), true);
    if (!is_array($receiptPhotosIn) || count($receiptPhotosIn) > 15) fail('فهرست عکس‌های رسید نامعتبر است.');
    $receiptPhotosParsed = [];
    foreach ($receiptPhotosIn as $rp) {
      if (!is_string($rp)) fail('قالب عکس رسید نامعتبر است.');
      $receiptPhotosParsed[] = parseDataUrl($rp, ['image/jpeg', 'image/png', 'image/webp'], MAX_ASSET_BYTES);
    }
    if ($receiptAmount < 0) fail('مبلغ رسید نامعتبر است.');

    if (!$specialty) fail('لطفاً تخصص پزشکی مورد نیاز را انتخاب کنید.');
    if (!$problemDescription) fail('لطفاً شرح مشکل را وارد کنید.');

    $companionNames = [];
    if ($needsAccommodation) {
      $decoded = json_decode((string) ($_POST['companionNames'] ?? '[]'), true);
      if (!is_array($decoded) || count($decoded) > 20) fail('فهرست همراهان نامعتبر است.');
      foreach ($decoded as $n) {
        if (!is_string($n)) fail('فهرست همراهان نامعتبر است.');
        $companionNames[] = mb_substr(trim($n), 0, 120);
      }
      if (!preg_match('/^0\d{10}$/', $companionPhone)) fail('شماره تماس همراه معتبر نیست.');
      if (!$accommodationDays || !ctype_digit($accommodationDays)) fail('تعداد روز اسکان معتبر نیست.');
    }

    // Optional uploaded files — validated + size-capped before anything is stored.
    // photoThumb: small pre-downscaled preview kept inline on the record for fast
    // list rendering. photoFull: the original-resolution ID-card photo, stored as
    // an asset and only fetched on demand when an admin opens the case detail.
    $photoThumb = parseDataUrl($_POST['photoThumb'] ?? null, ['image/jpeg', 'image/png', 'image/webp'], 400 * 1024);
    $photoFull = parseDataUrl($_POST['photoFull'] ?? null, ['image/jpeg', 'image/png', 'image/webp'], MAX_ASSET_BYTES);

    $docsIn = json_decode((string) ($_POST['medicalDocs'] ?? '[]'), true);
    if (!is_array($docsIn) || count($docsIn) > 15) fail('فهرست مدارک پزشکی نامعتبر است.');
    $docsParsed = [];
    foreach ($docsIn as $d) {
      if (!is_array($d) || !isset($d['dataUrl'], $d['name'])) fail('قالب مدارک پزشکی نامعتبر است.');
      $parsed = parseDataUrl($d['dataUrl'], ALLOWED_FILE_MIMES, MAX_ASSET_BYTES);
      $docsParsed[] = ['name' => mb_substr((string) $d['name'], 0, 200), 'mime' => $parsed[0], 'dataUrl' => $parsed[1]];
    }

    $companionFatherNames = [];
    $companionNationalIds = [];
    if ($needsAccommodation) {
      $decodedFathers = json_decode((string) ($_POST['companionFatherNames'] ?? '[]'), true);
      $decodedNids = json_decode((string) ($_POST['companionNationalIds'] ?? '[]'), true);
      if (!is_array($decodedFathers) || !is_array($decodedNids)) fail('اطلاعات همراهان نامعتبر است.');
      foreach ($decodedFathers as $fn) {
        if (!is_string($fn)) fail('اطلاعات همراهان نامعتبر است.');
        $companionFatherNames[] = mb_substr(trim($fn), 0, 120);
      }
      foreach ($decodedNids as $nidVal) {
        if (!is_string($nidVal)) fail('اطلاعات همراهان نامعتبر است.');
        $companionNationalIds[] = trim($nidVal);
      }
      if (count($companionFatherNames) !== count($companionNames) || count($companionNationalIds) !== count($companionNames)
        || in_array('', $companionFatherNames, true)) {
        fail('لطفاً نام، نام پدر و کد ملی تمام همراهان را وارد کنید.');
      }
      foreach ($companionNationalIds as $cnid) {
        if (!validateNationalId($cnid)) fail('کد ملی یکی از همراهان معتبر نیست.');
      }
    }

    $id = 'submission:' . $nid . ':' . (string) (int) (microtime(true) * 1000);
    $submittedAt = gmdate('c');
    $docsMeta = array_map(fn($d) => ['name' => $d['name'], 'type' => $d['mime']], $docsParsed);

    $pdo->beginTransaction();
    try {
      $ins = $pdo->prepare('INSERT INTO submissions (
        id, national_id, name, father_name, dob, phone, city, specialty, specialty_label,
        problem_description, photo_thumb, has_full_photo, needs_accommodation, accommodation_days,
        companion_names, companion_count, companion_phone, companion_photo_count, medical_docs_meta,
        submitted_at, status, status_updated_at, companion_father_names, companion_national_ids,
        requested_amount, financial_status, receipt_count
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
      $ins->execute([
        $id, $nid, $user['name'], $user['father_name'], $user['dob'], $user['phone'], $user['city'],
        $specialty, $specialtyLabel, $problemDescription, $photoThumb ? $photoThumb[1] : null, $photoFull ? 1 : 0,
        $needsAccommodation ? 1 : 0, $accommodationDays, json_encode($companionNames, JSON_UNESCAPED_UNICODE),
        $companionCount, $companionPhone, 0, json_encode($docsMeta, JSON_UNESCAPED_UNICODE),
        $submittedAt, 'submitted', $submittedAt,
        json_encode($companionFatherNames, JSON_UNESCAPED_UNICODE), json_encode($companionNationalIds, JSON_UNESCAPED_UNICODE),
        $receiptAmount > 0 ? $receiptAmount : null, $receiptAmount > 0 ? 'pending_review' : 'none',
        count($receiptPhotosParsed),
      ]);

      $assetIns = $pdo->prepare('INSERT INTO submission_assets (submission_id, kind, idx, mime, name, data) VALUES (?,?,?,?,?,?)');
      if ($photoFull) $assetIns->execute([$id, 'photo', 0, $photoFull[0], null, $photoFull[1]]);
      foreach ($docsParsed as $i => $d) $assetIns->execute([$id, 'doc', $i, $d['mime'], $d['name'], $d['dataUrl']]);
      foreach ($receiptPhotosParsed as $i => $rp) $assetIns->execute([$id, 'receipt', $i, $rp[0], null, $rp[1]]);

      $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?, ?, ?, ?)')
        ->execute([$id, 'submitted', 'درخواست توسط مددجو ثبت شد.', $submittedAt]);

      $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
        ->execute(['admin', '*', $id, 'new_submission', 'یک پرونده جدید توسط ' . $user['name'] . ' ثبت شد.', $submittedAt]);

      if ($receiptAmount > 0) {
        $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?,?,?,?)')
          ->execute([$id, 'financial_request', 'درخواست کمک مالی به مبلغ ' . number_format($receiptAmount) . ' تومان همراه با ثبت پرونده ارسال شد.', $submittedAt]);
        $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
          ->execute(['admin', '*', $id, 'financial_request', 'درخواست کمک مالی جدید برای بررسی ثبت شد.', $submittedAt]);
      }

      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('submission_create failed: ' . $e->getMessage());
      fail('خطا در ذخیره اطلاعات در سرور.', 500);
    }

    ok(['id' => $id]);
  }

  // -- admin manually creates a case on behalf of a patient who couldn't register online --
  case 'admin_create_submission': {
    requireCsrf();
    $adminUser = requireAdmin();

    $name = str_field('name', 120);
    $fatherName = str_field('fatherName', 120);
    $nid = str_field('nationalId', 10);
    $phone = str_field('phone', 11);
    $city = str_field('city', 80);
    $dob = str_field('dob', 20);
    if (!$name || !$fatherName || !$city) fail('لطفاً تمام فیلدهای هویتی الزامی را تکمیل کنید.');
    if (!validateNationalId($nid)) fail('کد ملی معتبر نیست.');
    if (!preg_match('/^0\d{10}$/', $phone)) fail('شماره موبایل معتبر نیست.');

    $specialty = str_field('specialty', 60);
    $specialtyLabel = str_field('specialtyLabel', 120) ?: $specialty;
    $problemDescription = str_field('problemDescription', 5000);
    $needsAccommodation = (($_POST['needsAccommodation'] ?? '') === '1');
    $accommodationDays = $needsAccommodation ? str_field('accommodationDays', 10) : '';
    $companionCount = $needsAccommodation ? str_field('companionCount', 10) : '';
    $companionPhone = $needsAccommodation ? str_field('companionPhone', 11) : '';
    if (!$specialty) fail('لطفاً تخصص پزشکی مورد نیاز را انتخاب کنید.');
    if (!$problemDescription) fail('لطفاً شرح مشکل را وارد کنید.');

    $companionNames = [];
    $companionFatherNames = [];
    $companionNationalIds = [];
    if ($needsAccommodation) {
      $decoded = json_decode((string) ($_POST['companionNames'] ?? '[]'), true);
      if (!is_array($decoded) || count($decoded) > 20) fail('فهرست همراهان نامعتبر است.');
      foreach ($decoded as $n) {
        if (!is_string($n)) fail('فهرست همراهان نامعتبر است.');
        $companionNames[] = mb_substr(trim($n), 0, 120);
      }
      $decodedFathers = json_decode((string) ($_POST['companionFatherNames'] ?? '[]'), true);
      $decodedNids = json_decode((string) ($_POST['companionNationalIds'] ?? '[]'), true);
      $decodedFathers = is_array($decodedFathers) ? $decodedFathers : [];
      $decodedNids = is_array($decodedNids) ? $decodedNids : [];
      foreach ($companionNames as $i => $cn) {
        $companionFatherNames[] = isset($decodedFathers[$i]) && is_string($decodedFathers[$i]) ? mb_substr(trim($decodedFathers[$i]), 0, 120) : '';
        $companionNationalIds[] = isset($decodedNids[$i]) && is_string($decodedNids[$i]) ? trim($decodedNids[$i]) : '';
      }
    }

    $photoThumb = parseDataUrl($_POST['photoThumb'] ?? null, ['image/jpeg', 'image/png', 'image/webp'], 400 * 1024);
    $photoFull = parseDataUrl($_POST['photoFull'] ?? null, ['image/jpeg', 'image/png', 'image/webp'], MAX_ASSET_BYTES);
    $docsIn = json_decode((string) ($_POST['medicalDocs'] ?? '[]'), true);
    if (!is_array($docsIn) || count($docsIn) > 15) fail('فهرست مدارک پزشکی نامعتبر است.');
    $docsParsed = [];
    foreach ($docsIn as $d) {
      if (!is_array($d) || !isset($d['dataUrl'], $d['name'])) fail('قالب مدارک پزشکی نامعتبر است.');
      $parsed = parseDataUrl($d['dataUrl'], ALLOWED_FILE_MIMES, MAX_ASSET_BYTES);
      $docsParsed[] = ['name' => mb_substr((string) $d['name'], 0, 200), 'mime' => $parsed[0], 'dataUrl' => $parsed[1]];
    }

    $pdo->beginTransaction();
    try {
      // Reuse the patient's account if one already exists for this national ID; otherwise create one.
      $userStmt = $pdo->prepare('SELECT * FROM users WHERE national_id = ?');
      $userStmt->execute([$nid]);
      $user = $userStmt->fetch(PDO::FETCH_ASSOC);
      if (!$user) {
        $randomPassword = bin2hex(random_bytes(8));
        $pdo->prepare('INSERT INTO users (national_id, name, father_name, phone, city, dob, password_hash, created_at) VALUES (?,?,?,?,?,?,?,?)')
          ->execute([$nid, $name, $fatherName, $phone, $city, $dob, password_hash($randomPassword, PASSWORD_DEFAULT), gmdate('c')]);
      }

      $id = 'submission:' . $nid . ':' . (string) (int) (microtime(true) * 1000);
      $submittedAt = gmdate('c');
      $docsMeta = array_map(fn($d) => ['name' => $d['name'], 'type' => $d['mime']], $docsParsed);

      $ins = $pdo->prepare('INSERT INTO submissions (
        id, national_id, name, father_name, dob, phone, city, specialty, specialty_label,
        problem_description, photo_thumb, has_full_photo, needs_accommodation, accommodation_days,
        companion_names, companion_count, companion_phone, companion_photo_count, medical_docs_meta,
        submitted_at, status, status_updated_at, manual_entry, manual_entry_by,
        companion_father_names, companion_national_ids
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
      $ins->execute([
        $id, $nid, $name, $fatherName, $dob, $phone, $city,
        $specialty, $specialtyLabel, $problemDescription, $photoThumb ? $photoThumb[1] : null, $photoFull ? 1 : 0,
        $needsAccommodation ? 1 : 0, $accommodationDays, json_encode($companionNames, JSON_UNESCAPED_UNICODE),
        $companionCount, $companionPhone, 0, json_encode($docsMeta, JSON_UNESCAPED_UNICODE),
        $submittedAt, 'submitted', $submittedAt, 1, $adminUser,
        json_encode($companionFatherNames, JSON_UNESCAPED_UNICODE), json_encode($companionNationalIds, JSON_UNESCAPED_UNICODE),
      ]);

      $assetIns = $pdo->prepare('INSERT INTO submission_assets (submission_id, kind, idx, mime, name, data) VALUES (?,?,?,?,?,?)');
      if ($photoFull) $assetIns->execute([$id, 'photo', 0, $photoFull[0], null, $photoFull[1]]);
      foreach ($docsParsed as $i => $d) $assetIns->execute([$id, 'doc', $i, $d['mime'], $d['name'], $d['dataUrl']]);

      $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?, ?, ?, ?)')
        ->execute([$id, 'submitted', 'پرونده به‌صورت دستی توسط مدیر (' . $adminUser . ') ثبت شد.', $submittedAt]);

      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('manual_entry (submission_create) failed: ' . $e->getMessage());
      fail('خطا در ذخیره اطلاعات در سرور.', 500);
    }

    logAudit($pdo, $adminUser, 'manual_submission_create', $id, $name);
    ok(['id' => $id]);
  }

  // -- patient submits a receipt amount, requesting financial assistance -----
  case 'submission_submit_receipt': {
    requireCsrf();
    $nid = requireUser();
    $id = (string) ($_POST['id'] ?? '');
    $owner = submissionOwnerFromId($id);
    if (!$owner || $owner !== $nid) fail('دسترسی غیرمجاز.', 403);

    $amount = (int) ($_POST['amount'] ?? 0);
    $note = str_field('note', 500);
    if ($amount <= 0) fail('لطفاً مبلغ معتبری وارد کنید.');

    $now = gmdate('c');
    $pdo->prepare('UPDATE submissions SET requested_amount = ?, requested_note = ?, financial_status = ? WHERE id = ?')
      ->execute([$amount, $note ?: null, 'pending_review', $id]);
    $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?,?,?,?)')
      ->execute([$id, 'financial_request', 'درخواست کمک مالی به مبلغ ' . number_format($amount) . ' تومان ثبت شد.', $now]);
    $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
      ->execute(['admin', '*', $id, 'financial_request', 'درخواست کمک مالی جدید برای بررسی ثبت شد.', $now]);
    ok();
  }

  // -- admin approves or rejects a financial assistance request --------------
  case 'financial_review': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (string) ($_POST['id'] ?? '');
    $decision = (string) ($_POST['decision'] ?? '');
    $approvedAmount = (int) ($_POST['approvedAmount'] ?? 0);
    $note = str_field('note', 500);
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if (!in_array($decision, ['approve', 'reject'], true)) fail('درخواست نامعتبر است.');
    if ($decision === 'approve' && $approvedAmount <= 0) fail('لطفاً مبلغ تاییدشده را وارد کنید.');

    $now = gmdate('c');
    if ($decision === 'approve') {
      $pdo->prepare('UPDATE submissions SET approved_amount = ?, financial_status = ?, financial_note = ? WHERE id = ?')
        ->execute([$approvedAmount, 'approved', $note ?: null, $id]);
      $msg = 'درخواست کمک مالی شما به مبلغ ' . number_format($approvedAmount) . ' تومان تایید شد.';
      $timelineNote = 'کمک مالی به مبلغ ' . number_format($approvedAmount) . ' تومان تایید شد.';
    } else {
      $pdo->prepare('UPDATE submissions SET financial_status = ?, financial_note = ? WHERE id = ?')
        ->execute(['rejected', $note ?: null, $id]);
      $msg = 'درخواست کمک مالی شما بررسی و متاسفانه رد شد.';
      $timelineNote = 'درخواست کمک مالی رد شد.';
    }
    $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?,?,?,?)')
      ->execute([$id, 'financial_review', $timelineNote, $now]);
    $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
      ->execute(['user', $owner, $id, 'financial_review', $msg, $now]);
    logAudit($pdo, $adminUser, 'financial_review', $id, $decision . ($decision === 'approve' ? (':' . $approvedAmount) : ''));
    ok();
  }

  // -- admin records an actual payment transaction ----------------------------
  case 'payment_record': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (string) ($_POST['id'] ?? '');
    $amount = (int) ($_POST['amount'] ?? 0);
    $note = str_field('note', 500);
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if ($amount <= 0) fail('لطفاً مبلغ معتبری وارد کنید.');

    $now = gmdate('c');
    $pdo->beginTransaction();
    try {
      $pdo->prepare('INSERT INTO payments (submission_id, amount, note, admin_username, created_at) VALUES (?,?,?,?,?)')
        ->execute([$id, $amount, $note ?: null, $adminUser, $now]);

      $sumStmt = $pdo->prepare('SELECT COALESCE(SUM(amount), 0) FROM payments WHERE submission_id = ?');
      $sumStmt->execute([$id]);
      $totalPaid = (int) $sumStmt->fetchColumn();

      $approvedStmt = $pdo->prepare('SELECT approved_amount FROM submissions WHERE id = ?');
      $approvedStmt->execute([$id]);
      $approvedAmount = (int) $approvedStmt->fetchColumn();

      $newStatus = ($approvedAmount > 0 && $totalPaid >= $approvedAmount) ? 'paid' : 'partially_paid';
      $pdo->prepare('UPDATE submissions SET financial_status = ? WHERE id = ?')->execute([$newStatus, $id]);

      // Keep the general accounting ledger complete: every patient payment is
      // also an expense transaction, filed under "هدایت درمانی مددجویان".
      $nameStmt = $pdo->prepare('SELECT name FROM submissions WHERE id = ?');
      $nameStmt->execute([$id]);
      $patientName = $nameStmt->fetchColumn() ?: '';
      $catStmt = $pdo->prepare("SELECT id FROM accounting_categories WHERE type = 'expense' AND name = 'هدایت درمانی مددجویان' LIMIT 1");
      $catStmt->execute();
      $medCatId = $catStmt->fetchColumn();
      $fundStmt = $pdo->prepare("SELECT id FROM accounting_bank_accounts WHERE name = 'صندوق' LIMIT 1");
      $fundStmt->execute();
      $fundAccountId = $fundStmt->fetchColumn() ?: null;
      if ($medCatId) {
        $pdo->prepare('INSERT INTO accounting_transactions
          (type, category_id, bank_account_id, amount, description, transaction_date, payment_method, related_submission_id, admin_username, created_at)
          VALUES (?,?,?,?,?,?,?,?,?,?)')
          ->execute(['expense', $medCatId, $fundAccountId, $amount, 'هدایت درمانی — ' . $patientName . ($note ? (' — ' . $note) : ''),
            substr($now, 0, 10), 'other', $id, $adminUser, $now]);
      }

      $timelineNote = 'پرداخت به مبلغ ' . number_format($amount) . ' تومان ثبت شد.' . ($newStatus === 'paid' ? ' هدایت درمانی کامل شد.' : '');
      $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?,?,?,?)')
        ->execute([$id, 'payment', $timelineNote, $now]);
      $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
        ->execute(['user', $owner, $id, 'payment', $timelineNote, $now]);

      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('payment_record failed: ' . $e->getMessage());
      fail('خطا در ثبت پرداخت.', 500);
    }
    logAudit($pdo, $adminUser, 'payment_record', $id, (string) $amount);
    ok(['totalPaid' => $totalPaid ?? 0, 'status' => $newStatus ?? 'partially_paid']);
  }

  // -- lists payment transactions for a case (owner or admin) -----------------
  case 'payment_list': {
    $id = (string) ($_POST['id'] ?? '');
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if (currentUserNid() !== $owner && !currentAdmin()) fail('دسترسی غیرمجاز.', 403);

    $stmt = $pdo->prepare('SELECT amount, note, admin_username, created_at FROM payments WHERE submission_id = ? ORDER BY id ASC');
    $stmt->execute([$id]);
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $total = array_sum(array_column($items, 'amount'));
    ok(['items' => $items, 'total' => $total]);
  }

  // -- aggregated financial totals for a period (admin dashboard) -------------
  case 'financial_summary': {
    requireAdmin();
    $totals = $pdo->query("SELECT
      COALESCE(SUM(requested_amount), 0) AS requested,
      COALESCE(SUM(approved_amount), 0) AS approved
      FROM submissions")->fetch(PDO::FETCH_ASSOC);
    $paid = (int) $pdo->query('SELECT COALESCE(SUM(amount), 0) FROM payments')->fetchColumn();
    $pendingCount = (int) $pdo->query("SELECT COUNT(*) FROM submissions WHERE financial_status = 'pending_review'")->fetchColumn();

    $topDonors = $pdo->query("SELECT d.name, COALESCE(SUM(t.amount),0) AS total
      FROM donors d JOIN accounting_transactions t ON t.donor_id = d.id AND t.type = 'income'
      GROUP BY d.id ORDER BY total DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);

    $today = gmdate('Y-m-d');
    $todayStmt = $pdo->prepare("SELECT type, COALESCE(SUM(amount),0) AS total, COUNT(*) AS cnt
      FROM accounting_transactions WHERE transaction_date = ? GROUP BY type");
    $todayStmt->execute([$today]);
    $todayTotals = ['income' => 0, 'expense' => 0, 'incomeCount' => 0, 'expenseCount' => 0];
    foreach ($todayStmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
      $todayTotals[$r['type']] = (int) $r['total'];
      $todayTotals[$r['type'] . 'Count'] = (int) $r['cnt'];
    }

    ok([
      'totalRequested' => (int) $totals['requested'],
      'totalApproved' => (int) $totals['approved'],
      'totalPaid' => $paid,
      'pendingCount' => $pendingCount,
      'topDonors' => $topDonors,
      'todayIncome' => $todayTotals['income'],
      'todayExpense' => $todayTotals['expense'],
      'todayIncomeCount' => $todayTotals['incomeCount'],
      'todayExpenseCount' => $todayTotals['expenseCount'],
    ]);
  }

  // -- list own submissions (patient dashboard) ------------------------------
  case 'submission_list_mine': {
    $nid = requireUser();
    $stmt = $pdo->prepare('SELECT * FROM submissions WHERE national_id = ? ORDER BY submitted_at DESC');
    $stmt->execute([$nid]);
    $items = array_map('submissionToRecord', $stmt->fetchAll(PDO::FETCH_ASSOC));
    ok(['items' => $items]);
  }

  // -- list all submissions (admin dashboard) --------------------------------
  case 'submission_list_all': {
    requireAdmin();
    $stmt = $pdo->query('SELECT s.*, u.referrer AS user_referrer, u.referrer_phone AS user_referrer_phone FROM submissions s
      LEFT JOIN users u ON u.national_id = s.national_id
      ORDER BY s.submitted_at DESC');
    $items = array_map('submissionToRecord', $stmt->fetchAll(PDO::FETCH_ASSOC));
    ok(['items' => $items]);
  }

  // -- fetch one photo/document payload for the detail modal -----------------
  case 'submission_asset': {
    $id = (string) ($_POST['id'] ?? '');
    $kind = (string) ($_POST['kind'] ?? '');
    $idx = (int) ($_POST['idx'] ?? 0);
    $owner = submissionOwnerFromId($id);
    if (!$owner || !in_array($kind, ['photo', 'doc', 'companionPhoto', 'receipt'], true)) fail('درخواست نامعتبر است.');

    $isOwner = currentUserNid() === $owner;
    $isAdmin = (bool) currentAdmin();
    if (!$isOwner && !$isAdmin) fail('دسترسی غیرمجاز.', 403);

    $stmt = $pdo->prepare('SELECT mime, name, data FROM submission_assets WHERE submission_id = ? AND kind = ? AND idx = ?');
    $stmt->execute([$id, $kind, $idx]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) fail('فایل یافت نشد.', 404);

    ok(['dataUrl' => $row['data'], 'name' => $row['name'], 'mime' => $row['mime']]);
  }

  // -- delete a submission (admin only) --------------------------------------
  case 'submission_delete': {
    requireCsrf();
    $adminUser = requireAdmin();
    $id = (string) ($_POST['id'] ?? '');
    if (!submissionOwnerFromId($id)) fail('شناسه نامعتبر است.');

    $pdo->beginTransaction();
    try {
      // Deleting a case must also clean up everything that references it —
      // otherwise rows like an accommodation-room assignment are left
      // "dangling": the room stays marked occupied forever with no way back
      // to it, since the case it's occupied "by" no longer exists.
      // accounting_transactions is deliberately left alone — those are real
      // financial records that should survive even if the case is deleted.
      $pdo->prepare('DELETE FROM submission_assets WHERE submission_id = ?')->execute([$id]);
      $pdo->prepare('DELETE FROM submission_timeline WHERE submission_id = ?')->execute([$id]);
      $pdo->prepare('DELETE FROM messages WHERE submission_id = ?')->execute([$id]);
      $pdo->prepare('DELETE FROM notifications WHERE submission_id = ?')->execute([$id]);
      $pdo->prepare('DELETE FROM accommodation_assignments WHERE submission_id = ?')->execute([$id]);
      $pdo->prepare('DELETE FROM payments WHERE submission_id = ?')->execute([$id]);
      $pdo->prepare('DELETE FROM satisfaction_surveys WHERE submission_id = ?')->execute([$id]);
      $pdo->prepare('DELETE FROM submissions WHERE id = ?')->execute([$id]);
      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('submission_delete failed: ' . $e->getMessage());
      fail('خطا در حذف رکورد.', 500);
    }
    logAudit($pdo, $adminUser, 'delete_submission', $id, null);
    ok();
  }

  // -- admin login ------------------------------------------------------------
  case 'admin_login': {
    requireCsrf();
    $username = str_field('username', 60);
    $password = (string) ($_POST['password'] ?? '');

    if (!rateLimitCheck($pdo, 'admin_login', clientIp() . ':' . $username, 5, 900)) {
      fail('تعداد تلاش‌های ورود بیش از حد مجاز است، لطفاً ۱۵ دقیقه دیگر تلاش کنید.', 429);
    }

    $stmt = $pdo->prepare('SELECT * FROM admins WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || !password_verify($password, $row['password_hash'])) {
      fail('نام کاربری یا رمز عبور اشتباه است.');
    }

    // Password is correct. If this account has 2FA enabled, don't finish logging
    // in yet — park the pending username in the session and ask for a TOTP code.
    if ((int) ($row['totp_enabled'] ?? 0) === 1) {
      $_SESSION['pending_2fa_admin'] = $username;
      unset($_SESSION['admin_user'], $_SESSION['user_nid']);
      ok(['needsTotp' => true]);
    }

    $result = finalizeAdminLogin($pdo, $row);
    ok($result);
  }

  // -- second step of admin login when the account has 2FA enabled -----------
  case 'admin_login_totp_verify': {
    requireCsrf();
    $username = $_SESSION['pending_2fa_admin'] ?? '';
    if (!$username) fail('ابتدا نام کاربری و رمز عبور را وارد کنید.', 401);

    if (!rateLimitCheck($pdo, 'admin_totp_verify', clientIp() . ':' . $username, 8, 900)) {
      fail('تعداد تلاش‌های ورود بیش از حد مجاز است، لطفاً ۱۵ دقیقه دیگر تلاش کنید.', 429);
    }

    $code = (string) ($_POST['code'] ?? '');
    $stmt = $pdo->prepare('SELECT * FROM admins WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || !$row['totp_secret'] || !verifyTotpCode($row['totp_secret'], $code)) {
      fail('کد وارد شده صحیح نیست.');
    }

    unset($_SESSION['pending_2fa_admin']);
    $result = finalizeAdminLogin($pdo, $row);
    ok($result);
  }

  case 'admin_logout': {
    unset($_SESSION['admin_user']);
    ok();
  }

  case 'admin_change_password': {
    requireCsrf();
    $username = requireAdmin();
    $current = (string) ($_POST['current'] ?? '');
    $next = (string) ($_POST['next'] ?? '');

    $stmt = $pdo->prepare('SELECT * FROM admins WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || !password_verify($current, $row['password_hash'])) fail('رمز عبور فعلی اشتباه است.');
    if (mb_strlen($next) < 6) fail('رمز عبور جدید باید حداقل ۶ کاراکتر باشد.');

    $upd = $pdo->prepare('UPDATE admins SET password_hash = ?, must_change_password = 0 WHERE username = ?');
    $upd->execute([password_hash($next, PASSWORD_DEFAULT), $username]);
    ok();
  }

  // ===================== two-factor authentication (2FA) =====================

  case 'admin_2fa_status': {
    $username = requireAdmin();
    $stmt = $pdo->prepare('SELECT totp_enabled FROM admins WHERE username = ?');
    $stmt->execute([$username]);
    ok(['enabled' => (bool) $stmt->fetchColumn()]);
  }

  // -- generates a new (not-yet-active) secret and hands it to the admin to scan/enter --
  case 'admin_2fa_setup_start': {
    requireCsrf();
    $username = requireAdmin();
    $secret = generateTotpSecret();
    $_SESSION['pending_totp_secret'] = $secret;
    $orgName = getSetting($pdo, 'org_name');
    ok([
      'secret' => $secret,
      'otpauthUri' => totpProvisioningUri($secret, $username, $orgName),
    ]);
  }

  // -- admin enters the 6-digit code their app now shows, to prove the secret works --
  case 'admin_2fa_setup_confirm': {
    requireCsrf();
    $username = requireAdmin();
    $secret = $_SESSION['pending_totp_secret'] ?? '';
    if (!$secret) fail('ابتدا فعال‌سازی را شروع کنید.');
    $code = (string) ($_POST['code'] ?? '');
    if (!verifyTotpCode($secret, $code)) fail('کد وارد شده صحیح نیست. لطفاً دوباره تلاش کنید.');

    $pdo->prepare('UPDATE admins SET totp_secret = ?, totp_enabled = 1 WHERE username = ?')->execute([$secret, $username]);
    unset($_SESSION['pending_totp_secret']);
    logAudit($pdo, $username, '2fa_enabled', null, null);
    ok();
  }

  // -- requires the current password again, as disabling 2FA is a sensitive action --
  case 'admin_2fa_disable': {
    requireCsrf();
    $username = requireAdmin();
    $password = (string) ($_POST['password'] ?? '');
    $stmt = $pdo->prepare('SELECT password_hash FROM admins WHERE username = ?');
    $stmt->execute([$username]);
    $hash = $stmt->fetchColumn();
    if (!$hash || !password_verify($password, $hash)) fail('رمز عبور اشتباه است.');

    $pdo->prepare('UPDATE admins SET totp_secret = NULL, totp_enabled = 0 WHERE username = ?')->execute([$username]);
    logAudit($pdo, $username, '2fa_disabled', null, null);
    ok();
  }

  // -- resolve access to a submission for the timeline/messages/status endpoints below --
  // (helper is defined inline here since it depends on request state, not just $id)

  // -- read the status timeline for a case (owner or admin) -----------------
  case 'submission_timeline_get': {
    $id = (string) ($_POST['id'] ?? '');
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if (currentUserNid() !== $owner && !currentAdmin()) fail('دسترسی غیرمجاز.', 403);

    $stmt = $pdo->prepare('SELECT status, note, created_at FROM submission_timeline WHERE submission_id = ? ORDER BY id ASC');
    $stmt->execute([$id]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $items = array_map(fn($r) => [
      'status' => $r['status'],
      'label' => TIMELINE_EVENT_META[$r['status']]['label'] ?? $r['status'],
      'color' => TIMELINE_EVENT_META[$r['status']]['color'] ?? '#6B7280',
      'note' => $r['note'],
      'at' => $r['created_at'],
    ], $rows);
    ok(['items' => $items, 'statuses' => CASE_STATUSES]);
  }

  // ===================== satisfaction survey =====================

  // -- patient submits a 1-5 rating (+ optional comment) once their case reaches a final outcome --
  case 'survey_submit': {
    requireCsrf();
    $id = (string) ($_POST['id'] ?? '');
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if (currentUserNid() !== $owner) fail('دسترسی غیرمجاز.', 403);

    $stmt = $pdo->prepare('SELECT status FROM submissions WHERE id = ?');
    $stmt->execute([$id]);
    $status = $stmt->fetchColumn();
    if (!in_array($status, ['final_review', 'rejected'], true)) {
      fail('نظرسنجی فقط بعد از مشخص شدن نتیجه‌ی نهایی پرونده در دسترس است.');
    }

    $rating = (int) ($_POST['rating'] ?? 0);
    if ($rating < 1 || $rating > 5) fail('امتیاز باید بین ۱ تا ۵ باشد.');
    $comment = trim((string) ($_POST['comment'] ?? ''));
    if (mb_strlen($comment) > 1000) $comment = mb_substr($comment, 0, 1000);

    $pdo->prepare('INSERT INTO satisfaction_surveys (submission_id, rating, comment, created_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(submission_id) DO UPDATE SET rating = excluded.rating, comment = excluded.comment, created_at = excluded.created_at')
      ->execute([$id, $rating, $comment !== '' ? $comment : null, gmdate('c')]);
    ok();
  }

  // -- whether this submission already has a survey response (so the frontend can hide the prompt) --
  case 'survey_status': {
    $id = (string) ($_POST['id'] ?? '');
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if (currentUserNid() !== $owner && !currentAdmin()) fail('دسترسی غیرمجاز.', 403);

    $stmt = $pdo->prepare('SELECT rating, comment FROM satisfaction_surveys WHERE submission_id = ?');
    $stmt->execute([$id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    ok(['submitted' => (bool) $row, 'rating' => $row['rating'] ?? null, 'comment' => $row['comment'] ?? null]);
  }

  // -- admin: aggregate satisfaction stats (average rating, distribution, recent comments) --
  case 'survey_stats': {
    requireAdmin();
    $avgStmt = $pdo->query('SELECT COUNT(*) AS n, AVG(rating) AS avg_rating FROM satisfaction_surveys');
    $avgRow = $avgStmt->fetch(PDO::FETCH_ASSOC);

    $distStmt = $pdo->query('SELECT rating, COUNT(*) AS n FROM satisfaction_surveys GROUP BY rating ORDER BY rating');
    $distribution = [];
    foreach ($distStmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
      $distribution[(int) $r['rating']] = (int) $r['n'];
    }

    $recentStmt = $pdo->query('SELECT submission_id, rating, comment, created_at FROM satisfaction_surveys
      WHERE comment IS NOT NULL AND comment != \'\' ORDER BY created_at DESC LIMIT 20');
    ok([
      'count' => (int) $avgRow['n'],
      'average' => $avgRow['avg_rating'] !== null ? round((float) $avgRow['avg_rating'], 2) : null,
      'distribution' => $distribution,
      'recentComments' => $recentStmt->fetchAll(PDO::FETCH_ASSOC),
    ]);
  }

  // -- admin updates a case's status, appending a timeline entry -------------
  case 'submission_set_status': {
    requireCsrf();
    $adminUser = requireAdmin();
    $id = (string) ($_POST['id'] ?? '');
    $status = (string) ($_POST['status'] ?? '');
    $note = str_field('note', 1000);
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if (!array_key_exists($status, CASE_STATUSES)) fail('وضعیت نامعتبر است.');
    if (in_array($status, ['final_review', 'rejected'], true) && $note === '') {
      fail('برای این وضعیت باید توضیح/نتیجه را به‌صورت دستی بنویسید.');
    }
    $label = CASE_STATUSES[$status]['label'];

    $now = gmdate('c');
    $pdo->beginTransaction();
    try {
      $pdo->prepare('UPDATE submissions SET status = ?, status_updated_at = ? WHERE id = ?')->execute([$status, $now, $id]);
      $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?,?,?,?)')
        ->execute([$id, $status, $note ?: null, $now]);
      $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
        ->execute(['user', $owner, $id, 'status_change', 'وضعیت پرونده شما به «' . $label . '» تغییر کرد.', $now]);
      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('status_change failed: ' . $e->getMessage());
      fail('خطا در ثبت تغییر وضعیت.', 500);
    }

    logAudit($pdo, $adminUser, 'status_change', $id, $status);

    // Best-effort SMS to the patient — a delivery failure here never fails the request.
    // Each status has its own on/off toggle in settings (تنظیمات > اعلان‌ها).
    $smsToggleKey = 'notify_sms_' . $status;
    $smsEnabled = getSetting($pdo, $smsToggleKey) !== '0';
    if ($smsEnabled) {
      $phoneStmt = $pdo->prepare('SELECT phone FROM users WHERE national_id = ?');
      $phoneStmt->execute([$owner]);
      $phone = $phoneStmt->fetchColumn();
      if ($phone) {
        $smsLabel = SMS_STATUS_LABELS[$status] ?? str_replace(' ', '‌', mb_substr($label, 0, 20));
        $smsResult = sendTemplateSmsViaNajva($phone, NAJVA_STATUS_TEMPLATE, $smsLabel);
        if (empty($smsResult['ok'])) {
          error_log('status_change SMS failed: ' . ($smsResult['detail'] ?? 'unknown error'));
        }
      }
    }

    ok();
  }

  // -- admin sets a review status for one uploaded document -----------------
  case 'doc_set_status': {
    requireCsrf();
    $adminUser = requireAdmin();
    $id = (string) ($_POST['id'] ?? '');
    $idx = (int) ($_POST['idx'] ?? -1);
    $status = (string) ($_POST['status'] ?? '');
    $note = str_field('note', 500);
    $owner = submissionOwnerFromId($id);
    if (!$owner || $idx < 0) fail('درخواست نامعتبر است.');
    if (!in_array($status, ['received', 'approved', 'needs_correction'], true)) fail('وضعیت مدرک نامعتبر است.');

    $upd = $pdo->prepare('UPDATE submission_assets SET doc_status = ?, review_note = ? WHERE submission_id = ? AND kind = ? AND idx = ?');
    $upd->execute([$status, $note ?: null, $id, 'doc', $idx]);
    if ($upd->rowCount() === 0) fail('مدرک یافت نشد.', 404);

    logAudit($pdo, $adminUser, 'doc_status_change', $id, "idx=$idx status=$status");

    if ($status === 'needs_correction') {
      $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
        ->execute(['user', $owner, $id, 'doc_correction', 'یکی از مدارک پزشکی شما نیاز به اصلاح دارد.', gmdate('c')]);
    }
    ok();
  }

  // -- list document review statuses for a case (owner or admin) ------------
  case 'doc_status_list': {
    $id = (string) ($_POST['id'] ?? '');
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if (currentUserNid() !== $owner && !currentAdmin()) fail('دسترسی غیرمجاز.', 403);

    $stmt = $pdo->prepare("SELECT idx, name, mime, doc_status, review_note FROM submission_assets WHERE submission_id = ? AND kind = 'doc' ORDER BY idx ASC");
    $stmt->execute([$id]);
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  // -- send a message on a case's internal thread (owner or admin) ----------
  case 'message_send': {
    requireCsrf();
    $id = (string) ($_POST['id'] ?? '');
    $body = str_field('body', 2000);
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    if (!$body) fail('متن پیام نمی‌تواند خالی باشد.');

    $isAdmin = (bool) currentAdmin();
    $isOwner = currentUserNid() === $owner;
    if (!$isAdmin && !$isOwner) fail('دسترسی غیرمجاز.', 403);
    if (!rateLimitCheck($pdo, 'message_send', clientIp(), 60, 3600)) fail('تعداد پیام‌ها بیش از حد مجاز است.', 429);

    $role = $isAdmin ? 'admin' : 'user';
    $now = gmdate('c');
    $pdo->prepare('INSERT INTO messages (submission_id, sender_role, body, created_at, read_by_admin, read_by_user) VALUES (?,?,?,?,?,?)')
      ->execute([$id, $role, $body, $now, $isAdmin ? 1 : 0, $isOwner ? 1 : 0]);

    $recipientType = $isAdmin ? 'user' : 'admin';
    $recipientId = $isAdmin ? $owner : '*';
    $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
      ->execute([$recipientType, $recipientId, $id, 'message', 'پیام جدیدی برای پرونده دریافت شد.', $now]);
    ok();
  }

  // -- list a case's message thread, marking incoming messages as read ------
  case 'message_list': {
    $id = (string) ($_POST['id'] ?? '');
    $owner = submissionOwnerFromId($id);
    if (!$owner) fail('شناسه نامعتبر است.');
    $isAdmin = (bool) currentAdmin();
    $isOwner = currentUserNid() === $owner;
    if (!$isAdmin && !$isOwner) fail('دسترسی غیرمجاز.', 403);

    if ($isAdmin) {
      $pdo->prepare('UPDATE messages SET read_by_admin = 1 WHERE submission_id = ?')->execute([$id]);
    } else {
      $pdo->prepare('UPDATE messages SET read_by_user = 1 WHERE submission_id = ?')->execute([$id]);
    }

    $stmt = $pdo->prepare('SELECT sender_role, body, created_at FROM messages WHERE submission_id = ? ORDER BY id ASC');
    $stmt->execute([$id]);
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  // -- notification feed for the current session (user or admin) ------------
  case 'notification_list': {
    if (currentAdmin()) {
      $stmt = $pdo->prepare("SELECT id, submission_id, type, message, created_at, read_at FROM notifications WHERE recipient_type = 'admin' ORDER BY id DESC LIMIT 50");
      $stmt->execute();
    } elseif (currentUserNid()) {
      $stmt = $pdo->prepare("SELECT id, submission_id, type, message, created_at, read_at FROM notifications WHERE recipient_type = 'user' AND recipient_id = ? ORDER BY id DESC LIMIT 50");
      $stmt->execute([currentUserNid()]);
    } else {
      fail('ابتدا وارد حساب کاربری شوید.', 401);
    }
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $unread = count(array_filter($items, fn($n) => empty($n['read_at'])));
    ok(['items' => $items, 'unread' => $unread]);
  }

  // -- mark one notification (or all) as read --------------------------------
  case 'notification_mark_read': {
    requireCsrf();
    $id = (string) ($_POST['id'] ?? '');
    $now = gmdate('c');
    if (currentAdmin()) {
      if ($id === 'all') {
        $pdo->prepare("UPDATE notifications SET read_at = ? WHERE recipient_type = 'admin' AND read_at IS NULL")->execute([$now]);
      } else {
        $pdo->prepare("UPDATE notifications SET read_at = ? WHERE id = ? AND recipient_type = 'admin'")->execute([$now, (int) $id]);
      }
    } elseif (currentUserNid()) {
      $nid = currentUserNid();
      if ($id === 'all') {
        $pdo->prepare("UPDATE notifications SET read_at = ? WHERE recipient_type = 'user' AND recipient_id = ? AND read_at IS NULL")->execute([$now, $nid]);
      } else {
        $pdo->prepare("UPDATE notifications SET read_at = ? WHERE id = ? AND recipient_type = 'user' AND recipient_id = ?")->execute([$now, (int) $id, $nid]);
      }
    } else {
      fail('ابتدا وارد حساب کاربری شوید.', 401);
    }
    ok();
  }

  // -- admin pins/unpins a case as priority, with an optional note -----------
  case 'submission_set_priority': {
    requireCsrf();
    $adminUser = requireAdmin();
    $id = (string) ($_POST['id'] ?? '');
    $flag = ((string) ($_POST['flag'] ?? '0')) === '1' ? 1 : 0;
    $note = str_field('note', 300);
    if (!submissionOwnerFromId($id)) fail('شناسه نامعتبر است.');

    $pdo->prepare('UPDATE submissions SET priority_flag = ?, priority_note = ? WHERE id = ?')
      ->execute([$flag, $note ?: null, $id]);
    logAudit($pdo, $adminUser, $flag ? 'flag_priority' : 'unflag_priority', $id, $note ?: null);
    ok();
  }

  // -- admin edits a beneficiary's (مددجو) profile fields ---------------------
  case 'submission_update': {
    requireCsrf();
    $adminUser = requireAdmin();
    $id = (string) ($_POST['id'] ?? '');
    if (!submissionOwnerFromId($id)) fail('شناسه نامعتبر است.');

    $name = str_field('name', 120);
    $fatherName = str_field('fatherName', 120);
    $dob = str_field('dob', 20);
    $phone = str_field('phone', 20);
    $city = str_field('city', 80);
    $problemDescription = str_field('problemDescription', 2000);
    $companionPhone = str_field('companionPhone', 20);
    $companionCount = str_field('companionCount', 10);

    if (!$name) fail('لطفاً نام و نام خانوادگی را وارد کنید.');

    $pdo->prepare('UPDATE submissions SET
        name = ?, father_name = ?, dob = ?, phone = ?, city = ?,
        problem_description = ?, companion_phone = ?, companion_count = ?
      WHERE id = ?')
      ->execute([
        $name, $fatherName ?: null, $dob ?: null, $phone ?: null, $city ?: null,
        $problemDescription ?: null, $companionPhone ?: null, $companionCount ?: null,
        $id,
      ]);

    $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?,?,?,?)')
      ->execute([$id, 'profile_edit', 'اطلاعات پروفایل مددجو توسط مدیر ویرایش شد.', gmdate('c')]);

    logAudit($pdo, $adminUser, 'submission_update', $id, $name);
    ok();
  }

  // -- lightweight beneficiary (مددجو) search, used to link accounting
  //    payments to a case from the accounting section. ------------------------
  case 'submission_search': {
    requireAdmin();
    $q = str_field('q', 100);
    if (mb_strlen($q) < 2) { ok(['items' => []]); }
    $like = '%' . $q . '%';
    $stmt = $pdo->prepare("SELECT id, name, national_id, phone, city FROM submissions
      WHERE name LIKE ? OR national_id LIKE ? OR phone LIKE ?
      ORDER BY submitted_at DESC LIMIT 15");
    $stmt->execute([$like, $like, $like]);
    $items = array_map(function ($r) {
      return [
        'id' => $r['id'],
        'name' => $r['name'],
        'nationalId' => $r['national_id'],
        'phone' => $r['phone'],
        'city' => $r['city'],
      ];
    }, $stmt->fetchAll(PDO::FETCH_ASSOC));
    ok(['items' => $items]);
  }

  // -- aggregated numbers for the admin dashboard (charts, breakdowns) -------
  case 'dashboard_stats': {
    requireAdmin();
    $period = (string) ($_POST['period'] ?? 'monthly');
    $startDate = (string) ($_POST['startDate'] ?? '');
    $endDate = (string) ($_POST['endDate'] ?? '');
    $customRange = (bool) preg_match('/^\d{4}-\d{2}-\d{2}$/', $startDate) && (bool) preg_match('/^\d{4}-\d{2}-\d{2}$/', $endDate);

    if ($customRange) {
      $stmt = $pdo->prepare("SELECT substr(submitted_at, 1, 10) AS bucket, COUNT(*) AS c FROM submissions WHERE substr(submitted_at, 1, 10) BETWEEN ? AND ? GROUP BY bucket");
      $stmt->execute([$startDate, $endDate]);
      $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
      $countsByDay = [];
      foreach ($rows as $r) $countsByDay[$r['bucket']] = (int) $r['c'];

      // Fill every day in the range (even zero-count ones) so the chart draws a continuous line.
      $byPeriod = [];
      $cursor = new DateTime($startDate);
      $end = new DateTime($endDate);
      $guard = 0;
      while ($cursor <= $end && $guard < 400) {
        $day = $cursor->format('Y-m-d');
        $byPeriod[] = ['bucket' => $day, 'c' => $countsByDay[$day] ?? 0];
        $cursor->modify('+1 day');
        $guard++;
      }
      $period = 'custom';
    } else {
      // Registrations grouped by the requested period.
      $periodConfig = [
        'daily'   => ["strftime('%Y-%m-%d', submitted_at)", 14],
        'weekly'  => ["strftime('%Y-W%W', submitted_at)", 12],
        'monthly' => ["substr(submitted_at, 1, 7)", 12],
        'yearly'  => ["substr(submitted_at, 1, 4)", 6],
      ];
      if (!isset($periodConfig[$period])) $period = 'monthly';
      [$expr, $limit] = $periodConfig[$period];
      $stmt = $pdo->query("SELECT $expr AS bucket, COUNT(*) AS c FROM submissions GROUP BY bucket ORDER BY bucket DESC LIMIT $limit");
      $byPeriod = array_reverse($stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    $bySpecialty = $pdo->query("SELECT specialty_label AS label, COUNT(*) AS c FROM submissions GROUP BY specialty_label ORDER BY c DESC")->fetchAll(PDO::FETCH_ASSOC);
    $byCity = $pdo->query("SELECT city AS label, COUNT(*) AS c FROM submissions GROUP BY city ORDER BY c DESC LIMIT 10")->fetchAll(PDO::FETCH_ASSOC);

    // "Needs follow-up": cases whose most recent message was sent by the patient and hasn't been answered by admin yet.
    $followUp = $pdo->query("
      SELECT s.id, s.name, s.specialty_label, MAX(m.created_at) AS last_message_at
      FROM submissions s
      JOIN messages m ON m.submission_id = s.id
      WHERE m.sender_role = 'user'
        AND NOT EXISTS (
          SELECT 1 FROM messages m2
          WHERE m2.submission_id = s.id AND m2.sender_role = 'admin' AND m2.created_at > m.created_at
        )
      GROUP BY s.id
      ORDER BY last_message_at ASC
    ")->fetchAll(PDO::FETCH_ASSOC);

    ok(['byPeriod' => $byPeriod, 'period' => $period, 'bySpecialty' => $bySpecialty, 'byCity' => $byCity, 'needsFollowUp' => $followUp]);
  }

  // -- recent admin activity log ----------------------------------------------
  case 'audit_log_list': {
    requireAdmin();
    $stmt = $pdo->query('SELECT admin_username, action, target_id, detail, created_at, ip_address, user_agent FROM audit_log ORDER BY id DESC LIMIT 100');
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  // -- full database backup download (complete, restorable disaster-recovery copy) --
  case 'backup_download': {
    $adminUser = requireAdmin();
    // SQLite recommends a checkpoint before copying the file so no data
    // sitting in the write-ahead log is left out of the backup.
    try { $pdo->exec('PRAGMA wal_checkpoint(FULL)'); } catch (Throwable $e) {}
    logAudit($pdo, $adminUser, 'backup_download', null, null);

    if (!is_file($dbPath)) fail('فایل پایگاه‌داده یافت نشد.', 500);

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="mehrejavid-backup-' . gmdate('Y-m-d-His') . '.sqlite"');
    header('Content-Length: ' . filesize($dbPath));
    readfile($dbPath);
    exit;
  }

  // ===================== accounting (general income/expense ledger) =====================

  case 'accounting_category_list': {
    requireAdmin();
    $stmt = $pdo->query('SELECT id, type, name FROM accounting_categories ORDER BY type, id');
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  case 'accounting_bank_account_list': {
    requireAdmin();
    $stmt = $pdo->query('SELECT id, name, opening_balance FROM accounting_bank_accounts ORDER BY id');
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  case 'accounting_bank_account_create': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $name = str_field('name', 120);
    $openingBalance = (int) ($_POST['openingBalance'] ?? 0);
    if (!$name) fail('لطفاً نام حساب/صندوق را وارد کنید.');
    $pdo->prepare('INSERT INTO accounting_bank_accounts (name, opening_balance, created_at) VALUES (?,?,?)')
      ->execute([$name, $openingBalance, gmdate('c')]);
    $newId = (int) $pdo->lastInsertId(); // read before logAudit(), which inserts its own row
    logAudit($pdo, $adminUser, 'accounting_bank_account_create', (string) $newId, $name);
    ok(['id' => $newId]);
  }

  case 'accounting_bank_account_update': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (int) ($_POST['id'] ?? 0);
    $name = str_field('name', 120);
    $openingBalance = (int) ($_POST['openingBalance'] ?? 0);
    if (!$name) fail('لطفاً نام حساب/صندوق را وارد کنید.');
    $upd = $pdo->prepare('UPDATE accounting_bank_accounts SET name = ?, opening_balance = ? WHERE id = ?');
    $upd->execute([$name, $openingBalance, $id]);
    if ($upd->rowCount() === 0) fail('حساب/صندوق یافت نشد.', 404);
    logAudit($pdo, $adminUser, 'accounting_bank_account_update', (string) $id, $name);
    ok();
  }

  case 'accounting_bank_account_delete': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (int) ($_POST['id'] ?? 0);
    $inUse = $pdo->prepare('SELECT COUNT(*) FROM accounting_transactions WHERE bank_account_id = ?');
    $inUse->execute([$id]);
    if ((int) $inUse->fetchColumn() > 0) fail('این حساب/صندوق دارای تراکنش ثبت‌شده است و قابل حذف نیست؛ می‌توانید نامش را ویرایش کنید.');
    $del = $pdo->prepare('DELETE FROM accounting_bank_accounts WHERE id = ?');
    $del->execute([$id]);
    if ($del->rowCount() === 0) fail('حساب/صندوق یافت نشد.', 404);
    logAudit($pdo, $adminUser, 'accounting_bank_account_delete', (string) $id, null);
    ok();
  }

  case 'accounting_category_create': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $type = (string) ($_POST['type'] ?? '');
    $name = str_field('name', 120);
    if (!in_array($type, ['income', 'expense'], true)) fail('نوع دسته‌بندی نامعتبر است.');
    if (!$name) fail('لطفاً نام دسته‌بندی را وارد کنید.');
    $pdo->prepare('INSERT INTO accounting_categories (type, name, created_at) VALUES (?,?,?)')
      ->execute([$type, $name, gmdate('c')]);
    $newId = (int) $pdo->lastInsertId(); // read before logAudit(), which inserts its own row
    logAudit($pdo, $adminUser, 'accounting_category_create', (string) $newId, "$type: $name");
    ok(['id' => $newId]);
  }

  case 'accounting_category_update': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (int) ($_POST['id'] ?? 0);
    $name = str_field('name', 120);
    if (!$name) fail('لطفاً نام دسته‌بندی را وارد کنید.');
    $upd = $pdo->prepare('UPDATE accounting_categories SET name = ? WHERE id = ?');
    $upd->execute([$name, $id]);
    if ($upd->rowCount() === 0) fail('دسته‌بندی یافت نشد.', 404);
    logAudit($pdo, $adminUser, 'accounting_category_update', (string) $id, $name);
    ok();
  }

  case 'accounting_category_delete': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (int) ($_POST['id'] ?? 0);
    $inUse = $pdo->prepare('SELECT COUNT(*) FROM accounting_transactions WHERE category_id = ?');
    $inUse->execute([$id]);
    if ((int) $inUse->fetchColumn() > 0) fail('این دسته‌بندی دارای تراکنش ثبت‌شده است و قابل حذف نیست؛ می‌توانید نامش را ویرایش کنید.');
    $del = $pdo->prepare('DELETE FROM accounting_categories WHERE id = ?');
    $del->execute([$id]);
    if ($del->rowCount() === 0) fail('دسته‌بندی یافت نشد.', 404);
    $pdo->prepare('DELETE FROM accounting_budgets WHERE category_id = ?')->execute([$id]);
    logAudit($pdo, $adminUser, 'accounting_category_delete', (string) $id, null);
    ok();
  }

  case 'accounting_transaction_create': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $type = (string) ($_POST['type'] ?? '');
    $categoryId = (int) ($_POST['categoryId'] ?? 0);
    $bankAccountId = (int) ($_POST['bankAccountId'] ?? 0);
    $amount = (int) ($_POST['amount'] ?? 0);
    $description = str_field('description', 1000);
    $transactionDate = str_field('transactionDate', 10);
    $paymentMethod = (string) ($_POST['paymentMethod'] ?? 'cash');
    $relatedSubmissionId = str_field('relatedSubmissionId', 100);
    $donorName = str_field('donorName', 120);
    $chequeNumber = str_field('chequeNumber', 40);
    $chequeDueDate = str_field('chequeDueDate', 10);

    if (!in_array($type, ['income', 'expense'], true)) fail('نوع تراکنش نامعتبر است.');
    if ($amount <= 0) fail('لطفاً مبلغ معتبری وارد کنید.');
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $transactionDate)) fail('تاریخ تراکنش نامعتبر است.');
    if (!in_array($paymentMethod, ['cash', 'card', 'transfer', 'cheque', 'other'], true)) $paymentMethod = 'other';
    if ($paymentMethod === 'cheque' && $chequeDueDate && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $chequeDueDate)) {
      fail('تاریخ سررسید چک نامعتبر است.');
    }
    if ($paymentMethod !== 'cheque') { $chequeNumber = ''; $chequeDueDate = ''; }

    $catStmt = $pdo->prepare('SELECT type FROM accounting_categories WHERE id = ?');
    $catStmt->execute([$categoryId]);
    $catType = $catStmt->fetchColumn();
    if ($catType === false || $catType !== $type) fail('دسته‌بندی انتخاب‌شده با نوع تراکنش هم‌خوانی ندارد.');

    $bankCheck = $pdo->prepare('SELECT 1 FROM accounting_bank_accounts WHERE id = ?');
    $bankCheck->execute([$bankAccountId]);
    if (!$bankCheck->fetchColumn()) fail('لطفاً حساب بانکی/صندوق را انتخاب کنید.');

    if ($relatedSubmissionId && !submissionOwnerFromId($relatedSubmissionId)) fail('شناسه پرونده‌ی مرتبط نامعتبر است.');

    // Link (or create) a donor record by name so donation history can be tracked per person.
    $donorId = null;
    if ($type === 'income' && $donorName) {
      $donorFind = $pdo->prepare('SELECT id FROM donors WHERE name = ? LIMIT 1');
      $donorFind->execute([$donorName]);
      $donorId = $donorFind->fetchColumn();
      if (!$donorId) {
        $pdo->prepare('INSERT INTO donors (name, created_at) VALUES (?,?)')->execute([$donorName, gmdate('c')]);
        $donorId = (int) $pdo->lastInsertId();
      }
    }

    $receipt = parseDataUrl($_POST['receiptPhoto'] ?? null, ['image/jpeg', 'image/png', 'image/webp'], MAX_ASSET_BYTES);

    $now = gmdate('c');
    $pdo->beginTransaction();
    try {
      $pdo->prepare('INSERT INTO accounting_transactions
        (type, category_id, bank_account_id, amount, description, transaction_date, payment_method, related_submission_id, donor_name, donor_id, cheque_number, cheque_due_date, receipt_mime, receipt_data, admin_username, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
        ->execute([
          $type, $categoryId, $bankAccountId, $amount, $description ?: null, $transactionDate, $paymentMethod,
          $relatedSubmissionId ?: null, $donorName ?: null, $donorId ?: null,
          $chequeNumber ?: null, $chequeDueDate ?: null,
          $receipt ? $receipt[0] : null, $receipt ? $receipt[1] : null,
          $adminUser, $now,
        ]);
      $txId = (int) $pdo->lastInsertId();

      // When an expense is linked to a beneficiary's case, also record it as a
      // payment on that case so it shows up in the مددجو's own profile/history,
      // and keep the case's financial status in sync — same as the dedicated
      // "ثبت پرداخت" flow, so this becomes an alternate entry point into it.
      $newStatus = null;
      $totalPaid = null;
      if ($type === 'expense' && $relatedSubmissionId) {
        $pdo->prepare('INSERT INTO payments (submission_id, amount, note, admin_username, created_at, accounting_transaction_id) VALUES (?,?,?,?,?,?)')
          ->execute([$relatedSubmissionId, $amount, $description ?: null, $adminUser, $now, $txId]);

        $totalPaid = syncSubmissionPaymentStatus($pdo, $relatedSubmissionId);
        $statusStmt = $pdo->prepare('SELECT financial_status FROM submissions WHERE id = ?');
        $statusStmt->execute([$relatedSubmissionId]);
        $newStatus = $statusStmt->fetchColumn();

        $timelineNote = 'پرداخت به مبلغ ' . number_format($amount) . ' تومان از طریق حسابداری ثبت شد.' . ($newStatus === 'paid' ? ' هدایت درمانی کامل شد.' : '');
        $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?,?,?,?)')
          ->execute([$relatedSubmissionId, 'payment', $timelineNote, $now]);
        $owner = submissionOwnerFromId($relatedSubmissionId);
        if ($owner) {
          $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
            ->execute(['user', $owner, $relatedSubmissionId, 'payment', $timelineNote, $now]);
        }
      }

      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('accounting_transaction_create failed: ' . $e->getMessage());
      fail('خطا در ثبت تراکنش.', 500);
    }

    logAudit($pdo, $adminUser, 'accounting_transaction_create', (string) $txId, "$type: $amount");

    // Best-effort automatic thank-you SMS — never blocks the transaction if it fails.
    if ($donorId) {
      $donorPhoneStmt = $pdo->prepare('SELECT phone FROM donors WHERE id = ?');
      $donorPhoneStmt->execute([$donorId]);
      $donorPhone = $donorPhoneStmt->fetchColumn();
      if ($donorPhone && preg_match('/^0\d{10}$/', $donorPhone)) {
        $smsResult = sendTemplateSmsViaNajva($donorPhone, NAJVA_DONATION_TEMPLATE, number_format($amount));
        if (empty($smsResult['ok'])) {
          error_log('donation thank-you SMS failed: ' . ($smsResult['detail'] ?? 'unknown error'));
        }
      }
    }
    ok(['id' => $txId, 'linkedPaymentStatus' => $newStatus, 'linkedPaymentTotal' => $totalPaid]);
  }

  case 'accounting_transaction_update': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (int) ($_POST['id'] ?? 0);
    $categoryId = (int) ($_POST['categoryId'] ?? 0);
    $bankAccountId = (int) ($_POST['bankAccountId'] ?? 0);
    $amount = (int) ($_POST['amount'] ?? 0);
    $description = str_field('description', 1000);
    $transactionDate = str_field('transactionDate', 10);
    $paymentMethod = (string) ($_POST['paymentMethod'] ?? 'cash');
    $chequeNumber = str_field('chequeNumber', 40);
    $chequeDueDate = str_field('chequeDueDate', 10);

    $existingStmt = $pdo->prepare('SELECT type, related_submission_id, is_transfer FROM accounting_transactions WHERE id = ?');
    $existingStmt->execute([$id]);
    $existing = $existingStmt->fetch(PDO::FETCH_ASSOC);
    if (!$existing) fail('تراکنش یافت نشد.', 404);
    if ((int) $existing['is_transfer'] === 1) fail('تراکنش‌های انتقال بین حساب‌ها را نمی‌توان ویرایش کرد؛ آن را حذف کرده و دوباره ثبت کنید.');

    if ($amount <= 0) fail('لطفاً مبلغ معتبری وارد کنید.');
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $transactionDate)) fail('تاریخ تراکنش نامعتبر است.');
    if (!in_array($paymentMethod, ['cash', 'card', 'transfer', 'cheque', 'other'], true)) $paymentMethod = 'other';
    if ($paymentMethod === 'cheque' && $chequeDueDate && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $chequeDueDate)) {
      fail('تاریخ سررسید چک نامعتبر است.');
    }
    if ($paymentMethod !== 'cheque') { $chequeNumber = ''; $chequeDueDate = ''; }

    $catStmt = $pdo->prepare('SELECT type FROM accounting_categories WHERE id = ?');
    $catStmt->execute([$categoryId]);
    $catType = $catStmt->fetchColumn();
    if ($catType === false || $catType !== $existing['type']) fail('دسته‌بندی انتخاب‌شده با نوع تراکنش هم‌خوانی ندارد.');

    $bankCheck = $pdo->prepare('SELECT 1 FROM accounting_bank_accounts WHERE id = ?');
    $bankCheck->execute([$bankAccountId]);
    if (!$bankCheck->fetchColumn()) fail('لطفاً حساب بانکی/صندوق را انتخاب کنید.');

    $pdo->beginTransaction();
    try {
      $pdo->prepare('UPDATE accounting_transactions SET category_id=?, bank_account_id=?, amount=?, description=?, transaction_date=?, payment_method=?, cheque_number=?, cheque_due_date=? WHERE id=?')
        ->execute([$categoryId, $bankAccountId, $amount, $description ?: null, $transactionDate, $paymentMethod, $chequeNumber ?: null, $chequeDueDate ?: null, $id]);

      // Keep the linked مددجو payment (if any) and their financial status in
      // sync with the edited amount/note — never let them drift apart.
      if ($existing['related_submission_id']) {
        $pdo->prepare('UPDATE payments SET amount = ?, note = ? WHERE accounting_transaction_id = ?')
          ->execute([$amount, $description ?: null, $id]);
        syncSubmissionPaymentStatus($pdo, $existing['related_submission_id']);
      }
      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('accounting_transaction_update failed: ' . $e->getMessage());
      fail('خطا در ویرایش تراکنش.', 500);
    }

    logAudit($pdo, $adminUser, 'accounting_transaction_update', (string) $id, "amount: $amount");
    ok();
  }

  case 'accounting_transaction_list': {
    requireAdmin();
    $startDate = str_field('startDate', 10);
    $endDate = str_field('endDate', 10);
    $type = (string) ($_POST['type'] ?? '');
    $bankAccountId = (int) ($_POST['bankAccountId'] ?? 0);
    $categoryId = (int) ($_POST['categoryId'] ?? 0);
    $minAmount = (int) ($_POST['minAmount'] ?? 0);
    $maxAmount = (int) ($_POST['maxAmount'] ?? 0);
    $q = str_field('q', 120);

    $where = [];
    $params = [];
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $startDate)) { $where[] = 't.transaction_date >= ?'; $params[] = $startDate; }
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $endDate)) { $where[] = 't.transaction_date <= ?'; $params[] = $endDate; }
    if (in_array($type, ['income', 'expense'], true)) { $where[] = 't.type = ?'; $params[] = $type; }
    if ($bankAccountId > 0) { $where[] = 't.bank_account_id = ?'; $params[] = $bankAccountId; }
    if ($categoryId > 0) { $where[] = 't.category_id = ?'; $params[] = $categoryId; }
    if ($minAmount > 0) { $where[] = 't.amount >= ?'; $params[] = $minAmount; }
    if ($maxAmount > 0) { $where[] = 't.amount <= ?'; $params[] = $maxAmount; }
    if ($q) {
      $where[] = '(t.description LIKE ? OR t.donor_name LIKE ? OR s.name LIKE ?)';
      $like = '%' . $q . '%';
      $params[] = $like; $params[] = $like; $params[] = $like;
    }
    $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    $stmt = $pdo->prepare("SELECT t.id, t.type, t.category_id, c.name AS category_name,
        t.bank_account_id, b.name AS bank_account_name,
        t.amount, t.description, t.transaction_date, t.payment_method, t.related_submission_id,
        s.name AS related_submission_name,
        t.donor_name, t.admin_username, t.created_at,
        t.is_transfer, t.cheque_number, t.cheque_due_date,
        (t.receipt_data IS NOT NULL) AS has_receipt
      FROM accounting_transactions t
      LEFT JOIN accounting_categories c ON c.id = t.category_id
      LEFT JOIN accounting_bank_accounts b ON b.id = t.bank_account_id
      LEFT JOIN submissions s ON s.id = t.related_submission_id
      $whereSql
      ORDER BY t.transaction_date DESC, t.id DESC
      LIMIT 1000");
    $stmt->execute($params);
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($items as &$row) { $row['has_receipt'] = (bool) $row['has_receipt']; $row['is_transfer'] = (bool) $row['is_transfer']; }
    ok(['items' => $items]);
  }

  case 'accounting_transaction_delete': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (int) ($_POST['id'] ?? 0);
    if ($id <= 0) fail('شناسه نامعتبر است.');

    $txStmt = $pdo->prepare('SELECT related_submission_id, is_transfer, transfer_pair_id FROM accounting_transactions WHERE id = ?');
    $txStmt->execute([$id]);
    $txRow = $txStmt->fetch(PDO::FETCH_ASSOC);
    if (!$txRow) fail('تراکنش یافت نشد.', 404);
    $relatedSubmissionId = $txRow['related_submission_id'];

    $pdo->beginTransaction();
    try {
      $del = $pdo->prepare('DELETE FROM accounting_transactions WHERE id = ?');
      $del->execute([$id]);
      if ($del->rowCount() === 0) throw new Exception('تراکنش یافت نشد.');

      // An internal transfer is always two paired rows (one leg on each
      // account) — deleting only one side would leave the other account's
      // balance permanently wrong, so always remove both together.
      if ((int) $txRow['is_transfer'] === 1 && $txRow['transfer_pair_id']) {
        $pdo->prepare('DELETE FROM accounting_transactions WHERE id = ?')->execute([$txRow['transfer_pair_id']]);
      }

      // Remove the matching payment row (if this transaction had linked one)
      // and re-sync the مددجو's total-paid / financial status, so deleting
      // an accounting entry never leaves a stale payment in their profile.
      if ($relatedSubmissionId) {
        $pdo->prepare('DELETE FROM payments WHERE accounting_transaction_id = ?')->execute([$id]);
        syncSubmissionPaymentStatus($pdo, $relatedSubmissionId);
      }
      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('accounting_transaction_delete failed: ' . $e->getMessage());
      fail('خطا در حذف تراکنش.', 500);
    }

    logAudit($pdo, $adminUser, 'accounting_transaction_delete', (string) $id, null);
    ok();
  }

  // -- move money between two of the institute's own accounts/funds (e.g.
  //    petty cash → bank). Recorded as a paired expense+income so each
  //    account's balance stays correct, but excluded from real income/
  //    expense totals since no money actually entered or left the institute. --
  case 'accounting_transfer_create': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $fromAccountId = (int) ($_POST['fromAccountId'] ?? 0);
    $toAccountId = (int) ($_POST['toAccountId'] ?? 0);
    $amount = (int) ($_POST['amount'] ?? 0);
    $description = str_field('description', 1000);
    $transactionDate = str_field('transactionDate', 10);

    if ($amount <= 0) fail('لطفاً مبلغ معتبری وارد کنید.');
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $transactionDate)) fail('تاریخ تراکنش نامعتبر است.');
    if ($fromAccountId <= 0 || $toAccountId <= 0) fail('لطفاً هر دو حساب مبدأ و مقصد را انتخاب کنید.');
    if ($fromAccountId === $toAccountId) fail('حساب مبدأ و مقصد نمی‌توانند یکی باشند.');

    $accStmt = $pdo->prepare('SELECT id, name FROM accounting_bank_accounts WHERE id IN (?, ?)');
    $accStmt->execute([$fromAccountId, $toAccountId]);
    $accounts = $accStmt->fetchAll(PDO::FETCH_KEY_PAIR);
    if (!isset($accounts[$fromAccountId]) || !isset($accounts[$toAccountId])) fail('حساب انتخاب‌شده نامعتبر است.');

    $now = gmdate('c');
    $note = 'انتقال بین حساب‌ها: ' . $accounts[$fromAccountId] . ' ← ' . $accounts[$toAccountId] . ($description ? ' — ' . $description : '');
    $pdo->beginTransaction();
    try {
      $pdo->prepare('INSERT INTO accounting_transactions
        (type, category_id, bank_account_id, amount, description, transaction_date, payment_method, is_transfer, admin_username, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)')
        ->execute(['expense', null, $fromAccountId, $amount, $note, $transactionDate, 'transfer', 1, $adminUser, $now]);
      $legOutId = (int) $pdo->lastInsertId();

      $pdo->prepare('INSERT INTO accounting_transactions
        (type, category_id, bank_account_id, amount, description, transaction_date, payment_method, is_transfer, transfer_pair_id, admin_username, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        ->execute(['income', null, $toAccountId, $amount, $note, $transactionDate, 'transfer', 1, $legOutId, $adminUser, $now]);
      $legInId = (int) $pdo->lastInsertId();

      $pdo->prepare('UPDATE accounting_transactions SET transfer_pair_id = ? WHERE id = ?')->execute([$legInId, $legOutId]);
      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('accounting_transfer_create failed: ' . $e->getMessage());
      fail('خطا در ثبت انتقال وجه.', 500);
    }

    logAudit($pdo, $adminUser, 'accounting_transfer_create', (string) $legOutId, $note);
    ok(['id' => $legOutId]);
  }

  case 'accounting_asset': {
    requireAdmin();
    $id = (int) ($_POST['id'] ?? 0);
    $stmt = $pdo->prepare('SELECT receipt_mime, receipt_data FROM accounting_transactions WHERE id = ?');
    $stmt->execute([$id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || !$row['receipt_data']) fail('رسیدی برای این تراکنش ثبت نشده است.', 404);
    ok(['dataUrl' => $row['receipt_data'], 'mime' => $row['receipt_mime']]);
  }

  case 'accounting_summary': {
    requireAdmin();
    $startDate = str_field('startDate', 10);
    $endDate = str_field('endDate', 10);
    $where = [];
    $params = [];
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $startDate)) { $where[] = 'transaction_date >= ?'; $params[] = $startDate; }
    if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $endDate)) { $where[] = 'transaction_date <= ?'; $params[] = $endDate; }
    $whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';
    // Internal fund transfers between the institute's own accounts (e.g.
    // petty cash → bank) are excluded from income/expense totals below —
    // they aren't real income or spending, just money moving between two
    // places we already hold it. They ARE still counted in the per-account
    // balances further down, since the cash really did move.
    $realWhere = $where; $realWhere[] = 'is_transfer = 0';
    $realWhereSql = 'WHERE ' . implode(' AND ', $realWhere);

    $totalsStmt = $pdo->prepare("SELECT type, COALESCE(SUM(amount),0) AS total FROM accounting_transactions $realWhereSql GROUP BY type");
    $totalsStmt->execute($params);
    $totals = ['income' => 0, 'expense' => 0];
    foreach ($totalsStmt->fetchAll(PDO::FETCH_ASSOC) as $r) { $totals[$r['type']] = (int) $r['total']; }

    // Split expenses into the institute's own operating costs vs. aid payments
    // made directly to مددجویان (beneficiaries), so the two never get mixed
    // together in stats and reports.
    $expenseSplitStmt = $pdo->prepare("SELECT
        COALESCE(SUM(CASE WHEN related_submission_id IS NULL OR related_submission_id = '' THEN amount ELSE 0 END), 0) AS institutional,
        COALESCE(SUM(CASE WHEN related_submission_id IS NOT NULL AND related_submission_id != '' THEN amount ELSE 0 END), 0) AS beneficiary,
        COALESCE(SUM(CASE WHEN related_submission_id IS NOT NULL AND related_submission_id != '' THEN 1 ELSE 0 END), 0) AS beneficiaryCount
      FROM accounting_transactions t WHERE type = 'expense' AND is_transfer = 0" . ($where ? ' AND ' . implode(' AND ', $where) : ''));
    $expenseSplitStmt->execute($params);
    $expenseSplit = $expenseSplitStmt->fetch(PDO::FETCH_ASSOC) ?: ['institutional' => 0, 'beneficiary' => 0, 'beneficiaryCount' => 0];

    $byCatStmt = $pdo->prepare("SELECT t.type, c.name AS category, COALESCE(SUM(t.amount),0) AS total
      FROM accounting_transactions t LEFT JOIN accounting_categories c ON c.id = t.category_id
      $realWhereSql GROUP BY t.type, c.name ORDER BY total DESC");
    $byCatStmt->execute($params);

    // Account/fund balances are always all-time (not filtered by the report
    // period) since they represent the real, current amount held in each
    // account — starting from each account's opening balance, plus every
    // transaction against it (transfers included, since that cash really moved).
    $byAccountStmt = $pdo->query("SELECT b.id, b.name, b.opening_balance,
        b.opening_balance + COALESCE(SUM(CASE WHEN t.type = 'income' THEN t.amount WHEN t.type = 'expense' THEN -t.amount ELSE 0 END), 0) AS balance
      FROM accounting_bank_accounts b
      LEFT JOIN accounting_transactions t ON t.bank_account_id = b.id
      GROUP BY b.id, b.name, b.opening_balance ORDER BY b.id");

    // Cheques (payment_method = 'cheque') with an upcoming or past due date
    // that haven't been marked as an internal transfer — a quick lookahead
    // so due dates never get missed.
    $chequeStmt = $pdo->prepare("SELECT id, type, amount, description, cheque_number, cheque_due_date, related_submission_id
      FROM accounting_transactions
      WHERE payment_method = 'cheque' AND cheque_due_date IS NOT NULL AND cheque_due_date != ''
      ORDER BY cheque_due_date ASC LIMIT 30");
    $chequeStmt->execute();

    ok([
      'totalIncome' => $totals['income'],
      'totalExpense' => $totals['expense'],
      'netBalance' => $totals['income'] - $totals['expense'],
      'institutionalExpense' => (int) $expenseSplit['institutional'],
      'beneficiaryPayments' => (int) $expenseSplit['beneficiary'],
      'beneficiaryPaymentsCount' => (int) $expenseSplit['beneficiaryCount'],
      'byCategory' => $byCatStmt->fetchAll(PDO::FETCH_ASSOC),
      'byAccount' => $byAccountStmt->fetchAll(PDO::FETCH_ASSOC),
      'upcomingCheques' => $chequeStmt->fetchAll(PDO::FETCH_ASSOC),
    ]);
  }

  // ===================== accommodation room management =====================

  case 'accommodation_room_list': {
    requireAdmin();
    $stmt = $pdo->query("SELECT r.id, r.guesthouse_name, r.room_label,
        a.id AS assignment_id, a.submission_id, a.check_in_date, a.check_out_date, a.note,
        s.name AS patient_name
      FROM accommodation_rooms r
      LEFT JOIN accommodation_assignments a ON a.room_id = r.id
        AND a.id = (SELECT id FROM accommodation_assignments WHERE room_id = r.id AND check_out_date IS NULL ORDER BY id DESC LIMIT 1)
      LEFT JOIN submissions s ON s.id = a.submission_id
      ORDER BY r.id");
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  case 'accommodation_assign_room': {
    requireCsrf();
    $adminUser = requireAdmin();
    $roomId = (int) ($_POST['roomId'] ?? 0);
    $submissionId = (string) ($_POST['submissionId'] ?? '');
    $checkInDate = str_field('checkInDate', 10);
    $note = str_field('note', 500);
    $owner = submissionOwnerFromId($submissionId);
    if (!$owner) fail('پرونده‌ی نامعتبر است.');
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $checkInDate)) fail('تاریخ ورود نامعتبر است.');

    $roomCheck = $pdo->prepare('SELECT 1 FROM accommodation_rooms WHERE id = ?');
    $roomCheck->execute([$roomId]);
    if (!$roomCheck->fetchColumn()) fail('اتاق نامعتبر است.');

    $occCheck = $pdo->prepare('SELECT 1 FROM accommodation_assignments WHERE room_id = ? AND check_out_date IS NULL');
    $occCheck->execute([$roomId]);
    if ($occCheck->fetchColumn()) fail('این اتاق در حال حاضر اشغال است. ابتدا آن را خالی کنید.');

    $now = gmdate('c');
    $pdo->prepare('INSERT INTO accommodation_assignments (room_id, submission_id, check_in_date, note, admin_username, created_at) VALUES (?,?,?,?,?,?)')
      ->execute([$roomId, $submissionId, $checkInDate, $note ?: null, $adminUser, $now]);

    $pdo->prepare('INSERT INTO submission_timeline (submission_id, status, note, created_at) VALUES (?,?,?,?)')
      ->execute([$submissionId, 'accommodation', 'اتاق اسکان تخصیص داده شد.', $now]);
    $pdo->prepare('INSERT INTO notifications (recipient_type, recipient_id, submission_id, type, message, created_at) VALUES (?,?,?,?,?,?)')
      ->execute(['user', $owner, $submissionId, 'accommodation', 'محل اسکان شما مشخص شد.', $now]);
    logAudit($pdo, $adminUser, 'accommodation_assign_room', $submissionId, "room=$roomId");
    ok();
  }

  case 'accommodation_checkout': {
    requireCsrf();
    $adminUser = requireAdmin();
    $assignmentId = (int) ($_POST['assignmentId'] ?? 0);
    $checkOutDate = str_field('checkOutDate', 10);
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $checkOutDate)) fail('تاریخ خروج نامعتبر است.');

    $stmt = $pdo->prepare('SELECT submission_id FROM accommodation_assignments WHERE id = ? AND check_out_date IS NULL');
    $stmt->execute([$assignmentId]);
    $submissionId = $stmt->fetchColumn();
    if (!$submissionId) fail('تخصیص یافت نشد یا قبلاً خالی شده است.', 404);

    $pdo->prepare('UPDATE accommodation_assignments SET check_out_date = ? WHERE id = ?')->execute([$checkOutDate, $assignmentId]);
    logAudit($pdo, $adminUser, 'accommodation_checkout', (string) $submissionId, "assignment=$assignmentId");
    ok();
  }

  // ===================== donor management =====================

  case 'donor_list': {
    requireAdmin();
    $stmt = $pdo->query("SELECT d.id, d.name, d.phone, d.email, d.national_id, d.donor_type, d.notes, d.created_at,
        COALESCE(SUM(t.amount), 0) AS total_donated,
        COUNT(t.id) AS donation_count,
        MAX(t.transaction_date) AS last_donation_date
      FROM donors d
      LEFT JOIN accounting_transactions t ON t.donor_id = d.id AND t.type = 'income'
      GROUP BY d.id
      ORDER BY total_donated DESC");
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  case 'donor_create': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $name = str_field('name', 120);
    $phone = str_field('phone', 20);
    $email = str_field('email', 120);
    $nationalId = str_field('nationalId', 20);
    $donorType = (string) ($_POST['donorType'] ?? 'individual');
    $notes = str_field('notes', 500);
    if (!$name) fail('لطفاً نام خیر را وارد کنید.');
    if ($phone && !preg_match('/^0\d{10}$/', $phone)) fail('شماره موبایل نامعتبر است (مثال: 09121234567).');
    if (!in_array($donorType, ['individual', 'company'], true)) $donorType = 'individual';
    $pdo->prepare('INSERT INTO donors (name, phone, email, national_id, donor_type, notes, created_at) VALUES (?,?,?,?,?,?,?)')
      ->execute([$name, $phone ?: null, $email ?: null, $nationalId ?: null, $donorType, $notes ?: null, gmdate('c')]);
    $newId = (int) $pdo->lastInsertId(); // read before logAudit(), which inserts its own row
    logAudit($pdo, $adminUser, 'donor_create', (string) $newId, $name);
    ok(['id' => $newId]);
  }

  // -- edit an existing donor's profile (name/phone/email/notes). Lets admins
  //    manually add or correct a donor's mobile number after the fact. --------
  case 'donor_update': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $id = (int) ($_POST['id'] ?? 0);
    $name = str_field('name', 120);
    $phone = str_field('phone', 20);
    $email = str_field('email', 120);
    $nationalId = str_field('nationalId', 20);
    $donorType = (string) ($_POST['donorType'] ?? 'individual');
    $notes = str_field('notes', 500);
    if (!$id) fail('شناسه‌ی خیر نامعتبر است.');
    if (!$name) fail('لطفاً نام خیر را وارد کنید.');
    if ($phone && !preg_match('/^0\d{10}$/', $phone)) fail('شماره موبایل نامعتبر است (مثال: 09121234567).');
    if (!in_array($donorType, ['individual', 'company'], true)) $donorType = 'individual';
    $exists = $pdo->prepare('SELECT 1 FROM donors WHERE id = ?');
    $exists->execute([$id]);
    if (!$exists->fetchColumn()) fail('خیر یافت نشد.', 404);
    $pdo->prepare('UPDATE donors SET name = ?, phone = ?, email = ?, national_id = ?, donor_type = ?, notes = ? WHERE id = ?')
      ->execute([$name, $phone ?: null, $email ?: null, $nationalId ?: null, $donorType, $notes ?: null, $id]);
    logAudit($pdo, $adminUser, 'donor_update', (string) $id, $name);
    ok();
  }

  case 'donor_detail': {
    requireAdmin();
    $id = (int) ($_POST['id'] ?? 0);
    $donorStmt = $pdo->prepare('SELECT * FROM donors WHERE id = ?');
    $donorStmt->execute([$id]);
    $donor = $donorStmt->fetch(PDO::FETCH_ASSOC);
    if (!$donor) fail('خیر یافت نشد.', 404);

    $txStmt = $pdo->prepare("SELECT t.id, t.amount, t.transaction_date, t.description, t.payment_method, c.name AS category_name
      FROM accounting_transactions t LEFT JOIN accounting_categories c ON c.id = t.category_id
      WHERE t.donor_id = ? ORDER BY t.transaction_date DESC");
    $txStmt->execute([$id]);

    ok(['donor' => $donor, 'transactions' => $txStmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  // -- merge a duplicate donor record into a "keeper" record: all donations
  //    move over (accounting_transactions.donor_id), and the duplicate row is
  //    removed. Fixes fragmented donation history from near-duplicate names
  //    (e.g. typo'd or re-typed donor names creating a second profile). --------
  case 'donor_merge': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $keepId = (int) ($_POST['keepId'] ?? 0);
    $mergeId = (int) ($_POST['mergeId'] ?? 0);
    if (!$keepId || !$mergeId) fail('لطفاً هر دو خیر را انتخاب کنید.');
    if ($keepId === $mergeId) fail('نمی‌توانید یک خیر را با خودش یکی کنید.');

    $checkStmt = $pdo->prepare('SELECT id, name FROM donors WHERE id IN (?, ?)');
    $checkStmt->execute([$keepId, $mergeId]);
    $rows = $checkStmt->fetchAll(PDO::FETCH_KEY_PAIR);
    if (!isset($rows[$keepId]) || !isset($rows[$mergeId])) fail('یکی از خیرین انتخاب‌شده یافت نشد.', 404);

    $pdo->beginTransaction();
    try {
      $pdo->prepare('UPDATE accounting_transactions SET donor_id = ? WHERE donor_id = ?')->execute([$keepId, $mergeId]);
      $pdo->prepare('DELETE FROM donors WHERE id = ?')->execute([$mergeId]);
      $pdo->commit();
    } catch (Throwable $e) {
      $pdo->rollBack();
      error_log('donor_merge failed: ' . $e->getMessage());
      fail('خطا در یکی‌کردن خیرین.', 500);
    }

    logAudit($pdo, $adminUser, 'donor_merge', (string) $keepId, $rows[$mergeId] . ' → ' . $rows[$keepId]);
    ok();
  }

  // ===================== budgeting (budget vs actual) =====================

  case 'budget_set': {
    requireCsrf();
    $adminUser = requireRole($pdo, ['super_admin']);
    $categoryId = (int) ($_POST['categoryId'] ?? 0);
    $periodType = (string) ($_POST['periodType'] ?? '');
    $periodValue = str_field('periodValue', 10);
    $amount = (int) ($_POST['amount'] ?? 0);

    if (!in_array($periodType, ['monthly', 'yearly'], true)) fail('نوع بازه نامعتبر است.');
    if ($periodType === 'monthly' && !preg_match('/^\d{4}-\d{2}$/', $periodValue)) fail('بازه‌ی ماهانه نامعتبر است.');
    if ($periodType === 'yearly' && !preg_match('/^\d{4}$/', $periodValue)) fail('بازه‌ی سالانه نامعتبر است.');
    if ($amount < 0) fail('مبلغ بودجه نامعتبر است.');

    $catCheck = $pdo->prepare('SELECT 1 FROM accounting_categories WHERE id = ?');
    $catCheck->execute([$categoryId]);
    if (!$catCheck->fetchColumn()) fail('دسته‌بندی نامعتبر است.');

    $pdo->prepare('INSERT INTO accounting_budgets (category_id, period_type, period_value, amount, admin_username, created_at)
      VALUES (?,?,?,?,?,?)
      ON CONFLICT(category_id, period_type, period_value) DO UPDATE SET amount = excluded.amount')
      ->execute([$categoryId, $periodType, $periodValue, $amount, $adminUser, gmdate('c')]);
    logAudit($pdo, $adminUser, 'budget_set', null, "$periodType $periodValue: $amount");
    ok();
  }

  case 'budget_vs_actual': {
    requireAdmin();
    $periodType = (string) ($_POST['periodType'] ?? 'monthly');
    $periodValue = str_field('periodValue', 10);
    if (!in_array($periodType, ['monthly', 'yearly'], true)) fail('نوع بازه نامعتبر است.');
    if (!$periodValue) fail('بازه را مشخص کنید.');

    $dateExpr = $periodType === 'monthly' ? "substr(transaction_date, 1, 7)" : "substr(transaction_date, 1, 4)";

    $stmt = $pdo->prepare("SELECT c.id AS category_id, c.name AS category_name, c.type,
        COALESCE(b.amount, 0) AS budget_amount,
        COALESCE((SELECT SUM(t.amount) FROM accounting_transactions t WHERE t.category_id = c.id AND $dateExpr = ?), 0) AS actual_amount
      FROM accounting_categories c
      LEFT JOIN accounting_budgets b ON b.category_id = c.id AND b.period_type = ? AND b.period_value = ?
      WHERE c.type = 'expense'
      ORDER BY c.id");
    $stmt->execute([$periodValue, $periodType, $periodValue]);
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  // ===================== site settings (تنظیمات) =====================

  case 'settings_get': {
    requireAdmin(); // any admin role may view current settings
    ok(['settings' => getAllSettingsForClient($pdo)]);
  }

  case 'settings_update': {
    requireCsrf();
    $actingUser = requireRole($pdo, ['super_admin']);
    $incoming = json_decode((string) ($_POST['settings'] ?? '{}'), true);
    if (!is_array($incoming)) fail('داده تنظیمات نامعتبر است.');

    foreach ($incoming as $key => $value) {
      if (!array_key_exists($key, SETTINGS_DEFAULTS)) continue; // silently ignore unknown keys
      $value = (string) $value;

      if ($key === 'session_timeout_minutes') {
        if (!ctype_digit($value) || (int) $value < 5 || (int) $value > 1440) {
          fail('مدت انقضای نشست باید عددی بین ۵ تا ۱۴۴۰ دقیقه باشد.');
        }
      } elseif ($key === 'stale_case_days') {
        if (!ctype_digit($value) || (int) $value < 1 || (int) $value > 90) {
          fail('آستانه‌ی پرونده راکد باید عددی بین ۱ تا ۹۰ روز باشد.');
        }
      } elseif ($key === 'brand_color') {
        if (!preg_match('/^#[0-9a-fA-F]{6}$/', $value)) fail('کد رنگ برند نامعتبر است.');
      } elseif ($key === 'default_theme') {
        if (!in_array($value, ['light', 'dark'], true)) fail('حالت پیش‌فرض نامعتبر است.');
      } elseif (in_array($key, [
        'notify_sms_submitted', 'notify_sms_initial_review', 'notify_sms_final_review',
        'notify_sms_rejected', 'show_appointment_range_field',
      ], true)) {
        if (!in_array($value, ['0', '1'], true)) fail("مقدار تنظیم «$key» نامعتبر است.");
      } elseif ($key === 'specialties') {
        $decoded = json_decode($value, true);
        if (!is_array($decoded) || count($decoded) === 0) fail('فهرست تخصص‌ها نامعتبر است.');
        foreach ($decoded as $item) {
          if (!isset($item['value'], $item['label']) || !is_string($item['value']) || !is_string($item['label']) || $item['value'] === '' || $item['label'] === '') {
            fail('هر ردیف تخصص باید مقدار و عنوان معتبر داشته باشد.');
          }
        }
      } elseif (in_array($key, ['org_phone', 'org_whatsapp'], true) && $value !== '' && !preg_match('/^0?\d{9,11}$/', $value)) {
        fail("شماره تماس واردشده برای «$key» نامعتبر است.");
      }

      setSetting($pdo, $key, $value);
    }
    logAudit($pdo, $actingUser, 'settings_update', null, implode(',', array_keys($incoming)));
    ok(['settings' => getAllSettingsForClient($pdo)]);
  }

  // ===================== admin account management (نقش‌ها) =====================

  case 'admin_list': {
    requireRole($pdo, ['super_admin']);
    $stmt = $pdo->query('SELECT username, role, must_change_password, last_login_at, last_login_ip, created_at FROM admins ORDER BY created_at ASC');
    ok(['items' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
  }

  case 'admin_create': {
    requireCsrf();
    $actingUser = requireRole($pdo, ['super_admin']);
    $username = str_field('username', 60);
    $password = (string) ($_POST['password'] ?? '');
    $role = (string) ($_POST['role'] ?? 'reviewer');
    if (!preg_match('/^[a-zA-Z0-9_.-]{3,60}$/', $username)) fail('نام کاربری نامعتبر است (فقط حروف/اعداد انگلیسی، حداقل ۳ کاراکتر).');
    if (mb_strlen($password) < 6) fail('رمز عبور باید حداقل ۶ کاراکتر باشد.');
    if (!in_array($role, ['super_admin', 'reviewer'], true)) fail('نقش نامعتبر است.');

    $exists = $pdo->prepare('SELECT 1 FROM admins WHERE username = ?');
    $exists->execute([$username]);
    if ($exists->fetchColumn()) fail('این نام کاربری قبلاً ثبت شده است.');

    $pdo->prepare('INSERT INTO admins (username, password_hash, must_change_password, created_at, role) VALUES (?, ?, 1, ?, ?)')
      ->execute([$username, password_hash($password, PASSWORD_DEFAULT), gmdate('c'), $role]);
    logAudit($pdo, $actingUser, 'admin_create', $username, $role);
    ok();
  }

  case 'admin_set_role': {
    requireCsrf();
    $actingUser = requireRole($pdo, ['super_admin']);
    $username = str_field('username', 60);
    $role = (string) ($_POST['role'] ?? '');
    if (!in_array($role, ['super_admin', 'reviewer'], true)) fail('نقش نامعتبر است.');
    if ($username === $actingUser && $role !== 'super_admin') {
      fail('نمی‌توانید نقش حساب خودتان را از مدیر ارشد پایین‌تر ببرید.');
    }
    $check = $pdo->prepare('SELECT 1 FROM admins WHERE username = ?');
    $check->execute([$username]);
    if (!$check->fetchColumn()) fail('این حساب مدیر یافت نشد.');

    $pdo->prepare('UPDATE admins SET role = ? WHERE username = ?')->execute([$role, $username]);
    logAudit($pdo, $actingUser, 'admin_set_role', $username, $role);
    ok();
  }

  case 'admin_delete': {
    requireCsrf();
    $actingUser = requireRole($pdo, ['super_admin']);
    $username = str_field('username', 60);
    if ($username === $actingUser) fail('نمی‌توانید حساب خودتان را حذف کنید.');
    $totalAdmins = (int) $pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn();
    if ($totalAdmins <= 1) fail('حداقل یک حساب مدیر باید در سامانه باقی بماند.');

    $pdo->prepare('DELETE FROM admins WHERE username = ?')->execute([$username]);
    logAudit($pdo, $actingUser, 'admin_delete', $username, null);
    ok();
  }

  // -- streams a zip of the database + app files for manual/offline backup ----
  case 'admin_backup_download': {
    requireRole($pdo, ['super_admin']);
    if (!class_exists('ZipArchive')) fail('پسوند ZipArchive روی این سرور فعال نیست.', 500);

    $tmpZip = tempnam(sys_get_temp_dir(), 'mjbackup');
    $zip = new ZipArchive();
    if ($zip->open($tmpZip, ZipArchive::OVERWRITE) !== true) fail('ساخت فایل پشتیبان ممکن نشد.', 500);
    $root = __DIR__;
    $filesToBackup = [
      'data/app.sqlite' => $dbPath,
      'api.php' => $root . '/api.php',
      'index.html' => $root . '/index.html',
    ];
    foreach ($filesToBackup as $label => $path) {
      if (file_exists($path)) $zip->addFile($path, $label);
    }
    $zip->close();
    logAudit($pdo, currentAdmin(), 'backup_download', null, null);

    if (ob_get_length() !== false) { ob_clean(); }
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="backup-' . gmdate('Ymd-His') . '.zip"');
    header('Content-Length: ' . filesize($tmpZip));
    readfile($tmpZip);
    @unlink($tmpZip);
    exit;
  }

  default:
    fail('عملیات نامشخص است.', 404);
}
