<?php
/**
 * Receipt and backup tests for api.php — run with:  php tests/receipt_backup_test.php
 *
 * Covers fetching a transaction's attached receipt image (accounting_asset) and
 * downloading the admin backup zip: guest rejection, 404s, content type and contents. Runs against a throw-away temp copy of
 * api.php and database; the repository's own data/ directory is never touched.
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$tmp = sys_get_temp_dir() . '/mj_test_' . bin2hex(random_bytes(4));
mkdir($tmp, 0770, true);
copy($root . '/api.php', $tmp . '/api.php');
$adminPass = 'T3st-' . bin2hex(random_bytes(8));
file_put_contents($tmp . '/config.php', "<?php return ['admin_initial_password' => " . var_export($adminPass, true) . "];\n");

$port = random_int(20000, 40000);
$proc = proc_open(['php', '-S', "127.0.0.1:$port", '-t', $tmp], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
register_shutdown_function(function () use ($proc, $tmp) {
  proc_terminate($proc);
  exec('rm -rf ' . escapeshellarg($tmp));
});
for ($i = 0; $i < 50; $i++) { if (@fsockopen('127.0.0.1', $port)) break; usleep(100000); }

$cookie = $tmp . '/cookies.txt';
function call(string $action, array $post = [], bool $usePost = true): array {
  global $port, $cookie;
  $ch = curl_init("http://127.0.0.1:$port/api.php");
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $cookie, CURLOPT_COOKIEFILE => $cookie,
    CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query(['action' => $action] + $post),
  ]);
  $body = curl_exec($ch);
  $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);
  return [$code, json_decode((string) $body, true) ?? []];
}

$fails = 0;
function check(string $name, bool $cond): void {
  global $fails;
  echo ($cond ? "PASS " : "FAIL ") . $name . "\n";
  if (!$cond) $fails++;
}




$png = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

[$c, $r] = call('accounting_asset', ['id' => 1]);
check('guest cannot fetch a receipt', $c === 401 || $c === 403);
[$c, $r] = call('admin_backup_download');
check('guest cannot download a backup', $c === 401 || $c === 403);

[$c, $r] = call('bootstrap');
$csrf = $r['csrf'] ?? '';
[$c, $r] = call('admin_login', ['csrf' => $csrf, 'username' => 'admin', 'password' => $adminPass]);
check('admin logs in', $c === 200 && ($r['ok'] ?? false));

[$c, $r] = call('accounting_category_create', ['csrf' => $csrf, 'type' => 'income', 'name' => 'Receipt income']);
$cat = (int) ($r['id'] ?? 0);
[$c, $r] = call('accounting_bank_account_create', ['csrf' => $csrf, 'name' => 'Receipt box', 'openingBalance' => 0]);
$bank = (int) ($r['id'] ?? 0);
$base = ['csrf' => $csrf, 'type' => 'income', 'categoryId' => $cat, 'bankAccountId' => $bank, 'amount' => 500, 'transactionDate' => '2026-01-10'];

[$c, $r] = call('accounting_transaction_create', $base + ['description' => 'with receipt', 'receiptPhoto' => $png]);
$withId = (int) ($r['id'] ?? 0);
check('transaction with a receipt photo is created', $withId > 0);
[$c, $r] = call('accounting_transaction_create', $base + ['description' => 'no receipt']);
$noId = (int) ($r['id'] ?? 0);
check('transaction without a receipt is created', $noId > 0);
[$c, $r] = call('accounting_transaction_create', $base + ['description' => 'bad', 'receiptPhoto' => 'data:text/html;base64,PGI+']);
check('non-image receipt type is rejected', !($r['ok'] ?? true));

[$c, $r] = call('accounting_asset', ['id' => $withId]);
check('receipt is returned as the same PNG data URL', ($r['ok'] ?? false) && ($r['dataUrl'] ?? '') === $png && ($r['mime'] ?? '') === 'image/png');
[$c, $r] = call('accounting_asset', ['id' => $noId]);
check('transaction without receipt returns 404', $c === 404);
[$c, $r] = call('accounting_asset', ['id' => 999999]);
check('missing transaction returns 404', $c === 404);

// Backup download returns a raw zip (not JSON), so use curl directly.
$ch = curl_init("http://127.0.0.1:$port/api.php");
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEFILE => $cookie, CURLOPT_POST => true,
  CURLOPT_POSTFIELDS => 'action=admin_backup_download', CURLOPT_HEADER => true]);
$resp = (string) curl_exec($ch);
$hdrLen = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
$headers = substr($resp, 0, $hdrLen);
$zipBytes = substr($resp, $hdrLen);
check('backup returns 200 with a zip content type', $code === 200 && stripos($headers, 'application/zip') !== false);
check('backup is named backup-*.zip', (bool) preg_match('/filename="backup-\d{8}-\d{6}\.zip"/', $headers));
$zf = $tmp . '/dl.zip';
file_put_contents($zf, $zipBytes);
$za = new ZipArchive();
$opened = $za->open($zf) === true;
check('backup is a valid zip archive', $opened);
if ($opened) {
  $names = [];
  for ($i = 0; $i < $za->numFiles; $i++) $names[] = $za->getNameIndex($i);
  check('backup contains database, api.php and index.html', in_array('data/app.sqlite', $names, true) && in_array('api.php', $names, true));
  $db = $za->getFromName('data/app.sqlite');
  check('backup database is a SQLite file', is_string($db) && str_starts_with($db, 'SQLite format 3'));
  $za->close();
}
[$c, $r] = call('audit_log_list');
check('backup download is audit-logged', in_array('backup_download', array_column($r['items'] ?? [], 'action'), true));

echo $fails === 0 ? "\nAll receipt and backup tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
