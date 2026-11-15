<?php
/**
 * Accounting maintenance tests for api.php — run with:  php tests/accounting_admin_test.php
 *
 * Covers editing and deleting accounting categories and bank accounts: guest and
 * CSRF rejection, validation, 404s, and the guard that refuses to delete a category
 * or account that already has transactions. Runs against a throw-away temp copy of
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



[$c, $r] = call('accounting_category_update', ['id' => 1, 'name' => 'X']);
check('guest cannot update a category', $c === 401 || $c === 403);
[$c, $r] = call('accounting_bank_account_list');
check('guest cannot list bank accounts', $c === 401);

[$c, $r] = call('bootstrap');
$csrf = $r['csrf'] ?? '';
[$c, $r] = call('admin_login', ['csrf' => $csrf, 'username' => 'admin', 'password' => $adminPass]);
check('admin logs in', $c === 200 && ($r['ok'] ?? false));

[$c, $r] = call('accounting_category_create', ['csrf' => $csrf, 'type' => 'income', 'name' => 'Old income']);
$cat = (int) ($r['id'] ?? 0);
[$c, $r] = call('accounting_category_create', ['csrf' => $csrf, 'type' => 'expense', 'name' => 'Unused']);
$unused = (int) ($r['id'] ?? 0);
[$c, $r] = call('accounting_bank_account_create', ['csrf' => $csrf, 'name' => 'Old box', 'openingBalance' => 100]);
$bank = (int) ($r['id'] ?? 0);
[$c, $r] = call('accounting_bank_account_create', ['csrf' => $csrf, 'name' => 'Spare box', 'openingBalance' => 0]);
$spare = (int) ($r['id'] ?? 0);

// --- categories ---
[$c, $r] = call('accounting_category_update', ['id' => $cat, 'name' => 'Renamed']);
check('category update without CSRF is refused (403)', $c === 403);
[$c, $r] = call('accounting_category_update', ['csrf' => $csrf, 'id' => $cat, 'name' => '']);
check('category update rejects an empty name', !($r['ok'] ?? true));
[$c, $r] = call('accounting_category_update', ['csrf' => $csrf, 'id' => 999999, 'name' => 'Ghost']);
check('category update of a missing id returns 404', $c === 404);
[$c, $r] = call('accounting_category_update', ['csrf' => $csrf, 'id' => $cat, 'name' => 'Renamed']);
check('category update succeeds', ($r['ok'] ?? false) === true);
[$c, $r] = call('accounting_category_list');
$names = array_column($r['items'] ?? [], 'name', 'id');
check('renamed category shows in the list', ($names[$cat] ?? '') === 'Renamed');

// A transaction pins the category and the bank account.
[$c, $r] = call('accounting_transaction_create', ['csrf' => $csrf, 'type' => 'income', 'categoryId' => $cat,
  'bankAccountId' => $bank, 'amount' => 700, 'transactionDate' => '2026-02-01', 'paymentMethod' => 'cash']);
check('transaction is recorded', ($r['ok'] ?? false) === true);

[$c, $r] = call('accounting_category_delete', ['id' => $cat]);
check('category delete without CSRF is refused (403)', $c === 403);
[$c, $r] = call('accounting_category_delete', ['csrf' => $csrf, 'id' => $cat]);
check('category with transactions cannot be deleted', !($r['ok'] ?? true));
[$c, $r] = call('accounting_category_delete', ['csrf' => $csrf, 'id' => 999999]);
check('category delete of a missing id returns 404', $c === 404);
[$c, $r] = call('accounting_category_delete', ['csrf' => $csrf, 'id' => $unused]);
check('unused category can be deleted', ($r['ok'] ?? false) === true);
[$c, $r] = call('accounting_category_list');
check('deleted category is gone, used one remains', !isset(array_column($r['items'] ?? [], 'name', 'id')[$unused]) && isset(array_column($r['items'] ?? [], 'name', 'id')[$cat]));

// --- bank accounts ---
[$c, $r] = call('accounting_bank_account_update', ['id' => $bank, 'name' => 'New box', 'openingBalance' => 250]);
check('account update without CSRF is refused (403)', $c === 403);
[$c, $r] = call('accounting_bank_account_update', ['csrf' => $csrf, 'id' => $bank, 'name' => '', 'openingBalance' => 1]);
check('account update rejects an empty name', !($r['ok'] ?? true));
[$c, $r] = call('accounting_bank_account_update', ['csrf' => $csrf, 'id' => 999999, 'name' => 'Ghost', 'openingBalance' => 1]);
check('account update of a missing id returns 404', $c === 404);
[$c, $r] = call('accounting_bank_account_update', ['csrf' => $csrf, 'id' => $bank, 'name' => 'New box', 'openingBalance' => 250]);
check('account update succeeds', ($r['ok'] ?? false) === true);
[$c, $r] = call('accounting_bank_account_list');
$accts = [];
foreach (($r['items'] ?? []) as $a) $accts[(int) $a['id']] = $a;
check('account list shows the new name and opening balance', ($accts[$bank]['name'] ?? '') === 'New box' && (int) ($accts[$bank]['opening_balance'] ?? 0) === 250);
[$c, $r] = call('accounting_summary');
$bal = null;
foreach (($r['byAccount'] ?? []) as $a) { if ((int) $a['id'] === $bank) $bal = (int) $a['balance']; }
check('edited opening balance feeds into the balance (250 + 700)', $bal === 950);

[$c, $r] = call('accounting_bank_account_delete', ['id' => $spare]);
check('account delete without CSRF is refused (403)', $c === 403);
[$c, $r] = call('accounting_bank_account_delete', ['csrf' => $csrf, 'id' => $bank]);
check('account with transactions cannot be deleted', !($r['ok'] ?? true));
[$c, $r] = call('accounting_bank_account_delete', ['csrf' => $csrf, 'id' => 999999]);
check('account delete of a missing id returns 404', $c === 404);
[$c, $r] = call('accounting_bank_account_delete', ['csrf' => $csrf, 'id' => $spare]);
check('unused account can be deleted', ($r['ok'] ?? false) === true);
[$c, $r] = call('accounting_bank_account_list');
$ids = array_map('intval', array_column($r['items'] ?? [], 'id'));
check('deleted account is gone, used one remains', !in_array($spare, $ids, true) && in_array($bank, $ids, true));

[$c, $r] = call('audit_log_list');
$acts = array_column($r['items'] ?? [], 'action');
check('updates and deletes are audit-logged',
  in_array('accounting_category_update', $acts, true) && in_array('accounting_category_delete', $acts, true)
  && in_array('accounting_bank_account_update', $acts, true) && in_array('accounting_bank_account_delete', $acts, true));

echo $fails === 0 ? "\nAll accounting maintenance tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
