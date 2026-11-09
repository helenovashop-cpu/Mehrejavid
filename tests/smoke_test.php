<?php
/**
 * Smoke tests for api.php — run with:  php tests/smoke_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises the main security contracts (CSRF, role checks,
 * login, rate limiting). No real data and no network access are involved;
 * the repository's own data/ directory is never touched.
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

[$c, $r] = call('bootstrap');
check('bootstrap returns ok + csrf token', $c === 200 && ($r['ok'] ?? false) && strlen($r['csrf'] ?? '') === 64);
check('bootstrap starts as guest', ($r['role'] ?? '') === 'guest');
$csrf = $r['csrf'] ?? '';

[$c, $r] = call('donation_public_stats');
check('public stats are readable by guests', $c === 200 && isset($r['totalRaised']));

[$c, $r] = call('submission_list_all');
check('submission_list_all rejects guests (401)', $c === 401 && !($r['ok'] ?? true));

[$c, $r] = call('audit_log_list');
check('audit_log_list rejects guests (401)', $c === 401);

[$c, $r] = call('backup_download');
check('backup_download rejects guests', $c === 401 || $c === 403);

[$c, $r] = call('admin_login', ['username' => 'admin', 'password' => $adminPass]);
check('admin_login without CSRF is refused (403)', $c === 403);

[$c, $r] = call('admin_login', ['csrf' => $csrf, 'username' => 'admin', 'password' => 'wrong-password']);
check('admin_login with wrong password fails', $c === 400 && !($r['ok'] ?? true));

[$c, $r] = call('admin_login', ['csrf' => $csrf, 'username' => 'admin', 'password' => $adminPass]);
check('admin_login with configured password succeeds', $c === 200 && ($r['ok'] ?? false));
check('first login forces password change', ($r['mustChangePassword'] ?? false) === true);

[$c, $r] = call('bootstrap');
check('session is now admin', ($r['role'] ?? '') === 'admin');

[$c, $r] = call('submission_list_all');
check('submission_list_all works for admin', $c === 200 && is_array($r['items'] ?? null));

// --- Accounting flow (super_admin): categories, accounts, transactions, summary ---
[$c, $r] = call('accounting_category_create', ['type' => 'income', 'name' => 'Test donations']);
check('accounting_category_create without CSRF is refused (403)', $c === 403);

[$c, $r] = call('accounting_category_create', ['csrf' => $csrf, 'type' => 'bogus', 'name' => 'X']);
check('accounting_category_create rejects an invalid type', !($r['ok'] ?? true));

[$c, $r] = call('accounting_category_create', ['csrf' => $csrf, 'type' => 'income', 'name' => 'Test donations']);
check('accounting_category_create (income) succeeds', ($r['ok'] ?? false) && ($r['id'] ?? 0) > 0);
$incomeCat = (int) ($r['id'] ?? 0);
[$c, $r2] = call('accounting_category_list');
$found = false;
foreach (($r2['items'] ?? []) as $it) { if ((int) $it['id'] === $incomeCat && $it['name'] === 'Test donations') $found = true; }
check('create endpoints return the new record id (not the audit-log id)', $found);

[$c, $r] = call('accounting_category_create', ['csrf' => $csrf, 'type' => 'expense', 'name' => 'Test costs']);
$expenseCat = (int) ($r['id'] ?? 0);

[$c, $r] = call('accounting_bank_account_create', ['csrf' => $csrf, 'name' => 'Test cash box', 'openingBalance' => 1000]);
check('accounting_bank_account_create succeeds', ($r['ok'] ?? false) && ($r['id'] ?? 0) > 0);
$bank = (int) ($r['id'] ?? 0);

$tx = ['csrf' => $csrf, 'bankAccountId' => $bank, 'transactionDate' => '2026-01-15', 'paymentMethod' => 'cash'];
[$c, $r] = call('accounting_transaction_create', $tx + ['type' => 'income', 'categoryId' => $incomeCat, 'amount' => 5000]);
check('income transaction is recorded', ($r['ok'] ?? false) && ($r['id'] ?? 0) > 0);

[$c, $r] = call('accounting_transaction_create', $tx + ['type' => 'expense', 'categoryId' => $expenseCat, 'amount' => 1200]);
check('expense transaction is recorded', ($r['ok'] ?? false));

[$c, $r] = call('accounting_transaction_create', $tx + ['type' => 'expense', 'categoryId' => $incomeCat, 'amount' => 100]);
check('transaction with mismatched category type is rejected', !($r['ok'] ?? true));

[$c, $r] = call('accounting_transaction_create', $tx + ['type' => 'income', 'categoryId' => $incomeCat, 'amount' => -5]);
check('transaction with non-positive amount is rejected', !($r['ok'] ?? true));

[$c, $r] = call('accounting_transaction_create', ['transactionDate' => '15/01/2026'] + $tx + ['type' => 'income', 'categoryId' => $incomeCat, 'amount' => 10]);
check('transaction with malformed date is rejected', !($r['ok'] ?? true));

[$c, $r] = call('accounting_summary');
check('accounting_summary totals match recorded transactions',
  ($r['ok'] ?? false) && ($r['totalIncome'] ?? -1) === 5000 && ($r['totalExpense'] ?? -1) === 1200 && ($r['netBalance'] ?? 0) === 3800);
$balance = null;
foreach (($r['byAccount'] ?? []) as $a) { if ((int) $a['id'] === $bank) $balance = (int) $a['balance']; }
check('account balance = opening balance + income - expense', $balance === 1000 + 5000 - 1200);

// Internal transfers: move money between two accounts without touching income/expense totals.
$balanceOf = function (array $summary, int $accountId): ?int {
  foreach (($summary['byAccount'] ?? []) as $a) { if ((int) $a['id'] === $accountId) return (int) $a['balance']; }
  return null;
};
[$c, $r] = call('accounting_bank_account_create', ['csrf' => $csrf, 'name' => 'Test bank', 'openingBalance' => 0]);
$bank2 = (int) ($r['id'] ?? 0);
$tr = ['csrf' => $csrf, 'fromAccountId' => $bank, 'toAccountId' => $bank2, 'transactionDate' => '2026-01-16'];
[$c, $r] = call('accounting_transfer_create', $tr + ['amount' => 500]);
check('accounting_transfer_create succeeds', ($r['ok'] ?? false) && ($r['id'] ?? 0) > 0);
$legId = (int) ($r['id'] ?? 0);
[$c, $r] = call('accounting_transfer_create', ['toAccountId' => $bank] + $tr + ['fromAccountId' => $bank, 'amount' => 500]);
check('transfer to the same account is rejected', !($r['ok'] ?? true));
[$c, $r] = call('accounting_transfer_create', $tr + ['amount' => 0]);
check('transfer with non-positive amount is rejected', !($r['ok'] ?? true));
[$c, $r] = call('accounting_transfer_create', ['toAccountId' => 999999] + $tr + ['amount' => 5]);
check('transfer to an unknown account is rejected', !($r['ok'] ?? true));

[$c, $r] = call('accounting_summary');
check('transfers do not change income/expense totals', ($r['totalIncome'] ?? -1) === 5000 && ($r['totalExpense'] ?? -1) === 1200);
check('transfer moves the balance between the two accounts',
  $balanceOf($r, $bank) === 1000 + 5000 - 1200 - 500 && $balanceOf($r, $bank2) === 500);

[$c, $r] = call('accounting_transaction_delete', ['csrf' => $csrf, 'id' => $legId]);
check('deleting one transfer leg succeeds', ($r['ok'] ?? false));
[$c, $r] = call('accounting_summary');
check('deleting one leg removes the paired leg too (balances restored)',
  $balanceOf($r, $bank) === 1000 + 5000 - 1200 && $balanceOf($r, $bank2) === 0);

// Donors: create / validate / update / attach donations / merge duplicates.
[$c, $r] = call('donor_create', ['csrf' => $csrf, 'name' => 'Test donor A', 'phone' => '09121234567']);
check('donor_create succeeds and returns the new donor id', ($r['ok'] ?? false) && ($r['id'] ?? 0) > 0);
$donorA = (int) ($r['id'] ?? 0);
[$c, $r] = call('donor_create', ['csrf' => $csrf, 'name' => 'Test donor A (duplicate)']);
$donorB = (int) ($r['id'] ?? 0);
[$c, $r] = call('donor_create', ['csrf' => $csrf, 'name' => '']);
check('donor_create rejects an empty name', !($r['ok'] ?? true));
[$c, $r] = call('donor_create', ['csrf' => $csrf, 'name' => 'Bad phone', 'phone' => '12345']);
check('donor_create rejects a malformed phone number', !($r['ok'] ?? true));
[$c, $r] = call('donor_update', ['csrf' => $csrf, 'id' => 999999, 'name' => 'Ghost']);
check('donor_update on a missing donor returns 404', $c === 404);
[$c, $r] = call('donor_update', ['csrf' => $csrf, 'id' => $donorA, 'name' => 'Test donor A2', 'phone' => '09120000000']);
check('donor_update succeeds', ($r['ok'] ?? false));
[$c, $r] = call('donor_detail', ['id' => $donorA]);
check('donor_detail reflects the update', ($r['donor']['name'] ?? '') === 'Test donor A2' && ($r['donor']['phone'] ?? '') === '09120000000');

[$c, $r] = call('accounting_transaction_create', $tx + ['type' => 'income', 'categoryId' => $incomeCat, 'amount' => 300, 'donorName' => 'Test donor A (duplicate)']);
$donationOk = ($r['ok'] ?? false);
[$c, $r] = call('donor_merge', ['csrf' => $csrf, 'keepId' => $donorA, 'mergeId' => $donorA]);
check('donor_merge refuses to merge a donor with itself', !($r['ok'] ?? true));
[$c, $r] = call('donor_merge', ['csrf' => $csrf, 'keepId' => $donorA, 'mergeId' => $donorB]);
check('donor_merge succeeds', ($r['ok'] ?? false));
[$c, $r] = call('donor_detail', ['id' => $donorB]);
check('merged-away donor no longer exists (404)', $c === 404);
if ($donationOk) {
  [$c, $r] = call('donor_detail', ['id' => $donorA]);
  check('donations of the merged donor move to the keeper', count($r['transactions'] ?? []) === 1);
}

// --- Transaction list/update/delete, budgets, audit log and backup ---
[$c, $r] = call('accounting_transaction_list', ['type' => 'income']);
$incomeTxId = 0; $onlyIncome = ($r['ok'] ?? false) && count($r['items'] ?? []) >= 1;
foreach (($r['items'] ?? []) as $it) { if ($it['type'] !== 'income') $onlyIncome = false; $incomeTxId = (int) $it['id']; }
check('accounting_transaction_list filters by type', $onlyIncome);
[$c, $r] = call('accounting_transaction_list', ['minAmount' => 4000]);
check('accounting_transaction_list filters by minimum amount', ($r['ok'] ?? false) && count($r['items'] ?? []) === 1);

[$c, $r] = call('accounting_transaction_update', ['csrf' => $csrf, 'id' => $incomeTxId, 'categoryId' => $incomeCat, 'bankAccountId' => $bank, 'amount' => 0, 'transactionDate' => '2026-01-15']);
check('accounting_transaction_update rejects a non-positive amount', !($r['ok'] ?? true));
[$c, $r] = call('accounting_transaction_update', ['csrf' => $csrf, 'id' => $incomeTxId, 'categoryId' => $incomeCat, 'bankAccountId' => $bank, 'amount' => 6000, 'transactionDate' => '2026-01-15', 'paymentMethod' => 'cash']);
check('accounting_transaction_update changes the amount', ($r['ok'] ?? false));
[$c, $r] = call('accounting_summary');
check('summary reflects the edited transaction', ($r['totalIncome'] ?? -1) === 6300);

[$c, $r] = call('budget_set', ['csrf' => $csrf, 'categoryId' => $expenseCat, 'periodType' => 'monthly', 'periodValue' => '2026-01', 'amount' => 2000]);
check('budget_set stores a monthly budget', ($r['ok'] ?? false));
[$c, $r] = call('budget_set', ['csrf' => $csrf, 'categoryId' => $expenseCat, 'periodType' => 'weekly', 'periodValue' => '2026-01', 'amount' => 1]);
check('budget_set rejects an invalid period type', !($r['ok'] ?? true));
[$c, $r] = call('budget_vs_actual', ['periodType' => 'monthly', 'periodValue' => '2026-01']);
$row = null; foreach (($r['items'] ?? []) as $it) { if ((int) $it['category_id'] === $expenseCat) $row = $it; }
check('budget_vs_actual compares budget (2000) with actual spend (1200)', $row !== null && (int) $row['budget_amount'] === 2000 && (int) $row['actual_amount'] === 1200);

[$c, $r] = call('audit_log_list');
$actions = array_column($r['items'] ?? [], 'action');
check('audit log records admin actions', in_array('budget_set', $actions, true) && in_array('accounting_transaction_update', $actions, true));

[$c, $r] = call('accounting_transaction_delete', ['id' => $incomeTxId]);
check('accounting_transaction_delete without CSRF is refused (403)', $c === 403);
[$c, $r] = call('accounting_transaction_delete', ['csrf' => $csrf, 'id' => $incomeTxId]);
check('accounting_transaction_delete removes the transaction', ($r['ok'] ?? false));
[$c, $r] = call('accounting_transaction_delete', ['csrf' => $csrf, 'id' => $incomeTxId]);
check('deleting a missing transaction returns 404', $c === 404);
[$c, $r] = call('accounting_summary');
check('summary reflects the deletion', ($r['totalIncome'] ?? -1) === 300);

$ch = curl_init("http://127.0.0.1:$port/api.php");
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEFILE => $cookie, CURLOPT_POST => true, CURLOPT_POSTFIELDS => 'action=backup_download']);
$bk = (string) curl_exec($ch); curl_close($ch);
check('backup_download returns a SQLite database for admins', str_starts_with($bk, 'SQLite format 3'));

// Password change: wrong current password is refused, correct one works.
[$c, $r] = call('admin_change_password', ['csrf' => $csrf, 'current' => 'not-the-password', 'next' => 'N3w-passw0rd!']);
check('admin_change_password rejects a wrong current password', !($r['ok'] ?? true));
[$c, $r] = call('admin_change_password', ['csrf' => $csrf, 'current' => $adminPass, 'next' => '123']);
check('admin_change_password rejects a too-short new password', !($r['ok'] ?? true));
[$c, $r] = call('admin_change_password', ['csrf' => $csrf, 'current' => $adminPass, 'next' => 'N3w-passw0rd!']);
check('admin_change_password succeeds with valid input', ($r['ok'] ?? false));

[$c, $r] = call('admin_logout', ['csrf' => $csrf]);
[$c, $r] = call('bootstrap');
check('logout returns to guest', ($r['role'] ?? '') === 'guest');

// Brute-force protection: >5 wrong attempts for one username must hit HTTP 429.
[$c, $r] = call('bootstrap'); $csrf = $r['csrf'] ?? '';
$limited = false;
for ($i = 0; $i < 8; $i++) {
  [$c] = call('admin_login', ['csrf' => $csrf, 'username' => 'bruteforce', 'password' => 'x' . $i]);
  if ($c === 429) { $limited = true; break; }
}
check('repeated failed logins are rate-limited (429)', $limited);

echo $fails === 0 ? "\nAll tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
