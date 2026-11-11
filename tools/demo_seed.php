<?php
/**
 * Demo instance with FAKE data — run with:  php tools/demo_seed.php [port]
 *
 * Copies api.php into a throw-away temp directory, fills it with invented
 * donors, accounts and transactions through the public API, then serves it at
 * http://127.0.0.1:<port>/ (default 8088) so you can click around the app.
 * Login: admin / demo-Admin-12345 (demo only). Press Ctrl+C to stop; the temp
 * directory is deleted. The repository's own data/ is never touched.
 * All names and numbers below are made up.
 */
declare(strict_types=1);

$root = dirname(__DIR__);
$port = (int) ($argv[1] ?? 8088);
$tmp = sys_get_temp_dir() . '/mj_demo_' . bin2hex(random_bytes(4));
mkdir($tmp, 0770, true);
copy($root . '/api.php', $tmp . '/api.php');
copy($root . '/index.html', $tmp . '/index.html');
$pass = 'demo-Admin-12345';
file_put_contents($tmp . '/config.php', "<?php return ['admin_initial_password' => " . var_export($pass, true) . "];\n");

$proc = proc_open(['php', '-S', "127.0.0.1:$port", '-t', $tmp], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
register_shutdown_function(function () use ($proc, $tmp) {
  proc_terminate($proc);
  exec('rm -rf ' . escapeshellarg($tmp));
});
for ($i = 0; $i < 50; $i++) { if (@fsockopen('127.0.0.1', $port)) break; usleep(100000); }

$cookie = $tmp . '/cookies.txt';
function call(string $action, array $post = []): array {
  global $port, $cookie;
  $ch = curl_init("http://127.0.0.1:$port/api.php");
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true, CURLOPT_COOKIEJAR => $cookie, CURLOPT_COOKIEFILE => $cookie,
    CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query(['action' => $action] + $post),
  ]);
  $body = curl_exec($ch);
  curl_close($ch);
  return json_decode((string) $body, true) ?? [];
}

$csrf = call('bootstrap')['csrf'] ?? '';
$r = call('admin_login', ['csrf' => $csrf, 'username' => 'admin', 'password' => $pass]);
if (!($r['ok'] ?? false)) { fwrite(STDERR, "Admin login failed\n"); exit(1); }

$inc = [];
foreach (['کمک‌های نقدی', 'نذورات'] as $n) $inc[] = (int) call('accounting_category_create', ['csrf' => $csrf, 'type' => 'income', 'name' => $n])['id'];
$exp = [];
foreach (['هزینه درمان', 'اسکان', 'هزینه اداری'] as $n) $exp[] = (int) call('accounting_category_create', ['csrf' => $csrf, 'type' => 'expense', 'name' => $n])['id'];
$bank = (int) call('accounting_bank_account_create', ['csrf' => $csrf, 'name' => 'حساب نمونه', 'openingBalance' => 10000000])['id'];

foreach (['نیکوکار نمونه ۱' => '09120000001', 'نیکوکار نمونه ۲' => '09120000002', 'نیکوکار نمونه ۳' => '09120000003'] as $name => $phone) {
  call('donor_create', ['csrf' => $csrf, 'name' => $name, 'phone' => $phone]);
}

mt_srand(42);
for ($m = 1; $m <= 6; $m++) {
  for ($k = 0; $k < 4; $k++) {
    $date = sprintf('2026-%02d-%02d', $m, 3 + $k * 7);
    $isIncome = $k % 2 === 0;
    $res = call('accounting_transaction_create', [
      'csrf' => $csrf, 'bankAccountId' => $bank, 'transactionDate' => $date, 'paymentMethod' => 'cash',
      'type' => $isIncome ? 'income' : 'expense',
      'categoryId' => $isIncome ? $inc[$k % 2] : $exp[mt_rand(0, 2)],
      'amount' => mt_rand(5, 40) * 100000,
    ]);
    if (!($res['ok'] ?? false)) { fwrite(STDERR, "Transaction failed on $date\n"); exit(1); }
  }
}

echo "Demo ready (fake data): http://127.0.0.1:$port/\nLogin: admin / $pass\nCtrl+C to stop.\n";
if (getenv('DEMO_SEED_ONLY')) exit(0);
proc_wait($proc);
