<?php
/**
 * Online donation tests for api.php — run with:  php tests/donation_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises the public donation endpoints that do NOT need the
 * payment gateway: input validation of donation_request_payment, the public
 * transparency stats and the donation_verify callback (unknown authority, failed
 * status, already-paid replay). Gateway calls are never made, so no network access
 * and no real money are involved; the repository's own data/ directory is untouched.
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



/** GET without following redirects; returns [status, Location header]. */
function getRedirect(string $query): array {
  global $port;
  $ch = curl_init("http://127.0.0.1:$port/api.php?$query");
  curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_FOLLOWLOCATION => false]);
  $raw = (string) curl_exec($ch);
  $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);
  $loc = preg_match('/^Location:\s*(\S+)/mi', $raw, $m) ? $m[1] : '';
  return [$code, $loc];
}

[$c, $r] = call('bootstrap');
$csrf = $r['csrf'] ?? '';
$pdo = new PDO('sqlite:' . $tmp . '/data/app.sqlite');

// --- donation_request_payment: validation (rejected before any gateway call) ---
[$c, $r] = call('donation_request_payment', ['amount' => 50000]);
check('payment request without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('donation_request_payment', ['csrf' => $csrf, 'amount' => 9999]);
check('amount below the 10,000 Toman minimum is rejected', !($r['ok'] ?? false));
[$c, $r] = call('donation_request_payment', ['csrf' => $csrf, 'amount' => 500000001]);
check('amount above the maximum is rejected', !($r['ok'] ?? false));
[$c, $r] = call('donation_request_payment', ['csrf' => $csrf, 'amount' => 'abc']);
check('non-numeric amount is rejected', !($r['ok'] ?? false));
foreach (['12345', '9120000001', '0912abc0001'] as $badPhone) {
  [$c, $r] = call('donation_request_payment', ['csrf' => $csrf, 'amount' => 50000, 'phone' => $badPhone]);
  check("invalid phone '$badPhone' is rejected", !($r['ok'] ?? false));
}
check('no pending donation is recorded by rejected requests', (int) $pdo->query('SELECT COUNT(*) FROM online_donations')->fetchColumn() === 0);

// --- donation_public_stats: public, aggregate-only ---
[$c, $r] = call('donation_public_stats');
check('public stats work without logging in', ($r['ok'] ?? false));
check('public stats start at zero', ($r['totalRaised'] ?? -1) === 0 && ($r['donorCount'] ?? -1) === 0);
$keys = array_keys($r);
sort($keys);
check('public stats expose only aggregate fields', $keys === ['casesHelped', 'donorCount', 'ok', 'totalAidDisbursed', 'totalRaised']);

// --- donation_verify: gateway callback paths that never reach the gateway ---
[$c, $loc] = getRedirect('action=donation_verify');
check('verify without authority redirects to failure', $c === 302 && str_contains($loc, 'donation=failed'));
[$c, $loc] = getRedirect('action=donation_verify&Authority=NOPE&Status=OK');
check('verify with unknown authority redirects to failure', $c === 302 && str_contains($loc, 'donation=failed'));

$ins = $pdo->prepare('INSERT INTO online_donations (authority, amount, donor_name, donor_phone, description, status, ref_id, created_at) VALUES (?,?,?,?,?,?,?,?)');
$ins->execute(['A-PENDING', 50000, 'Test Donor', '09120000003', 'test', 'pending', null, gmdate('c')]);
$ins->execute(['A-PAID', 70000, 'Test Donor 2', null, 'test', 'paid', 'REF-12345', gmdate('c')]);

[$c, $loc] = getRedirect('action=donation_verify&Authority=A-PENDING&Status=NOK');
check('cancelled payment redirects to failure', $c === 302 && str_contains($loc, 'donation=failed'));
$st = $pdo->query("SELECT status FROM online_donations WHERE authority = 'A-PENDING'")->fetchColumn();
check('cancelled payment is marked failed', $st === 'failed');

[$c, $loc] = getRedirect('action=donation_verify&Authority=A-PAID&Status=OK');
check('replaying a paid callback redirects to success with the reference', $c === 302 && str_contains($loc, 'donation=success') && str_contains($loc, 'ref=REF-12345'));
check('replay does not create accounting transactions', (int) $pdo->query('SELECT COUNT(*) FROM accounting_transactions')->fetchColumn() === 0);
check('replay does not create donors', (int) $pdo->query('SELECT COUNT(*) FROM donors')->fetchColumn() === 0);

echo $fails === 0 ? "\nAll donation tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
