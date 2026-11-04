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
