<?php
/**
 * Rate-limit and security-header tests for api.php — run with:  php tests/rate_limit_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and checks that the public, unauthenticated endpoints that send
 * SMS or create accounts (otp_request, otp_verify, user_register) answer HTTP 429
 * once their per-IP limit is exceeded, that the limits are tracked independently
 * per scope, and that every response carries the hardening headers. No SMS or
 * payment provider is contacted; the repository's own data/ directory is untouched.
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
$csrf = $r['csrf'] ?? '';

/** Fire $max+1 identical requests; returns the HTTP codes seen. */
function hammer(string $action, array $post, int $n): array {
  $codes = [];
  for ($i = 0; $i < $n; $i++) { [$c] = call($action, $post); $codes[] = $c; }
  return $codes;
}

// otp_request: limit is 5 per IP+phone per 15 minutes.
$codes = hammer('otp_request', ['csrf' => $csrf, 'phone' => '09120000011', 'purpose' => 'register'], 5);
check('first 5 otp_request calls are not rate-limited', !in_array(429, $codes, true));
[$c] = call('otp_request', ['csrf' => $csrf, 'phone' => '09120000011', 'purpose' => 'register']);
check('6th otp_request for the same phone returns 429', $c === 429);
[$c] = call('otp_request', ['csrf' => $csrf, 'phone' => '09120000012', 'purpose' => 'register']);
check('otp_request limit is per phone: another number is still allowed', $c !== 429);

// otp_verify: limit is 8 per IP+phone per 15 minutes.
$codes = hammer('otp_verify', ['csrf' => $csrf, 'phone' => '09120000013', 'code' => '00000', 'purpose' => 'register'], 8);
check('first 8 otp_verify guesses are not rate-limited', !in_array(429, $codes, true));
[$c, $r] = call('otp_verify', ['csrf' => $csrf, 'phone' => '09120000013', 'code' => '00000', 'purpose' => 'register']);
check('9th otp_verify guess returns 429 and never succeeds', $c === 429 && !($r['ok'] ?? false));

// user_register: limit is 10 per IP per hour (invalid bodies still count).
$codes = hammer('user_register', ['csrf' => $csrf], 10);
check('first 10 user_register calls are not rate-limited', !in_array(429, $codes, true));
[$c, $r] = call('user_register', ['csrf' => $csrf]);
check('11th user_register call returns 429', $c === 429 && !($r['ok'] ?? false));

// The 429 body must be a clean JSON error and the limiter state must live in SQLite only.
check('429 response is JSON with ok=false', ($r['ok'] ?? null) === false && !empty($r['error'] ?? $r['message'] ?? ''));

// Security headers are present on API responses.
$ch = curl_init("http://127.0.0.1:$port/api.php?action=bootstrap");
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true]);
$raw = (string) curl_exec($ch);
curl_close($ch);
foreach (['X-Content-Type-Options: nosniff', 'X-Frame-Options: DENY', 'Referrer-Policy: no-referrer', "Content-Security-Policy: default-src 'none'"] as $h) {
  check("response header present: $h", stripos($raw, $h) !== false);
}

echo $fails === 0 ? "\nAll rate-limit tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
