<?php
/**
 * Admin two-factor (TOTP) tests for api.php — run with:  php tests/two_factor_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises the admin 2FA flow: setup start/confirm, the two-step login, wrong or
 * malformed codes, clock-drift tolerance, disabling with the password and the TOTP
 * attempt rate limit. Codes come from an independent RFC 6238 implementation. No real
 * data and no network access are involved; the repository's own data/ directory is never touched.
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


/** Independent RFC 6238 (SHA-1, 6 digits, 30 s) implementation used to produce valid codes. */
function b32decode(string $s): string {
  $a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $bits = '';
  foreach (str_split(strtoupper($s)) as $ch) $bits .= str_pad(decbin((int) strpos($a, $ch)), 5, '0', STR_PAD_LEFT);
  $out = '';
  foreach (str_split($bits, 8) as $b) { if (strlen($b) === 8) $out .= chr(bindec($b)); }
  return $out;
}
function totp(string $secret, int $step): string {
  $h = hash_hmac('sha1', pack('J', $step), b32decode($secret), true);
  $o = ord($h[19]) & 0x0F;
  $n = ((ord($h[$o]) & 0x7F) << 24) | (ord($h[$o + 1]) << 16) | (ord($h[$o + 2]) << 8) | ord($h[$o + 3]);
  return str_pad((string) ($n % 1000000), 6, '0', STR_PAD_LEFT);
}
function nowStep(): int { return intdiv(time(), 30); }
function freshSession(string $name): string {
  global $tmp, $cookie;
  $cookie = $tmp . '/' . $name . '.txt';
  [$c, $r] = call('bootstrap');
  return $r['csrf'] ?? '';
}
/** A code that is valid in none of the accepted steps (now-1, now, now+1). */
function badCode(string $secret): string {
  $ok = [totp($secret, nowStep() - 1), totp($secret, nowStep()), totp($secret, nowStep() + 1)];
  for ($i = 0; $i < 1000; $i++) {
    $c = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    if (!in_array($c, $ok, true)) return $c;
  }
  return '000000';
}

// RFC 6238 appendix B test vector (secret "12345678901234567890", T=59s -> ...287082).
check('test TOTP generator matches the RFC 6238 vector', totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', intdiv(59, 30)) === '287082');

// --- guests cannot touch 2FA endpoints -------------------------------------
$csrf = freshSession('guest');
[$c, $r] = call('admin_2fa_status');
check('guest cannot read 2FA status', !($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_setup_start', ['csrf' => $csrf]);
check('guest cannot start 2FA setup', !($r['ok'] ?? false));
[$c, $r] = call('admin_login_totp_verify', ['csrf' => $csrf, 'code' => '123456']);
check('totp verify without a pending login is refused (401)', $c === 401 && !($r['ok'] ?? false));

// --- admin enables 2FA --------------------------------------------------------
$csrf = freshSession('admin1');
[$c, $r] = call('admin_login', ['csrf' => $csrf, 'username' => 'admin', 'password' => $adminPass]);
check('admin logs in with the password only while 2FA is off', ($r['ok'] ?? false) && empty($r['needsTotp']));
[$c, $r] = call('bootstrap'); $csrf = $r['csrf'] ?? $csrf;
[$c, $r] = call('admin_2fa_status');
check('2FA status is initially disabled', ($r['ok'] ?? false) && $r['enabled'] === false);

[$c, $r] = call('admin_2fa_setup_start');
check('setup start without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_setup_confirm', ['csrf' => $csrf, 'code' => '123456']);
check('confirm before start is refused', !($r['ok'] ?? false));

[$c, $r] = call('admin_2fa_setup_start', ['csrf' => $csrf]);
$secret = (string) ($r['secret'] ?? '');
check('setup start returns a 32-char base32 secret', ($r['ok'] ?? false) && preg_match('/^[A-Z2-7]{32}$/', $secret) === 1);
$uri = (string) ($r['otpauthUri'] ?? '');
check('setup start returns an otpauth URI carrying the secret', str_starts_with($uri, 'otpauth://totp/') && str_contains($uri, "secret=$secret") && str_contains($uri, 'digits=6') && str_contains($uri, 'period=30'));
[$c, $r] = call('admin_2fa_status');
check('secret is not active until confirmed', $r['enabled'] === false);

[$c, $r] = call('admin_2fa_setup_confirm', ['csrf' => $csrf, 'code' => badCode($secret)]);
check('confirm with a wrong code is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_setup_confirm', ['csrf' => $csrf, 'code' => '12345']);
check('confirm with a too-short code is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_setup_confirm', ['csrf' => $csrf, 'code' => totp($secret, nowStep())]);
check('confirm with the right code enables 2FA', ($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_status');
check('2FA status is now enabled', $r['enabled'] === true);

$pdo = new PDO('sqlite:' . $tmp . '/data/app.sqlite');
check('enabling 2FA is written to the audit log', (int) $pdo->query("SELECT COUNT(*) FROM audit_log WHERE action = '2fa_enabled'")->fetchColumn() === 1);
[$c, $r] = call('admin_2fa_setup_confirm', ['csrf' => $csrf, 'code' => totp($secret, nowStep())]);
check('the pending secret cannot be confirmed a second time', !($r['ok'] ?? false));

// --- two-step login ------------------------------------------------------------
$csrf = freshSession('admin2');
[$c, $r] = call('admin_login', ['csrf' => $csrf, 'username' => 'admin', 'password' => $adminPass]);
check('password step now asks for a TOTP code', ($r['ok'] ?? false) && ($r['needsTotp'] ?? false) === true);
[$c, $r] = call('admin_2fa_status');
check('no admin session exists after the password step alone', !($r['ok'] ?? false));

[$c, $r] = call('admin_login_totp_verify', ['code' => totp($secret, nowStep())]);
check('totp verify without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_login_totp_verify', ['csrf' => $csrf, 'code' => badCode($secret)]);
check('wrong TOTP code is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_login_totp_verify', ['csrf' => $csrf, 'code' => 'abcdef']);
check('non-numeric TOTP code is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_status');
check('still no admin session after failed codes', !($r['ok'] ?? false));

// Previous time step is accepted (±30 s clock-drift tolerance); two steps back is not.
[$c, $r] = call('admin_login_totp_verify', ['csrf' => $csrf, 'code' => totp($secret, nowStep() - 3)]);
check('a code from three steps ago is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_login_totp_verify', ['csrf' => $csrf, 'code' => totp($secret, nowStep() - 1)]);
check('a code from the previous step is accepted (clock drift)', ($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_status');
check('admin session exists after the TOTP step', ($r['ok'] ?? false) && $r['enabled'] === true);
[$c, $r] = call('admin_login_totp_verify', ['csrf' => $csrf, 'code' => totp($secret, nowStep())]);
check('the pending login is consumed (no second verify)', $c === 401 && !($r['ok'] ?? false));

// --- disabling 2FA ---------------------------------------------------------------
[$c, $r] = call('bootstrap'); $csrf = $r['csrf'] ?? $csrf;
[$c, $r] = call('admin_2fa_disable', ['password' => $adminPass]);
check('disable without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_disable', ['csrf' => $csrf, 'password' => 'definitely-wrong']);
check('disable with a wrong password is refused', !($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_status');
check('2FA is still enabled after a failed disable', $r['enabled'] === true);
[$c, $r] = call('admin_2fa_disable', ['csrf' => $csrf, 'password' => $adminPass]);
check('disable with the right password works', ($r['ok'] ?? false));
[$c, $r] = call('admin_2fa_status');
check('2FA status is disabled again', $r['enabled'] === false);
check('disabling 2FA is written to the audit log', (int) $pdo->query("SELECT COUNT(*) FROM audit_log WHERE action = '2fa_disabled'")->fetchColumn() === 1);
check('the stored secret is wiped', $pdo->query("SELECT totp_secret FROM admins WHERE username = 'admin'")->fetchColumn() === null);

// --- TOTP attempt rate limit --------------------------------------------------------
// Re-enable 2FA directly in the database, park a pending login, then hammer the verify step.
$pdo->prepare("UPDATE admins SET totp_secret = ?, totp_enabled = 1 WHERE username = 'admin'")->execute([$secret]);
$csrf = freshSession('admin3');
[$c, $r] = call('admin_login', ['csrf' => $csrf, 'username' => 'admin', 'password' => $adminPass]);
check('2FA login is pending again', ($r['needsTotp'] ?? false) === true);
$limited = false;
for ($i = 0; $i < 12; $i++) {
  [$c, $r] = call('admin_login_totp_verify', ['csrf' => $csrf, 'code' => badCode($secret)]);
  if ($c === 429) { $limited = true; break; }
}
check('repeated wrong TOTP codes are rate-limited (429)', $limited);
[$c, $r] = call('admin_login_totp_verify', ['csrf' => $csrf, 'code' => totp($secret, nowStep())]);
check('even a correct code is refused while rate-limited', $c === 429 && !($r['ok'] ?? false));

echo $fails === 0 ? "\nAll 2FA tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
