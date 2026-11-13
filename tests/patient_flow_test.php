<?php
/**
 * Patient-side flow tests for api.php — run with:  php tests/patient_flow_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises the patient (user) flow: login, logout, creating a
 * request and the isolation between two patients' data. Users are seeded
 * straight into the temp SQLite file because registration needs a real SMS code. No real data and no network access are involved;
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


function makeNid(string $nine): string {
  $sum = 0;
  for ($i = 0; $i < 9; $i++) $sum += ((int) $nine[$i]) * (10 - $i);
  $rem = $sum % 11;
  return $nine . ($rem < 2 ? $rem : 11 - $rem);
}
$nidA = makeNid('123456789');
$nidB = makeNid('987654321');

[$c, $r] = call('bootstrap');
$csrf = $r['csrf'] ?? '';

// Seed two fake patients directly into the throw-away database.
$pdo = new PDO('sqlite:' . $tmp . '/data/app.sqlite');
$ins = $pdo->prepare('INSERT INTO users (national_id, name, father_name, phone, city, dob, password_hash, created_at) VALUES (?,?,?,?,?,?,?,?)');
$ins->execute([$nidA, 'Test Patient A', 'Father A', '09120000001', 'Tehran', '1370/01/01', password_hash('Pass-A-1234', PASSWORD_DEFAULT), gmdate('c')]);
$ins->execute([$nidB, 'Test Patient B', 'Father B', '09120000002', 'Shiraz', '1375/05/05', password_hash('Pass-B-1234', PASSWORD_DEFAULT), gmdate('c')]);

[$c, $r] = call('submission_list_mine');
check('submission_list_mine rejects guests (401)', $c === 401);
[$c, $r] = call('submission_create', ['csrf' => $csrf, 'specialty' => 'x', 'problemDescription' => 'y']);
check('submission_create rejects guests (401)', $c === 401);

[$c, $r] = call('user_login', ['nationalId' => $nidA, 'password' => 'Pass-A-1234']);
check('user_login without CSRF token is refused', !($r['ok'] ?? false));
[$c, $r] = call('user_login', ['csrf' => $csrf, 'nationalId' => $nidA, 'password' => 'wrong']);
check('user_login rejects a wrong password', !($r['ok'] ?? false));
[$c, $r] = call('user_login', ['csrf' => $csrf, 'nationalId' => '1234567890', 'password' => 'Pass-A-1234']);
check('user_login rejects an invalid national id', !($r['ok'] ?? false));
[$c, $r] = call('user_login', ['csrf' => $csrf, 'nationalId' => $nidA, 'password' => 'Pass-A-1234']);
check('user_login succeeds with correct credentials', ($r['ok'] ?? false) && ($r['user']['nationalId'] ?? '') === $nidA);
check('user_login response never leaks the password hash', !isset($r['user']['password_hash']) && !str_contains(json_encode($r), '$2y$'));

[$c, $r] = call('bootstrap'); $csrf = $r['csrf'] ?? $csrf;
check('bootstrap reports the patient role after login', ($r['role'] ?? '') !== 'guest');

[$c, $r] = call('submission_list_all');
check('a patient cannot list all submissions', in_array($c, [401, 403], true) && !($r['ok'] ?? false));
[$c, $r] = call('audit_log_list');
check('a patient cannot read the audit log', in_array($c, [401, 403], true));
[$c, $r] = call('admin_list');
check('a patient cannot list admins', in_array($c, [401, 403], true));

[$c, $r] = call('submission_create', ['csrf' => $csrf, 'specialty' => 'cardiology', 'problemDescription' => '']);
check('submission_create requires a problem description', !($r['ok'] ?? false));
[$c, $r] = call('submission_create', ['csrf' => $csrf, 'problemDescription' => 'chest pain']);
check('submission_create requires a specialty', !($r['ok'] ?? false));
[$c, $r] = call('submission_create', ['csrf' => $csrf, 'specialty' => 'cardiology', 'problemDescription' => 'chest pain', 'receiptAmount' => '-5']);
check('submission_create rejects a negative receipt amount', !($r['ok'] ?? false));
[$c, $r] = call('submission_create', ['csrf' => $csrf, 'specialty' => 'cardiology', 'problemDescription' => 'chest pain',
  'needsAccommodation' => '1', 'accommodationDays' => '2', 'companionPhone' => '123', 'companionNames' => '["C"]']);
check('submission_create rejects an invalid companion phone', !($r['ok'] ?? false));
[$c, $r] = call('submission_create', ['csrf' => $csrf, 'specialty' => 'cardiology', 'problemDescription' => 'chest pain', 'photoFull' => 'data:text/html;base64,PGI+']);
check('submission_create rejects a non-image ID photo', !($r['ok'] ?? false));

[$c, $r] = call('submission_create', ['csrf' => $csrf, 'specialty' => 'cardiology', 'specialtyLabel' => 'Cardiology', 'problemDescription' => 'Needs a heart checkup']);
check('submission_create succeeds for a logged-in patient', ($r['ok'] ?? false));
[$c, $r] = call('submission_list_mine');
check('patient A sees exactly their own request', ($r['ok'] ?? false) && count($r['items'] ?? []) === 1 && ($r['items'][0]['nationalId'] ?? '') === $nidA);

[$c, $r] = call('user_logout');
[$c, $r] = call('submission_list_mine');
check('after user_logout the patient is a guest again (401)', $c === 401);

// Patient B signs in on a fresh session and must not see A's request.
$cookie = $tmp . '/cookies_b.txt';
[$c, $r] = call('bootstrap'); $csrfB = $r['csrf'] ?? '';
[$c, $r] = call('user_login', ['csrf' => $csrfB, 'nationalId' => $nidB, 'password' => 'Pass-B-1234']);
check('patient B can log in', ($r['ok'] ?? false));
[$c, $r] = call('submission_list_mine');
check("patient B does not see patient A's requests", ($r['ok'] ?? false) && count($r['items'] ?? []) === 0);

// Brute-force protection is per (ip, national id): 5 bad tries lock the account out.
[$c, $r] = call('bootstrap'); $csrfB = $r['csrf'] ?? '';
$limited = false;
for ($i = 0; $i < 8; $i++) {
  [$c] = call('user_login', ['csrf' => $csrfB, 'nationalId' => $nidA, 'password' => 'bad' . $i]);
  if ($c === 429) { $limited = true; break; }
}
check('repeated failed patient logins are rate-limited (429)', $limited);

echo $fails === 0 ? "\nAll patient-flow tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
