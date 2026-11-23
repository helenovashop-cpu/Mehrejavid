<?php
/**
 * Registration and OTP tests for api.php — run with:  php tests/registration_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises otp_request/otp_verify validation, the verified-phone
 * requirement of user_register, field validation, duplicate prevention, password hashing,
 * the patient financial request (submission_submit_receipt) and admin profile edits
 * (submission_update). OTP codes are seeded straight into the temp SQLite file because
 * the SMS gateway is not reachable. No real data is involved; the repository's data/
 * directory is never touched.
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


$pdo = new PDO('sqlite:' . $tmp . '/data/app.sqlite');
$phone = '09120000077';
$nid = makeNid('555666777');
$base = ['name' => 'Test New', 'fatherName' => 'Father', 'nationalId' => $nid, 'phone' => $phone, 'city' => 'Tehran', 'dob' => '1380/01/01', 'password' => 'Pass-New-1234'];

// -- otp_request validation (no SMS provider is configured in tests) --------
[$c, $r] = call('otp_request', ['phone' => $phone, 'purpose' => 'register']);
check('otp_request without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('bootstrap'); $csrf = $r['csrf'] ?? '';
[$c, $r] = call('otp_request', ['csrf' => $csrf, 'phone' => '123', 'purpose' => 'register']);
check('otp_request rejects an invalid phone', !($r['ok'] ?? false));
[$c, $r] = call('otp_request', ['csrf' => $csrf, 'phone' => $phone, 'purpose' => 'hack']);
check('otp_request rejects an unknown purpose', !($r['ok'] ?? false));
[$c, $r] = call('otp_request', ['csrf' => $csrf, 'phone' => '09120000088', 'purpose' => 'login']);
check('otp_request(login) does not reveal unregistered phones as a server error', !($r['ok'] ?? false) && $c < 500);

// -- registration requires a verified phone ---------------------------------
[$c, $r] = call('user_register', $base);
check('user_register without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('user_register', ['csrf' => $csrf] + $base);
check('user_register refuses an unverified phone', !($r['ok'] ?? false));

// Seed a known OTP directly (the SMS gateway is not reachable in tests).
function seedOtp(PDO $pdo, string $phone, string $code, int $ttl = 120): void {
  $pdo->prepare('DELETE FROM otp_codes WHERE phone = ?')->execute([$phone]);
  $pdo->prepare('INSERT INTO otp_codes (phone, purpose, code, expires_at, created_at) VALUES (?,?,?,?,?)')
    ->execute([$phone, 'register', $code, time() + $ttl, gmdate('c')]);
}
seedOtp($pdo, $phone, '12345', -10);
[$c, $r] = call('otp_verify', ['csrf' => $csrf, 'phone' => $phone, 'code' => '12345', 'purpose' => 'register']);
check('an expired OTP is rejected', !($r['ok'] ?? false));
seedOtp($pdo, $phone, '12345');
[$c, $r] = call('otp_verify', ['csrf' => $csrf, 'phone' => $phone, 'code' => '00000', 'purpose' => 'register']);
check('a wrong OTP is rejected', !($r['ok'] ?? false));
[$c, $r] = call('user_register', ['csrf' => $csrf] + $base);
check('a failed OTP does not unlock registration', !($r['ok'] ?? false));
[$c, $r] = call('otp_verify', ['csrf' => $csrf, 'phone' => $phone, 'code' => '12345', 'purpose' => 'register']);
check('the correct OTP verifies the phone', ($r['ok'] ?? false));
[$c, $r] = call('otp_verify', ['csrf' => $csrf, 'phone' => $phone, 'code' => '12345', 'purpose' => 'register']);
check('an OTP cannot be reused', !($r['ok'] ?? false));

// -- field validation (phone stays verified for the session) ----------------
[$c, $r] = call('user_register', ['csrf' => $csrf, 'nationalId' => '1234567890'] + $base);
check('user_register rejects an invalid national id', !($r['ok'] ?? false));
[$c, $r] = call('user_register', ['csrf' => $csrf, 'password' => '123'] + $base);
check('user_register rejects a too-short password', !($r['ok'] ?? false));
[$c, $r] = call('user_register', ['csrf' => $csrf, 'name' => ''] + $base);
check('user_register requires a name', !($r['ok'] ?? false));
[$c, $r] = call('user_register', ['csrf' => $csrf, 'referrerPhone' => 'abc'] + $base);
check('user_register rejects an invalid referrer phone', !($r['ok'] ?? false));
[$c, $r] = call('user_register', ['csrf' => $csrf, 'phone' => '09120000099'] + $base);
check('user_register rejects a phone different from the verified one', !($r['ok'] ?? false));

[$c, $r] = call('user_register', ['csrf' => $csrf] + $base);
check('user_register succeeds after phone verification', ($r['ok'] ?? false) && ($r['user']['nationalId'] ?? '') === $nid);
check('user_register response never leaks the password', !str_contains(json_encode($r), 'Pass-New-1234') && !str_contains(json_encode($r), '$2y$'));
$hash = (string) $pdo->query('SELECT password_hash FROM users WHERE national_id = ' . $pdo->quote($nid))->fetchColumn();
check('the password is stored hashed', $hash !== '' && $hash !== 'Pass-New-1234' && password_verify('Pass-New-1234', $hash));
[$c, $r] = call('bootstrap'); $csrf = $r['csrf'] ?? $csrf;
check('the new patient is logged in after registering', ($r['role'] ?? '') !== 'guest');

// A second registration with the same national id must fail, even with a fresh OTP.
$cookie = $tmp . '/second.txt';
[$c, $r] = call('bootstrap'); $csrf2 = $r['csrf'] ?? '';
seedOtp($pdo, $phone, '54321');
call('otp_verify', ['csrf' => $csrf2, 'phone' => $phone, 'code' => '54321', 'purpose' => 'register']);
[$c, $r] = call('user_register', ['csrf' => $csrf2] + $base);
check('a duplicate national id cannot register twice', !($r['ok'] ?? false));
[$c, $r] = call('otp_request', ['csrf' => $csrf2, 'phone' => $phone, 'purpose' => 'register']);
check('otp_request(register) refuses an already registered phone', !($r['ok'] ?? false) && $c < 500);

// -- financial request submitted by the owner -------------------------------
$cookie = $tmp . '/owner.txt';
$pdo->prepare('INSERT INTO users (national_id, name, father_name, phone, city, dob, password_hash, created_at) VALUES (?,?,?,?,?,?,?,?)')
  ->execute([makeNid('111222333'), 'Other', 'F', '09120000055', 'Shiraz', '1375/05/05', password_hash('Pass-O-1234', PASSWORD_DEFAULT), gmdate('c')]);
[$c, $r] = call('bootstrap'); $t = $r['csrf'] ?? '';
call('user_login', ['csrf' => $t, 'nationalId' => $nid, 'password' => 'Pass-New-1234']);
[$c, $r] = call('bootstrap'); $csrfO = $r['csrf'] ?? '';
call('submission_create', ['csrf' => $csrfO, 'specialty' => 'cardiology', 'specialtyLabel' => 'Cardiology', 'problemDescription' => 'Needs a heart checkup']);
[$c, $r] = call('submission_list_mine');
$sid = (string) ($r['items'][0]['id'] ?? '');
check('test case was created', $sid !== '');

[$c, $r] = call('submission_submit_receipt', ['csrf' => $csrfO, 'id' => $sid, 'amount' => 0]);
check('financial request needs a positive amount', !($r['ok'] ?? false));
[$c, $r] = call('submission_submit_receipt', ['csrf' => $csrfO, 'id' => $sid, 'amount' => 750000, 'note' => 'medication']);
check('owner can submit a financial request', ($r['ok'] ?? false));
$row = $pdo->query('SELECT requested_amount, financial_status FROM submissions WHERE id = ' . $pdo->quote($sid))->fetch(PDO::FETCH_ASSOC);
check('financial request is stored as pending review', (int) $row['requested_amount'] === 750000 && $row['financial_status'] === 'pending_review');
$n = (int) $pdo->query("SELECT COUNT(*) FROM notifications WHERE submission_id = " . $pdo->quote($sid) . " AND type = 'financial_request'")->fetchColumn();
check('admins are notified of the financial request', $n === 1);

// Another patient cannot touch it.
$cookie = $tmp . '/other.txt';
[$c, $r] = call('bootstrap'); $t = $r['csrf'] ?? '';
call('user_login', ['csrf' => $t, 'nationalId' => makeNid('111222333'), 'password' => 'Pass-O-1234']);
[$c, $r] = call('bootstrap'); $csrfX = $r['csrf'] ?? '';
[$c, $r] = call('submission_submit_receipt', ['csrf' => $csrfX, 'id' => $sid, 'amount' => 1]);
check("another patient cannot submit a financial request on someone else's case", !($r['ok'] ?? false) && $c === 403);
[$c, $r] = call('submission_update', ['csrf' => $csrfX, 'id' => $sid, 'name' => 'Hacked']);
check('a patient cannot use submission_update', !($r['ok'] ?? false) && $c >= 401);

// -- admin edits the profile -------------------------------------------------
$cookie = $tmp . '/admin.txt';
[$c, $r] = call('bootstrap'); $csrfAd = $r['csrf'] ?? '';
call('admin_login', ['csrf' => $csrfAd, 'username' => 'admin', 'password' => $adminPass]);
[$c, $r] = call('submission_update', ['id' => $sid, 'name' => 'Edited']);
check('submission_update without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('submission_update', ['csrf' => $csrfAd, 'id' => 'bogus', 'name' => 'Edited']);
check('submission_update rejects an invalid id', !($r['ok'] ?? false));
[$c, $r] = call('submission_update', ['csrf' => $csrfAd, 'id' => $sid, 'name' => '']);
check('submission_update requires a name', !($r['ok'] ?? false));
[$c, $r] = call('submission_update', ['csrf' => $csrfAd, 'id' => $sid, 'name' => 'Edited Name', 'city' => 'Mashhad', 'problemDescription' => 'Updated']);
check('admin can edit a beneficiary profile', ($r['ok'] ?? false));
$row = $pdo->query('SELECT name, city, problem_description FROM submissions WHERE id = ' . $pdo->quote($sid))->fetch(PDO::FETCH_ASSOC);
check('the profile edit is stored', $row['name'] === 'Edited Name' && $row['city'] === 'Mashhad' && $row['problem_description'] === 'Updated');
$n = (int) $pdo->query("SELECT COUNT(*) FROM submission_timeline WHERE submission_id = " . $pdo->quote($sid) . " AND status = 'profile_edit'")->fetchColumn();
check('the edit is recorded on the timeline', $n === 1);

echo $fails === 0 ? "\nAll registration tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
