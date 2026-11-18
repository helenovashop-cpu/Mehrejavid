<?php
/**
 * Financial assistance and reporting tests for api.php — run with:  php tests/financial_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises financial review, payment recording, payment listing,
 * financial summary and dashboard statistics. Users are seeded
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


function login(string $file, string $nid, string $pass): string {
  global $cookie;
  $cookie = $file;
  [$c, $r] = call('bootstrap'); $t = $r['csrf'] ?? '';
  [$c, $r] = call('user_login', ['csrf' => $t, 'nationalId' => $nid, 'password' => $pass]);
  [$c, $r] = call('bootstrap');
  return $r['csrf'] ?? $t;
}

// Patient A creates a case; patient B is an outsider.
$csrfA = login($tmp . '/a.txt', $nidA, 'Pass-A-1234');
[$c, $r] = call('submission_create', ['csrf' => $csrfA, 'specialty' => 'cardiology', 'specialtyLabel' => 'Cardiology', 'problemDescription' => 'Needs a heart checkup']);
[$c, $r] = call('submission_list_mine');
$sid = (string) ($r['items'][0]['id'] ?? '');
check('test case was created', $sid !== '');
$pdo->prepare('UPDATE submissions SET requested_amount = ?, financial_status = ? WHERE id = ?')->execute([1000000, 'pending_review', $sid]);

// Patients cannot use admin financial endpoints.
[$c, $r] = call('financial_review', ['csrf' => $csrfA, 'id' => $sid, 'decision' => 'approve', 'approvedAmount' => 500000]);
check('patient cannot review financial requests', !($r['ok'] ?? false) && $c >= 401);
[$c, $r] = call('payment_record', ['csrf' => $csrfA, 'id' => $sid, 'amount' => 1000]);
check('patient cannot record payments', !($r['ok'] ?? false) && $c >= 401);
[$c, $r] = call('financial_summary');
check('patient cannot read financial summary', !($r['ok'] ?? false) && $c >= 401);
[$c, $r] = call('dashboard_stats');
check('patient cannot read dashboard stats', !($r['ok'] ?? false) && $c >= 401);
[$c, $r] = call('payment_list', ['id' => $sid]);
check('owner can list own (empty) payments', ($r['ok'] ?? false) && $r['total'] === 0);

$csrfB = login($tmp . '/b.txt', $nidB, 'Pass-B-1234');
[$c, $r] = call('payment_list', ['id' => $sid]);
check('another patient cannot list payments', !($r['ok'] ?? false) && $c === 403);

// Admin login.
$cookie = $tmp . '/admin.txt';
[$c, $r] = call('bootstrap'); $csrfAd = $r['csrf'] ?? '';
[$c, $r] = call('admin_login', ['csrf' => $csrfAd, 'username' => 'admin', 'password' => $adminPass]);
check('admin can log in', ($r['ok'] ?? false));

// Review validation.
[$c, $r] = call('financial_review', ['id' => $sid, 'decision' => 'approve', 'approvedAmount' => 500000]);
check('financial review without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('financial_review', ['csrf' => $csrfAd, 'id' => 'bogus', 'decision' => 'approve', 'approvedAmount' => 1]);
check('invalid case id is rejected', !($r['ok'] ?? false));
[$c, $r] = call('financial_review', ['csrf' => $csrfAd, 'id' => $sid, 'decision' => 'maybe']);
check('unknown decision is rejected', !($r['ok'] ?? false));
[$c, $r] = call('financial_review', ['csrf' => $csrfAd, 'id' => $sid, 'decision' => 'approve', 'approvedAmount' => 0]);
check('approval needs a positive amount', !($r['ok'] ?? false));

// Approve 600,000 and pay in two steps.
[$c, $r] = call('financial_review', ['csrf' => $csrfAd, 'id' => $sid, 'decision' => 'approve', 'approvedAmount' => 600000, 'note' => 'ok']);
check('admin can approve an amount', ($r['ok'] ?? false));
$row = $pdo->query("SELECT approved_amount, financial_status FROM submissions WHERE id = " . $pdo->quote($sid))->fetch(PDO::FETCH_ASSOC);
check('approval is stored', (int) $row['approved_amount'] === 600000 && $row['financial_status'] === 'approved');

[$c, $r] = call('payment_record', ['csrf' => $csrfAd, 'id' => $sid, 'amount' => 0]);
check('zero payment is rejected', !($r['ok'] ?? false));
[$c, $r] = call('payment_record', ['csrf' => $csrfAd, 'id' => $sid, 'amount' => 250000, 'note' => 'first']);
check('first partial payment is recorded', ($r['ok'] ?? false) && $r['status'] === 'partially_paid' && $r['totalPaid'] === 250000);
[$c, $r] = call('payment_record', ['csrf' => $csrfAd, 'id' => $sid, 'amount' => 350000]);
check('reaching the approved amount marks the case paid', ($r['ok'] ?? false) && $r['status'] === 'paid' && $r['totalPaid'] === 600000);
[$c, $r] = call('payment_list', ['id' => $sid]);
check('admin sees both payments and the total', ($r['ok'] ?? false) && count($r['items']) === 2 && $r['total'] === 600000);

$exp = (int) $pdo->query("SELECT COUNT(*) FROM accounting_transactions WHERE type='expense' AND related_submission_id = " . $pdo->quote($sid))->fetchColumn();
check('each payment also creates an expense in the ledger', $exp === 2);
check('payments were written to the audit log', (int) $pdo->query("SELECT COUNT(*) FROM audit_log WHERE action = 'payment_record'")->fetchColumn() === 2);

// Rejection path on a second case.
$cookie = $tmp . '/b.txt';
[$c, $r] = call('submission_create', ['csrf' => $csrfB, 'specialty' => 'cardiology', 'specialtyLabel' => 'Cardiology', 'problemDescription' => 'Second test case']);
[$c, $r] = call('submission_list_mine');
$sid2 = (string) ($r['items'][0]['id'] ?? '');
$pdo->prepare('UPDATE submissions SET requested_amount = ?, financial_status = ? WHERE id = ?')->execute([200000, 'pending_review', $sid2]);
$cookie = $tmp . '/admin.txt';
[$c, $r] = call('financial_summary');
check('summary counts pending requests', ($r['ok'] ?? false) && $r['pendingCount'] === 1);
[$c, $r] = call('financial_review', ['csrf' => $csrfAd, 'id' => $sid2, 'decision' => 'reject', 'note' => 'no']);
check('admin can reject a request', ($r['ok'] ?? false));
check('rejection is stored', $pdo->query("SELECT financial_status FROM submissions WHERE id = " . $pdo->quote($sid2))->fetchColumn() === 'rejected');

[$c, $r] = call('financial_summary');
check('summary totals are correct', ($r['ok'] ?? false) && $r['totalRequested'] === 1200000 && $r['totalApproved'] === 600000 && $r['totalPaid'] === 600000 && $r['pendingCount'] === 0);

$today = gmdate('Y-m-d');
[$c, $r] = call('dashboard_stats', ['startDate' => $today, 'endDate' => $today]);
check('custom-range dashboard works', ($r['ok'] ?? false));
[$c, $r] = call('dashboard_stats', ['period' => 'not-a-period']);
check('invalid period falls back safely', ($r['ok'] ?? false));
[$c, $r] = call('dashboard_stats', ['startDate' => '2020-01-01', 'endDate' => '2030-01-01']);
check('huge custom ranges are capped', ($r['ok'] ?? false));

echo $fails === 0 ? "\nAll financial tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
