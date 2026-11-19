<?php
/**
 * Document review and donor list tests for api.php — run with:  php tests/document_review_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises the per-document review status (admin only, validation,
 * owner notification, access control) and the admin donor list. Users are seeded
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

// Patient A creates a case; patient B stays an outsider.
$csrfA = login($tmp . '/a.txt', $nidA, 'Pass-A-1234');
[$c, $r] = call('submission_create', ['csrf' => $csrfA, 'specialty' => 'cardiology', 'specialtyLabel' => 'Cardiology', 'problemDescription' => 'Needs a heart checkup']);
[$c, $r] = call('submission_list_mine');
$sid = (string) ($r['items'][0]['id'] ?? '');
check('test case was created', $sid !== '');

// Seed two fake uploaded documents straight into the database.
$insA = $pdo->prepare('INSERT INTO submission_assets (submission_id, kind, idx, mime, name, data) VALUES (?,?,?,?,?,?)');
$insA->execute([$sid, 'doc', 0, 'image/png', 'report1.png', 'ZmFrZQ==']);
$insA->execute([$sid, 'doc', 1, 'image/png', 'report2.png', 'ZmFrZQ==']);

// Access control on the review-status list.
[$c, $r] = call('doc_status_list', ['id' => $sid]);
check('owner can list document statuses', ($r['ok'] ?? false) && count($r['items']) === 2);
check('new documents start as received', ($r['items'][0]['doc_status'] ?? '') === 'received');
[$c, $r] = call('doc_status_list', ['id' => 'bogus']);
check('invalid case id is rejected on list', !($r['ok'] ?? false));

$csrfB = login($tmp . '/b.txt', $nidB, 'Pass-B-1234');
[$c, $r] = call('doc_status_list', ['id' => $sid]);
check('another patient cannot list statuses', !($r['ok'] ?? false) && $c === 403);

// A patient cannot set review statuses.
$csrfA = login($tmp . '/a.txt', $nidA, 'Pass-A-1234');
[$c, $r] = call('doc_set_status', ['csrf' => $csrfA, 'id' => $sid, 'idx' => 0, 'status' => 'approved']);
check('a patient cannot approve documents', !($r['ok'] ?? false) && $c >= 401);

// Admin flow.
$cookie = $tmp . '/admin.txt';
[$c, $r] = call('bootstrap'); $csrfAd = $r['csrf'] ?? '';
[$c, $r] = call('admin_login', ['csrf' => $csrfAd, 'username' => 'admin', 'password' => $adminPass]);

[$c, $r] = call('doc_set_status', ['id' => $sid, 'idx' => 0, 'status' => 'approved']);
check('setting a status without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('bootstrap'); $csrfAd = $r['csrf'] ?? $csrfAd;
[$c, $r] = call('doc_set_status', ['csrf' => $csrfAd, 'id' => $sid, 'idx' => 0, 'status' => 'bogus']);
check('an unknown status is rejected', !($r['ok'] ?? false));
[$c, $r] = call('doc_set_status', ['csrf' => $csrfAd, 'id' => $sid, 'idx' => -1, 'status' => 'approved']);
check('a negative index is rejected', !($r['ok'] ?? false));
[$c, $r] = call('doc_set_status', ['csrf' => $csrfAd, 'id' => $sid, 'idx' => 9, 'status' => 'approved']);
check('a missing document returns 404', !($r['ok'] ?? false) && $c === 404);
[$c, $r] = call('doc_set_status', ['csrf' => $csrfAd, 'id' => 'bogus', 'idx' => 0, 'status' => 'approved']);
check('an invalid case id is rejected', !($r['ok'] ?? false));

[$c, $r] = call('doc_set_status', ['csrf' => $csrfAd, 'id' => $sid, 'idx' => 0, 'status' => 'approved']);
check('admin can approve a document', ($r['ok'] ?? false));
check('approval sends no correction notice', (int) $pdo->query("SELECT COUNT(*) FROM notifications WHERE type = 'doc_correction'")->fetchColumn() === 0);

[$c, $r] = call('doc_set_status', ['csrf' => $csrfAd, 'id' => $sid, 'idx' => 1, 'status' => 'needs_correction', 'note' => str_repeat('n', 700)]);
check('a review note over 500 characters is rejected', !($r['ok'] ?? false) && $c === 400);
[$c, $r] = call('doc_set_status', ['csrf' => $csrfAd, 'id' => $sid, 'idx' => 1, 'status' => 'needs_correction', 'note' => 'Photo is blurry']);
check('admin can request a correction', ($r['ok'] ?? false));
check('a correction notifies the case owner', (int) $pdo->query("SELECT COUNT(*) FROM notifications WHERE type = 'doc_correction' AND recipient_type = 'user' AND recipient_id = " . $pdo->quote($nidA))->fetchColumn() === 1);
check('the audit log records the change', (int) $pdo->query("SELECT COUNT(*) FROM audit_log WHERE action = 'doc_status_change'")->fetchColumn() === 2);

[$c, $r] = call('doc_status_list', ['id' => $sid]);
check('admin can list statuses', ($r['ok'] ?? false) && count($r['items']) === 2);
check('statuses were stored', $r['items'][0]['doc_status'] === 'approved' && $r['items'][1]['doc_status'] === 'needs_correction');
check('the review note is stored', $r['items'][1]['review_note'] === 'Photo is blurry');

// Donor list: admin only, totals from income transactions only.
$pdo->prepare('INSERT INTO donors (name, phone, donor_type, created_at) VALUES (?,?,?,?)')->execute(['Fake Donor One', '09120000003', 'individual', gmdate('c')]);
$d1 = (int) $pdo->lastInsertId();
$pdo->prepare('INSERT INTO donors (name, donor_type, created_at) VALUES (?,?,?)')->execute(['Fake Donor Two', 'company', gmdate('c')]);
$cols = array_column($pdo->query('PRAGMA table_info(accounting_transactions)')->fetchAll(PDO::FETCH_ASSOC), 'name');
$hasCols = !array_diff(['type', 'amount', 'donor_id', 'transaction_date'], $cols);
check('transactions table has the expected columns', $hasCols);
if ($hasCols) {
  $notNull = array_column(array_filter($pdo->query('PRAGMA table_info(accounting_transactions)')->fetchAll(PDO::FETCH_ASSOC), fn($c) => $c['notnull'] && $c['dflt_value'] === null && !$c['pk']), 'name');
  $base = ['type' => 'income', 'amount' => 1000, 'donor_id' => $d1, 'transaction_date' => '2026-01-01'];
  foreach ($notNull as $n) if (!isset($base[$n])) $base[$n] = ($n === 'created_at') ? gmdate('c') : 'x';
  $insT = function (array $row) use ($pdo) {
    $pdo->prepare('INSERT INTO accounting_transactions (' . implode(',', array_keys($row)) . ') VALUES (' . implode(',', array_fill(0, count($row), '?')) . ')')->execute(array_values($row));
  };
  $insT($base);
  $insT(['amount' => 500, 'transaction_date' => '2026-02-01'] + $base);
  $insT(['type' => 'expense', 'amount' => 9999] + $base);
}
[$c, $r] = call('donor_list');
check('admin can list donors', ($r['ok'] ?? false) && count($r['items']) === 2);
check('donors are ordered by total donated', ($r['items'][0]['name'] ?? '') === 'Fake Donor One');
if ($hasCols) {
  check('totals count income only', (int) $r['items'][0]['total_donated'] === 1500);
  check('donation count is correct', (int) $r['items'][0]['donation_count'] === 2);
  check('last donation date is reported', ($r['items'][0]['last_donation_date'] ?? '') === '2026-02-01');
}
check('a donor with no donations totals zero', (int) $r['items'][1]['total_donated'] === 0 && (int) $r['items'][1]['donation_count'] === 0);

$cookie = $tmp . '/a.txt';
[$c, $r] = call('donor_list');
check('a patient cannot list donors', !($r['ok'] ?? false) && $c >= 401);
$cookie = $tmp . '/anon.txt';
[$c, $r] = call('donor_list');
check('anonymous visitors cannot list donors', !($r['ok'] ?? false) && $c >= 401);

echo $fails === 0 ? "\nAll document review and donor list tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
