<?php
/**
 * Messaging & notification tests for api.php — run with:  php tests/messaging_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises the per-case message thread and the notification feed
 * (patient <-> admin, and isolation between two patients). Users are seeded
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

// Patient A creates a case.
$csrfA = login($tmp . '/a.txt', $nidA, 'Pass-A-1234');
[$c, $r] = call('submission_create', ['csrf' => $csrfA, 'specialty' => 'cardiology', 'specialtyLabel' => 'Cardiology', 'problemDescription' => 'Needs a heart checkup']);
[$c, $r] = call('submission_list_mine');
$sid = (string) ($r['items'][0]['id'] ?? '');
check('test case was created', $sid !== '');

[$c, $r] = call('message_send', ['id' => $sid, 'body' => 'hello']);
check('message_send without CSRF is refused', !($r['ok'] ?? false));
[$c, $r] = call('message_send', ['csrf' => $csrfA, 'id' => $sid, 'body' => '   ']);
check('message_send rejects an empty body', !($r['ok'] ?? false));
[$c, $r] = call('message_send', ['csrf' => $csrfA, 'id' => 'not-a-valid-id', 'body' => 'hi']);
check('message_send rejects an invalid case id', !($r['ok'] ?? false));
[$c, $r] = call('message_send', ['csrf' => $csrfA, 'id' => $sid, 'body' => 'Hello from patient A']);
check('patient A can send a message on their own case', ($r['ok'] ?? false));
[$c, $r] = call('message_list', ['id' => $sid]);
check('patient A sees their message in the thread', ($r['ok'] ?? false) && count($r['items'] ?? []) === 1 && ($r['items'][0]['sender_role'] ?? '') === 'user');

// Patient B must not read or write A's thread.
$csrfB = login($tmp . '/b.txt', $nidB, 'Pass-B-1234');
[$c, $r] = call('message_list', ['id' => $sid]);
check("patient B cannot read patient A's thread (403)", $c === 403);
[$c, $r] = call('message_send', ['csrf' => $csrfB, 'id' => $sid, 'body' => 'intruder']);
check("patient B cannot post to patient A's thread (403)", $c === 403);

// Guests are refused.
$cookie = $tmp . '/guest.txt';
[$c, $r] = call('bootstrap'); $csrfG = $r['csrf'] ?? '';
[$c, $r] = call('message_list', ['id' => $sid]);
check('a guest cannot read a thread (403)', $c === 403);
[$c, $r] = call('notification_list');
check('a guest cannot read notifications (401)', $c === 401);
[$c, $r] = call('notification_mark_read', ['csrf' => $csrfG, 'id' => 'all']);
check('a guest cannot mark notifications read (401)', $c === 401);

// Admin sees the notification, replies, and the patient gets notified.
$cookie = $tmp . '/admin.txt';
[$c, $r] = call('bootstrap'); $csrfAd = $r['csrf'] ?? '';
[$c, $r] = call('admin_login', ['csrf' => $csrfAd, 'username' => 'admin', 'password' => $adminPass]);
[$c, $r] = call('bootstrap'); $csrfAd = $r['csrf'] ?? $csrfAd;
[$c, $r] = call('notification_list');
check('admin has an unread notification about the patient message', ($r['ok'] ?? false) && ($r['unread'] ?? 0) >= 1);
[$c, $r] = call('message_list', ['id' => $sid]);
check('admin can read the thread', ($r['ok'] ?? false) && count($r['items'] ?? []) === 1);
[$c, $r] = call('message_send', ['csrf' => $csrfAd, 'id' => $sid, 'body' => 'Reply from admin']);
check('admin can reply on the case', ($r['ok'] ?? false));
[$c, $r] = call('notification_mark_read', ['csrf' => $csrfAd, 'id' => 'all']);
[$c, $r] = call('notification_list');
check('admin mark-all-read clears the unread count', ($r['ok'] ?? false) && ($r['unread'] ?? -1) === 0);

// Patient A sees the reply and a notification; B sees none.
$cookie = $tmp . '/a.txt';
[$c, $r] = call('notification_list');
check('patient A got a notification for the admin reply', ($r['ok'] ?? false) && ($r['unread'] ?? 0) === 1);
$nid1 = (int) ($r['items'][0]['id'] ?? 0);
[$c, $r] = call('message_list', ['id' => $sid]);
check('patient A sees both messages in order', count($r['items'] ?? []) === 2 && ($r['items'][1]['sender_role'] ?? '') === 'admin');
[$c, $r] = call('notification_mark_read', ['csrf' => $csrfA, 'id' => (string) $nid1]);
[$c, $r] = call('notification_list');
check('patient A marking one notification read drops unread to 0', ($r['unread'] ?? -1) === 0);

$cookie = $tmp . '/b.txt';
[$c, $r] = call('notification_list');
check("patient B sees none of A's notifications", ($r['ok'] ?? false) && count($r['items'] ?? []) === 0);
[$c, $r] = call('notification_mark_read', ['csrf' => $csrfB, 'id' => (string) $nid1]);
$cookie = $tmp . '/a.txt';
[$c, $r] = call('notification_list');
check("patient B cannot alter A's notifications", ($r['items'][0]['read_at'] ?? null) !== null && count($r['items']) === 1);

echo $fails === 0 ? "\nAll messaging tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
