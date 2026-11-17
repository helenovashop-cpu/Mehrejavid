<?php
/**
 * Satisfaction survey tests for api.php — run with:  php tests/survey_test.php
 *
 * Copies api.php into a throw-away temp directory, starts PHP's built-in web
 * server there and exercises the satisfaction survey (only after a final case outcome,
 * only by the case owner, rating validation, admin statistics). Users are seeded
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

// Survey is locked until the case has a final outcome.
[$c, $r] = call('survey_submit', ['csrf' => $csrfA, 'id' => $sid, 'rating' => 5]);
check('survey is refused while the case is still open', !($r['ok'] ?? false));
[$c, $r] = call('survey_status', ['id' => $sid]);
check('status shows nothing submitted yet', ($r['ok'] ?? false) && $r['submitted'] === false);

// Move the case to a final outcome (seeded directly; the admin flow is covered elsewhere).
$pdo->prepare('UPDATE submissions SET status = ? WHERE id = ?')->execute(['final_review', $sid]);

[$c, $r] = call('survey_submit', ['id' => $sid, 'rating' => 5]);
check('survey without CSRF is refused', !($r['ok'] ?? false));
foreach ([0, 6, -1] as $bad) {
  [$c, $r] = call('survey_submit', ['csrf' => $csrfA, 'id' => $sid, 'rating' => $bad]);
  check("rating $bad is rejected", !($r['ok'] ?? false));
}
[$c, $r] = call('survey_submit', ['csrf' => $csrfA, 'id' => 'bogus', 'rating' => 4]);
check('invalid case id is rejected', !($r['ok'] ?? false));

[$c, $r] = call('survey_submit', ['csrf' => $csrfA, 'id' => $sid, 'rating' => 4, 'comment' => str_repeat('x', 1500)]);
check('owner can submit a rating', ($r['ok'] ?? false));
[$c, $r] = call('survey_status', ['id' => $sid]);
check('status reports the submitted rating', ($r['submitted'] ?? false) === true && (int) $r['rating'] === 4);
check('long comments are truncated to 1000 characters', mb_strlen((string) $r['comment']) === 1000);

[$c, $r] = call('survey_submit', ['csrf' => $csrfA, 'id' => $sid, 'rating' => 2, 'comment' => 'Changed my mind']);
check('resubmitting updates instead of duplicating', ($r['ok'] ?? false));
[$c, $r] = call('survey_status', ['id' => $sid]);
check('updated rating is stored', (int) $r['rating'] === 2 && $r['comment'] === 'Changed my mind');
check('only one survey row exists', (int) $pdo->query('SELECT COUNT(*) FROM satisfaction_surveys')->fetchColumn() === 1);

// Another patient cannot read or write this case's survey.
$csrfB = login($tmp . '/b.txt', $nidB, 'Pass-B-1234');
[$c, $r] = call('survey_submit', ['csrf' => $csrfB, 'id' => $sid, 'rating' => 1]);
check('another patient cannot submit', !($r['ok'] ?? false) && $c === 403);
[$c, $r] = call('survey_status', ['id' => $sid]);
check('another patient cannot read the status', !($r['ok'] ?? false) && $c === 403);
[$c, $r] = call('survey_stats');
check('a patient cannot read survey stats', !($r['ok'] ?? false) && $c >= 401);

// Rejected cases may also be rated; add a second response for the stats.
[$c, $r] = call('submission_create', ['csrf' => $csrfB, 'specialty' => 'cardiology', 'specialtyLabel' => 'Cardiology', 'problemDescription' => 'Second test case']);
[$c, $r] = call('submission_list_mine');
$sidB = (string) ($r['items'][0]['id'] ?? '');
$pdo->prepare('UPDATE submissions SET status = ? WHERE id = ?')->execute(['rejected', $sidB]);
[$c, $r] = call('survey_submit', ['csrf' => $csrfB, 'id' => $sidB, 'rating' => 5, 'comment' => 'Thanks']);
check('a rejected case can be rated too', ($r['ok'] ?? false));

// Admin statistics.
$cookie = $tmp . '/admin.txt';
[$c, $r] = call('bootstrap'); $csrfAd = $r['csrf'] ?? '';
[$c, $r] = call('admin_login', ['csrf' => $csrfAd, 'username' => 'admin', 'password' => $adminPass]);
[$c, $r] = call('survey_status', ['id' => $sid]);
check('admin can read any survey status', ($r['ok'] ?? false) && $r['submitted'] === true);
[$c, $r] = call('survey_stats');
check('admin sees the response count', ($r['ok'] ?? false) && $r['count'] === 2);
check('admin sees the average rating', abs((float) $r['average'] - 3.5) < 0.001);
check('admin sees the rating distribution', ($r['distribution'][2] ?? 0) === 1 && ($r['distribution'][5] ?? 0) === 1);
check('admin sees recent comments', count($r['recentComments'] ?? []) === 2);

echo $fails === 0 ? "\nAll survey tests passed.\n" : "\n$fails test(s) FAILED.\n";
exit($fails === 0 ? 0 : 1);
