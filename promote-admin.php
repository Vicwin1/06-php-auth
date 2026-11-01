<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$email = $argv[1] ?? null;
if ($argc !== 2 || !is_string($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Usage: php promote-admin.php email@example.com\n");
    exit(2);
}

$GLOBALS['app_config'] = require __DIR__ . '/config/config.php';
require_once __DIR__ . '/src/db.php';

$email = strtolower(trim($email));
$connection = db();
$statement = $connection->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
$statement->execute(['email' => $email]);
$user = $statement->fetch();

if ($user === false) {
    fwrite(STDERR, "No user found with that email address.\n");
    exit(1);
}

$statement = $connection->prepare('UPDATE users SET role = :role WHERE id = :id');
$statement->execute([
    'role' => 'admin',
    'id' => $user['id'],
]);

fwrite(STDOUT, "Administrator role granted to {$email}.\n");
