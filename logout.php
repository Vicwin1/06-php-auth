<?php
declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method not allowed.');
}

if (!csrf_verify()) {
    http_response_code(400);
    exit('Invalid request. Please try again.');
}

$sessionName = session_name();
$cookie = session_get_cookie_params();

$_SESSION = [];
session_destroy();
setcookie($sessionName, '', [
    'expires' => time() - 42000,
    'path' => $cookie['path'],
    'domain' => $cookie['domain'],
    'secure' => $cookie['secure'],
    'httponly' => $cookie['httponly'],
    'samesite' => $cookie['samesite'] ?? 'Lax',
]);
unset($_COOKIE[$sessionName]);

session_id('');
session_start();
flash('success', 'You have been signed out.');

redirect('login.php');
