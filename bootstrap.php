<?php
declare(strict_types=1);

$appConfig = require __DIR__ . '/config/config.php';
$GLOBALS['app_config'] = $appConfig;

error_reporting(E_ALL);
ini_set('display_errors', $appConfig['environment'] === 'development' ? '1' : '0');
ini_set('log_errors', '1');

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

require_once __DIR__ . '/src/db.php';
require_once __DIR__ . '/src/helpers.php';
require_once __DIR__ . '/src/csrf.php';
require_once __DIR__ . '/src/auth.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_name('SWDSESSID');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');

    $https = isset($_SERVER['HTTPS'])
        && $_SERVER['HTTPS'] !== ''
        && strtolower($_SERVER['HTTPS']) !== 'off';

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $https,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

enforce_idle_timeout();
