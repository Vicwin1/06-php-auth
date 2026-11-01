<?php
declare(strict_types=1);

/**
 * @return array{id: int, role: string}|null
 */
function current_user(): ?array
{
    static $resolved = false;
    static $resolvedUser = null;

    if ($resolved) {
        return $resolvedUser;
    }

    $resolved = true;
    $id = $_SESSION['user_id'] ?? null;
    if (!is_int($id)) {
        return null;
    }

    $statement = db()->prepare('SELECT role FROM users WHERE id = :id LIMIT 1');
    $statement->execute(['id' => $id]);
    $role = $statement->fetchColumn();

    if (!is_string($role)) {
        unset(
            $_SESSION['user_id'],
            $_SESSION['user_name'],
            $_SESSION['user_role'],
            $_SESSION['last_activity']
        );
        return null;
    }

    $_SESSION['user_role'] = $role;
    $resolvedUser = ['id' => $id, 'role' => $role];

    return $resolvedUser;
}

function local_return_url(mixed $url): ?string
{
    if (
        !is_string($url)
        || $url === ''
        || $url[0] !== '/'
        || str_starts_with($url, '//')
        || str_contains($url, '\\')
    ) {
        return null;
    }

    $decodedUrl = rawurldecode($url);
    if (
        preg_match('/[\x00-\x1F\x7F]/', $url) === 1
        || str_contains($decodedUrl, '\\')
        || preg_match('/[\x00-\x1F\x7F]/', $decodedUrl) === 1
        || str_starts_with($decodedUrl, '//')
    ) {
        return null;
    }

    $parts = parse_url($url);
    if (
        $parts === false
        || isset($parts['scheme'])
        || isset($parts['host'])
        || isset($parts['user'])
        || isset($parts['pass'])
        || isset($parts['fragment'])
        || !isset($parts['path'])
        || !str_starts_with($parts['path'], '/')
        || str_starts_with($parts['path'], '//')
    ) {
        return null;
    }

    return $parts['path'] . (isset($parts['query']) ? '?' . $parts['query'] : '');
}

function intended_url(): ?string
{
    $url = local_return_url($_SESSION['_intended_url'] ?? null);
    unset($_SESSION['_intended_url']);

    return $url;
}

function require_login(): void
{
    if (current_user() !== null) {
        return;
    }

    $requestUri = local_return_url($_SERVER['REQUEST_URI'] ?? null);
    if ($requestUri !== null) {
        $_SESSION['_intended_url'] = $requestUri;
    }

    redirect(app_url('login.php'));
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role): void
{
    require_login();

    if (current_user()['role'] !== $role) {
        http_response_code(403);
        $roleLabel = e($role);
        $stylesheet = e(app_url('assets/auth.css'));
        $dashboardUrl = e(app_url('dashboard.php'));
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>Access denied</title><link rel="stylesheet" href="' . $stylesheet . '">'
            . '</head><body><main class="auth-page"><section class="auth-card">'
            . '<header class="auth-header"><h1>Access denied</h1>'
            . '<p>You do not have permission to view this page. '
            . 'This area is restricted to ' . $roleLabel . ' accounts.</p></header>'
            . '<a class="auth-button auth-button-link" href="' . $dashboardUrl . '">Return to dashboard</a>'
            . '</section></main></body></html>';
        exit;
    }
}

function login_throttle_minutes(PDO $connection, string $email, string $ipAddress): int
{
    $minutesToWait = 0;
    $checks = [
        ['email', $email],
        ['ip', $ipAddress],
    ];

    foreach ($checks as [$column, $value]) {
        $statement = $connection->prepare(
            "SELECT COUNT(*) AS failure_count, "
            . "GREATEST(1, CEIL(TIMESTAMPDIFF(SECOND, CURRENT_TIMESTAMP, "
            . "DATE_ADD(MIN(attempted_at), INTERVAL 15 MINUTE)) / 60)) AS retry_minutes "
            . "FROM login_attempts "
            . "WHERE {$column} = :match_value "
            . "AND attempted_at >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 15 MINUTE)"
        );
        $statement->execute(['match_value' => $value]);
        $result = $statement->fetch();

        if ($result !== false && (int) $result['failure_count'] >= 5) {
            $minutesToWait = max($minutesToWait, (int) $result['retry_minutes']);
        }
    }

    return $minutesToWait;
}

function enforce_idle_timeout(): void
{
    $user = current_user();
    if ($user === null) {
        return;
    }

    $now = time();
    $lastActivity = $_SESSION['last_activity'] ?? $now;

    if (!is_int($lastActivity) || $now - $lastActivity >= 1800) {
        $requestUri = local_return_url($_SERVER['REQUEST_URI'] ?? null);
        $scriptName = basename((string) ($_SERVER['SCRIPT_NAME'] ?? ''));
        $cookie = session_get_cookie_params();
        $sessionName = session_name();

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

        if ($requestUri !== null && !in_array($scriptName, ['login.php', 'logout.php'], true)) {
            $_SESSION['_intended_url'] = $requestUri;
        }

        flash('info', 'Your session expired due to inactivity. Please sign in again.');

        if ($scriptName !== 'login.php') {
            redirect(app_url('login.php'));
        }

        return;
    }

    $_SESSION['last_activity'] = $now;
}
