<?php
declare(strict_types=1);

/**
 * @return array{id: int, role: string}|null
 */
function current_user(): ?array
{
    $id = $_SESSION['user_id'] ?? null;
    $role = $_SESSION['user_role'] ?? null;

    if (!is_int($id) || !is_string($role)) {
        return null;
    }

    return ['id' => $id, 'role' => $role];
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

    redirect('login.php');
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
        exit('Forbidden.');
    }
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
            redirect('login.php');
        }

        return;
    }

    $_SESSION['last_activity'] = $now;
}
