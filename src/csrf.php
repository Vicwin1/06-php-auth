<?php
declare(strict_types=1);

function csrf_token(): string
{
    if (!isset($_SESSION['_csrf_token']) || !is_string($_SESSION['_csrf_token'])) {
        $_SESSION['_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['_csrf_token'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function csrf_verify(?string $token = null): bool
{
    $submittedToken = $token ?? ($_POST['csrf_token'] ?? null);
    $sessionToken = $_SESSION['_csrf_token'] ?? null;

    return is_string($submittedToken)
        && is_string($sessionToken)
        && hash_equals($sessionToken, $submittedToken);
}
