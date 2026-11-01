<?php
declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

require_guest();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        flash('errors', ['Your session expired or the form was invalid. Please try again.']);
        redirect('login.php');
    }

    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    old('email', $email);
    $connection = db();
    $ipAddress = is_string($_SERVER['REMOTE_ADDR'] ?? null)
        ? $_SERVER['REMOTE_ADDR']
        : 'unknown';
    if (strlen($ipAddress) > 45) {
        $ipAddress = 'unknown';
    }
    $attemptEmail = strlen($email) <= 160
        ? $email
        : 'invalid:' . hash('sha256', $email);

    $retryMinutes = login_throttle_minutes($connection, $attemptEmail, $ipAddress);
    if ($retryMinutes > 0) {
        flash('errors', ["Too many attempts, try again in {$retryMinutes} minutes"]);
        redirect('login.php');
    }

    $user = false;
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $statement = $connection->prepare(
            'SELECT id, name, email, password_hash, role FROM users WHERE email = :email LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();
    }

    $storedHash = is_array($user) && is_string($user['password_hash'] ?? null)
        ? $user['password_hash']
        : '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.';
    $passwordIsValid = password_verify($password, $storedHash);

    if (!is_array($user) || !$passwordIsValid) {
        $statement = $connection->prepare(
            'INSERT INTO login_attempts (email, ip) VALUES (:email, :ip_address)'
        );
        $statement->execute([
            'email' => $attemptEmail,
            'ip_address' => $ipAddress,
        ]);
        flash('errors', ['Invalid email or password']);
        redirect('login.php');
    }

    if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
        $newHash = password_hash($password, PASSWORD_DEFAULT);
        $statement = $connection->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
        $statement->execute([
            'password_hash' => $newHash,
            'id' => $user['id'],
        ]);
    }

    $statement = $connection->prepare(
        'DELETE FROM login_attempts WHERE email = :email OR ip = :ip_address'
    );
    $statement->execute([
        'email' => $attemptEmail,
        'ip_address' => $ipAddress,
    ]);

    $statement = $connection->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
    $statement->execute(['id' => $user['id']]);

    $destination = intended_url() ?? 'dashboard.php';
    session_regenerate_id(true);
    unset($_SESSION['_csrf_token'], $_SESSION['_old']);
    $_SESSION['user_id'] = (int) $user['id'];
    $_SESSION['user_name'] = (string) $user['name'];
    $_SESSION['user_role'] = (string) $user['role'];
    $_SESSION['last_activity'] = time();

    redirect($destination);
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET, POST');
    exit('Method not allowed.');
}

$errors = flash('errors');
$errors = is_array($errors) ? $errors : [];
$info = flash('info');
$success = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
    <main class="auth-page">
        <section class="auth-card" aria-labelledby="login-title">
            <header class="auth-header">
                <h1 id="login-title">Sign in</h1>
                <p>Enter your email and password to continue.</p>
            </header>

            <?php if ($info !== null): ?>
                <div class="notice notice-success" role="status"><?= e((string) $info) ?></div>
            <?php endif; ?>

            <?php if ($success !== null): ?>
                <div class="notice notice-success" role="status"><?= e((string) $success) ?></div>
            <?php endif; ?>

            <?php if ($errors !== []): ?>
                <div class="notice notice-error" role="alert">
                    <ul>
                        <?php foreach ($errors as $error): ?>
                            <li><?= e((string) $error) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <form method="post" action="login.php">
                <?= csrf_field() ?>

                <div class="form-field">
                    <label for="email">Email address</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        autocomplete="email"
                        maxlength="160"
                        value="<?= e(old('email') ?? '') ?>"
                        required
                    >
                </div>

                <div class="form-field">
                    <label for="password">Password</label>
                    <input
                        id="password"
                        name="password"
                        type="password"
                        autocomplete="current-password"
                        required
                    >
                </div>

                <button class="auth-button" type="submit">Sign in</button>
            </form>
            <p class="auth-footer">Need an account? <a href="register.php">Create one</a></p>
        </section>
    </main>
</body>
</html>
