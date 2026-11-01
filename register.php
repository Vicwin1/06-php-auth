<?php
declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

require_guest();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        flash('errors', ['Your session expired or the form was invalid. Please try again.']);
        redirect('register.php');
    }

    $name = trim((string) ($_POST['name'] ?? ''));
    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $confirmPassword = is_string($_POST['confirm_password'] ?? null)
        ? $_POST['confirm_password']
        : '';
    $errors = [];

    foreach (['name' => $name, 'email' => $email] as $field => $value) {
        old($field, $value);
    }

    $nameLength = preg_match_all('/./us', $name);
    if ($name === '' || $nameLength === false || $nameLength > 100) {
        $errors[] = 'Enter a name of no more than 100 characters.';
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Enter a valid email address.';
    }

    $passwordLength = preg_match_all('/./us', $password);
    if (
        $passwordLength === false
        || $passwordLength < 10
        || preg_match('/\p{L}/u', $password) !== 1
        || preg_match('/\p{N}/u', $password) !== 1
    ) {
        $errors[] = 'Password must be at least 10 characters and include a letter and a number.';
    }

    if (PASSWORD_DEFAULT === PASSWORD_BCRYPT && strlen($password) > 72) {
        $errors[] = 'Password cannot exceed 72 bytes with the current password hashing algorithm.';
    }

    if ($password !== $confirmPassword) {
        $errors[] = 'The passwords do not match.';
    }

    if ($errors === []) {
        $statement = db()->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $statement->execute(['email' => $email]);

        if ($statement->fetch() !== false) {
            $errors[] = 'An account with that email address already exists.';
        }
    }

    if ($errors !== []) {
        flash('errors', $errors);
        redirect('register.php');
    }

    try {
        $statement = db()->prepare(
            'INSERT INTO users (name, email, password_hash, last_login_at) '
            . 'VALUES (:name, :email, :password_hash, CURRENT_TIMESTAMP)'
        );
        $statement->execute([
            'name' => $name,
            'email' => $email,
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        ]);
    } catch (PDOException $exception) {
        if ($exception->getCode() !== '23000') {
            throw $exception;
        }

        flash('errors', ['An account with that email address already exists.']);
        redirect('register.php');
    }

    session_regenerate_id(true);
    unset($_SESSION['_csrf_token']);
    $_SESSION['user_id'] = (int) db()->lastInsertId();
    $_SESSION['user_name'] = $name;
    $_SESSION['user_role'] = 'user';
    $_SESSION['last_activity'] = time();

    flash('success', 'Your account has been created.');
    redirect('dashboard.php');
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET, POST');
    exit('Method not allowed.');
}

$errors = flash('errors');
$errors = is_array($errors) ? $errors : [];
$success = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
    <main class="auth-page">
        <section class="auth-card" aria-labelledby="register-title">
            <header class="auth-header">
                <h1 id="register-title">Create your account</h1>
                <p>Get started by filling in your details below.</p>
            </header>

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

            <form method="post" action="register.php">
                <?= csrf_field() ?>

                <div class="form-field">
                    <label for="name">Name</label>
                    <input
                        id="name"
                        name="name"
                        type="text"
                        autocomplete="name"
                        maxlength="100"
                        value="<?= e(old('name') ?? '') ?>"
                        required
                    >
                </div>

                <div class="form-field">
                    <label for="email">Email address</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        autocomplete="email"
                        maxlength="254"
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
                        autocomplete="new-password"
                        minlength="10"
                        required
                    >
                    <small>At least 10 characters, including a letter and a number.</small>
                </div>

                <div class="form-field">
                    <label for="confirm_password">Confirm password</label>
                    <input
                        id="confirm_password"
                        name="confirm_password"
                        type="password"
                        autocomplete="new-password"
                        minlength="10"
                        required
                    >
                </div>

                <button class="auth-button" type="submit">Create account</button>
            </form>
            <p class="auth-footer">Already have an account? <a href="login.php">Sign in</a></p>
        </section>
    </main>
</body>
</html>
