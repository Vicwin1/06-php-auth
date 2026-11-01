<?php
declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        flash('errors', ['Your session expired or the form was invalid. Please try again.']);
        redirect(app_url('profile.php'));
    }

    $action = $_POST['action'] ?? null;

    if ($action === 'update_profile') {
        $name = is_string($_POST['name'] ?? null) ? trim($_POST['name']) : '';
        $email = is_string($_POST['email'] ?? null)
            ? strtolower(trim($_POST['email']))
            : '';
        old('name', $name);
        old('email', $email);
        $errors = [];

        $nameLength = preg_match_all('/./us', $name);
        if ($name === '' || $nameLength === false || $nameLength > 100) {
            $errors[] = 'Enter a name of no more than 100 characters.';
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 160) {
            $errors[] = 'Enter a valid email address.';
        }

        if ($errors === []) {
            $statement = db()->prepare(
                'SELECT id FROM users WHERE email = :email AND id <> :id LIMIT 1'
            );
            $statement->execute([
                'email' => $email,
                'id' => $user['id'],
            ]);

            if ($statement->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            }
        }

        if ($errors !== []) {
            flash('errors', $errors);
            redirect(app_url('profile.php'));
        }

        try {
            $statement = db()->prepare(
                'UPDATE users SET name = :name, email = :email WHERE id = :id'
            );
            $statement->execute([
                'name' => $name,
                'email' => $email,
                'id' => $user['id'],
            ]);
        } catch (PDOException $exception) {
            if ($exception->getCode() !== '23000') {
                throw $exception;
            }

            flash('errors', ['An account with that email address already exists.']);
            redirect(app_url('profile.php'));
        }

        $_SESSION['user_name'] = $name;
        flash('success', 'Your profile has been updated.');
        redirect(app_url('profile.php'));
    }

    if ($action === 'change_password') {
        $currentPassword = is_string($_POST['current_password'] ?? null)
            ? $_POST['current_password']
            : '';
        $newPassword = is_string($_POST['new_password'] ?? null)
            ? $_POST['new_password']
            : '';
        $confirmPassword = is_string($_POST['confirm_password'] ?? null)
            ? $_POST['confirm_password']
            : '';

        $statement = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
        $statement->execute(['id' => $user['id']]);
        $passwordHash = $statement->fetchColumn();

        if (!is_string($passwordHash) || !password_verify($currentPassword, $passwordHash)) {
            flash('errors', ['Current password is incorrect.']);
            redirect(app_url('profile.php'));
        }

        $passwordLength = preg_match_all('/./us', $newPassword);
        $errors = [];
        if (
            $passwordLength === false
            || $passwordLength < 10
            || preg_match('/\p{L}/u', $newPassword) !== 1
            || preg_match('/\p{N}/u', $newPassword) !== 1
        ) {
            $errors[] = 'New password must be at least 10 characters and include a letter and a number.';
        }

        if (PASSWORD_DEFAULT === PASSWORD_BCRYPT && strlen($newPassword) > 72) {
            $errors[] = 'Password cannot exceed 72 bytes with the current password hashing algorithm.';
        }

        if ($newPassword !== $confirmPassword) {
            $errors[] = 'The new passwords do not match.';
        }

        if ($errors !== []) {
            flash('errors', $errors);
            redirect(app_url('profile.php'));
        }

        $statement = db()->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
        $statement->execute([
            'password_hash' => password_hash($newPassword, PASSWORD_DEFAULT),
            'id' => $user['id'],
        ]);

        session_regenerate_id(true);
        unset($_SESSION['_csrf_token']);
        $_SESSION['last_activity'] = time();
        flash('success', 'Your password has been changed.');
        redirect(app_url('profile.php'));
    }

    flash('errors', ['Choose a valid profile action.']);
    redirect(app_url('profile.php'));
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET, POST');
    exit('Method not allowed.');
}

$statement = db()->prepare('SELECT name, email FROM users WHERE id = :id LIMIT 1');
$statement->execute(['id' => $user['id']]);
$account = $statement->fetch();
if ($account === false) {
    redirect(app_url('login.php'));
}

$success = flash('success');
$errors = flash('errors');
$errors = is_array($errors) ? $errors : [];
$name = old('name') ?? (string) $account['name'];
$email = old('email') ?? (string) $account['email'];
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your profile</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
    <?php require __DIR__ . '/src/nav.php'; ?>
    <main class="auth-page">
        <section class="auth-card profile-card" aria-labelledby="profile-title">
            <header class="auth-header">
                <h1 id="profile-title">Your profile</h1>
                <p>Manage your account details and password.</p>
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

            <section class="profile-section" aria-labelledby="profile-details-title">
                <h2 id="profile-details-title">Account details</h2>
                <form method="post" action="<?= e(app_url('profile.php')) ?>">
                    <?= csrf_field() ?>
                    <input type="hidden" name="action" value="update_profile">

                    <div class="form-field">
                        <label for="name">Name</label>
                        <input
                            id="name"
                            name="name"
                            type="text"
                            autocomplete="name"
                            maxlength="100"
                            value="<?= e($name) ?>"
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
                            maxlength="160"
                            value="<?= e($email) ?>"
                            required
                        >
                    </div>

                    <button class="auth-button" type="submit">Save profile</button>
                </form>
            </section>

            <section class="profile-section" aria-labelledby="password-title">
                <h2 id="password-title">Change password</h2>
                <form method="post" action="<?= e(app_url('profile.php')) ?>">
                    <?= csrf_field() ?>
                    <input type="hidden" name="action" value="change_password">

                    <div class="form-field">
                        <label for="current_password">Current password</label>
                        <input
                            id="current_password"
                            name="current_password"
                            type="password"
                            autocomplete="current-password"
                            required
                        >
                    </div>

                    <div class="form-field">
                        <label for="new_password">New password</label>
                        <input
                            id="new_password"
                            name="new_password"
                            type="password"
                            autocomplete="new-password"
                            minlength="10"
                            required
                        >
                        <small>At least 10 characters, including a letter and a number.</small>
                    </div>

                    <div class="form-field">
                        <label for="confirm_password">Confirm new password</label>
                        <input
                            id="confirm_password"
                            name="confirm_password"
                            type="password"
                            autocomplete="new-password"
                            minlength="10"
                            required
                        >
                    </div>

                    <button class="auth-button" type="submit">Change password</button>
                </form>
            </section>
        </section>
    </main>
</body>
</html>
