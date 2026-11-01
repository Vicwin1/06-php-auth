<?php
declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

require_login();

$user = current_user();
$statement = db()->prepare(
    'SELECT name, email, role, created_at, last_login_at FROM users WHERE id = :id LIMIT 1'
);
$statement->execute(['id' => $user['id']]);
$account = $statement->fetch();

if ($account === false) {
    unset(
        $_SESSION['user_id'],
        $_SESSION['user_name'],
        $_SESSION['user_role'],
        $_SESSION['last_activity']
    );
    flash('errors', ['Your account could not be found. Please sign in again.']);
    redirect('login.php');
}

$account['created_at'] = $account['created_at'] === null
    ? 'Not available'
    : date('F j, Y, g:i a', strtotime((string) $account['created_at']));
$account['last_login_at'] = $account['last_login_at'] === null
    ? 'Not available'
    : date('F j, Y, g:i a', strtotime((string) $account['last_login_at']));

$success = flash('success');
$errors = flash('errors');
$errors = is_array($errors) ? $errors : [];
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
    <?php require __DIR__ . '/src/nav.php'; ?>
    <main class="auth-page">
        <section class="auth-card" aria-labelledby="dashboard-title">
            <?php if ($errors !== []): ?>
                <div class="notice notice-error" role="alert">
                    <ul>
                        <?php foreach ($errors as $error): ?>
                            <li><?= e((string) $error) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            <?php if ($success !== null): ?>
                <div class="notice notice-success" role="status"><?= e((string) $success) ?></div>
            <?php endif; ?>
            <header class="auth-header">
                <h1 id="dashboard-title">Welcome, <?= e((string) $account['name']) ?></h1>
                <p>You are signed in to your account.</p>
            </header>
            <dl class="account-details">
                <div><dt>Name</dt><dd><?= e((string) $account['name']) ?></dd></div>
                <div><dt>Email</dt><dd><?= e((string) $account['email']) ?></dd></div>
                <div><dt>Role</dt><dd><?= e((string) $account['role']) ?></dd></div>
                <div><dt>Member since</dt><dd><?= e((string) $account['created_at']) ?></dd></div>
                <div><dt>Last login</dt><dd><?= e((string) $account['last_login_at']) ?></dd></div>
            </dl>
            <form method="post" action="logout.php">
                <?= csrf_field() ?>
                <button class="auth-button" type="submit">Sign out</button>
            </form>
        </section>
    </main>
</body>
</html>
