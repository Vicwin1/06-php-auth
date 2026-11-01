<?php
declare(strict_types=1);

require dirname(__DIR__) . '/bootstrap.php';

require_role('admin');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        flash('errors', ['Your session expired or the form was invalid. Please try again.']);
        redirect('users.php');
    }

    $targetUserId = filter_var(
        $_POST['user_id'] ?? null,
        FILTER_VALIDATE_INT,
        ['options' => ['min_range' => 1]]
    );
    $newRole = $_POST['role'] ?? null;

    if ($targetUserId === false || !in_array($newRole, ['user', 'admin'], true)) {
        flash('errors', ['Choose a valid user and role.']);
        redirect('users.php');
    }

    $currentUser = current_user();
    if ($targetUserId === $currentUser['id'] && $newRole !== 'admin') {
        flash('errors', ['You cannot remove your own admin role.']);
        redirect('users.php');
    }

    $statement = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
    $statement->execute([
        'role' => $newRole,
        'id' => $targetUserId,
    ]);

    if ($statement->rowCount() === 0) {
        $statement = db()->prepare('SELECT id FROM users WHERE id = :id');
        $statement->execute(['id' => $targetUserId]);

        if ($statement->fetch() === false) {
            flash('errors', ['That user could not be found.']);
            redirect('users.php');
        }
    }

    flash('success', 'User role updated.');
    redirect('users.php');
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET, POST');
    exit('Method not allowed.');
}

$statement = db()->query(
    'SELECT id, name, email, role, created_at, last_login_at FROM users ORDER BY id ASC'
);
$users = $statement->fetchAll();
$success = flash('success');
$errors = flash('errors');
$errors = is_array($errors) ? $errors : [];
$currentUser = current_user();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage users</title>
    <link rel="stylesheet" href="../assets/auth.css">
</head>
<body>
    <?php require dirname(__DIR__) . '/src/nav.php'; ?>
    <main class="admin-page">
        <header class="page-header">
            <h1>Manage users</h1>
            <p>Review accounts and manage administrator access.</p>
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

        <div class="table-wrap">
            <table class="user-table">
                <thead>
                    <tr>
                        <th scope="col">Name</th>
                        <th scope="col">Email</th>
                        <th scope="col">Role</th>
                        <th scope="col">Created</th>
                        <th scope="col">Last login</th>
                        <th scope="col">Update role</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><?= e((string) $user['name']) ?></td>
                            <td><?= e((string) $user['email']) ?></td>
                            <td><?= e((string) $user['role']) ?></td>
                            <td><?= e(date('M j, Y, g:i a', strtotime((string) $user['created_at']))) ?></td>
                            <td>
                                <?= $user['last_login_at'] === null
                                    ? 'Never'
                                    : e(date('M j, Y, g:i a', strtotime((string) $user['last_login_at']))) ?>
                            </td>
                            <td>
                                <?php if ((int) $user['id'] === $currentUser['id']): ?>
                                    <span class="muted">Your role cannot be changed here</span>
                                <?php else: ?>
                                    <form class="role-form" method="post" action="users.php">
                                        <?= csrf_field() ?>
                                        <input type="hidden" name="user_id" value="<?= (int) $user['id'] ?>">
                                        <label class="visually-hidden" for="role-<?= (int) $user['id'] ?>">
                                            Role for <?= e((string) $user['name']) ?>
                                        </label>
                                        <select id="role-<?= (int) $user['id'] ?>" name="role">
                                            <option value="user"<?= $user['role'] === 'user' ? ' selected' : '' ?>>User</option>
                                            <option value="admin"<?= $user['role'] === 'admin' ? ' selected' : '' ?>>Admin</option>
                                        </select>
                                        <button class="small-button" type="submit">Save</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    <?php if ($users === []): ?>
                        <tr><td colspan="6">No users found.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</body>
</html>
