<?php
declare(strict_types=1);

$navigationUser = current_user();
?>
<nav class="site-nav" aria-label="Main navigation">
    <a class="site-brand" href="<?= e(app_url('dashboard.php')) ?>">SWD Auth</a>
    <div class="site-nav-links">
        <a href="<?= e(app_url('dashboard.php')) ?>">Dashboard</a>
        <a href="<?= e(app_url('profile.php')) ?>">Profile</a>
        <?php if ($navigationUser !== null && $navigationUser['role'] === 'admin'): ?>
            <a href="<?= e(app_url('admin/users.php')) ?>">Admin</a>
        <?php endif; ?>
    </div>
</nav>
