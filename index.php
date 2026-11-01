<?php
declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

redirect(current_user() === null ? 'login.php' : 'dashboard.php');
