# SWD PHP Authentication

## Setup

1. Import `database/schema.sql` into MySQL using phpMyAdmin or the MySQL client. It creates the `swd_auth` database, `users` table, and `login_attempts` table.
2. Set `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASS` in the PHP/Apache environment if your local MySQL settings differ from the XAMPP defaults (`127.0.0.1:3306`, database `swd_auth`, user `root`, empty password).
3. If you already created the Stage 1 database, run `database/stage2_migration.sql` once to add the `role` and `last_login_at` columns. For a fresh install, `database/schema.sql` already includes them.
4. Open `register.php` or `login.php` through the local Apache server, for example `http://localhost/swd/06-php-auth/login.php`.

Set `APP_ENV=production` in production to disable displayed PHP errors. Keep error logging enabled and use HTTPS so the session cookie is marked secure.

## Sign-in behavior

Failed sign-ins always show “Invalid email or password” so the response does not disclose whether an email address has an account; exposing that distinction makes account enumeration easier. Login also rotates the session ID, upgrades outdated password hashes when needed, and returns users to a validated same-site URL if they were redirected to sign in. Sessions expire after 30 minutes without activity. Logout requires a CSRF-protected POST.

New accounts receive the `user` role. To grant administrator access, update the user's `role` to `admin` in a trusted database administration session. The `require_role('admin')` helper enforces that role on protected PHP pages.

## Password storage

The application stores only hashes created by PHP's `password_hash()` with `PASSWORD_DEFAULT`, never the submitted password. Password hashing algorithms are deliberately slow and salted, making stolen hashes much harder to crack; `password_verify()` can verify them later without recovering the original password. MD5 and SHA-1 are fast general-purpose hashes and are unsuitable for passwords: attackers can test guesses very quickly, and their obsolete designs do not provide password-specific protections.
