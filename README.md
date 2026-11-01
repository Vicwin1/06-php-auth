# SWD PHP Authentication

## Setup

1. Import `database/schema.sql` into MySQL using phpMyAdmin or the MySQL client. It creates the `swd_auth` database, `users` table, and `login_attempts` table.
2. Set `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASS` in the PHP/Apache environment if your local MySQL settings differ from the XAMPP defaults (`127.0.0.1:3306`, database `swd_auth`, user `root`, empty password).
3. If you already created the Stage 1 database, run `database/stage2_migration.sql` once to add the `role` and `last_login_at` columns. For a fresh install, `database/schema.sql` already includes them.
4. If your `login_attempts` table came from the earlier project schema and has an `ip_address` column, run `database/stage3_migration.sql` once to rename it to `ip`. The current XAMPP database already uses `ip`, so do not run that migration there.
5. Open `register.php` or `login.php` through the local Apache server, for example `http://localhost/swd/06-php-auth/login.php`.

Set `APP_ENV=production` in production to disable displayed PHP errors. Keep error logging enabled and use HTTPS so the session cookie is marked secure. Configure the web server/PHP environment with database credentials rather than committing secrets to this project.

## Security features

- **Passwords:** `password_hash()` with `PASSWORD_DEFAULT` stores only salted password hashes. Login verifies with `password_verify()` and upgrades outdated hashes using `password_needs_rehash()`. Password changes require the current password and rotate the session ID.
- **Authentication and sessions:** strict, HTTP-only, SameSite=Lax session cookies; HTTPS-only `Secure`; session ID rotation at login, registration, and password change; and logout via CSRF-protected POST. Sessions expire after 30 minutes of inactivity.
- **Brute-force protection:** failed logins are stored by email and client IP. Five failures for either identifier in 15 minutes temporarily block further attempts, and successful sign-in clears the matching attempts. Failed sign-ins show the same “Invalid email or password” message so the response does not reveal whether an email has an account.
- **Request integrity and redirects:** state-changing forms use session-backed CSRF tokens verified with `hash_equals()`. Post-login return URLs must be validated local paths, preventing external open redirects.
- **Database safety:** PDO uses native prepared statements and exceptions. Registration and profile updates validate email addresses and enforce email uniqueness in both application logic and the database.
- **Output and response headers:** dynamic HTML values are escaped with `htmlspecialchars()`. Responses set `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- **Authorization:** admin pages require the current database role, not just a role cached in the session. Role changes use CSRF protection and the admin UI prevents self-demotion. A CLI-only script supports first-admin setup.

## Profile and administration

Signed-in users can edit their name/email and change their password at `profile.php`. Admins can manage roles at `admin/users.php`. To create the first administrator from a terminal, run:

```text
C:\xampp\php\php.exe promote-admin.php me@example.com
```

The Admin navigation link is only shown to users whose current database role is `admin`.

## Why password hashes, not plain text/MD5/SHA-1

The application never stores submitted passwords. Password hashing algorithms are deliberately slow and salted, making stolen hashes much harder to crack; `password_verify()` checks them without recovering the original password. MD5 and SHA-1 are fast general-purpose hashes and are unsuitable for passwords because attackers can test guesses quickly and these algorithms lack password-specific protections.
