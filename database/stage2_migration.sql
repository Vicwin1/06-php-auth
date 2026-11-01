USE swd_auth;

ALTER TABLE users
    ADD COLUMN role VARCHAR(32) NOT NULL DEFAULT 'user' AFTER password_hash,
    ADD COLUMN last_login_at TIMESTAMP NULL DEFAULT NULL AFTER created_at;
