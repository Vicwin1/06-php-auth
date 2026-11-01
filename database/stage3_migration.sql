USE swd_auth;

ALTER TABLE login_attempts
    CHANGE COLUMN ip_address ip VARCHAR(45) NOT NULL;
