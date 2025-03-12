-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    account_non_locked BOOLEAN NOT NULL DEFAULT TRUE,
    failed_attempt INT NOT NULL DEFAULT 0,
    lock_time TIMESTAMP NULL,
    last_password_change_date TIMESTAMP NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

-- Check if index exists before dropping (MySQL workaround)
SET @exist_idx_user_username = (SELECT COUNT(1) FROM information_schema.statistics WHERE table_name = 'users' AND index_name = 'idx_user_username');
SET @drop_stmt1 = IF(@exist_idx_user_username, 'DROP INDEX idx_user_username ON users', 'SELECT 1');
PREPARE stmt FROM @drop_stmt1;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @exist_idx_user_email = (SELECT COUNT(1) FROM information_schema.statistics WHERE table_name = 'users' AND index_name = 'idx_user_email');
SET @drop_stmt2 = IF(@exist_idx_user_email, 'DROP INDEX idx_user_email ON users', 'SELECT 1');
PREPARE stmt FROM @drop_stmt2;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Create indexes
CREATE INDEX idx_user_username ON users(username);
CREATE INDEX idx_user_email ON users(email);

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255)
);

-- Create user_roles join table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

-- Create password history table
CREATE TABLE IF NOT EXISTS password_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    expiry_date TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create user login history table
CREATE TABLE IF NOT EXISTS user_login_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    login_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP NULL,
    successful BOOLEAN NOT NULL DEFAULT FALSE,
    error_message VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert default roles if they don't exist
INSERT INTO roles (name, description) 
SELECT 'ROLE_USER', 'Standard user with basic permissions' FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = 'ROLE_USER')
UNION ALL
SELECT 'ROLE_ADMIN', 'Administrator with full system access' FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = 'ROLE_ADMIN')
UNION ALL
SELECT 'ROLE_MANAGER', 'Manager with department-level access' FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE name = 'ROLE_MANAGER');

-- Insert admin user if not exists
INSERT INTO users (username, first_name, last_name, email, password_hash, is_active, account_non_locked, last_password_change_date)
SELECT 'admin', 'System', 'Administrator', 'admin@example.com', 
       '$2a$12$HsAFTBgBVNNyKOZnETZxJeuQbYjkKj.y.bXAgZ3LPsZiV9UHjXMd.', -- 'password123' hashed with BCrypt
       TRUE, TRUE, CURRENT_TIMESTAMP
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');

-- Assign admin role to admin user
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id 
FROM (SELECT id FROM users WHERE username = 'admin') u, (SELECT id FROM roles WHERE name = 'ROLE_ADMIN') r
WHERE NOT EXISTS (
    SELECT 1 FROM user_roles WHERE user_id = u.id AND role_id = r.id
);
