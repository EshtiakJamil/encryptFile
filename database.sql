-- Secure File Storage System Database Schema
-- Lightweight and secure design for managing encrypted file uploads and user access

CREATE DATABASE IF NOT EXISTS secure_file_storage;
USE secure_file_storage;

-- Users table to store user authentication information
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Files table to store encrypted file metadata
CREATE TABLE files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    encrypted_filename VARCHAR(255) UNIQUE NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100),
    encryption_key_hash VARCHAR(255) NOT NULL,
    iv VARCHAR(32) NOT NULL, -- Initialization Vector for encryption
    file_hash VARCHAR(64) NOT NULL, -- SHA-256 hash for integrity check
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP NULL,
    is_deleted BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_files (user_id, is_deleted),
    INDEX idx_encrypted_filename (encrypted_filename)
);

-- User sessions table for secure session management
CREATE TABLE user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_token VARCHAR(128) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_session_token (session_token),
    INDEX idx_user_sessions (user_id, is_active)
);

-- Activity log for security monitoring
CREATE TABLE activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(50) NOT NULL,
    file_id INT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL,
    INDEX idx_user_activity (user_id, timestamp),
    INDEX idx_action_timestamp (action, timestamp)
);

-- Insert a default admin user (password: admin123 — make sure to change this in production!)
INSERT INTO users (username, email, password_hash, salt) VALUES 
('admin', 'admin@example.com', 
 '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 
 'defaultsalt123456789012345678');

-- Server-side note:
-- Create directories with proper permissions for encrypted file storage
-- mkdir -p uploads/encrypted
-- chmod 755 uploads
-- chmod 755 uploads/encrypted
