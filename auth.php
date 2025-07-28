<?php
require_once 'config.php';

// Initialize session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Check if user is authenticated
 */
function isAuthenticated() {
    return isset($_SESSION['user_id']) && isset($_SESSION['username']);
}

/**
 * Require authentication (redirect if not authenticated)
 */
function requireAuth() {
    if (!isAuthenticated()) {
        header('Location: login.php');
        exit;
    }
}

/**
 * Authenticate user with username/email and password
 */
function authenticateUser($usernameOrEmail, $password) {
    global $pdo;
    
    try {
        // Find user by username or email
        $stmt = $pdo->prepare("
            SELECT id, username, email, password_hash, salt, is_active 
            FROM users 
            WHERE (username = ? OR email = ?) AND is_active = TRUE
        ");
        $stmt->execute([$usernameOrEmail, $usernameOrEmail]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            return ['success' => false, 'message' => 'Invalid credentials'];
        }
        
        // Verify password
        if (!verifyPassword($password, $user['password_hash'], $user['salt'])) {
            // Log failed login attempt
            logActivity($user['id'], 'failed_login', null, $_SERVER['REMOTE_ADDR'], 
                       $_SERVER['HTTP_USER_AGENT'], 'Invalid password');
            
            return ['success' => false, 'message' => 'Invalid credentials'];
        }
        
        // Create user session
        $sessionResult = createUserSession($user['id']);
        if (!$sessionResult['success']) {
            return $sessionResult;
        }
        
        // Set session variables
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['session_token'] = $sessionResult['session_token'];
        
        // Update last login
        $stmt = $pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$user['id']]);
        
        // Log successful login
        logActivity($user['id'], 'login', null, $_SERVER['REMOTE_ADDR'], 
                   $_SERVER['HTTP_USER_AGENT'], 'Successful login');
        
        return ['success' => true, 'message' => 'Login successful', 'user' => $user];
        
    } catch (PDOException $e) {
        error_log("Authentication error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Authentication system error'];
    }
}

/**
 * Register new user
 */
function registerUser($username, $email, $password) {
    global $pdo;
    
    try {
        // Validate input
        $validation = validateRegistrationData($username, $email, $password);
        if (!$validation['success']) {
            return $validation;
        }
        
        // Check if username or email already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        if ($stmt->fetch()) {
            return ['success' => false, 'message' => 'Username or email already exists'];
        }
        
        // Generate salt and hash password
        $salt = bin2hex(random_bytes(16));
        $passwordHash = hashPassword($password, $salt);
        
        // Insert new user
        $stmt = $pdo->prepare("
            INSERT INTO users (username, email, password_hash, salt) 
            VALUES (?, ?, ?, ?)
        ");
        
        if ($stmt->execute([$username, $email, $passwordHash, $salt])) {
            $userId = $pdo->lastInsertId();
            
            // Log registration
            logActivity($userId, 'login', null, $_SERVER['REMOTE_ADDR'], 
                       $_SERVER['HTTP_USER_AGENT'], 'User registered');
            
            return ['success' => true, 'message' => 'Registration successful', 'user_id' => $userId];
        } else {
            return ['success' => false, 'message' => 'Failed to create user account'];
        }
        
    } catch (PDOException $e) {
        error_log("Registration error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Registration system error'];
    }
}

/**
 * Logout user
 */
function logoutUser() {
    global $pdo;
    
    if (isset($_SESSION['user_id'])) {
        // Log logout activity
        logActivity($_SESSION['user_id'], 'logout', null, $_SERVER['REMOTE_ADDR'], 
                   $_SERVER['HTTP_USER_AGENT'], 'User logged out');
        
        // Deactivate session in database
        if (isset($_SESSION['session_token'])) {
            try {
                $stmt = $pdo->prepare("UPDATE user_sessions SET is_active = FALSE WHERE session_token = ?");
                $stmt->execute([$_SESSION['session_token']]);
            } catch (PDOException $e) {
                error_log("Failed to deactivate session: " . $e->getMessage());
            }
        }
    }
    
    // Clear all session variables
    $_SESSION = array();
    
    // Destroy session cookie
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/');
    }
    
    // Destroy session
    session_destroy();
    
    return ['success' => true, 'message' => 'Logged out successfully'];
}

/**
 * Create user session record
 */
function createUserSession($userId) {
    global $pdo;
    
    try {
        // Generate session token
        $sessionToken = bin2hex(random_bytes(64));
        $expiresAt = date('Y-m-d H:i:s', time() + getSetting('session_timeout', 3600));
        
        // Insert session record
        $stmt = $pdo->prepare("
            INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at) 
            VALUES (?, ?, ?, ?, ?)
        ");
        
        $result = $stmt->execute([
            $userId,
            $sessionToken,
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $expiresAt
        ]);
        
        if ($result) {
            return ['success' => true, 'session_token' => $sessionToken];
        } else {
            return ['success' => false, 'message' => 'Failed to create session'];
        }
        
    } catch (PDOException $e) {
        error_log("Session creation error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Session system error'];
    }
}

/**
 * Validate session and refresh if needed
 */
function validateSession() {
    global $pdo;
    
    if (!isset($_SESSION['session_token']) || !isset($_SESSION['user_id'])) {
        return false;
    }
    
    try {
        $stmt = $pdo->prepare("
            SELECT expires_at, is_active 
            FROM user_sessions 
            WHERE session_token = ? AND user_id = ?
        ");
        $stmt->execute([$_SESSION['session_token'], $_SESSION['user_id']]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$session || !$session['is_active']) {
            return false;
        }
        
        // Check if session has expired
        if (strtotime($session['expires_at']) < time()) {
            // Deactivate expired session
            $stmt = $pdo->prepare("UPDATE user_sessions SET is_active = FALSE WHERE session_token = ?");
            $stmt->execute([$_SESSION['session_token']]);
            return false;
        }
        
        return true;
        
    } catch (PDOException $e) {
        error_log("Session validation error: " . $e->getMessage());
        return false;
    }
}

/**
 * Hash password with salt
 */
function hashPassword($password, $salt) {
    return password_hash($password . $salt, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536, // 64 MB
        'time_cost' => 4,       // 4 iterations
        'threads' => 3          // 3 threads
    ]);
}

/**
 * Verify password against hash
 */
function verifyPassword($password, $hash, $salt) {
    return password_verify($password . $salt, $hash);
}

/**
 * Validate registration data
 */
function validateRegistrationData($username, $email, $password) {
    $errors = [];
    
    // Username validation
    if (empty($username)) {
        $errors[] = 'Username is required';
    } elseif (strlen($username) < 3) {
        $errors[] = 'Username must be at least 3 characters long';
    } elseif (strlen($username) > 50) {
        $errors[] = 'Username must be less than 50 characters';
    } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        $errors[] = 'Username can only contain letters, numbers, and underscores';
    }
    
    // Email validation
    if (empty($email)) {
        $errors[] = 'Email is required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Invalid email format';
    } elseif (strlen($email) > 100) {
        $errors[] = 'Email must be less than 100 characters';
    }
    
    // Password validation
    if (empty($password)) {
        $errors[] = 'Password is required';
    } elseif (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters long';
    } elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter, one uppercase letter, and one number';
    }
    
    if (!empty($errors)) {
        return ['success' => false, 'message' => implode('. ', $errors)];
    }
    
    return ['success' => true];
}

/**
 * Change user password
 */
function changePassword($userId, $currentPassword, $newPassword) {
    global $pdo;
    
    try {
        // Get current user data
        $stmt = $pdo->prepare("SELECT password_hash, salt FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            return ['success' => false, 'message' => 'User not found'];
        }
        
        // Verify current password
        if (!verifyPassword($currentPassword, $user['password_hash'], $user['salt'])) {
            return ['success' => false, 'message' => 'Current password is incorrect'];
        }
        
        // Validate new password
        $validation = validateRegistrationData('dummy', 'dummy@example.com', $newPassword);
        if (!$validation['success']) {
            return $validation;
        }
        
        // Generate new salt and hash new password
        $newSalt = bin2hex(random_bytes(16));
        $newPasswordHash = hashPassword($newPassword, $newSalt);
        
        // Update password
        $stmt = $pdo->prepare("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?");
        $result = $stmt->execute([$newPasswordHash, $newSalt, $userId]);
        
        if ($result) {
            // Log password change
            logActivity($userId, 'login', null, $_SERVER['REMOTE_ADDR'], 
                       $_SERVER['HTTP_USER_AGENT'], 'Password changed');
            
            return ['success' => true, 'message' => 'Password changed successfully'];
        } else {
            return ['success' => false, 'message' => 'Failed to update password'];
        }
        
    } catch (PDOException $e) {
        error_log("Password change error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Password change system error'];
    }
}

/**
 * Get user information
 */
function getUserInfo($userId) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("
            SELECT id, username, email, created_at, last_login, is_active 
            FROM users 
            WHERE id = ?
        ");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            return ['success' => true, 'user' => $user];
        } else {
            return ['success' => false, 'message' => 'User not found'];
        }
        
    } catch (PDOException $e) {
        error_log("Get user info error: " . $e->getMessage());
        return ['success' => false, 'message' => 'System error'];
    }
}

/**
 * Clean expired sessions
 */
function cleanExpiredSessions() {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("DELETE FROM user_sessions WHERE expires_at < NOW() OR is_active = FALSE");
        $stmt->execute();
        
        return $stmt->rowCount();
        
    } catch (PDOException $e) {
        error_log("Session cleanup error: " . $e->getMessage());
        return 0;
    }
}

/**
 * Get user's active sessions
 */
function getUserSessions($userId) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("
            SELECT session_token, ip_address, user_agent, created_at, expires_at 
            FROM user_sessions 
            WHERE user_id = ? AND is_active = TRUE AND expires_at > NOW()
            ORDER BY created_at DESC
        ");
        $stmt->execute([$userId]);
        $sessions = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return ['success' => true, 'sessions' => $sessions];
        
    } catch (PDOException $e) {
        error_log("Get user sessions error: " . $e->getMessage());
        return ['success' => false, 'message' => 'System error'];
    }
}

/**
 * Revoke user session
 */
function revokeSession($userId, $sessionToken) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("
            UPDATE user_sessions 
            SET is_active = FALSE 
            WHERE user_id = ? AND session_token = ?
        ");
        $result = $stmt->execute([$userId, $sessionToken]);
        
        if ($result && $stmt->rowCount() > 0) {
            return ['success' => true, 'message' => 'Session revoked successfully'];
        } else {
            return ['success' => false, 'message' => 'Session not found'];
        }
        
    } catch (PDOException $e) {
        error_log("Revoke session error: " . $e->getMessage());
        return ['success' => false, 'message' => 'System error'];
    }
}

/**
 * Check rate limiting for failed login attempts
 */
function checkRateLimit($identifier) {
    global $pdo;
    
    try {
        $maxAttempts = getSetting('max_login_attempts', 5);
        $timeWindow = 300; // 5 minutes
        
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as attempt_count 
            FROM activity_logs 
            WHERE ip_address = ? 
            AND activity_type = 'failed_login' 
            AND timestamp > DATE_SUB(NOW(), INTERVAL ? SECOND)
        ");
        $stmt->execute([$identifier, $timeWindow]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return $result['attempt_count'] < $maxAttempts;
        
    } catch (PDOException $e) {
        error_log("Rate limit check error: " . $e->getMessage());
        return true; // Allow if system error
    }
}

/**
 * Get CSRF token
 */
function getCsrfToken() {
    return $_SESSION['csrf_token'] ?? '';
}

/**
 * Validate CSRF token
 */
function validateCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Generate new CSRF token
 */
function regenerateCsrfToken() {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf_token'];
}

/**
 * Get setting value from database
 */
function getSetting($key, $default = null) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("SELECT setting_value FROM system_settings WHERE setting_key = ?");
        $stmt->execute([$key]);
        $result = $stmt->fetchColumn();
        
        return $result !== false ? $result : $default;
    } catch (PDOException $e) {
        error_log("Get setting error: " . $e->getMessage());
        return $default;
    }
}

/**
 * Log user activity
 */
function logActivity($userId, $activityType, $fileId, $ipAddress, $userAgent, $details) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("
            INSERT INTO activity_logs (user_id, activity_type, file_id, ip_address, user_agent, details) 
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([$userId, $activityType, $fileId, $ipAddress, $userAgent, $details]);
        
        return true;
    } catch (PDOException $e) {
        error_log("Failed to log activity: " . $e->getMessage());
        return false;
    }
}

// Auto-cleanup expired sessions on each request (with probability)
if (rand(1, 100) <= 5) { // 5% chance
    cleanExpiredSessions();
}
?>