<?php
// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'secure_file_storage');
define('DB_USER', 'root');
define('DB_PASS', '');

// Security Configuration
define('ENCRYPTION_METHOD', 'AES-256-CBC');
define('HASH_ALGORITHM', 'sha256');
define('SESSION_TIMEOUT', 3600); // 1 hour in seconds
define('MAX_FILE_SIZE', 50 * 1024 * 1024); // 50MB in bytes

// Fix: Use absolute path for uploads directory
define('UPLOAD_DIR', __DIR__ . '/uploads/encrypted/');
// Alternative: Use relative path from document root
// define('UPLOAD_DIR', $_SERVER['DOCUMENT_ROOT'] . '/enfile/uploads/encrypted/');

define('ALLOWED_EXTENSIONS', ['pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'zip', 'rar', 'mp3', 'mp4', 'avi']);

// Site Configuration
define('SITE_NAME', 'Secure File Storage');
define('SITE_URL', 'http://localhost/enfile/'); // Updated to match your project folder

// Error Reporting (set to false in production)
define('DEBUG_MODE', true);

if (DEBUG_MODE) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}

// Database Connection Class
class Database {
    private static $instance = null;
    private $connection;
    
    private function __construct() {
        try {
            $this->connection = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
        } catch (PDOException $e) {
            if (DEBUG_MODE) {
                die("Database connection failed: " . $e->getMessage());
            } else {
                die("Database connection failed. Please try again later.");
            }
        }
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function getConnection() {
        return $this->connection;
    }
    
    // Prevent cloning
    private function __clone() {}
    
    // Prevent unserialization
    public function __wakeup() {}
}

// Security headers
function setSecurityHeaders() {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

// CSRF Token functions
function generateCSRFToken() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Input sanitization
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Secure random string generation
function generateSecureToken($length = 32) {
    return bin2hex(random_bytes($length));
}

// File extension validation
function isAllowedFileType($filename) {
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($extension, ALLOWED_EXTENSIONS);
}

// File size validation
function isValidFileSize($fileSize) {
    return $fileSize > 0 && $fileSize <= MAX_FILE_SIZE;
}

// Session management
function isLoggedIn() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    return isset($_SESSION['user_id']) && isset($_SESSION['username']);
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit();
    }
}

function redirectIfLoggedIn() {
    if (isLoggedIn()) {
        header('Location: dashboard.php');
        exit();
    }
}

// Initialize security headers
setSecurityHeaders();

// Ensure upload directory exists with proper permissions
if (!file_exists(UPLOAD_DIR)) {
    if (!mkdir(UPLOAD_DIR, 0755, true)) {
        error_log("Failed to create upload directory: " . UPLOAD_DIR);
    }
}

// Create global $pdo variable for backward compatibility
$pdo = Database::getInstance()->getConnection();

// Debug: Log the upload directory path
if (DEBUG_MODE) {
    error_log("Upload directory set to: " . UPLOAD_DIR);
    error_log("Upload directory exists: " . (is_dir(UPLOAD_DIR) ? 'YES' : 'NO'));
}
?>