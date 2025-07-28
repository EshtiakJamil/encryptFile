<?php
require_once 'config.php';

// Encryption Functions
class SecureFileHandler {
    
    // Generate a secure encryption key
    public static function generateEncryptionKey() {
        return base64_encode(random_bytes(32));
    }
    
    // Generate initialization vector
    public static function generateIV() {
        $ivLength = openssl_cipher_iv_length(ENCRYPTION_METHOD);
        return openssl_random_pseudo_bytes($ivLength);
    }
    
    // Encrypt file content
    public static function encryptFile($filePath, $key, $iv) {
        if (!file_exists($filePath)) {
            throw new Exception("File not found for encryption");
        }
        
        $fileContent = file_get_contents($filePath);
        if ($fileContent === false) {
            throw new Exception("Failed to read file for encryption");
        }
        
        $encryptedContent = openssl_encrypt($fileContent, ENCRYPTION_METHOD, base64_decode($key), OPENSSL_RAW_DATA, $iv);
        
        if ($encryptedContent === false) {
            throw new Exception("Encryption failed");
        }
        
        return $encryptedContent;
    }
    
    // Decrypt file content
    public static function decryptFile($encryptedContent, $key, $iv) {
        $decryptedContent = openssl_decrypt($encryptedContent, ENCRYPTION_METHOD, base64_decode($key), OPENSSL_RAW_DATA, $iv);
        
        if ($decryptedContent === false) {
            throw new Exception("Decryption failed");
        }
        
        return $decryptedContent;
    }
    
    // Generate file hash for integrity check
    public static function generateFileHash($content) {
        return hash(HASH_ALGORITHM, $content);
    }
    
    // Verify file integrity
    public static function verifyFileIntegrity($content, $expectedHash) {
        return hash_equals($expectedHash, self::generateFileHash($content));
    }
    
    // Generate unique encrypted filename
    public static function generateEncryptedFilename($originalFilename) {
        $extension = pathinfo($originalFilename, PATHINFO_EXTENSION);
        $uniqueId = uniqid('enc_', true);
        $randomSuffix = bin2hex(random_bytes(8));
        return $uniqueId . '_' . $randomSuffix . '.enc';
    }
    
    // Store encrypted file
    public static function storeEncryptedFile($tempFilePath, $userId, $originalFilename) {
        try {
            // Generate encryption components
            $encryptionKey = self::generateEncryptionKey();
            $iv = self::generateIV();
            $encryptedFilename = self::generateEncryptedFilename($originalFilename);
            
            // Read and encrypt file
            $originalContent = file_get_contents($tempFilePath);
            $fileHash = self::generateFileHash($originalContent);
            $encryptedContent = self::encryptFile($tempFilePath, $encryptionKey, $iv);
            
            // Store encrypted file
            $encryptedFilePath = UPLOAD_DIR . $encryptedFilename;
            if (file_put_contents($encryptedFilePath, $encryptedContent) === false) {
                throw new Exception("Failed to store encrypted file");
            }
            
            // Store file metadata in database
            $db = getDB();
            $stmt = $db->prepare("
                INSERT INTO files (user_id, original_filename, encrypted_filename, file_size, 
                                   mime_type, encryption_key_hash, iv, file_hash) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $fileSize = filesize($tempFilePath);
            $mimeType = mime_content_type($tempFilePath);
            $keyHash = $encryptionKey; // Store the actual key (you should encrypt this with user password in production)
            $ivHex = bin2hex($iv);
            
            $stmt->execute([
                $userId,
                $originalFilename,
                $encryptedFilename,
                $fileSize,
                $mimeType,
                $keyHash,
                $ivHex, // instead of $ivBase64,
                $fileHash
            ]);
            
            $fileId = $db->lastInsertId();
            
            // Log activity
            logActivity($userId, 'FILE_UPLOAD', $fileId, "Uploaded: " . $originalFilename);
            
            return [
                'success' => true,
                'file_id' => $fileId,
                'message' => 'File uploaded and encrypted successfully'
            ];
            
        } catch (Exception $e) {
            // Clean up on failure
            if (isset($encryptedFilePath) && file_exists($encryptedFilePath)) {
                unlink($encryptedFilePath);
            }
            
            return [
                'success' => false,
                'message' => 'Upload failed: ' . $e->getMessage()
            ];
        }
    }
    
    // Retrieve and decrypt file
    public static function retrieveDecryptedFile($fileId, $userId, $encryptionKey) {
        try {
            $db = getDB();
            $stmt = $db->prepare("
                SELECT * FROM files 
                WHERE id = ? AND user_id = ? AND is_deleted = FALSE
            ");
            $stmt->execute([$fileId, $userId]);
            $fileData = $stmt->fetch();
            
            if (!$fileData) {
                throw new Exception("File not found or access denied");
            }
            
            // Verify encryption key
            if (!password_verify($encryptionKey, $fileData['encryption_key_hash'])) {
                throw new Exception("Invalid encryption key");
            }
            
            // Read encrypted file
            $encryptedFilePath = UPLOAD_DIR . $fileData['encrypted_filename'];
            if (!file_exists($encryptedFilePath)) {
                throw new Exception("Encrypted file not found on disk");
            }
            
            $encryptedContent = file_get_contents($encryptedFilePath);
            if ($encryptedContent === false) {
                throw new Exception("Failed to read encrypted file");
            }
            
            // Decrypt file
            $iv = base64_decode($fileData['iv']);
            $decryptedContent = self::decryptFile($encryptedContent, $encryptionKey, $iv);
            
            // Verify file integrity
            if (!self::verifyFileIntegrity($decryptedContent, $fileData['file_hash'])) {
                throw new Exception("File integrity check failed");
            }
            
            // Update last accessed time
            $updateStmt = $db->prepare("UPDATE files SET last_accessed = NOW() WHERE id = ?");
            $updateStmt->execute([$fileId]);
            
            // Log activity
            logActivity($userId, 'FILE_DOWNLOAD', $fileId, "Downloaded: " . $fileData['original_filename']);
            
            return [
                'success' => true,
                'content' => $decryptedContent,
                'filename' => $fileData['original_filename'],
                'mime_type' => $fileData['mime_type'],
                'file_size' => $fileData['file_size']
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Decryption failed: ' . $e->getMessage()
            ];
        }
    }
    
    // Delete file securely
    public static function deleteFile($fileId, $userId) {
        try {
            $db = getDB();
            
            // Get file information
            $stmt = $db->prepare("
                SELECT * FROM files 
                WHERE id = ? AND user_id = ? AND is_deleted = FALSE
            ");
            $stmt->execute([$fileId, $userId]);
            $fileData = $stmt->fetch();
            
            if (!$fileData) {
                throw new Exception("File not found or already deleted");
            }
            
            // Mark as deleted in database
            $deleteStmt = $db->prepare("UPDATE files SET is_deleted = TRUE WHERE id = ?");
            $deleteStmt->execute([$fileId]);
            
            // Remove physical file
            $encryptedFilePath = UPLOAD_DIR . $fileData['encrypted_filename'];
            if (file_exists($encryptedFilePath)) {
                unlink($encryptedFilePath);
            }
            
            // Log activity
            logActivity($userId, 'FILE_DELETE', $fileId, "Deleted: " . $fileData['original_filename']);
            
            return [
                'success' => true,
                'message' => 'File deleted successfully'
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Delete failed: ' . $e->getMessage()
            ];
        }
    }
}

// User Management Functions
class UserManager {
    
    // Create new user
    public static function createUser($username, $email, $password) {
        try {
            $db = getDB();
            
            // Check if username or email already exists
            $checkStmt = $db->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
            $checkStmt->execute([$username, $email]);
            
            if ($checkStmt->fetch()) {
                return [
                    'success' => false,
                    'message' => 'Username or email already exists'
                ];
            }
            
            // Generate salt and hash password
            $salt = bin2hex(random_bytes(16));
            $passwordHash = password_hash($password . $salt, PASSWORD_DEFAULT);
            
            // Insert new user
            $stmt = $db->prepare("
                INSERT INTO users (username, email, password_hash, salt) 
                VALUES (?, ?, ?, ?)
            ");
            $stmt->execute([$username, $email, $passwordHash, $salt]);
            
            $userId = $db->lastInsertId();
            
            // Log activity
            logActivity($userId, 'USER_REGISTER', null, "New user registered: " . $username);
            
            return [
                'success' => true,
                'user_id' => $userId,
                'message' => 'User created successfully'
            ];
            
        } catch (PDOException $e) {
            return [
                'success' => false,
                'message' => 'Registration failed: Database error'
            ];
        }
    }
    
    // Authenticate user
    public static function authenticateUser($username, $password) {
        try {
            $db = getDB();
            $stmt = $db->prepare("
                SELECT id, username, email, password_hash, salt, is_active 
                FROM users 
                WHERE (username = ? OR email = ?) AND is_active = TRUE
            ");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();
            
            if (!$user) {
                return [
                    'success' => false,
                    'message' => 'Invalid username or password'
                ];
            }
            
            // Verify password
            if (!password_verify($password . $user['salt'], $user['password_hash'])) {
                return [
                    'success' => false,
                    'message' => 'Invalid username or password'
                ];
            }
            
            // Update last login
            $updateStmt = $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
            $updateStmt->execute([$user['id']]);
            
            // Log activity
            logActivity($user['id'], 'USER_LOGIN', null, "User logged in: " . $user['username']);
            
            return [
                'success' => true,
                'user' => $user,
                'message' => 'Login successful'
            ];
            
        } catch (PDOException $e) {
            return [
                'success' => false,
                'message' => 'Authentication failed: Database error'
            ];
        }
    }
    
    // Get user files
    public static function getUserFiles($userId, $limit = 50, $offset = 0) {
        try {
            $db = getDB();
            $stmt = $db->prepare("
                SELECT id, original_filename, file_size, mime_type, upload_date, last_accessed
                FROM files 
                WHERE user_id = ? AND is_deleted = FALSE 
                ORDER BY upload_date DESC 
                LIMIT ? OFFSET ?
            ");
            $stmt->execute([$userId, $limit, $offset]);
            
            return $stmt->fetchAll();
            
        } catch (PDOException $e) {
            return [];
        }
    }
    
    // Get user statistics
    public static function getUserStats($userId) {
        try {
            $db = getDB();
            
            // Get file count and total size
            $stmt = $db->prepare("
                SELECT COUNT(*) as file_count, COALESCE(SUM(file_size), 0) as total_size
                FROM files 
                WHERE user_id = ? AND is_deleted = FALSE
            ");
            $stmt->execute([$userId]);
            $stats = $stmt->fetch();
            
            // Get recent activity count
            $activityStmt = $db->prepare("
                SELECT COUNT(*) as activity_count
                FROM activity_log 
                WHERE user_id = ? AND timestamp > DATE_SUB(NOW(), INTERVAL 7 DAY)
            ");
            $activityStmt->execute([$userId]);
            $activity = $activityStmt->fetch();
            
            return [
                'file_count' => $stats['file_count'],
                'total_size' => $stats['total_size'],
                'recent_activity' => $activity['activity_count']
            ];
            
        } catch (PDOException $e) {
            return [
                'file_count' => 0,
                'total_size' => 0,
                'recent_activity' => 0
            ];
        }
    }
}

// Database connection function
function getDB() {
    static $pdo = null;
    
    if ($pdo === null) {
        try {
            $pdo = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                ]
            );
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection failed");
        }
    }
    
    return $pdo;
}

// Activity logging function
function logActivity($userId, $action, $fileId = null, $details = null) {
    try {
        $db = getDB();
        $stmt = $db->prepare("
            INSERT INTO activity_log (user_id, action, file_id, ip_address, user_agent, details) 
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        
        $stmt->execute([$userId, $action, $fileId, $ipAddress, $userAgent, $details]);
        
    } catch (PDOException $e) {
        error_log("Failed to log activity: " . $e->getMessage());
    }
}

// Utility Functions
function formatFileSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    
    $bytes /= pow(1024, $pow);
    
    return round($bytes, 2) . ' ' . $units[$pow];
}

function timeAgo($datetime) {
    $time = time() - strtotime($datetime);
    
    if ($time < 60) return 'just now';
    if ($time < 3600) return floor($time/60) . ' minutes ago';
    if ($time < 86400) return floor($time/3600) . ' hours ago';
    if ($time < 2592000) return floor($time/86400) . ' days ago';
    if ($time < 31536000) return floor($time/2592000) . ' months ago';
    
    return floor($time/31536000) . ' years ago';
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function validatePassword($password) {
    return strlen($password) >= 8 && 
           preg_match('/[A-Z]/', $password) && 
           preg_match('/[a-z]/', $password) && 
           preg_match('/[0-9]/', $password);
}

function getUserInfo($userId) {
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT id, username, email, created_at, last_login FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            throw new Exception("User not found");
        }
        
        return $user;
    } catch (Exception $e) {
        error_log("Error getting user info: " . $e->getMessage());
        return false;
    }
}

function getUserFiles($userId, $search = '', $filter = 'all', $sort = 'newest') {
    try {
        $db = getDB(); // Use the centralized getDB() function
        
        $sql = "SELECT * FROM files WHERE user_id = :user_id AND is_deleted = FALSE";
        $params = ['user_id' => $userId];
        
        // Add search condition
        if (!empty($search)) {
            $sql .= " AND original_filename LIKE :search";
            $params['search'] = '%' . $search . '%';
        }
        
        // Add filter condition
        if ($filter !== 'all') {
            switch ($filter) {
                case 'image':
                    $sql .= " AND mime_type LIKE 'image/%'";
                    break;
                case 'document':
                    $sql .= " AND (mime_type LIKE 'application/msword%' OR mime_type LIKE 'application/vnd.openxmlformats-officedocument%')";
                    break;
                case 'pdf':
                    $sql .= " AND mime_type = 'application/pdf'";
                    break;
                case 'text':
                    $sql .= " AND mime_type LIKE 'text/%'";
                    break;
            }
        }
        
        // Add sort condition
        switch ($sort) {
            case 'oldest':
                $sql .= " ORDER BY upload_date ASC";
                break;
            case 'name':
                $sql .= " ORDER BY original_filename ASC";
                break;
            case 'size':
                $sql .= " ORDER BY file_size DESC";
                break;
            case 'newest':
            default:
                $sql .= " ORDER BY upload_date DESC";
                break;
        }
        
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Error fetching user files: " . $e->getMessage());
        return [];
    }
}

function getFileIcon($mimeType) {
    $iconMap = [
        'image/' => '<i class="fas fa-image text-success"></i>',
        'application/pdf' => '<i class="fas fa-file-pdf text-danger"></i>',
        'text/' => '<i class="fas fa-file-alt text-primary"></i>',
        'application/msword' => '<i class="fas fa-file-word text-primary"></i>',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => '<i class="fas fa-file-word text-primary"></i>',
        'application/vnd.ms-excel' => '<i class="fas fa-file-excel text-success"></i>',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => '<i class="fas fa-file-excel text-success"></i>',
        'application/vnd.ms-powerpoint' => '<i class="fas fa-file-powerpoint text-warning"></i>',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation' => '<i class="fas fa-file-powerpoint text-warning"></i>',
        'application/zip' => '<i class="fas fa-file-archive text-secondary"></i>',
        'application/x-rar-compressed' => '<i class="fas fa-file-archive text-secondary"></i>',
        'video/' => '<i class="fas fa-file-video text-info"></i>',
        'audio/' => '<i class="fas fa-file-audio text-warning"></i>',
    ];
    
    foreach ($iconMap as $type => $icon) {
        if (strpos($mimeType, $type) === 0) {
            return $icon;
        }
    }
    
    return '<i class="fas fa-file text-secondary"></i>';
}

function getRecentActivity($userId, $limit = 10) {
    try {
        $db = getDB();
        $stmt = $db->prepare("
            SELECT action, file_id, timestamp, details 
            FROM activity_log 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        ");
        $stmt->execute([$userId, $limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Error fetching recent activity: " . $e->getMessage());
        return [];
    }
}
?>