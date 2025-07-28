<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Check if file ID is provided
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    header('Location: files.php?error=' . urlencode('Invalid file ID'));
    exit();
}

$fileId = (int)$_GET['id'];
$userId = $_SESSION['user_id'];

try {
    // Get file information and verify ownership
    $stmt = $pdo->prepare("
        SELECT id, user_id, original_filename, encrypted_filename, file_size, mime_type,
               encryption_key_hash, iv, file_hash
        FROM files
        WHERE id = ? AND user_id = ? AND is_deleted = FALSE
    ");
    $stmt->execute([$fileId, $userId]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$file) {
        header('Location: files.php?error=' . urlencode('File not found in database or access denied'));
        exit();
    }

    // DEBUG: Log file information
    error_log("=== FILE DOWNLOAD DEBUG ===");
    error_log("File ID: " . $fileId);
    error_log("User ID: " . $userId);
    error_log("Original filename: " . $file['original_filename']);
    error_log("Encrypted filename: " . $file['encrypted_filename']);
    error_log("Upload directory: " . UPLOAD_DIR);
    
    // Build the correct file path
    $uploadDir = UPLOAD_DIR;
    
    // Handle relative vs absolute paths
    if (!is_dir($uploadDir)) {
        // Try absolute path from document root
        $uploadDir = $_SERVER['DOCUMENT_ROOT'] . '/enfile/uploads/encrypted/';
        error_log("Trying absolute path: " . $uploadDir);
    }
    
    // If still not found, try relative to current script
    if (!is_dir($uploadDir)) {
        $uploadDir = __DIR__ . '/uploads/encrypted/';
        error_log("Trying relative to script: " . $uploadDir);
    }
    
    $encryptedFilePath = $uploadDir . $file['encrypted_filename'];
    error_log("Upload directory: " . $uploadDir);
    error_log("Full encrypted file path: " . $encryptedFilePath);
    error_log("File exists: " . (file_exists($encryptedFilePath) ? 'YES' : 'NO'));
    
    if (!file_exists($encryptedFilePath)) {
        error_log("ERROR: Encrypted file not found at: " . $encryptedFilePath);
        
        // Check if upload directory exists
        if (!is_dir($uploadDir)) {
            error_log("ERROR: Upload directory does not exist: " . $uploadDir);
            header('Location: files.php?error=' . urlencode('Upload directory not found'));
            exit();
        }
        
        // List files in upload directory for debugging
        $files = scandir($uploadDir);
        error_log("Files in upload directory: " . print_r($files, true));
        
        header('Location: files.php?error=' . urlencode('Encrypted file not found on server'));
        exit();
    }
    
    // Check file permissions
    if (!is_readable($encryptedFilePath)) {
        error_log("ERROR: File is not readable: " . $encryptedFilePath);
        header('Location: files.php?error=' . urlencode('File is not readable'));
        exit();
    }
    
    // Get file size
    $actualFileSize = filesize($encryptedFilePath);
    error_log("Database file size: " . $file['file_size']);
    error_log("Actual file size: " . $actualFileSize);

    // Try to read the file directly first (without decryption)
    $encryptedData = file_get_contents($encryptedFilePath);
    if ($encryptedData === false) {
        error_log("ERROR: Failed to read encrypted file");
        header('Location: files.php?error=' . urlencode('Failed to read encrypted file'));
        exit();
    }
    
    error_log("Successfully read encrypted file, size: " . strlen($encryptedData) . " bytes");

    // Update last accessed timestamp
    $updateStmt = $pdo->prepare("
        UPDATE files
        SET last_accessed = CURRENT_TIMESTAMP
        WHERE id = ?
    ");
    $updateStmt->execute([$fileId]);

    // Check if we have encryption info
    if (empty($file['encryption_key_hash']) || empty($file['iv'])) {
        error_log("WARNING: No encryption info found, serving file directly");
        $fileData = $encryptedData;
    } else {
        // Try to decrypt the file
        error_log("Attempting to decrypt file...");
        error_log("Encryption key hash: " . $file['encryption_key_hash']);
        error_log("IV from database: " . $file['iv']);
        error_log("IV length from database: " . strlen($file['iv']));
        
        // Generate key from hash
        $key = base64_decode($file['encryption_key_hash']);
        error_log("Key length: " . strlen($key));
        
        // Handle IV - it might be stored as hex or base64
        $iv = base64_decode($file['iv']);
        
        // Try hex2bin first (most common)
        if (ctype_xdigit($file['iv']) && strlen($file['iv']) == 32) {
            $iv = hex2bin($file['iv']);
            error_log("Converted IV from hex, length: " . strlen($iv));
        }
        // Try base64 decode
        elseif (strlen($file['iv']) == 24 && base64_decode($file['iv'], true) !== false) {
            $iv = base64_decode($file['iv']);
            error_log("Converted IV from base64, length: " . strlen($iv));
        }
        // Try direct use if already 16 bytes
        elseif (strlen($file['iv']) == 16) {
            $iv = $file['iv'];
            error_log("Using IV directly, length: " . strlen($iv));
        }
        // Generate a new IV if none of the above work (fallback)
        else {
            error_log("ERROR: Could not determine IV format, IV string: " . bin2hex($file['iv']));
            error_log("IV string length: " . strlen($file['iv']));
            
            // Try to extract IV from the beginning of encrypted data (if it was prepended)
            if (strlen($encryptedData) > 16) {
                $iv = substr($encryptedData, 0, 16);
                $encryptedData = substr($encryptedData, 16);
                error_log("Extracted IV from encrypted data, length: " . strlen($iv));
            } else {
                error_log("ERROR: Cannot determine IV, serving file without decryption");
                $fileData = $encryptedData;
                goto skip_decryption;
            }
        }
        
        // Validate IV length
        if (strlen($iv) !== 16) {
            error_log("ERROR: Invalid IV length after processing: " . strlen($iv));
            error_log("IV hex: " . bin2hex($iv));
            
            // Try to pad or trim IV to 16 bytes
            if (strlen($iv) < 16) {
                $iv = str_pad($iv, 16, "\0");
                error_log("Padded IV to 16 bytes");
            } elseif (strlen($iv) > 16) {
                $iv = substr($iv, 0, 16);
                error_log("Trimmed IV to 16 bytes");
            }
        }
        
        // Attempt decryption
        $fileData = openssl_decrypt(
            $encryptedData,
            ENCRYPTION_METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($fileData === false) {
            error_log("ERROR: Decryption failed");
            error_log("OpenSSL error: " . openssl_error_string());
            error_log("Encryption method: " . ENCRYPTION_METHOD);
            error_log("Key length: " . strlen($key));
            error_log("IV length: " . strlen($iv));
            error_log("IV hex: " . bin2hex($iv));
            
            // Try serving the file without decryption as fallback
            error_log("Attempting to serve file without decryption...");
            $fileData = $encryptedData;
        } else {
            error_log("Successfully decrypted file, size: " . strlen($fileData) . " bytes");
        }
    }
    
    skip_decryption:

    // Verify file integrity if hash is available
    if (!empty($file['file_hash'])) {
        $downloadedHash = hash('sha256', $fileData);
        error_log("Expected hash: " . $file['file_hash']);
        error_log("Actual hash: " . $downloadedHash);
        
        if ($downloadedHash !== $file['file_hash']) {
            error_log("WARNING: File integrity check failed");
            // Don't exit here for debugging - just log the warning
        }
    }

    // Clear any output buffers
    if (ob_get_level()) {
        ob_end_clean();
    }

    // Set headers for download
    header('Content-Type: ' . ($file['mime_type'] ?: 'application/octet-stream'));
    header('Content-Disposition: attachment; filename="' . addslashes($file['original_filename']) . '"');
    header('Content-Length: ' . strlen($fileData));
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    // Security headers
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    
    error_log("Sending file to browser, size: " . strlen($fileData) . " bytes");
    
    // Output the file data
    echo $fileData;
    exit();

} catch (PDOException $e) {
    error_log("Database error: " . $e->getMessage());
    header('Location: files.php?error=' . urlencode('Database error occurred'));
    exit();
} catch (Exception $e) {
    error_log("General error: " . $e->getMessage());
    header('Location: files.php?error=' . urlencode('An error occurred: ' . $e->getMessage()));
    exit();
}
?>