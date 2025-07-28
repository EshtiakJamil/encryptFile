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
    header('Location: files.php?error=Invalid file ID');
    exit();
}

$fileId = (int)$_GET['id'];
$userId = $_SESSION['user_id'];

// Get database connection using the Database class
$pdo = Database::getInstance()->getConnection();

try {
    // Get file information and verify ownership
    $stmt = $pdo->prepare("
        SELECT id, user_id, original_filename, encrypted_filename, file_size
        FROM files 
        WHERE id = ? AND user_id = ? AND is_deleted = FALSE
    ");
    $stmt->execute([$fileId, $userId]);
    $file = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$file) {
        header('Location: files.php?error=File not found or access denied');
        exit();
    }

    // Handle POST request for actual deletion
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirm_delete'])) {
        
        // Begin transaction for atomic operation
        $pdo->beginTransaction();
        
        try {
            // Build the file path
            $uploadDir = rtrim(UPLOAD_DIR, '/') . '/';
            
            // Handle relative path - make it absolute if needed
            if (!is_dir($uploadDir)) {
                $uploadDir = __DIR__ . '/' . $uploadDir;
            }
            
            $physicalPath = $uploadDir . $file['encrypted_filename'];
            
            logActivity($userId, 'info', $fileId, 'Attempting to delete file: ' . $physicalPath);
            
            $fileDeleted = false;
            $errorMessage = '';
            
            // Check if file exists
            if (file_exists($physicalPath)) {
                // Simple deletion approach
                if (unlink($physicalPath)) {
                    $fileDeleted = true;
                    logActivity($userId, 'info', $fileId, 'Physical file deleted successfully: ' . $file['encrypted_filename']);
                } else {
                    // Get the last error for debugging
                    $lastError = error_get_last();
                    $errorMessage = $lastError ? $lastError['message'] : 'Unknown error during file deletion';
                    logActivity($userId, 'error', $fileId, 'File deletion failed: ' . $errorMessage);
                    
                    // Try alternative method on Windows
                    if (PHP_OS_FAMILY === 'Windows' && function_exists('exec')) {
                        $escapedPath = escapeshellarg($physicalPath);
                        $output = [];
                        $returnCode = -1;
                        
                        exec("del /F /Q $escapedPath 2>&1", $output, $returnCode);
                        
                        if ($returnCode === 0 && !file_exists($physicalPath)) {
                            $fileDeleted = true;
                            logActivity($userId, 'info', $fileId, 'Physical file deleted with system command: ' . $file['encrypted_filename']);
                        } else {
                            $errorMessage = 'Both unlink() and system command failed. Output: ' . implode(' ', $output);
                            logActivity($userId, 'error', $fileId, $errorMessage);
                        }
                    }
                }
            } else {
                // File doesn't exist physically, proceed with database cleanup
                logActivity($userId, 'warning', $fileId, 'Physical file not found, proceeding with database cleanup: ' . $file['encrypted_filename']);
                $fileDeleted = true;
            }

            // Update database if physical deletion was successful (or file didn't exist)
            if ($fileDeleted) {
                // Mark file as deleted in database (soft delete)
                $deleteStmt = $pdo->prepare("
                    UPDATE files 
                    SET is_deleted = TRUE 
                    WHERE id = ? AND user_id = ?
                ");
                $result = $deleteStmt->execute([$fileId, $userId]);
                
                if (!$result || $deleteStmt->rowCount() === 0) {
                    throw new Exception('Failed to update database record');
                }

                // Log deletion activity
                logActivity($userId, 'file_delete', $fileId, 'File deleted successfully: ' . $file['original_filename']);

                $pdo->commit();
                header('Location: files.php?success=' . urlencode('File "' . $file['original_filename'] . '" deleted successfully'));
                exit();
            } else {
                throw new Exception('File deletion failed: ' . $errorMessage);
            }

        } catch (Exception $e) {
            $pdo->rollBack();
            
            // Log the specific error
            $errorMsg = 'Error during file deletion: ' . $e->getMessage();
            logActivity($userId, 'error', $fileId, $errorMsg);
            
            header('Location: files.php?error=' . urlencode('File deletion failed: ' . $e->getMessage()));
            exit();
        }
    }

    // If not POST request, show confirmation page
    $userInfo = getUserInfo($userId);

} catch (PDOException $e) {
    logActivity($userId, 'error', $fileId, 'Database error during file deletion: ' . $e->getMessage());
    header('Location: files.php?error=' . urlencode('Database connection error'));
    exit();
} catch (Exception $e) {
    logActivity($userId, 'error', $fileId, 'General error during file deletion: ' . $e->getMessage());
    header('Location: files.php?error=' . urlencode('An unexpected error occurred'));
    exit();
}

// Direct delete action for testing
if (isset($_GET['action']) && $_GET['action'] === 'delete_now') {
    $uploadDir = rtrim(UPLOAD_DIR, '/') . '/';
    if (!is_dir($uploadDir)) {
        $uploadDir = __DIR__ . '/' . $uploadDir;
    }
    $physicalPath = $uploadDir . $file['encrypted_filename'];
    
    echo "<div class='alert alert-warning'>";
    echo "<h5>🔄 Direct Delete Action Started</h5>";
    echo "<p><strong>Target File:</strong> " . htmlspecialchars($physicalPath) . "</p>";
    
    if (file_exists($physicalPath)) {
        echo "<p>✅ File exists, attempting deletion...</p>";
        
        // Method 1: Simple unlink
        if (unlink($physicalPath)) {
            echo "<p>✅ <strong>SUCCESS!</strong> File deleted with unlink()</p>";
            
            // Update database
            try {
                $pdo->beginTransaction();
                $deleteStmt = $pdo->prepare("UPDATE files SET is_deleted = TRUE WHERE id = ? AND user_id = ?");
                $result = $deleteStmt->execute([$fileId, $userId]);
                
                if ($result && $deleteStmt->rowCount() > 0) {
                    logActivity($userId, 'file_delete', $fileId, 'File deleted via direct action: ' . $file['original_filename']);
                    $pdo->commit();
                    echo "<p>✅ Database updated successfully</p>";
                    echo "<p><a href='files.php' class='btn btn-success'>Return to Files</a></p>";
                } else {
                    $pdo->rollBack();
                    echo "<p>❌ Database update failed</p>";
                }
            } catch (Exception $e) {
                $pdo->rollBack();
                echo "<p>❌ Database error: " . htmlspecialchars($e->getMessage()) . "</p>";
            }
        } else {
            echo "<p>❌ unlink() failed, trying alternative method...</p>";
            
            // Method 2: System command
            if (PHP_OS_FAMILY === 'Windows' && function_exists('exec')) {
                $escapedPath = escapeshellarg($physicalPath);
                $output = [];
                $returnCode = -1;
                
                exec("del /F /Q $escapedPath 2>&1", $output, $returnCode);
                
                if ($returnCode === 0 && !file_exists($physicalPath)) {
                    echo "<p>✅ <strong>SUCCESS!</strong> File deleted with system command</p>";
                } else {
                    echo "<p>❌ System command failed. Return code: $returnCode</p>";
                    echo "<p>Output: " . htmlspecialchars(implode(' ', $output)) . "</p>";
                    
                    // Method 3: Try with different approach
                    $lastError = error_get_last();
                    echo "<p>Last PHP error: " . htmlspecialchars($lastError ? $lastError['message'] : 'None') . "</p>";
                }
            } else {
                echo "<p>❌ No alternative deletion method available</p>";
            }
        }
    } else {
        echo "<p>❌ File does not exist at specified path</p>";
    }
    
    echo "</div>";
}

// Enhanced debugging information
if (isset($_GET['debug']) && $_GET['debug'] === '1') {
    $uploadDir = rtrim(UPLOAD_DIR, '/') . '/';
    if (!is_dir($uploadDir)) {
        $uploadDir = __DIR__ . '/' . $uploadDir;
    }
    $fullPath = $uploadDir . $file['encrypted_filename'];
    
    echo "<div class='alert alert-info'>";
    echo "<h5>Debug Information:</h5>";
    echo "<p><strong>Upload Dir Constant:</strong> " . UPLOAD_DIR . "</p>";
    echo "<p><strong>Resolved Upload Dir:</strong> " . $uploadDir . "</p>";
    echo "<p><strong>Full File Path:</strong> " . $fullPath . "</p>";
    echo "<p><strong>File Exists:</strong> " . (file_exists($fullPath) ? 'Yes' : 'No') . "</p>";
    echo "<p><strong>Directory Exists:</strong> " . (is_dir($uploadDir) ? 'Yes' : 'No') . "</p>";
    echo "<p><strong>Directory Writable:</strong> " . (is_writable($uploadDir) ? 'Yes' : 'No') . "</p>";
    echo "<p><strong>Current Working Directory:</strong> " . getcwd() . "</p>";
    echo "<p><strong>Script Directory:</strong> " . __DIR__ . "</p>";
    
    if (file_exists($fullPath)) {
        echo "<p><strong>File Readable:</strong> " . (is_readable($fullPath) ? 'Yes' : 'No') . "</p>";
        echo "<p><strong>File Writable:</strong> " . (is_writable($fullPath) ? 'Yes' : 'No') . "</p>";
        echo "<p><strong>File Permissions:</strong> " . substr(sprintf('%o', fileperms($fullPath)), -4) . "</p>";
        echo "<p><strong>File Size:</strong> " . filesize($fullPath) . " bytes</p>";
        
        // Test deletion capability
        echo "<p><strong>Deletion Test:</strong> ";
        $testPath = $uploadDir . 'test_delete_' . time() . '.tmp';
        if (file_put_contents($testPath, 'test')) {
            if (unlink($testPath)) {
                echo "✅ Can create and delete files in directory";
            } else {
                echo "❌ Can create but cannot delete files in directory";
            }
        } else {
            echo "❌ Cannot create files in directory";
        }
        echo "</p>";
    }
    
    echo "<p><strong>PHP OS Family:</strong> " . PHP_OS_FAMILY . "</p>";
    echo "<p><strong>Exec Function Available:</strong> " . (function_exists('exec') ? 'Yes' : 'No') . "</p>";
    echo "<p><strong>Disabled Functions:</strong> " . (ini_get('disable_functions') ?: 'None') . "</p>";
    
    // Show recent error logs
    echo "<h6>Recent PHP Errors:</h6>";
    $errorLog = ini_get('error_log');
    if ($errorLog && file_exists($errorLog)) {
        $lines = file($errorLog);
        $recentLines = array_slice($lines, -10);
        echo "<pre style='font-size: 12px; max-height: 200px; overflow-y: auto;'>";
        foreach ($recentLines as $line) {
            echo htmlspecialchars($line);
        }
        echo "</pre>";
    } else {
        echo "<p>No error log found or accessible</p>";
    }
    
    echo "</div>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Delete File - Secure File Storage</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .navbar-brand {
            font-weight: bold;
        }
        
        .danger-zone {
            border: 2px solid #dc3545;
            border-radius: 10px;
            background-color: #f8d7da;
            padding: 30px;
            text-align: center;
        }
        
        .file-info {
            background-color: #fff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="index.php">
                <i class="fas fa-shield-alt"></i> Secure File Storage
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, <?php echo htmlspecialchars($userInfo['username']); ?></span>
                <a class="nav-link" href="logout.php">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </a>
            </div>
        </div>
    </nav>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header bg-danger text-white">
                        <h4 class="mb-0">
                            <i class="fas fa-exclamation-triangle"></i> Delete File
                        </h4>
                    </div>
                    <div class="card-body">
                        <div class="file-info">
                            <h5>File Information</h5>
                            <div class="row">
                                <div class="col-md-6">
                                    <p><strong>Filename:</strong> <?php echo htmlspecialchars($file['original_filename']); ?></p>
                                    <p><strong>Size:</strong> <?php echo formatFileSize($file['file_size']); ?></p>
                                </div>
                                <div class="col-md-6">
                                    <p><strong>File ID:</strong> #<?php echo $file['id']; ?></p>
                                    <p><strong>Owner:</strong> <?php echo htmlspecialchars($userInfo['username']); ?></p>
                                </div>
                            </div>
                        </div>

                        <div class="danger-zone">
                            <i class="fas fa-trash-alt fa-3x text-danger mb-3"></i>
                            <h4 class="text-danger">Permanent Deletion Warning</h4>
                            <p class="mb-4">
                                You are about to permanently delete this file. This action cannot be undone.
                                The encrypted file will be removed from our servers immediately.
                            </p>

                            <form method="POST" class="mt-4">
                                <div class="d-grid gap-2 d-md-flex justify-content-md-center">
                                    <a href="files.php" class="btn btn-secondary btn-lg me-md-2">
                                        <i class="fas fa-arrow-left"></i> Cancel
                                    </a>
                                    <button type="submit" name="confirm_delete" class="btn btn-danger btn-lg" 
                                            onclick="return confirmDeletion()">
                                        <i class="fas fa-trash"></i> Delete Forever
                                    </button>
                                </div>
                            </form>
                        </div>

                        <div class="mt-4">
                            <h6>What happens when you delete a file?</h6>
                            <ul class="list-unstyled">
                                <li><i class="fas fa-check text-success me-2"></i> File is immediately removed from your file list</li>
                                <li><i class="fas fa-check text-success me-2"></i> File becomes completely unrecoverable</li>
                                <li><i class="fas fa-check text-success me-2"></i> Storage space is freed up</li>
                            </ul>
                        </div>
                        
                        <!-- Debug and Direct Delete Actions -->
                        <div class="mt-3">
                            <?php if (!isset($_GET['debug']) && !isset($_GET['action'])): ?>
                            <a href="?id=<?php echo $fileId; ?>&debug=1" class="btn btn-sm btn-outline-info me-2">
                                <i class="fas fa-bug"></i> Show Debug Info
                            </a>
                            <?php endif; ?>
                            
                            <?php if (!isset($_GET['action'])): ?>
                            <a href="?id=<?php echo $fileId; ?>&action=delete_now" class="btn btn-sm btn-warning" 
                               onclick="return confirm('This will immediately attempt to delete the file. Continue?')">
                                <i class="fas fa-bolt"></i> Direct Delete (Test)
                            </a>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function confirmDeletion() {
            return confirm('Are you absolutely sure you want to delete this file? This action cannot be undone.');
        }

        // Add visual feedback for form submission
        document.querySelector('form').addEventListener('submit', function(e) {
            const btn = document.querySelector('button[name="confirm_delete"]');
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deleting...';
            btn.disabled = true;
        });
    </script>
</body>
</html>