<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$userId = $_SESSION['user_id'];
$message = '';
$messageType = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Update Profile Information
    if (isset($_POST['update_profile'])) {
        $newUsername = trim($_POST['username']);
        $newEmail = trim($_POST['email']);
        
        // Validate inputs
        if (empty($newUsername) || empty($newEmail)) {
            $message = 'Username and email are required';
            $messageType = 'danger';
        } elseif (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            $message = 'Please enter a valid email address';
            $messageType = 'danger';
        } else {
            try {
                // Check if username/email already exists (excluding current user)
                $checkStmt = $pdo->prepare("
                    SELECT id FROM users 
                    WHERE (username = ? OR email = ?) AND id != ?
                ");
                $checkStmt->execute([$newUsername, $newEmail, $userId]);
                
                if ($checkStmt->fetch()) {
                    $message = 'Username or email already exists';
                    $messageType = 'danger';
                } else {
                    // Update profile
                    $updateStmt = $pdo->prepare("
                        UPDATE users 
                        SET username = ?, email = ? 
                        WHERE id = ?
                    ");
                    $updateStmt->execute([$newUsername, $newEmail, $userId]);
                    
                    logActivity($userId, 'profile_update', null, 'Profile information updated');
                    $message = 'Profile updated successfully';
                    $messageType = 'success';
                }
            } catch (PDOException $e) {
                $message = 'Database error occurred';
                $messageType = 'danger';
            }
        }
    }
    
    // Change Password
    if (isset($_POST['change_password'])) {
        $currentPassword = $_POST['current_password'];
        $newPassword = $_POST['new_password'];
        $confirmPassword = $_POST['confirm_password'];
        
        // Validate inputs
        if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
            $message = 'All password fields are required';
            $messageType = 'danger';
        } elseif ($newPassword !== $confirmPassword) {
            $message = 'New passwords do not match';
            $messageType = 'danger';
        } elseif (strlen($newPassword) < 6) {
            $message = 'New password must be at least 6 characters long';
            $messageType = 'danger';
        } else {
            try {
                // Verify current password
                $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
                $stmt->execute([$userId]);
                $user = $stmt->fetch();
                
                if (!password_verify($currentPassword, $user['password_hash'])) {
                    $message = 'Current password is incorrect';
                    $messageType = 'danger';
                } else {
                    // Update password
                    $hashedNewPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                    $updateStmt = $pdo->prepare("
                        UPDATE users 
                        SET password_hash = ? 
                        WHERE id = ?
                    ");
                    $updateStmt->execute([$hashedNewPassword, $userId]);
                    
                    logActivity($userId, 'password_change', null, 'Password changed successfully');
                    $message = 'Password changed successfully';
                    $messageType = 'success';
                    
                    // Clear password fields
                    $_POST = array();
                }
            } catch (PDOException $e) {
                $message = 'Database error occurred';
                $messageType = 'danger';
            }
        }
    }
}

// Get user information and statistics
$userInfo = getUserInfo($userId);
$userStats = UserManager::getUserStats($userId);
$recentActivity = getRecentActivity($userId, 10);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - Secure File Storage</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .navbar-brand {
            font-weight: bold;
        }
        
        .sidebar {
            background-color: #f8f9fa;
            min-height: calc(100vh - 56px);
        }
        
        .nav-link {
            color: #495057;
        }
        
        .nav-link:hover, .nav-link.active {
            color: #007bff;
            background-color: #e9ecef;
        }
        
        .profile-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
        }
        
        .stats-card {
            border: none;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .stats-card:hover {
            transform: translateY(-2px);
        }
        
        .activity-item {
            border-left: 3px solid #007bff;
            padding-left: 15px;
            margin-bottom: 15px;
        }
        
        .form-section {
            background-color: #fff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 25px;
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

    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 sidebar">
                <div class="d-flex flex-column p-3">
                    <ul class="nav nav-pills flex-column mb-auto">
                        <li class="nav-item">
                            <a href="index.php" class="nav-link">
                                <i class="fas fa-home"></i> Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="upload.php" class="nav-link">
                                <i class="fas fa-upload"></i> Upload Files
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="files.php" class="nav-link">
                                <i class="fas fa-folder"></i> My Files
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="profile.php" class="nav-link active">
                                <i class="fas fa-user"></i> Profile
                            </a>
                        </li>
                    </ul>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-9">
                <div class="container-fluid py-4">
                    <!-- Profile Header -->
                    <div class="profile-header">
                        <div class="row align-items-center">
                            <div class="col-md-8">
                                <h2><i class="fas fa-user-circle"></i> Profile Settings</h2>
                                <p class="mb-0">Manage your account information and security settings</p>
                            </div>
                            <div class="col-md-4 text-end">
                                <div class="text-end">
                                    <p class="mb-1">Member since</p>
                                    <h5><?php echo date('F Y', strtotime($userInfo['created_at'])); ?></h5>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Alert Messages -->
                    <?php if ($message): ?>
                        <div class="alert alert-<?php echo $messageType; ?> alert-dismissible fade show">
                            <?php echo htmlspecialchars($message); ?>
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    <?php endif; ?>

                    <div class="row">
                        <!-- Profile Forms -->
                        <div class="col-lg-8">
                            <!-- Update Profile Form -->
                            <div class="form-section">
                                <h5><i class="fas fa-user-edit"></i> Update Profile Information</h5>
                                <form method="POST">
                                    <div class="row">
                                        <div class="col-md-6">
                                            <label class="form-label">Username</label>
                                            <input type="text" name="username" class="form-control" 
                                                   value="<?php echo htmlspecialchars($userInfo['username']); ?>" required>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Email Address</label>
                                            <input type="email" name="email" class="form-control" 
                                                   value="<?php echo htmlspecialchars($userInfo['email']); ?>" required>
                                        </div>
                                    </div>
                                    <div class="mt-3">
                                        <button type="submit" name="update_profile" class="btn btn-primary">
                                            <i class="fas fa-save"></i> Update Profile
                                        </button>
                                    </div>
                                </form>
                            </div>

                            <!-- Change Password Form -->
                            <div class="form-section">
                                <h5><i class="fas fa-lock"></i> Change Password</h5>
                                <form method="POST">
                                    <div class="mb-3">
                                        <label class="form-label">Current Password</label>
                                        <input type="password" name="current_password" class="form-control" required>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <label class="form-label">New Password</label>
                                            <input type="password" name="new_password" class="form-control" 
                                                   minlength="6" required>
                                            <div class="form-text">Minimum 6 characters</div>
                                        </div>
                                        <div class="col-md-6">
                                            <label class="form-label">Confirm New Password</label>
                                            <input type="password" name="confirm_password" class="form-control" 
                                                   minlength="6" required>
                                        </div>
                                    </div>
                                    <div class="mt-3">
                                        <button type="submit" name="change_password" class="btn btn-warning">
                                            <i class="fas fa-key"></i> Change Password
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>

                        <!-- Statistics and Activity -->
                        <div class="col-lg-4">
                            <!-- Statistics Cards -->
                            <div class="row mb-4">
                                <div class="col-12 mb-3">
                                    <div class="card stats-card text-center">
                                        <div class="card-body">
                                            <i class="fas fa-files-o fa-2x text-primary mb-2"></i>
                                            <h4><?php echo $userStats['file_count']; ?></h4>
                                            <p class="text-muted mb-0">Total Files</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12 mb-3">
                                    <div class="card stats-card text-center">
                                        <div class="card-body">
                                            <i class="fas fa-hdd fa-2x text-success mb-2"></i>
                                            <h4><?php echo formatFileSize($userStats['total_size']); ?></h4>
                                            <p class="text-muted mb-0">Storage Used</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="card stats-card text-center">
                                        <div class="card-body">
                                            <i class="fas fa-chart-line fa-2x text-warning mb-2"></i>
                                            <h4><?php echo $userStats['recent_activity']; ?></h4>
                                            <p class="text-muted mb-0">Recent Actions</p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Recent Activity -->
                            <div class="card">
                                <div class="card-header">
                                    <h6><i class="fas fa-history"></i> Recent Activity</h6>
                                </div>
                                <div class="card-body">
                                    <?php if (empty($recentActivity)): ?>
                                        <p class="text-muted">No recent activity</p>
                                    <?php else: ?>
                                        <?php foreach ($recentActivity as $activity): ?>
                                            <div class="activity-item">
                                                <div class="d-flex justify-content-between">
                                                    <strong><?php echo ucfirst(str_replace('_', ' ', $activity['action'])); ?></strong>
                                                    <small class="text-muted">
                                                        <?php echo date('M d, H:i', strtotime($activity['timestamp'])); ?>
                                                    </small>
                                                </div>
                                                <?php if ($activity['details']): ?>
                                                    <small class="text-muted">
                                                        <?php echo htmlspecialchars($activity['details']); ?>
                                                    </small>
                                                <?php endif; ?>
                                            </div>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Account Information -->
                    <div class="row mt-4">
                        <div class="col-12">
                            <div class="card">
                                <div class="card-header">
                                    <h6><i class="fas fa-info-circle"></i> Account Information</h6>
                                </div>
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col-md-6">
                                            <p><strong>Account ID:</strong> #<?php echo $userInfo['id']; ?></p>
                                            <p><strong>Username:</strong> <?php echo htmlspecialchars($userInfo['username']); ?></p>
                                            <p><strong>Email:</strong> <?php echo htmlspecialchars($userInfo['email']); ?></p>
                                        </div>
                                        <div class="col-md-6">
                                            <p><strong>Member Since:</strong> <?php echo date('F d, Y', strtotime($userInfo['created_at'])); ?></p>
                                            <p><strong>Last Login:</strong> 
                                                <?php echo $userInfo['last_login'] ? date('F d, Y H:i', strtotime($userInfo['last_login'])) : 'Never'; ?>
                                            </p>
                                            <p><strong>Account Status:</strong> 
                                                <span class="badge bg-success">Active</span>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Password confirmation validation
        const newPasswordInput = document.querySelector('input[name="new_password"]');
        const confirmPasswordInput = document.querySelector('input[name="confirm_password"]');
        
        function validatePasswords() {
            if (newPasswordInput.value !== confirmPasswordInput.value) {
                confirmPasswordInput.setCustomValidity('Passwords do not match');
            } else {
                confirmPasswordInput.setCustomValidity('');
            }
        }
        
        if (newPasswordInput && confirmPasswordInput) {
            newPasswordInput.addEventListener('input', validatePasswords);
            confirmPasswordInput.addEventListener('input', validatePasswords);
        }
    </script>
</body>
</html>