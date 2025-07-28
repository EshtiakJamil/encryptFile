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
$username = $_SESSION['username'] ?? 'User';

// Get user statistics
$stats = UserManager::getUserStats($userId);

// Get recent files
$recentFiles = UserManager::getUserFiles($userId, 5, 0);

// Get recent activity
try {
    $db = getDB();
    $activityStmt = $db->prepare("
        SELECT action, details, timestamp 
        FROM activity_log 
        WHERE user_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 10
    ");
    $activityStmt->execute([$userId]);
    $recentActivity = $activityStmt->fetchAll();
} catch (Exception $e) {
    $recentActivity = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Secure File Storage</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .dashboard-card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .dashboard-card:hover {
            transform: translateY(-5px);
        }
        .stat-icon {
            font-size: 2.5rem;
            opacity: 0.8;
        }
        .activity-item {
            border-left: 3px solid #007bff;
            padding-left: 15px;
            margin-bottom: 15px;
        }
        .navbar-brand {
            font-weight: bold;
        }
    </style>
</head>
<body class="bg-light">
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">
                <i class="fas fa-shield-alt me-2"></i>Secure Files
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link active" href="dashboard.php">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="files.php">My Files</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="upload.php">Upload</a>
                    </li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user me-1"></i><?php echo htmlspecialchars($username); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user-cog me-2"></i>Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Welcome Header -->
        <div class="row mb-4">
            <div class="col-12">
                <h1 class="display-6">Welcome back, <?php echo htmlspecialchars($username); ?>!</h1>
                <p class="text-muted">Here's an overview of your secure file storage account.</p>
            </div>
        </div>

        <!-- Statistics Cards -->
        <div class="row mb-4">
            <div class="col-lg-4 col-md-6 mb-3">
                <div class="card dashboard-card text-white bg-primary">
                    <div class="card-body">
                        <div class="d-flex justify-content-between">
                            <div>
                                <h5 class="card-title">Total Files</h5>
                                <h2 class="mb-0"><?php echo number_format($stats['file_count']); ?></h2>
                            </div>
                            <div class="stat-icon">
                                <i class="fas fa-file-alt"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-4 col-md-6 mb-3">
                <div class="card dashboard-card text-white bg-success">
                    <div class="card-body">
                        <div class="d-flex justify-content-between">
                            <div>
                                <h5 class="card-title">Storage Used</h5>
                                <h2 class="mb-0"><?php echo formatFileSize($stats['total_size']); ?></h2>
                            </div>
                            <div class="stat-icon">
                                <i class="fas fa-hdd"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-4 col-md-6 mb-3">
                <div class="card dashboard-card text-white bg-info">
                    <div class="card-body">
                        <div class="d-flex justify-content-between">
                            <div>
                                <h5 class="card-title">Recent Activity</h5>
                                <h2 class="mb-0"><?php echo number_format($stats['recent_activity']); ?></h2>
                                <small>Last 7 days</small>
                            </div>
                            <div class="stat-icon">
                                <i class="fas fa-activity"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Recent Files -->
            <div class="col-lg-8 mb-4">
                <div class="card dashboard-card">
                    <div class="card-header bg-white">
                        <h5 class="mb-0"><i class="fas fa-file me-2"></i>Recent Files</h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($recentFiles)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-folder-open fa-3x text-muted mb-3"></i>
                                <p class="text-muted">No files uploaded yet</p>
                                <a href="upload.php" class="btn btn-primary">Upload Your First File</a>
                            </div>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>File Name</th>
                                            <th>Size</th>
                                            <th>Uploaded</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($recentFiles as $file): ?>
                                        <tr>
                                            <td>
                                                <i class="fas fa-file me-2 text-primary"></i>
                                                <?php echo htmlspecialchars($file['original_filename']); ?>
                                            </td>
                                            <td><?php echo formatFileSize($file['file_size']); ?></td>
                                            <td><?php echo timeAgo($file['upload_date']); ?></td>
                                            <td>
                                                <a href="download.php?id=<?php echo $file['id']; ?>" 
                                                   class="btn btn-sm btn-outline-primary" title="Download">
                                                    <i class="fas fa-download"></i>
                                                </a>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                            <div class="text-center">
                                <a href="files.php" class="btn btn-outline-primary">View All Files</a>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Recent Activity -->
            <div class="col-lg-4 mb-4">
                <div class="card dashboard-card">
                    <div class="card-header bg-white">
                        <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent Activity</h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($recentActivity)): ?>
                            <p class="text-muted text-center">No recent activity</p>
                        <?php else: ?>
                            <?php foreach ($recentActivity as $activity): ?>
                                <div class="activity-item">
                                    <small class="text-muted"><?php echo timeAgo($activity['timestamp']); ?></small>
                                    <div class="fw-bold">
                                        <?php
                                        $actionText = [
                                            'FILE_UPLOAD' => 'File Uploaded',
                                            'FILE_DOWNLOAD' => 'File Downloaded',
                                            'FILE_DELETE' => 'File Deleted',
                                            'USER_LOGIN' => 'Logged In',
                                            'USER_LOGOUT' => 'Logged Out'
                                        ];
                                        echo $actionText[$activity['action']] ?? $activity['action'];
                                        ?>
                                    </div>
                                    <?php if ($activity['details']): ?>
                                        <small class="text-muted"><?php echo htmlspecialchars($activity['details']); ?></small>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card dashboard-card">
                    <div class="card-body text-center">
                        <h5 class="mb-3">Quick Actions</h5>
                        <a href="upload.php" class="btn btn-primary me-2 mb-2">
                            <i class="fas fa-upload me-2"></i>Upload File
                        </a>
                        <a href="files.php" class="btn btn-outline-primary me-2 mb-2">
                            <i class="fas fa-folder me-2"></i>Browse Files
                        </a>
                        <a href="profile.php" class="btn btn-outline-secondary mb-2">
                            <i class="fas fa-user-cog me-2"></i>Account Settings
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>