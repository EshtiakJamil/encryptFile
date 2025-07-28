<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Get search and filter parameters
$search = isset($_GET['search']) ? trim($_GET['search']) : '';
$filter = isset($_GET['filter']) ? $_GET['filter'] : 'all';
$sort = isset($_GET['sort']) ? $_GET['sort'] : 'newest';

// Get user files
$files = getUserFiles($_SESSION['user_id'], $search, $filter, $sort);
$userInfo = getUserInfo($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Files - Secure File Storage</title>
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
        
        .file-icon {
            font-size: 24px;
            margin-right: 10px;
        }
        
        .file-row:hover {
            background-color: #f8f9fa;
        }
        
        .search-filter-bar {
            background-color: #fff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .file-stats {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
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
                            <a href="files.php" class="nav-link active">
                                <i class="fas fa-folder"></i> My Files
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="profile.php" class="nav-link">
                                <i class="fas fa-user"></i> Profile
                            </a>
                        </li>
                    </ul>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-9">
                <div class="container-fluid py-4">
                    <h2><i class="fas fa-folder"></i> My Files</h2>
                    
                    <!-- File Statistics -->
                    <div class="file-stats">
                        <div class="row">
                            <div class="col-md-4">
                                <h4><?php echo count($files); ?></h4>
                                <p class="mb-0">Total Files</p>
                            </div>
                            <div class="col-md-4">
                                <h4><?php echo formatFileSize(array_sum(array_column($files, 'file_size'))); ?></h4>
                                <p class="mb-0">Total Size</p>
                            </div>
                            <div class="col-md-4">
                                <h4><?php echo date('M d, Y'); ?></h4>
                                <p class="mb-0">Last Login</p>
                            </div>
                        </div>
                    </div>

                    <!-- Search and Filter Bar -->
                    <div class="search-filter-bar">
                        <form method="GET" class="row g-3">
                            <div class="col-md-4">
                                <label class="form-label">Search Files</label>
                                <input type="text" name="search" class="form-control" 
                                       placeholder="Search by filename..." 
                                       value="<?php echo htmlspecialchars($search); ?>">
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Filter by Type</label>
                                <select name="filter" class="form-select">
                                    <option value="all" <?php echo $filter === 'all' ? 'selected' : ''; ?>>All Files</option>
                                    <option value="image" <?php echo $filter === 'image' ? 'selected' : ''; ?>>Images</option>
                                    <option value="document" <?php echo $filter === 'document' ? 'selected' : ''; ?>>Documents</option>
                                    <option value="pdf" <?php echo $filter === 'pdf' ? 'selected' : ''; ?>>PDF Files</option>
                                    <option value="text" <?php echo $filter === 'text' ? 'selected' : ''; ?>>Text Files</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <label class="form-label">Sort by</label>
                                <select name="sort" class="form-select">
                                    <option value="newest" <?php echo $sort === 'newest' ? 'selected' : ''; ?>>Newest First</option>
                                    <option value="oldest" <?php echo $sort === 'oldest' ? 'selected' : ''; ?>>Oldest First</option>
                                    <option value="name" <?php echo $sort === 'name' ? 'selected' : ''; ?>>Name A-Z</option>
                                    <option value="size" <?php echo $sort === 'size' ? 'selected' : ''; ?>>Size (Large to Small)</option>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <label class="form-label">&nbsp;</label>
                                <button type="submit" class="btn btn-primary d-block w-100">
                                    <i class="fas fa-search"></i> Search
                                </button>
                            </div>
                        </form>
                    </div>

                    <!-- Files List -->
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">Files (<?php echo count($files); ?>)</h5>
                            <a href="upload.php" class="btn btn-success btn-sm">
                                <i class="fas fa-plus"></i> Upload New File
                            </a>
                        </div>
                        <div class="card-body p-0">
                            <?php if (empty($files)): ?>
                                <div class="text-center py-5">
                                    <i class="fas fa-folder-open fa-3x text-muted mb-3"></i>
                                    <h5>No files found</h5>
                                    <p class="text-muted">
                                        <?php if ($search || $filter !== 'all'): ?>
                                            Try adjusting your search criteria or <a href="files.php">view all files</a>
                                        <?php else: ?>
                                            <a href="upload.php">Upload your first file</a> to get started
                                        <?php endif; ?>
                                    </p>
                                </div>
                            <?php else: ?>
                                <div class="table-responsive">
                                    <table class="table table-hover mb-0">
                                        <thead class="table-light">
                                            <tr>
                                                <th>File</th>
                                                <th>Size</th>
                                                <th>Type</th>
                                                <th>Uploaded</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($files as $file): ?>
                                                <tr class="file-row">
                                                    <td>
                                                        <div class="d-flex align-items-center">
                                                            <span class="file-icon">
                                                                <?php echo getFileIcon($file['mime_type']); ?>
                                                            </span>
                                                            <div>
                                                                <strong><?php echo htmlspecialchars($file['original_filename']); ?></strong>
                                                                <?php if ($file['last_accessed']): ?>
                                                                    <br><small class="text-muted">Last accessed: <?php echo date('M d, Y H:i', strtotime($file['last_accessed'])); ?></small>
                                                                <?php endif; ?>
                                                            </div>
                                                        </div>
                                                    </td>
                                                    <td><?php echo formatFileSize($file['file_size']); ?></td>
                                                    <td>
                                                        <span class="badge bg-secondary">
                                                            <?php echo strtoupper(pathinfo($file['original_filename'], PATHINFO_EXTENSION)); ?>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        <small class="text-muted">
                                                            <?php echo date('M d, Y H:i', strtotime($file['upload_date'])); ?>
                                                        </small>
                                                    </td>
                                                    <td>
                                                        <div class="btn-group btn-group-sm">
                                                            <a href="download.php?id=<?php echo $file['id']; ?>" 
                                                               class="btn btn-outline-primary" 
                                                               title="Download">
                                                                <i class="fas fa-download"></i>
                                                            </a>
                                                            <button type="button" 
                                                                    class="btn btn-outline-danger" 
                                                                    onclick="confirmDelete(<?php echo $file['id']; ?>, '<?php echo htmlspecialchars($file['original_filename'], ENT_QUOTES); ?>')"
                                                                    title="Delete">
                                                                <i class="fas fa-trash"></i>
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div class="modal fade" id="deleteModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Confirm Delete</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete <strong id="deleteFileName"></strong>?</p>
                    <p class="text-danger">This action cannot be undone.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <a href="#" id="deleteConfirmBtn" class="btn btn-danger">Delete File</a>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function confirmDelete(fileId, fileName) {
            document.getElementById('deleteFileName').textContent = fileName;
            document.getElementById('deleteConfirmBtn').href = 'delete.php?id=' + fileId;
            
            const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
            deleteModal.show();
        }

        // Auto-submit search form on filter/sort change
        document.querySelector('select[name="filter"]').addEventListener('change', function() {
            this.form.submit();
        });
        
        document.querySelector('select[name="sort"]').addEventListener('change', function() {
            this.form.submit();
        });
    </script>
</body>
</html>