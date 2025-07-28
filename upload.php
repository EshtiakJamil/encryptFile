<?php
session_start();
require_once 'config.php';
require_once 'functions.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$uploadMessage = '';
$uploadSuccess = false;

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    
    // Validate file upload
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $uploadMessage = 'File upload failed. Error code: ' . $file['error'];
    } elseif ($file['size'] > MAX_FILE_SIZE) {
        $uploadMessage = 'File size exceeds maximum allowed size of ' . formatFileSize(MAX_FILE_SIZE);
    } elseif ($file['size'] === 0) {
        $uploadMessage = 'Cannot upload empty files';
    } else {
        // Check file type
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 
                        'text/plain', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
        
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if (!in_array($mimeType, $allowedTypes)) {
            $uploadMessage = 'File type not allowed. Allowed types: JPEG, PNG, GIF, PDF, TXT, DOC, DOCX, XLS, XLSX';
        } else {
            // Process file upload
            $result = SecureFileHandler::storeEncryptedFile($file['tmp_name'], $_SESSION['user_id'], $file['name']);
            
            if ($result['success']) {
                $uploadSuccess = true;
                $uploadMessage = $result['message'];
            } else {
                $uploadMessage = $result['message'];
            }
        }
    }
}

// Get user info
$userInfo = getUserInfo($_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Files - Secure File Storage</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .upload-area {
            border: 2px dashed #007bff;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            transition: all 0.3s ease;
            background-color: #f8f9fa;
            cursor: pointer;
        }
        
        .upload-area:hover {
            border-color: #0056b3;
            background-color: #e9ecef;
        }
        
        .upload-area.dragover {
            border-color: #28a745;
            background-color: #d4edda;
        }
        
        .upload-icon {
            font-size: 48px;
            color: #007bff;
            margin-bottom: 20px;
        }
        
        .file-info {
            display: none;
            background-color: #fff;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-top: 20px;
        }
        
        .progress {
            display: none;
            margin-top: 20px;
        }
        
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
                            <a href="upload.php" class="nav-link active">
                                <i class="fas fa-upload"></i> Upload Files
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="files.php" class="nav-link">
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
                    <h2><i class="fas fa-upload"></i> Upload Files</h2>
                    <p class="text-muted">Upload your files securely. All files are encrypted before storage.</p>

                    <?php if ($uploadMessage): ?>
                        <div class="alert alert-<?php echo $uploadSuccess ? 'success' : 'danger'; ?> alert-dismissible fade show">
                            <?php echo htmlspecialchars($uploadMessage); ?>
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    <?php endif; ?>

                    <div class="row">
                        <div class="col-lg-8">
                            <div class="card">
                                <div class="card-body">
                                    <form id="uploadForm" method="POST" enctype="multipart/form-data">
                                        <div class="upload-area" id="uploadArea">
                                            <div class="upload-icon">
                                                <i class="fas fa-cloud-upload-alt"></i>
                                            </div>
                                            <h4>Drag & Drop Files Here</h4>
                                            <p class="text-muted">or click to browse files</p>
                                            <input type="file" name="file" id="fileInput" class="d-none" required>
                                            <button type="button" class="btn btn-primary" id="browseBtn">
                                                <i class="fas fa-folder-open"></i> Browse Files
                                            </button>
                                        </div>

                                        <div class="file-info" id="fileInfo">
                                            <h6>Selected File:</h6>
                                            <div id="fileName"></div>
                                            <div id="fileSize"></div>
                                            <div id="fileType"></div>
                                            <button type="submit" class="btn btn-success mt-3">
                                                <i class="fas fa-upload"></i> Upload File
                                            </button>
                                            <button type="button" class="btn btn-secondary mt-3" id="cancelBtn">
                                                <i class="fas fa-times"></i> Cancel
                                            </button>
                                        </div>

                                        <div class="progress" id="uploadProgress">
                                            <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                                 role="progressbar" style="width: 0%"></div>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>

                        <div class="col-lg-4">
                            <div class="card">
                                <div class="card-header">
                                    <h6><i class="fas fa-info-circle"></i> Upload Guidelines</h6>
                                </div>
                                <div class="card-body">
                                    <ul class="list-unstyled">
                                        <li><i class="fas fa-check text-success"></i> Maximum file size: <?php echo formatFileSize(MAX_FILE_SIZE); ?></li>
                                        <li><i class="fas fa-check text-success"></i> Allowed formats: JPEG, PNG, GIF, PDF, TXT, DOC, DOCX, XLS, XLSX</li>
                                        <li><i class="fas fa-lock text-warning"></i> Files are encrypted automatically</li>
                                        <li><i class="fas fa-shield-alt text-info"></i> Only you can access your files</li>
                                    </ul>
                                </div>
                            </div>

                            <div class="card mt-3">
                                <div class="card-header">
                                    <h6><i class="fas fa-chart-bar"></i> Storage Usage</h6>
                                </div>
                                <div class="card-body">
                                    <?php $stats = UserManager::getUserStats($_SESSION['user_id']); ?>
                                    <p><strong>Files:</strong> <?php echo $stats['file_count']; ?></p>
                                    <p><strong>Total Size:</strong> <?php echo formatFileSize($stats['total_size']); ?></p>
                                    <p><strong>Recent Activity:</strong> <?php echo $stats['recent_activity']; ?> actions this week</p>
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
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const browseBtn = document.getElementById('browseBtn');
        const fileInfo = document.getElementById('fileInfo');
        const fileName = document.getElementById('fileName');
        const fileSize = document.getElementById('fileSize');
        const fileType = document.getElementById('fileType');
        const cancelBtn = document.getElementById('cancelBtn');
        const uploadForm = document.getElementById('uploadForm');
        const uploadProgress = document.getElementById('uploadProgress');

        // Browse button click
        browseBtn.addEventListener('click', () => {
            fileInput.click();
        });

        // Upload area click
        uploadArea.addEventListener('click', (e) => {
            if (e.target !== browseBtn) {
                fileInput.click();
            }
        });

        // File input change
        fileInput.addEventListener('change', handleFileSelect);

        // Drag and drop events
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                handleFileSelect();
            }
        });

        // Cancel button
        cancelBtn.addEventListener('click', () => {
            fileInput.value = '';
            fileInfo.style.display = 'none';
            uploadProgress.style.display = 'none';
        });

        // Form submission
        uploadForm.addEventListener('submit', (e) => {
            if (fileInput.files.length > 0) {
                uploadProgress.style.display = 'block';
                const progressBar = uploadProgress.querySelector('.progress-bar');
                progressBar.style.width = '100%';
            }
        });

        function handleFileSelect() {
            const file = fileInput.files[0];
            if (file) {
                fileName.innerHTML = `<strong>Name:</strong> ${file.name}`;
                fileSize.innerHTML = `<strong>Size:</strong> ${formatFileSize(file.size)}`;
                fileType.innerHTML = `<strong>Type:</strong> ${file.type}`;
                fileInfo.style.display = 'block';
            }
        }

        function formatFileSize(bytes) {
            const units = ['B', 'KB', 'MB', 'GB'];
            let size = bytes;
            let unitIndex = 0;
            
            while (size >= 1024 && unitIndex < units.length - 1) {
                size /= 1024;
                unitIndex++;
            }
            
            return Math.round(size * 100) / 100 + ' ' + units[unitIndex];
        }
    </script>
</body>
</html>