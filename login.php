<?php
require_once 'config.php';
require_once 'functions.php';

session_start();

// Redirect if already logged in
redirectIfLoggedIn();

$error = '';
$success = '';

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $username = sanitizeInput($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        if (empty($username) || empty($password)) {
            $error = 'Please fill in all fields.';
        } else {
            $result = UserManager::authenticateUser($username, $password);
            
            if ($result['success']) {
                // Set session variables
                $_SESSION['user_id'] = $result['user']['id'];
                $_SESSION['username'] = $result['user']['username'];
                $_SESSION['email'] = $result['user']['email'];
                $_SESSION['login_time'] = time();
                
                // Regenerate session ID for security
                session_regenerate_id(true);
                
                // Redirect to dashboard
                header('Location: dashboard.php');
                exit();
            } else {
                $error = $result['message'];
            }
        }
    }
}

$csrfToken = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo SITE_NAME; ?></title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    
    <style>
        body {
            background: linear-gradient(135deg, #000000 0%, #333333 50%, #666666 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .login-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            overflow: hidden;
            border: 2px solid #e0e0e0;
        }
        
        .login-header {
            background: linear-gradient(45deg, #000000, #333333);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .login-form {
            padding: 2rem;
        }
        
        .form-control {
            border-radius: 15px;
            border: 2px solid #d0d0d0;
            padding: 15px 20px;
            font-size: 16px;
            transition: all 0.3s ease;
            background-color: #fafafa;
        }
        
        .form-control:focus {
            border-color: #333333;
            box-shadow: 0 0 0 0.2rem rgba(51, 51, 51, 0.25);
            background-color: white;
        }
        
        .btn-login {
            background: linear-gradient(45deg, #000000, #333333);
            border: none;
            border-radius: 15px;
            padding: 15px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
            color: white;
        }
        
        .btn-login:hover {
            background: linear-gradient(45deg, #333333, #555555);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.4);
            color: white;
        }
        
        .input-group-text {
            background: #f0f0f0;
            border: 2px solid #d0d0d0;
            border-right: none;
            border-radius: 15px 0 0 15px;
            color: #333333;
        }
        
        .input-group .form-control {
            border-left: none;
            border-radius: 0 15px 15px 0;
        }
        
        .alert {
            border-radius: 15px;
            border: none;
        }
        
        .alert-danger {
            background-color: #f8f9fa;
            color: #212529;
            border: 2px solid #dee2e6;
        }
        
        .alert-success {
            background-color: #f8f9fa;
            color: #212529;
            border: 2px solid #dee2e6;
        }
        
        .login-links {
            text-align: center;
            margin-top: 2rem;
        }
        
        .login-links a {
            color: #333333;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }
        
        .login-links a:hover {
            color: #000000;
            text-decoration: underline;
        }
        
        .password-field {
            position: relative;
        }
        
        .password-toggle {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #666666;
            cursor: pointer;
            z-index: 10;
        }
        
        .password-toggle:hover {
            color: #333333;
        }
        
        .input-group .password-toggle {
            right: 20px;
        }
        
        .brand-logo {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .form-check-input:checked {
            background-color: #333333;
            border-color: #333333;
        }
        
        .form-check-input:focus {
            border-color: #666666;
            box-shadow: 0 0 0 0.25rem rgba(51, 51, 51, 0.25);
        }
        
        .btn-close {
            filter: invert(0);
        }
        
        /* Custom scrollbar for webkit browsers */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #f1f1f1;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-5">
                <div class="login-container">
                    <div class="login-header">
                        <div class="brand-logo">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <h2 class="mb-0">Welcome Back</h2>
                        <p class="mb-0 opacity-75">Sign in to your secure account</p>
                    </div>
                    
                    <div class="login-form">
                        <?php if ($error): ?>
                            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                <?php echo htmlspecialchars($error); ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        <?php endif; ?>
                        
                        <?php if ($success): ?>
                            <div class="alert alert-success alert-dismissible fade show" role="alert">
                                <i class="fas fa-check-circle me-2"></i>
                                <?php echo htmlspecialchars($success); ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST" action="login.php" id="loginForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                            
                            <div class="mb-3">
                                <div class="input-group">
                                    <span class="input-group-text">
                                        <i class="fas fa-user"></i>
                                    </span>
                                    <input type="text" class="form-control" id="username" name="username" 
                                           placeholder="Username or Email" required autocomplete="username">
                                </div>
                            </div>
                            
                            <div class="mb-3">
                                <div class="input-group password-field">
                                    <span class="input-group-text">
                                        <i class="fas fa-lock"></i>
                                    </span>
                                    <input type="password" class="form-control" id="password" name="password" 
                                           placeholder="Password" required autocomplete="current-password">
                                    <button type="button" class="password-toggle" onclick="togglePassword()">
                                        <i class="fas fa-eye" id="passwordToggleIcon"></i>
                                    </button>
                                </div>
                            </div>
                            
                            <div class="mb-4">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="rememberMe" name="remember_me">
                                    <label class="form-check-label" for="rememberMe">
                                        Remember me
                                    </label>
                                </div>
                            </div>
                            
                            <div class="d-grid mb-4">
                                <button type="submit" class="btn btn-primary btn-login btn-lg">
                                    <i class="fas fa-sign-in-alt me-2"></i>
                                    Sign In
                                </button>
                            </div>
                        </form>
                        
                        <div class="login-links">
                            <p class="mb-2">
                                <a href="forgot-password.php">
                                    <i class="fas fa-key me-1"></i>Forgot Password?
                                </a>
                            </p>
                            <p class="mb-2">
                                Don't have an account? 
                                <a href="register.php">
                                    <i class="fas fa-user-plus me-1"></i>Sign up here
                                </a>
                            </p>
                            <p class="mb-0">
                                <a href="index.php">
                                    <i class="fas fa-arrow-left me-1"></i>Back to Home
                                </a>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Password toggle functionality
        function togglePassword() {
            const passwordField = document.getElementById('password');
            const toggleIcon = document.getElementById('passwordToggleIcon');
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                toggleIcon.className = 'fas fa-eye-slash';
            } else {
                passwordField.type = 'password';
                toggleIcon.className = 'fas fa-eye';
            }
        }
        
        // Form validation
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            
            if (!username || !password) {
                e.preventDefault();
                showAlert('Please fill in all fields.', 'danger');
                return false;
            }
            
            if (username.length < 3) {
                e.preventDefault();
                showAlert('Username must be at least 3 characters long.', 'danger');
                return false;
            }
            
            if (password.length < 6) {
                e.preventDefault();
                showAlert('Password must be at least 6 characters long.', 'danger');
                return false;
            }
            
            // Show loading state
            const submitBtn = document.querySelector('.btn-login');
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Signing In...';
            submitBtn.disabled = true;
        });
        
        // Show alert function
        function showAlert(message, type) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                <i class="fas fa-exclamation-triangle me-2"></i>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            const form = document.getElementById('loginForm');
            form.insertBefore(alertDiv, form.firstChild);
            
            // Auto dismiss after 5 seconds
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, 5000);
        }
        
        // Auto-hide alerts after 5 seconds
        document.addEventListener('DOMContentLoaded', function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                setTimeout(() => {
                    if (alert.parentNode) {
                        alert.remove();
                    }
                }, 5000);
            });
        });
        
        // Add focus animations
        const inputs = document.querySelectorAll('.form-control');
        inputs.forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement.style.transform = 'scale(1.02)';
            });
            
            input.addEventListener('blur', function() {
                this.parentElement.style.transform = 'scale(1)';
            });
        });
        
        // Prevent form resubmission on page refresh
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }
    </script>
</body>
</html>