<?php
require_once 'config.php';
require_once 'functions.php';

session_start();

// Redirect if already logged in
redirectIfLoggedIn();

$error = '';
$success = '';

// Handle registration form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please try again.';
    } else {
        $username = sanitizeInput($_POST['username'] ?? '');
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        // Validation
        if (empty($username) || empty($email) || empty($password) || empty($confirmPassword)) {
            $error = 'Please fill in all fields.';
        } elseif (strlen($username) < 3 || strlen($username) > 50) {
            $error = 'Username must be between 3 and 50 characters.';
        } elseif (!validateEmail($email)) {
            $error = 'Please enter a valid email address.';
        } elseif (!validatePassword($password)) {
            $error = 'Password must be at least 8 characters and contain uppercase, lowercase, and numbers.';
        } elseif ($password !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } else {
            $result = UserManager::createUser($username, $email, $password);
            
            if ($result['success']) {
                $success = 'Account created successfully! You can now log in.';
                // Clear form data
                $_POST = [];
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
    <title>Register - <?php echo SITE_NAME; ?></title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    
    <style>
        body {
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 50%, #000000 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 2rem 0;
            color: #ffffff;
        }
        
        .register-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            overflow: hidden;
            max-width: 500px;
            width: 100%;
            border: 2px solid #333333;
        }
        
        .register-header {
            background: linear-gradient(45deg, #000000, #333333);
            color: white;
            padding: 2rem;
            text-align: center;
            border-bottom: 2px solid #666666;
        }
        
        .register-form {
            padding: 2rem;
            background: #ffffff;
            color: #000000;
        }
        
        .form-control {
            border-radius: 15px;
            border: 2px solid #cccccc;
            padding: 15px 20px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: #ffffff;
            color: #000000;
        }
        
        .form-control:focus {
            border-color: #000000;
            box-shadow: 0 0 0 0.2rem rgba(0, 0, 0, 0.25);
            background: #ffffff;
            color: #000000;
        }
        
        .btn-register {
            background: linear-gradient(45deg, #000000, #333333);
            border: none;
            border-radius: 15px;
            padding: 15px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
            color: #ffffff;
        }
        
        .btn-register:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
            background: linear-gradient(45deg, #333333, #555555);
            color: #ffffff;
        }
        
        .input-group-text {
            background: #f8f9fa;
            border: 2px solid #cccccc;
            border-right: none;
            border-radius: 15px 0 0 15px;
            color: #000000;
        }
        
        .input-group .form-control {
            border-left: none;
            border-radius: 0 15px 15px 0;
        }
        
        .alert {
            border-radius: 15px;
            border: 2px solid;
        }
        
        .alert-danger {
            background: #f8f9fa;
            border-color: #666666;
            color: #000000;
        }
        
        .alert-success {
            background: #f8f9fa;
            border-color: #333333;
            color: #000000;
        }
        
        .register-links {
            text-align: center;
            margin-top: 2rem;
        }
        
        .register-links a {
            color: #000000;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
        }
        
        .register-links a:hover {
            color: #333333;
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
        
        .password-field {
            position: relative;
        }
        
        .brand-logo {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .password-strength {
            margin-top: 0.5rem;
        }
        
        .strength-bar {
            height: 4px;
            border-radius: 2px;
            background: #e9ecef;
            overflow: hidden;
        }
        
        .strength-fill {
            height: 100%;
            transition: all 0.3s ease;
            border-radius: 2px;
        }
        
        .strength-weak { background: #666666; width: 25%; }
        .strength-fair { background: #888888; width: 50%; }
        .strength-good { background: #333333; width: 75%; }
        .strength-strong { background: #000000; width: 100%; }
        
        .requirements {
            font-size: 0.875rem;
            margin-top: 0.5rem;
        }
        
        .requirement {
            color: #666666;
            transition: color 0.3s ease;
        }
        
        .requirement.met {
            color: #000000;
            font-weight: 600;
        }
        
        .form-label {
            color: #000000;
            font-weight: 600;
        }
        
        .form-text {
            color: #666666;
        }
        
        .form-check-label {
            color: #000000;
        }
        
        .form-check-input:checked {
            background-color: #000000;
            border-color: #000000;
        }
        
        .form-check-input:focus {
            border-color: #000000;
            box-shadow: 0 0 0 0.25rem rgba(0, 0, 0, 0.25);
        }
        
        .btn-close {
            filter: invert(1);
        }
        
        .text-success {
            color: #000000 !important;
        }
        
        .text-danger {
            color: #666666 !important;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="register-container mx-auto">
                    <div class="register-header">
                        <div class="brand-logo">
                            <i class="fas fa-user-plus"></i>
                        </div>
                        <h2 class="mb-0">Create Account</h2>
                        <p class="mb-0 opacity-75">Join our secure file storage platform</p>
                    </div>
                    
                    <div class="register-form">
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
                        
                        <form method="POST" action="register.php" id="registerForm">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                            
                            <div class="mb-4">
                                <label for="username" class="form-label fw-bold">
                                    <i class="fas fa-user me-2"></i>Username
                                </label>
                                <div class="input-group">
                                    <span class="input-group-text">
                                        <i class="fas fa-user"></i>
                                    </span>
                                    <input type="text" 
                                           class="form-control" 
                                           id="username" 
                                           name="username" 
                                           placeholder="Choose a username"
                                           value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                                           maxlength="50"
                                           required>
                                </div>
                                <div class="form-text">
                                    <i class="fas fa-info-circle me-1"></i>
                                    Username must be 3-50 characters long
                                </div>
                            </div>
                            
                            <div class="mb-4">
                                <label for="email" class="form-label fw-bold">
                                    <i class="fas fa-envelope me-2"></i>Email Address
                                </label>
                                <div class="input-group">
                                    <span class="input-group-text">
                                        <i class="fas fa-envelope"></i>
                                    </span>
                                    <input type="email" 
                                           class="form-control" 
                                           id="email" 
                                           name="email" 
                                           placeholder="Enter your email address"
                                           value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>"
                                           required>
                                </div>
                            </div>
                            
                            <div class="mb-4">
                                <label for="password" class="form-label fw-bold">
                                    <i class="fas fa-lock me-2"></i>Password
                                </label>
                                <div class="input-group password-field">
                                    <span class="input-group-text">
                                        <i class="fas fa-lock"></i>
                                    </span>
                                    <input type="password" 
                                           class="form-control" 
                                           id="password" 
                                           name="password" 
                                           placeholder="Create a strong password"
                                           required>
                                    <button type="button" class="password-toggle" onclick="togglePassword('password', 'passwordToggleIcon')">
                                        <i class="fas fa-eye" id="passwordToggleIcon"></i>
                                    </button>
                                </div>
                                <div class="password-strength">
                                    <div class="strength-bar">
                                        <div class="strength-fill" id="strengthFill"></div>
                                    </div>
                                    <div class="requirements mt-2">
                                        <div class="requirement" id="req-length">
                                            <i class="fas fa-times me-1"></i>At least 8 characters
                                        </div>
                                        <div class="requirement" id="req-upper">
                                            <i class="fas fa-times me-1"></i>One uppercase letter
                                        </div>
                                        <div class="requirement" id="req-lower">
                                            <i class="fas fa-times me-1"></i>One lowercase letter
                                        </div>
                                        <div class="requirement" id="req-number">
                                            <i class="fas fa-times me-1"></i>One number
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="mb-4">
                                <label for="confirm_password" class="form-label fw-bold">
                                    <i class="fas fa-lock me-2"></i>Confirm Password
                                </label>
                                <div class="input-group password-field">
                                    <span class="input-group-text">
                                        <i class="fas fa-lock"></i>
                                    </span>
                                    <input type="password" 
                                           class="form-control" 
                                           id="confirm_password" 
                                           name="confirm_password" 
                                           placeholder="Confirm your password"
                                           required>
                                    <button type="button" class="password-toggle" onclick="togglePassword('confirm_password', 'confirmToggleIcon')">
                                        <i class="fas fa-eye" id="confirmToggleIcon"></i>
                                    </button>
                                </div>
                                <div id="passwordMatch" class="form-text"></div>
                            </div>
                            
                            <div class="mb-4">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="agreeTerms" name="agree_terms" required>
                                    <label class="form-check-label" for="agreeTerms">
                                        I agree to the <a href="#" class="text-decoration-none">Terms of Service</a> and 
                                        <a href="#" class="text-decoration-none">Privacy Policy</a>
                                    </label>
                                </div>
                            </div>
                            
                            <div class="d-grid mb-4">
                                <button type="submit" class="btn btn-primary btn-register btn-lg" id="submitBtn">
                                    <i class="fas fa-user-plus me-2"></i>
                                    Create Account
                                </button>
                            </div>
                        </form>
                        
                        <div class="register-links">
                            <p class="mb-2">
                                Already have an account? 
                                <a href="login.php">
                                    <i class="fas fa-sign-in-alt me-1"></i>Sign in here
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
        function togglePassword(fieldId, iconId) {
            const passwordField = document.getElementById(fieldId);
            const toggleIcon = document.getElementById(iconId);
            
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                toggleIcon.className = 'fas fa-eye-slash';
            } else {
                passwordField.type = 'password';
                toggleIcon.className = 'fas fa-eye';
            }
        }
        
        // Password strength checker
        function checkPasswordStrength(password) {
            let strength = 0;
            const requirements = {
                length: password.length >= 8,
                upper: /[A-Z]/.test(password),
                lower: /[a-z]/.test(password),
                number: /[0-9]/.test(password)
            };
            
            // Update requirement indicators
            updateRequirement('req-length', requirements.length);
            updateRequirement('req-upper', requirements.upper);
            updateRequirement('req-lower', requirements.lower);
            updateRequirement('req-number', requirements.number);
            
            // Calculate strength
            Object.values(requirements).forEach(met => {
                if (met) strength++;
            });
            
            // Update strength bar
            const strengthFill = document.getElementById('strengthFill');
            strengthFill.className = 'strength-fill';
            
            if (strength === 0) {
                strengthFill.classList.add('strength-weak');
            } else if (strength === 1 || strength === 2) {
                strengthFill.classList.add('strength-fair');
            } else if (strength === 3) {
                strengthFill.classList.add('strength-good');
            } else if (strength === 4) {
                strengthFill.classList.add('strength-strong');
            }
            
            return strength === 4;
        }
        
        function updateRequirement(id, met) {
            const element = document.getElementById(id);
            const icon = element.querySelector('i');
            
            if (met) {
                element.classList.add('met');
                icon.className = 'fas fa-check me-1';
            } else {
                element.classList.remove('met');
                icon.className = 'fas fa-times me-1';
            }
        }
        
        // Check password match
        function checkPasswordMatch() {
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const matchIndicator = document.getElementById('passwordMatch');
            
            if (confirmPassword === '') {
                matchIndicator.innerHTML = '';
                return false;
            }
            
            if (password === confirmPassword) {
                matchIndicator.innerHTML = '<i class="fas fa-check text-success me-1"></i>Passwords match';
                matchIndicator.className = 'form-text text-success';
                return true;
            } else {
                matchIndicator.innerHTML = '<i class="fas fa-times text-danger me-1"></i>Passwords do not match';
                matchIndicator.className = 'form-text text-danger';
                return false;
            }
        }
        
        // Event listeners
        document.getElementById('password').addEventListener('input', function() {
            checkPasswordStrength(this.value);
            checkPasswordMatch();
        });
        
        document.getElementById('confirm_password').addEventListener('input', checkPasswordMatch);
        
        // Form validation
        document.getElementById('registerForm').addEventListener('submit', function(e) {
            const username = document.getElementById('username').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const agreeTerms = document.getElementById('agreeTerms').checked;
            
            let isValid = true;
            let errorMessage = '';
            
            if (!username || username.length < 3) {
                isValid = false;
                errorMessage = 'Username must be at least 3 characters long.';
            } else if (!email || !validateEmail(email)) {
                isValid = false;
                errorMessage = 'Please enter a valid email address.';
            } else if (!checkPasswordStrength(password)) {
                isValid = false;
                errorMessage = 'Password must meet all requirements.';
            } else if (password !== confirmPassword) {
                isValid = false;
                errorMessage = 'Passwords do not match.';
            } else if (!agreeTerms) {
                isValid = false;
                errorMessage = 'Please accept the terms and conditions.';
            }
            
            if (!isValid) {
                e.preventDefault();
                showAlert(errorMessage, 'danger');
                return false;
            }
            
            // Show loading state
            const submitBtn = document.getElementById('submitBtn');
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Creating Account...';
            submitBtn.disabled = true;
        });
        
        // Email validation
        function validateEmail(email) {
            const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return re.test(email);
        }
        
        // Show alert function
        function showAlert(message, type) {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
            alertDiv.innerHTML = `
                <i class="fas fa-exclamation-triangle me-2"></i>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            const form = document.getElementById('registerForm');
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
    </script>
</body>
</html>