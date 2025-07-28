<?php
session_start();

// Check if user is already logged in
$isLoggedIn = isset($_SESSION['user_id']);
$username = $isLoggedIn ? $_SESSION['username'] : '';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Storage System</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome for icons -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    
    <style>
        :root {
            --primary-black: #000000;
            --dark-gray: #1a1a1a;
            --medium-gray: #333333;
            --light-gray: #666666;
            --lighter-gray: #999999;
            --lightest-gray: #cccccc;
            --pure-white: #ffffff;
            --off-white: #f8f9fa;
        }
        
        body {
            background: linear-gradient(135deg, var(--primary-black) 0%, var(--dark-gray) 50%, var(--medium-gray) 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            position: relative;
            overflow-x: hidden;
            color: var(--pure-white);
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 20%, rgba(255, 255, 255, 0.05) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(255, 255, 255, 0.03) 0%, transparent 50%),
                radial-gradient(circle at 40% 60%, rgba(255, 255, 255, 0.02) 0%, transparent 50%);
            pointer-events: none;
            z-index: -1;
        }
        
        .hero-section {
            padding: 120px 0 80px;
            color: var(--pure-white);
            text-align: center;
            position: relative;
        }
        
        .hero-title {
            font-size: 4rem;
            font-weight: 900;
            margin-bottom: 1.5rem;
            text-shadow: 3px 3px 12px rgba(0,0,0,0.8);
            background: linear-gradient(45deg, var(--pure-white), var(--lightest-gray), var(--pure-white));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -2px;
        }
        
        .hero-subtitle {
            font-size: 1.4rem;
            margin-bottom: 3rem;
            opacity: 0.9;
            text-shadow: 2px 2px 6px rgba(0,0,0,0.5);
            max-width: 600px;
            margin-left: auto;
            margin-right: auto;
            color: var(--lightest-gray);
        }
        
        .feature-card {
            background: linear-gradient(145deg, var(--pure-white), var(--off-white));
            border-radius: 20px;
            padding: 2.5rem;
            margin: 1rem 0;
            box-shadow: 
                0 20px 40px rgba(0,0,0,0.3),
                inset 0 1px 0 rgba(255,255,255,0.9);
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            border: 1px solid rgba(0,0,0,0.1);
            position: relative;
            overflow: hidden;
        }
        
        .feature-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-black), var(--medium-gray), var(--primary-black));
        }
        
        .feature-card:hover {
            transform: translateY(-15px) scale(1.03);
            box-shadow: 
                0 30px 60px rgba(0,0,0,0.4),
                inset 0 1px 0 rgba(255,255,255,1);
            background: linear-gradient(145deg, var(--pure-white), #fafafa);
        }
        
        .feature-icon {
            font-size: 3.5rem;
            margin-bottom: 1.5rem;
            transition: all 0.4s ease;
            filter: drop-shadow(0 6px 12px rgba(0,0,0,0.2));
            color: var(--primary-black);
        }
        
        .feature-card:hover .feature-icon {
            transform: scale(1.15) rotate(5deg);
            filter: drop-shadow(0 8px 16px rgba(0,0,0,0.3));
        }
        
        .feature-card h4 {
            color: var(--primary-black);
            font-weight: 800;
            margin-bottom: 1rem;
            font-size: 1.3rem;
            letter-spacing: -0.5px;
        }
        
        .feature-card p {
            color: var(--light-gray);
            line-height: 1.6;
            font-size: 1rem;
            font-weight: 500;
        }
        
        .btn-custom {
            border: 2px solid var(--pure-white);
            background: linear-gradient(145deg, var(--primary-black), var(--dark-gray));
            /* border: 2px solid var(--primary-black); */
            border-radius: 50px;
            padding: 15px 35px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.4s ease;
            box-shadow: 
                0 10px 25px rgba(0,0,0,0.4),
                inset 0 1px 0 rgba(255,255,255,0.1);
            color: var(--pure-white);
            text-decoration: none;
            display: inline-block;
            position: relative;
            overflow: hidden;
        }
        
        .btn-custom::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.6s ease;
        }
        
        .btn-custom:hover::before {
            left: 100%;
        }
        
        .btn-custom:hover {
            transform: translateY(-4px);
            box-shadow: 
                0 15px 35px rgba(0,0,0,0.5),
                inset 0 1px 0 rgba(255,255,255,0.2);
            background: linear-gradient(145deg, var(--dark-gray), var(--primary-black));
            color: var(--pure-white);
            border-color: var(--dark-gray);
        }
        
        .btn-outline-custom {
            border: 2px solid var(--pure-white);
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50px;
            padding: 13px 33px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.4s ease;
            color: var(--pure-white);
            text-decoration: none;
            display: inline-block;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.3);
            position: relative;
            overflow: hidden;
        }
        
        .btn-outline-custom::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: var(--pure-white);
            transition: left 0.4s ease;
            z-index: -1;
        }
        
        .btn-outline-custom:hover::before {
            left: 0;
        }
        
        .btn-outline-custom:hover {
            background: var(--pure-white);
            border-color: var(--pure-white);
            transform: translateY(-4px);
            color: var(--primary-black);
            box-shadow: 0 12px 30px rgba(0,0,0,0.4);
        }
        
        .navbar-custom {
            background: rgba(255, 255, 255, 0.98);
            backdrop-filter: blur(20px);
            box-shadow: 0 4px 30px rgba(0,0,0,0.2);
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }
        
        .navbar-brand {
            font-weight: 900;
            font-size: 1.6rem;
            color: var(--primary-black) !important;
            letter-spacing: -1px;
        }
        
        .navbar-brand i {
            color: var(--primary-black);
        }
        
        .nav-link {
            font-weight: 700;
            color: var(--primary-black) !important;
            transition: all 0.3s ease;
            position: relative;
        }
        
        .nav-link::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            width: 0;
            height: 2px;
            background: var(--primary-black);
            transition: all 0.3s ease;
            transform: translateX(-50%);
        }
        
        .nav-link:hover::after {
            width: 80%;
        }
        
        .nav-link:hover {
            color: var(--primary-black) !important;
            transform: translateY(-1px);
        }
        
        .stats-section {
            background: linear-gradient(145deg, rgba(255, 255, 255, 0.15), rgba(255, 255, 255, 0.05));
            border-radius: 25px;
            padding: 3rem 2rem;
            margin: 4rem 0;
            backdrop-filter: blur(20px);
            border: 2px solid rgba(255, 255, 255, 0.2);
            box-shadow: 
                0 25px 50px rgba(0,0,0,0.3),
                inset 0 1px 0 rgba(255,255,255,0.3);
        }
        
        .stat-item {
            text-align: center;
            position: relative;
        }
        
        .stat-number {
            font-size: 4rem;
            font-weight: 900;
            background: linear-gradient(45deg, var(--pure-white), var(--lightest-gray), var(--pure-white));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
            text-shadow: 2px 2px 8px rgba(0,0,0,0.5);
            letter-spacing: -2px;
        }
        
        .stat-label {
            font-size: 1.2rem;
            color: var(--lightest-gray);
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .footer-custom {
            background: linear-gradient(145deg, var(--primary-black), var(--dark-gray));
            color: var(--pure-white);
            padding: 3rem 0;
            margin-top: 5rem;
            position: relative;
            box-shadow: 0 -10px 30px rgba(0,0,0,0.5);
        }
        
        .footer-custom::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--pure-white), var(--lightest-gray), var(--pure-white));
        }
        
        .section-features {
            padding: 5rem 0;
            position: relative;
        }
        
        .floating-shapes {
            position: absolute;
            width: 100%;
            height: 100%;
            overflow: hidden;
            pointer-events: none;
        }
        
        .shape {
            position: absolute;
            opacity: 0.08;
            animation: float 8s ease-in-out infinite;
            background: var(--pure-white);
        }
        
        .shape-1 {
            top: 10%;
            left: 10%;
            width: 120px;
            height: 120px;
            border-radius: 50%;
            animation-delay: 0s;
            box-shadow: 0 10px 30px rgba(255,255,255,0.1);
        }
        
        .shape-2 {
            top: 60%;
            right: 15%;
            width: 100px;
            height: 100px;
            transform: rotate(45deg);
            animation-delay: 3s;
            box-shadow: 0 10px 30px rgba(255,255,255,0.1);
        }
        
        .shape-3 {
            bottom: 20%;
            left: 20%;
            width: 80px;
            height: 80px;
            border-radius: 30%;
            animation-delay: 6s;
            box-shadow: 0 10px 30px rgba(255,255,255,0.1);
        }
        
        @keyframes float {
            0%, 100% { 
                transform: translateY(0px) rotate(0deg); 
                opacity: 0.08;
            }
            50% { 
                transform: translateY(-30px) rotate(180deg); 
                opacity: 0.12;
            }
        }
        
        .dropdown-menu {
            background: var(--pure-white);
            border: 1px solid rgba(0,0,0,0.1);
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            border-radius: 10px;
        }
        
        .dropdown-item {
            color: var(--primary-black);
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .dropdown-item:hover {
            background: var(--off-white);
            color: var(--primary-black);
            transform: translateX(5px);
        }
        
        @media (max-width: 768px) {
            .hero-title {
                font-size: 2.8rem;
            }
            
            .hero-subtitle {
                font-size: 1.2rem;
            }
            
            .stat-number {
                font-size: 3rem;
            }
            
            .feature-card {
                padding: 2rem;
            }
            
            .btn-custom, .btn-outline-custom {
                padding: 12px 28px;
                font-size: 0.9rem;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light navbar-custom fixed-top">
        <div class="container">
            <a class="navbar-brand fw-bold" href="index.php">
                <i class="fas fa-shield-alt me-2"></i>
                SecureFiles
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <?php if ($isLoggedIn): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="dashboard.php">
                                <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="upload.php">
                                <i class="fas fa-upload me-1"></i>Upload
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="files.php">
                                <i class="fas fa-folder me-1"></i>My Files
                            </a>
                        </li>
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
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="login.php">
                                <i class="fas fa-sign-in-alt me-1"></i>Login
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="register.php">
                                <i class="fas fa-user-plus me-1"></i>Register
                            </a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-10">
                    <h1 class="hero-title">
                        <i class="fas fa-lock me-3"></i>
                        Secure File Storage
                    </h1>
                    <p class="hero-subtitle">
                        Your files, encrypted and protected with military-grade security. 
                        Upload, store, and access your documents with complete peace of mind.
                    </p>
                    
                    <?php if (!$isLoggedIn): ?>
                        <div class="mt-4">
                            <a href="register.php" class="btn-custom me-3">
                                <i class="fas fa-rocket me-2"></i>Get Started
                            </a>
                            <a href="login.php" class="btn-outline-custom">
                                <i class="fas fa-sign-in-alt me-2"></i>Sign In
                            </a>
                        </div>
                    <?php else: ?>
                        <div class="mt-4">
                            <a href="dashboard.php" class="btn-custom me-3">
                                <i class="fas fa-tachometer-alt me-2"></i>Go to Dashboard
                            </a>
                            <a href="upload.php" class="btn-outline-custom">
                                <i class="fas fa-upload me-2"></i>Upload Files
                            </a>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Stats Section -->
            <div class="row stats-section">
                <div class="col-md-4 stat-item">
                    <div class="stat-number">256</div>
                    <div class="stat-label">Bit Encryption</div>
                </div>
                <div class="col-md-4 stat-item">
                    <div class="stat-number">100%</div>
                    <div class="stat-label">Secure</div>
                </div>
                <div class="col-md-4 stat-item">
                    <div class="stat-number">24/7</div>
                    <div class="stat-label">Protected</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section class="section-features">
        <div class="floating-shapes">
            <div class="shape shape-1"></div>
            <div class="shape shape-2"></div>
            <div class="shape shape-3"></div>
        </div>
        
        <div class="container">
            <div class="row">
                <div class="col-lg-4">
                    <div class="feature-card text-center">
                        <div class="feature-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <h4>Military-Grade Encryption</h4>
                        <p>Your files are protected with AES-256 encryption, the same standard used by governments and militaries worldwide for maximum security.</p>
                    </div>
                </div>
                
                <div class="col-lg-4">
                    <div class="feature-card text-center">
                        <div class="feature-icon">
                            <i class="fas fa-cloud-upload-alt"></i>
                        </div>
                        <h4>Easy File Upload</h4>
                        <p>Simple drag-and-drop interface makes uploading your files quick and effortless. No technical knowledge required for secure storage.</p>
                    </div>
                </div>
                
                <div class="col-lg-4">
                    <div class="feature-card text-center">
                        <div class="feature-icon">
                            <i class="fas fa-user-lock"></i>
                        </div>
                        <h4>Private & Secure</h4>
                        <p>Only you have access to your files. We use zero-knowledge architecture - even we can't see your private data.</p>
                    </div>
                </div>
            </div>
            
            <div class="row mt-4">
                <div class="col-lg-4">
                    <div class="feature-card text-center">
                        <div class="feature-icon">
                            <i class="fas fa-download"></i>
                        </div>
                        <h4>Instant Access</h4>
                        <p>Access and download your files anytime, anywhere. Your encrypted data is always available when you need it most.</p>
                    </div>
                </div>
                
                <div class="col-lg-4">
                    <div class="feature-card text-center">
                        <div class="feature-icon">
                            <i class="fas fa-history"></i>
                        </div>
                        <h4>Activity Monitoring</h4>
                        <p>Keep track of all file activities with detailed logs and timestamps for complete transparency and security auditing.</p>
                    </div>
                </div>
                
                <div class="col-lg-4">
                    <div class="feature-card text-center">
                        <div class="feature-icon">
                            <i class="fas fa-mobile-alt"></i>
                        </div>
                        <h4>Cross-Platform</h4>
                        <p>Access your secure files from any device - desktop, tablet, or mobile. Responsive design optimized for all screen sizes.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer-custom text-center">
        <div class="container">
            <div class="row">
                <div class="col-md-12">
                    <p class="mb-2">&copy; 2025 Secure File Storage System. Built with security in mind.</p>
                    <p class="mb-0">
                        <i class="fas fa-lock me-2"></i>
                        Your privacy is our priority
                    </p>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Add smooth scrolling and animations
        document.addEventListener('DOMContentLoaded', function() {
            // Animate feature cards on scroll
            const observerOptions = {
                threshold: 0.1,
                rootMargin: '0px 0px -50px 0px'
            };
            
            const observer = new IntersectionObserver(function(entries) {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.style.opacity = '1';
                        entry.target.style.transform = 'translateY(0)';
                    }
                });
            }, observerOptions);
            
            // Observe all feature cards
            document.querySelectorAll('.feature-card').forEach((card, index) => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(60px)';
                card.style.transition = `opacity 1s ease ${index * 0.15}s, transform 1s ease ${index * 0.15}s`;
                observer.observe(card);
            });
            
            // Add navbar background on scroll
            window.addEventListener('scroll', function() {
                const navbar = document.querySelector('.navbar-custom');
                if (window.scrollY > 50) {
                    navbar.style.background = 'rgba(255, 255, 255, 0.99)';
                    navbar.style.boxShadow = '0 4px 35px rgba(0,0,0,0.25)';
                } else {
                    navbar.style.background = 'rgba(255, 255, 255, 0.98)';
                    navbar.style.boxShadow = '0 4px 30px rgba(0,0,0,0.2)';
                }
            });
            
            // Add parallax effect to floating shapes
            window.addEventListener('scroll', function() {
                const scrolled = window.pageYOffset;
                const shapes = document.querySelectorAll('.shape');
                
                shapes.forEach((shape, index) => {
                    const speed = 0.3 + (index * 0.1);
                    const yPos = -(scrolled * speed);
                    shape.style.transform = `translateY(${yPos}px)`;
                });
            });
            
            // Add smooth hover effects to buttons
            document.querySelectorAll('.btn-custom, .btn-outline-custom').forEach(btn => {
                btn.addEventListener('mouseenter', function() {
                    this.style.transform = 'translateY(-4px) scale(1.02)';
                });
                
                btn.addEventListener('mouseleave', function() {
                    this.style.transform = 'translateY(0) scale(1)';
                });
            });
        });
    </script>
</body>
</html>