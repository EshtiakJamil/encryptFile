<?php
session_start();
require_once 'config.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// try {
//     $db = getDB();
//     $userId = $_SESSION['user_id'];
    
//     // Log logout activity
//     if (function_exists('logActivity')) {
//         logActivity($userId, 'USER_LOGOUT', null, "User logged out");
//     }
    
//     // Invalidate session in database if session token exists
//     if (isset($_SESSION['session_token'])) {
//         $stmt = $db->prepare("UPDATE user_sessions SET is_active = FALSE WHERE session_token = ?");
//         $stmt->execute([$_SESSION['session_token']]);
//     }
    
//     // Clean up expired sessions for this user
//     $cleanupStmt = $db->prepare("UPDATE user_sessions SET is_active = FALSE WHERE user_id = ? AND expires_at < NOW()");
//     $cleanupStmt->execute([$userId]);
    
// } catch (Exception $e) {
//     // Continue with logout even if database operations fail
//     error_log("Logout cleanup error: " . $e->getMessage());
// }

// Clear all session data
$_SESSION = array();

// Delete the session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Destroy the session
session_destroy();

// Redirect to login page with logout message
header('Location: login.php?msg=logged_out');
exit();
?>