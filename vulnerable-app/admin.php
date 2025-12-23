<?php
// Vulnerable admin page with multiple security issues
session_start();

// Weak session management
if (!isset($_SESSION['logged_in'])) {
    // Still shows sensitive info even when not logged in
    echo "<p style='color: orange;'>Warning: You should be logged in to view this page</p>";
}

// Information disclosure
phpinfo();

echo "<h2>Admin Panel</h2>";
echo "<p>Database connection string: mysql://root:password123@localhost/webapp</p>";
echo "<p>API Key: sk-1234567890abcdef</p>";
echo "<p>Debug mode: ENABLED</p>";

// CSRF vulnerability
if ($_POST['action'] == 'delete_user') {
    $user_id = $_POST['user_id'];
    echo "<p>User " . $user_id . " would be deleted (CSRF vulnerable)</p>";
}
?>

<form method="POST">
    <input type="hidden" name="action" value="delete_user" />
    <input type="text" name="user_id" placeholder="User ID to delete" />
    <input type="submit" value="Delete User" />
</form>