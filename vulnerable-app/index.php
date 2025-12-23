<?php
// Vulnerable login page for security testing
$error = '';
session_start();

// Command Injection vulnerability
if (isset($_GET['ping'])) {
    $host = $_GET['host'] ?? 'localhost';
    // Vulnerable to command injection
    $output = shell_exec("ping -c 1 " . $host);
    echo "<pre>Ping Results:\n" . $output . "</pre>";
}

// File Inclusion vulnerability
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    // Vulnerable to LFI/RFI
    include($page . '.php');
}

// Directory Traversal vulnerability
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    // Vulnerable to directory traversal
    $content = file_get_contents($file);
    echo "<pre>" . htmlspecialchars($content) . "</pre>";
}

// Insecure Direct Object Reference
if (isset($_GET['user_id'])) {
    $user_id = $_GET['user_id'];
    // No authorization check
    echo "<h3>User Profile for ID: " . $user_id . "</h3>";
    echo "<p>Sensitive user data would be displayed here...</p>";
}

if ($_POST['username'] && $_POST['password']) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // SQL Injection vulnerability (intentional)
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    
    // XSS vulnerability (intentional)
    if ($username == 'admin' && $password == 'password') {
        echo "<h2>Welcome " . $_POST['username'] . "!</h2>";
        echo "<p>Secret data: FLAG{docker_security_lab_complete}</p>";
        $_SESSION['logged_in'] = true;
        $_SESSION['username'] = $username;
    } else {
        $error = "Invalid credentials for user: " . $_POST['username'];
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Login</title>
</head>
<body>
    <h1>Security Lab - Vulnerable Login</h1>
    
    <?php if ($error): ?>
        <div style="color: red;"><?php echo $error; ?></div>
    <?php endif; ?>
    
    <form method="POST">
        <p>Username: <input type="text" name="username" /></p>
        <p>Password: <input type="password" name="password" /></p>
        <p><input type="submit" value="Login" /></p>
    </form>
    
    <div style="margin-top: 30px; border-top: 1px solid #ccc; padding-top: 20px;">
        <h3>Additional Vulnerable Features:</h3>
        
        <h4>Command Injection Test:</h4>
        <form method="GET">
            <input type="text" name="host" placeholder="Enter host to ping" />
            <input type="submit" name="ping" value="Ping Host" />
        </form>
        
        <h4>File Operations:</h4>
        <a href="?page=admin">Admin Page</a> | 
        <a href="?file=/etc/passwd">View System File</a> |
        <a href="?user_id=1">User Profile 1</a>
        
        <h4>Upload Area:</h4>
        <form method="POST" enctype="multipart/form-data" action="upload.php">
            <input type="file" name="upload" />
            <input type="submit" value="Upload File" />
        </form>
    </div>
    
    <p><em>Hint: Try SQL injection, XSS, command injection, or file inclusion attacks!</em></p>
</body>
</html>
