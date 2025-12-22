<?php
// Vulnerable login page for security testing
$error = '';

if ($_POST['username'] && $_POST['password']) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // SQL Injection vulnerability (intentional)
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    
    // XSS vulnerability (intentional)
    if ($username == 'admin' && $password == 'password') {
        echo "<h2>Welcome " . $_POST['username'] . "!</h2>";
        echo "<p>Secret data: FLAG{docker_security_lab_complete}</p>";
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
    
    <p><em>Hint: Try SQL injection or XSS attacks!</em></p>
</body>
</html>