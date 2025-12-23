<?php
// Vulnerable file upload functionality
$upload_dir = '/var/www/html/uploads/';

if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

if ($_FILES['upload']) {
    $filename = $_FILES['upload']['name'];
    $tmp_name = $_FILES['upload']['tmp_name'];
    
    // No file type validation - vulnerable to malicious uploads
    $destination = $upload_dir . $filename;
    
    if (move_uploaded_file($tmp_name, $destination)) {
        echo "<h2>File uploaded successfully!</h2>";
        echo "<p>File saved as: <a href='uploads/" . $filename . "'>" . $filename . "</a></p>";
        
        // Execute uploaded PHP files - extremely dangerous
        if (pathinfo($filename, PATHINFO_EXTENSION) == 'php') {
            echo "<p>PHP file detected. Executing...</p>";
            include($destination);
        }
    } else {
        echo "<h2>Upload failed!</h2>";
    }
}
?>

<a href="index.php">Back to Login</a>