<?php
header('Content-Type: application/json');

if ($_GET['action'] === 'nmap') {
    $output = shell_exec('nmap -sV -sC -T4 vulnerable-web 2>&1');
    echo json_encode([
        'scan_type' => 'nmap',
        'target' => 'vulnerable-web',
        'timestamp' => date('Y-m-d H:i:s'),
        'results' => $output ?: 'nmap command failed'
    ]);
} elseif ($_GET['action'] === 'nikto') {
    // Use docker exec to run nikto from security-tools container (fixed syntax)
    $output = shell_exec('docker exec security-tools nikto -h http://vulnerable-web 2>&1');
    echo json_encode([
        'scan_type' => 'nikto', 
        'target' => 'vulnerable-web',
        'timestamp' => date('Y-m-d H:i:s'),
        'results' => $output ?: 'nikto command failed'
    ]);
} else {
    echo json_encode(['error' => 'Invalid action. Use ?action=nmap or ?action=nikto']);
}
?>
