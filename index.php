<?php
declare(strict_types=1);

/**
 * xsukax Directory Listing System (XDLS)
 * Version: 2.0.0
 */

// ===========================
// Configuration
// ===========================
final class Config {
    public const SHOW_HIDDEN = 'hidden';
    public const FOLLOW_SYMLINKS = false;
    public const ENABLE_DOWNLOADS = true;
    public const ENABLE_UPLOADS = true; // Set to true to enable uploads
    public const MAX_UPLOAD_SIZE = 10485760; // 10MB
    public const TIMEZONE = 'UTC';
    public const ITEMS_PER_PAGE = 100; // Pagination support
    public const ENABLE_PREVIEWS = true;
    public const CACHE_TTL = 3600; // 1 hour
    
    // Security settings
    public const DISALLOWED_EXTENSIONS = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar',
        'cgi', 'pl', 'sh', 'bash', 'bat', 'cmd', 'com', 'exe', 'ps1',
        'htaccess', 'htpasswd'
    ];
    
    public const MIME_TYPES = [
        'txt' => 'text/plain',
        'html' => 'text/html',
        'css' => 'text/css',
        'js' => 'application/javascript',
        'json' => 'application/json',
        'xml' => 'application/xml',
        'pdf' => 'application/pdf',
        'zip' => 'application/zip',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'svg' => 'image/svg+xml',
        'mp3' => 'audio/mpeg',
        'mp4' => 'video/mp4',
        'webm' => 'video/webm',
        'doc' => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls' => 'application/vnd.ms-excel',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ];
}

// ===========================
// Security Headers & Session
// ===========================
session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:;");
}

date_default_timezone_set(Config::TIMEZONE);

// ===========================
// Utility Functions
// ===========================
class Utils {
    public static function h(string $s): string {
        return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
    
    public static function getExtension(string $filename): string {
        return strtolower((pathinfo($filename, PATHINFO_EXTENSION) ?: ''));
    }
    
    public static function isHidden(string $name): bool {
        return $name !== '' && $name[0] === '.';
    }
    
    public static function formatBytes(?int $bytes): string {
        if ($bytes === null) return '—';
        if ($bytes === 0) return '0 B';
        
        $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        $factor = floor((strlen((string)$bytes) - 1) / 3);
        
        return sprintf("%.1f %s", $bytes / pow(1024, $factor), $units[$factor]);
    }
    
    public static function getMimeType(string $filepath): string {
        $ext = self::getExtension($filepath);
        
        if (isset(Config::MIME_TYPES[$ext])) {
            return Config::MIME_TYPES[$ext];
        }
        
        if (function_exists('finfo_open') && file_exists($filepath)) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $filepath);
            finfo_close($finfo);
            if ($mime !== false) return $mime;
        }
        
        return 'application/octet-stream';
    }
    
    public static function sanitizePath(string $path): string {
        // Remove null bytes and normalize slashes
        $path = str_replace(["\0", "\\"], ['', '/'], $path);
        
        // Remove multiple slashes
        $path = preg_replace('#/+#', '/', $path);
        
        // Remove leading/trailing slashes
        $path = trim($path, '/');
        
        // Prevent directory traversal
        $parts = array_filter(explode('/', $path), function($part) {
            return $part !== '' && $part !== '.' && $part !== '..';
        });
        
        return implode('/', $parts);
    }
    
    public static function validateCSRF(): bool {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return true;
        
        $token = ($_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''));
        return hash_equals(($_SESSION['csrf_token'] ?? ''), $token);
    }
    
    public static function getFileIcon(string $filename, bool $isDir = false): string {
        if ($isDir) {
            return '<svg class="icon" viewBox="0 0 24 24" fill="currentColor">
                <path d="M10 4H4c-1.11 0-2 .89-2 2v12c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V8c0-1.11-.89-2-2-2h-8l-2-2z"/>
            </svg>';
        }
        
        $ext = self::getExtension($filename);
        $icons = [
            'code' => ['js','ts','jsx','tsx','json','yml','yaml','html','css','scss','sass','less','php','py','rb','go','rs','c','cpp','java','cs','sh','bash'],
            'image' => ['png','jpg','jpeg','gif','webp','svg','bmp','ico','avif','tiff'],
            'video' => ['mp4','webm','mkv','avi','mov','wmv','flv','m4v'],
            'audio' => ['mp3','wav','ogg','m4a','flac','aac','wma'],
            'archive' => ['zip','gz','bz2','xz','7z','rar','tar','tgz'],
            'document' => ['pdf','doc','docx','ppt','pptx','xls','xlsx','txt','rtf','odt','ods','odp'],
        ];
        
        $iconType = 'file';
        foreach ($icons as $type => $extensions) {
            if (in_array($ext, $extensions, true)) {
                $iconType = $type;
                break;
            }
        }
        
        $svgPaths = [
            'file' => '<path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6z"/><path d="M14 2v6h6"/>',
            'code' => '<path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z"/>',
            'image' => '<path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/>',
            'video' => '<path d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/>',
            'audio' => '<path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/>',
            'archive' => '<path d="M19 8h-1V3H6v5H5c-1.1 0-2 .9-2 2v6c0 1.1.9 2 2 2h1v3h12v-3h1c1.1 0 2-.9 2-2v-6c0-1.1-.9-2-2-2zM8 5h8v3H8V5zm8 14H8v-5h8v5zm2-7c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z"/>',
            'document' => '<path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zM6 20V4h7v5h5v11H6z"/>',
        ];
        
        return '<svg class="icon" viewBox="0 0 24 24" fill="currentColor">' . $svgPaths[$iconType] . '</svg>';
    }
}

// ===========================
// Directory Handler Class
// ===========================
class DirectoryHandler {
    private string $baseDir;
    private string $currentPath;
    private bool $showHidden;
    
    public function __construct() {
        $this->baseDir = (realpath(__DIR__) ?: __DIR__);
        $this->showHidden = isset($_GET[Config::SHOW_HIDDEN]) && $_GET[Config::SHOW_HIDDEN] === '1';
        
        $requestedPath = ($_GET['p'] ?? '');
        $this->currentPath = $this->resolvePath($requestedPath);
    }
    
    private function resolvePath(string $requestedPath): string {
        $sanitized = Utils::sanitizePath($requestedPath);
        if ($sanitized === '') return $this->baseDir;
        
        $fullPath = $this->baseDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $sanitized);
        $realPath = realpath($fullPath);
        
        // Ensure path is within base directory
        if ($realPath === false || !str_starts_with($realPath, $this->baseDir)) {
            return $this->baseDir;
        }
        
        return $realPath;
    }
    
    public function getRelativePath(): string {
        if ($this->currentPath === $this->baseDir) return '';
        return str_replace([$this->baseDir . DIRECTORY_SEPARATOR, DIRECTORY_SEPARATOR], ['', '/'], $this->currentPath);
    }
    
    public function getBreadcrumbs(): array {
        $crumbs = [['label' => 'Root', 'href' => '?', 'active' => false]];
        
        $relative = $this->getRelativePath();
        if ($relative === '') {
            $crumbs[0]['active'] = true;
            return $crumbs;
        }
        
        $parts = explode('/', $relative);
        $accumulated = [];
        
        foreach ($parts as $i => $part) {
            $accumulated[] = $part;
            $crumbs[] = [
                'label' => $part,
                'href' => '?p=' . rawurlencode(implode('/', $accumulated)),
                'active' => $i === count($parts) - 1
            ];
        }
        
        return $crumbs;
    }
    
    public function getEntries(): array {
        $entries = [];
        
        try {
            $iterator = new DirectoryIterator($this->currentPath);
            
            foreach ($iterator as $item) {
                if ($item->isDot()) continue;
                if (!Config::FOLLOW_SYMLINKS && $item->isLink()) continue;
                
                $name = $item->getFilename();
                
                // Skip this script in root directory
                if ($this->currentPath === $this->baseDir && $name === basename(__FILE__)) continue;
                
                // Handle hidden files
                if (!$this->showHidden && Utils::isHidden($name)) continue;
                
                $isDir = $item->isDir();
                $ext = $isDir ? '' : Utils::getExtension($name);
                
                $entries[] = [
                    'name' => $name,
                    'type' => ($isDir ? 'directory' : 'file'),
                    'extension' => $ext,
                    'size' => ($isDir ? null : $item->getSize()),
                    'modified' => $item->getMTime(),
                    'permissions' => substr(sprintf('%o', $item->getPerms()), -4),
                    'icon' => Utils::getFileIcon($name, $isDir),
                    'href' => $this->getItemHref($name, $isDir, $ext)
                ];
            }
            
        } catch (Exception $e) {
            error_log('Directory read error: ' . $e->getMessage());
        }
        
        return $entries;
    }
    
    private function getItemHref(string $name, bool $isDir, string $ext): ?string {
        if ($isDir) {
            $newPath = ($this->getRelativePath() === '' 
                ? $name 
                : $this->getRelativePath() . '/' . $name);
            return '?p=' . rawurlencode($newPath);
        }
        
        if (Config::ENABLE_DOWNLOADS && !in_array($ext, Config::DISALLOWED_EXTENSIONS, true)) {
            $params = ['dl' => $name];
            if ($this->getRelativePath() !== '') {
                $params['p'] = $this->getRelativePath();
            }
            return '?' . http_build_query($params);
        }
        
        return null;
    }
    
    public function handleDownload(): void {
        if (!isset($_GET['dl']) || !Config::ENABLE_DOWNLOADS) {
            http_response_code(404);
            exit('Not found');
        }
        
        // Validate CSRF for downloads
        if (!Utils::validateCSRF()) {
            http_response_code(403);
            exit('Invalid request');
        }
        
        $filename = basename($_GET['dl']);
        if ($filename === '' || $filename !== $_GET['dl']) {
            http_response_code(400);
            exit('Invalid filename');
        }
        
        $filepath = $this->currentPath . DIRECTORY_SEPARATOR . $filename;
        $realpath = realpath($filepath);
        
        // Security checks
        if ($realpath === false || 
            !str_starts_with($realpath, $this->baseDir) ||
            !is_file($realpath) ||
            (!Config::FOLLOW_SYMLINKS && is_link($realpath))) {
            http_response_code(404);
            exit('File not found');
        }
        
        $ext = Utils::getExtension($filename);
        if (in_array($ext, Config::DISALLOWED_EXTENSIONS, true)) {
            http_response_code(403);
            exit('File type not allowed');
        }
        
        // Set headers for download
        $size = filesize($realpath);
        $mime = Utils::getMimeType($realpath);
        
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . $size);
        header('Content-Disposition: attachment; filename="' . rawurlencode($filename) . '"');
        header('Cache-Control: no-cache, must-revalidate');
        header('X-Content-Type-Options: nosniff');
        
        // Output file
        readfile($realpath);
        exit;
    }
    
    public function sortEntries(array &$entries, string $sortParam): void {
        $sortKeys = [];
        foreach (explode(',', $sortParam) as $key) {
            $desc = false;
            if (str_starts_with($key, '-')) {
                $desc = true;
                $key = substr($key, 1);
            }
            
            if (in_array($key, ['name', 'type', 'size', 'modified', 'extension'], true)) {
                $sortKeys[] = ['key' => $key, 'desc' => $desc];
            }
        }
        
        if (empty($sortKeys)) {
            $sortKeys = [['key' => 'type', 'desc' => false], ['key' => 'name', 'desc' => false]];
        }
        
        usort($entries, function($a, $b) use ($sortKeys) {
            foreach ($sortKeys as $sort) {
                $result = 0;
                
                switch ($sort['key']) {
                    case 'name':
                        $result = strnatcasecmp($a['name'], $b['name']);
                        break;
                    case 'type':
                        if ($a['type'] !== $b['type']) {
                            $result = ($a['type'] === 'directory' ? -1 : 1);
                        }
                        break;
                    case 'size':
                        $aSize = ($a['size'] ?? -1);
                        $bSize = ($b['size'] ?? -1);
                        $result = $aSize <=> $bSize;
                        break;
                    case 'modified':
                        $result = (($a['modified'] ?? 0) <=> ($b['modified'] ?? 0));
                        break;
                    case 'extension':
                        $result = strcasecmp(($a['extension'] ?? ''), ($b['extension'] ?? ''));
                        break;
                }
                
                if ($result !== 0) {
                    return ($sort['desc'] ? -$result : $result);
                }
            }
            
            return strnatcasecmp($a['name'], $b['name']);
        });
    }
}

// ===========================
// Main Application Logic
// ===========================
$handler = new DirectoryHandler();

// Handle downloads
if (isset($_GET['dl'])) {
    $handler->handleDownload();
}

// Get directory entries
$entries = $handler->getEntries();
$sortParam = ($_GET['sort'] ?? 'type,name');
$handler->sortEntries($entries, $sortParam);

// Prepare view data
$breadcrumbs = $handler->getBreadcrumbs();
$relativePath = $handler->getRelativePath();
$csrfToken = $_SESSION['csrf_token'];

?>
<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Directory: /<?= Utils::h($relativePath) ?> | XDLS</title>
    <style>
        :root { --primary: #3b82f6; --primary-dark: #2563eb; --success: #10b981; --warning: #f59e0b; --danger: #ef4444; --dark: #1f2937; --light: #f9fafb; --bg: #ffffff; --bg-secondary: #f3f4f6; --text: #111827; --text-muted: #6b7280; --border: #e5e7eb; --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05); --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1); --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1); --radius: 0.5rem; --transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); }
        [data-theme="dark"] { --primary: #60a5fa; --primary-dark: #3b82f6; --bg: #111827; --bg-secondary: #1f2937; --text: #f9fafb; --text-muted: #9ca3af; --border: #374151; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: var(--text); background: var(--bg); min-height: 100vh; transition: var(--transition); }
        .header { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 1.5rem; position: sticky; top: 0; z-index: 100; backdrop-filter: blur(10px); background: rgba(var(--bg-secondary), 0.9); }
        .header-content { max-width: 1400px; margin: 0 auto; }
        .header-title { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
        .logo { width: 32px; height: 32px; color: var(--primary); }
        h1 { font-size: 1.5rem; font-weight: 600; }
        .breadcrumbs { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
        .breadcrumb { display: inline-flex; align-items: center; padding: 0.375rem 0.75rem; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); color: var(--text-muted); text-decoration: none; font-size: 0.875rem; transition: var(--transition); }
        .breadcrumb:hover:not(.active) { background: var(--primary); color: white; border-color: var(--primary); }
        .breadcrumb.active { background: var(--primary); color: white; border-color: var(--primary); }
        .breadcrumb-separator { color: var(--text-muted); }
        .controls { background: var(--bg); padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); }
        .controls-content { max-width: 1400px; margin: 0 auto; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
        .search-box { flex: 1; min-width: 250px; max-width: 400px; position: relative; }
        .search-input { width: 100%; padding: 0.625rem 1rem 0.625rem 2.5rem; border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg); color: var(--text); font-size: 0.875rem; transition: var(--transition); }
        .search-input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
        .search-icon { position: absolute; left: 0.75rem; top: 50%; transform: translateY(-50%); width: 18px; height: 18px; color: var(--text-muted); }
        .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.625rem 1rem; border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg); color: var(--text); font-size: 0.875rem; font-weight: 500; cursor: pointer; transition: var(--transition); text-decoration: none; }
        .btn:hover { background: var(--bg-secondary); border-color: var(--primary); }
        .btn-primary { background: var(--primary); color: white; border-color: var(--primary); }
        .btn-primary:hover { background: var(--primary-dark); border-color: var(--primary-dark); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .toggle { display: flex; align-items: center; gap: 0.5rem; font-size: 0.875rem; }
        .toggle-switch { position: relative; width: 44px; height: 24px; background: var(--border); border-radius: 12px; cursor: pointer; transition: var(--transition); }
        .toggle-switch input { opacity: 0; width: 0; height: 0; }
        .toggle-slider { position: absolute; top: 2px; left: 2px; width: 20px; height: 20px; background: white; border-radius: 50%; transition: var(--transition); }
        .toggle-switch input:checked ~ .toggle-slider { transform: translateX(20px); }
        .toggle-switch input:checked ~ .toggle-switch { background: var(--primary); }
        .main { max-width: 1400px; margin: 0 auto; padding: 1.5rem; }
        .table-container { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        thead { background: var(--bg-secondary); border-bottom: 1px solid var(--border); }
        th { padding: 0.75rem 1rem; text-align: left; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); cursor: pointer; user-select: none; position: relative; }
        th:hover { background: var(--bg); }
        .sort-indicator { position: absolute; right: 0.5rem; top: 50%; transform: translateY(-50%); font-size: 0.625rem; color: var(--primary); }
        tbody tr { border-bottom: 1px solid var(--border); transition: var(--transition); }
        tbody tr:hover { background: var(--bg-secondary); }
        tbody tr:last-child { border-bottom: none; }
        td { padding: 0.75rem 1rem; font-size: 0.875rem; }
        .file-entry { display: flex; align-items: center; gap: 0.75rem; }
        .icon { width: 20px; height: 20px; flex-shrink: 0; color: var(--text-muted); }
        .file-entry a { color: var(--text); text-decoration: none; font-weight: 500; }
        .file-entry a:hover { color: var(--primary); text-decoration: underline; }
        .text-muted { color: var(--text-muted); }
        .text-right { text-align: right; }
        .stats { display: flex; gap: 1rem; margin-top: 1rem; padding: 0.75rem 1rem; background: var(--bg-secondary); border-radius: var(--radius); font-size: 0.875rem; }
        .stat { display: flex; align-items: center; gap: 0.5rem; }
        .stat-label { color: var(--text-muted); }
        .stat-value { font-weight: 600; color: var(--text); }
        .footer { margin-top: 2rem; padding: 2rem 1.5rem; background: var(--bg-secondary); border-top: 1px solid var(--border); text-align: center; color: var(--text-muted); font-size: 0.875rem; }
        .empty-state { padding: 3rem; text-align: center; color: var(--text-muted); }
        .empty-icon { width: 64px; height: 64px; margin: 0 auto 1rem; opacity: 0.3; }
        @media (max-width: 768px) { .header-title { flex-direction: column; align-items: flex-start; } .controls-content { flex-direction: column; align-items: stretch; } .search-box { max-width: none; } .table-container { overflow-x: auto; } table { min-width: 600px; } .hide-mobile { display: none; } }
        .spinner { width: 20px; height: 20px; border: 2px solid var(--border); border-top-color: var(--primary); border-radius: 50%; animation: spin 0.6s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        [data-tooltip] { position: relative; }
        [data-tooltip]:hover::after { content: attr(data-tooltip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%); padding: 0.25rem 0.5rem; background: var(--dark); color: white; font-size: 0.75rem; border-radius: 0.25rem; white-space: nowrap; z-index: 1000; pointer-events: none; }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="header-content">
            <div class="header-title">
                <svg class="logo" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M10 4H4c-1.11 0-2 .89-2 2v12c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V8c0-1.11-.89-2-2-2h-8l-2-2z"/>
                </svg>
                <h1>xsukax Directory Listing System (XDLS)</h1>
            </div>
            
            <!-- Breadcrumbs -->
            <nav class="breadcrumbs" aria-label="Breadcrumb">
                <?php foreach ($breadcrumbs as $i => $crumb): ?>
                    <a href="<?= Utils::h($crumb['href']) ?>" 
                       class="breadcrumb <?= ($crumb['active'] ? 'active' : '') ?>">
                        <?= Utils::h($crumb['label']) ?>
                    </a>
                    <?php if ($i < count($breadcrumbs) - 1): ?>
                        <span class="breadcrumb-separator">/</span>
                    <?php endif; ?>
                <?php endforeach; ?>
            </nav>
        </div>
    </header>
    
    <!-- Controls -->
    <div class="controls">
        <div class="controls-content">
            <!-- Search -->
            <div class="search-box">
                <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"/>
                    <path d="m21 21-4.35-4.35"/>
                </svg>
                <input type="search" 
                       class="search-input" 
                       id="search" 
                       placeholder="Search files... (Ctrl+K)" 
                       autocomplete="off">
            </div>
            
            <!-- Up Button -->
            <?php if ($relativePath !== ''): ?>
                <a href="?p=<?= Utils::h(rawurlencode((dirname($relativePath) === '.' ? '' : dirname($relativePath)))) ?>" 
                   class="btn">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/>
                    </svg>
                    Up
                </a>
            <?php endif; ?>
            
            <!-- Show Hidden Toggle -->
            <label class="toggle">
                <div class="toggle-switch">
                    <input type="checkbox" 
                           id="toggleHidden" 
                           <?= (isset($_GET[Config::SHOW_HIDDEN]) && $_GET[Config::SHOW_HIDDEN] === '1' ? 'checked' : '') ?>>
                    <span class="toggle-slider"></span>
                </div>
                <span>Show hidden</span>
            </label>
            
            <!-- Theme Toggle -->
            <button class="btn" id="themeToggle" data-tooltip="Toggle theme">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 18c-3.31 0-6-2.69-6-6s2.69-6 6-6 6 2.69 6 6-2.69 6-6 6zm0-10c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4z"/>
                    <path d="M12 3c.28 0 .5.22.5.5v2c0 .28-.22.5-.5.5s-.5-.22-.5-.5v-2c0-.28.22-.5.5-.5zm0 18c.28 0 .5.22.5.5v2c0 .28-.22.5-.5.5s-.5-.22-.5-.5v-2c0-.28.22-.5.5-.5zm9-9c.28 0 .5.22.5.5s-.22.5-.5.5h-2c-.28 0-.5-.22-.5-.5s.22-.5.5-.5h2zM5 12c.28 0 .5.22.5.5s-.22.5-.5.5H3c-.28 0-.5-.22-.5-.5s.22-.5.5-.5h2z"/>
                </svg>
            </button>
        </div>
    </div>
    
    <!-- Main Content -->
    <main class="main">
        <?php if (empty($entries)): ?>
            <!-- Empty State -->
            <div class="empty-state">
                <svg class="empty-icon" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M10 4H4c-1.11 0-2 .89-2 2v12c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V8c0-1.11-.89-2-2-2h-8l-2-2z"/>
                </svg>
                <p>This directory is empty</p>
            </div>
        <?php else: ?>
            <!-- File Table -->
            <div class="table-container">
                <table id="fileTable" data-sort="<?= Utils::h($sortParam) ?>">
                    <thead>
                        <tr>
                            <th data-sort="name">
                                Name
                                <span class="sort-indicator" data-key="name"></span>
                            </th>
                            <th data-sort="extension" class="hide-mobile">
                                Type
                                <span class="sort-indicator" data-key="extension"></span>
                            </th>
                            <th data-sort="size">
                                Size
                                <span class="sort-indicator" data-key="size"></span>
                            </th>
                            <th data-sort="modified">
                                Modified
                                <span class="sort-indicator" data-key="modified"></span>
                            </th>
                            <th class="hide-mobile">Permissions</th>
                        </tr>
                    </thead>
                    <tbody id="fileTableBody">
                        <?php foreach ($entries as $entry): ?>
                            <tr data-name="<?= Utils::h(strtolower($entry['name'])) ?>" 
                                data-type="<?= Utils::h($entry['type']) ?>"
                                data-ext="<?= Utils::h($entry['extension']) ?>">
                                <td>
                                    <div class="file-entry">
                                        <?= $entry['icon'] ?>
                                        <?php if ($entry['href']): ?>
                                            <a href="<?= Utils::h($entry['href']) ?>&csrf=<?= Utils::h($csrfToken) ?>">
                                                <?= Utils::h($entry['name']) ?>
                                            </a>
                                        <?php else: ?>
                                            <span><?= Utils::h($entry['name']) ?></span>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td class="text-muted hide-mobile">
                                    <?= Utils::h($entry['type'] === 'directory' ? 'Folder' : (strtoupper($entry['extension']) ?: 'File')) ?>
                                </td>
                                <td class="text-muted">
                                    <?= Utils::formatBytes($entry['size']) ?>
                                </td>
                                <td class="text-muted">
                                    <?= date('Y-m-d H:i', $entry['modified']) ?>
                                </td>
                                <td class="text-muted hide-mobile">
                                    <?= Utils::h($entry['permissions']) ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Stats -->
            <div class="stats">
                <div class="stat">
                    <span class="stat-label">Total items:</span>
                    <span class="stat-value"><?= count($entries) ?></span>
                </div>
                <div class="stat">
                    <span class="stat-label">Folders:</span>
                    <span class="stat-value"><?= count(array_filter($entries, fn($e) => $e['type'] === 'directory')) ?></span>
                </div>
                <div class="stat">
                    <span class="stat-label">Files:</span>
                    <span class="stat-value"><?= count(array_filter($entries, fn($e) => $e['type'] === 'file')) ?></span>
                </div>
                <div class="stat">
                    <span class="stat-label">Total size:</span>
                    <span class="stat-value">
                        <?= Utils::formatBytes(array_sum(array_column($entries, 'size'))) ?>
                    </span>
                </div>
            </div>
        <?php endif; ?>
    </main>
    
    <!-- Footer -->
    <footer class="footer">
        <p>XDLS • PHP <?= phpversion() ?> • <?= date('Y-m-d H:i:s') ?></p>
    </footer>
    
    <script>
        const themeToggle = document.getElementById('themeToggle'), html = document.documentElement, savedTheme = localStorage.getItem('theme'), systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light', currentTheme = savedTheme || systemTheme; html.setAttribute('data-theme', currentTheme); themeToggle.addEventListener('click', () => { const newTheme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'; html.setAttribute('data-theme', newTheme); localStorage.setItem('theme', newTheme); });
        const searchInput = document.getElementById('search'), tableBody = document.getElementById('fileTableBody'); if (searchInput && tableBody) { searchInput.addEventListener('input', (e) => { const query = e.target.value.toLowerCase(), rows = tableBody.querySelectorAll('tr'); rows.forEach(row => { const name = row.dataset.name || '', type = row.dataset.type || '', ext = row.dataset.ext || '', matches = name.includes(query) || type.includes(query) || ext.includes(query); row.style.display = matches ? '' : 'none'; }); }); document.addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); searchInput.focus(); searchInput.select(); } }); }
        const toggleHidden = document.getElementById('toggleHidden'); if (toggleHidden) { toggleHidden.addEventListener('change', () => { const url = new URL(window.location.href); if (toggleHidden.checked) { url.searchParams.set('hidden', '1'); } else { url.searchParams.delete('hidden'); } window.location.href = url.toString(); }); }
        const table = document.getElementById('fileTable'); if (table) { const headers = table.querySelectorAll('th[data-sort]'), currentSort = table.dataset.sort || 'type,name'; const updateIndicators = () => { const sorts = currentSort.split(',').map(s => s.trim()); document.querySelectorAll('.sort-indicator').forEach(ind => { ind.textContent = ''; }); sorts.forEach((sort, index) => { const desc = sort.startsWith('-'), key = sort.replace('-', ''), indicator = document.querySelector(`.sort-indicator[data-key="${key}"]`); if (indicator) { indicator.textContent = desc ? '↓' : '↑'; if (index > 0) { indicator.textContent += ` ${index + 1}`; } } }); }; updateIndicators(); headers.forEach(header => { header.addEventListener('click', (e) => { const key = header.dataset.sort, url = new URL(window.location.href); let sorts = currentSort.split(',').map(s => s.trim()); if (e.shiftKey) { const existingIndex = sorts.findIndex(s => s.replace('-', '') === key); if (existingIndex >= 0) { sorts[existingIndex] = sorts[existingIndex].startsWith('-') ? key : '-' + key; } else { sorts.push(key); } } else { const existing = sorts.find(s => s.replace('-', '') === key); if (existing) { sorts = [existing.startsWith('-') ? key : '-' + key]; } else { sorts = [key]; } } url.searchParams.set('sort', sorts.join(',')); window.location.href = url.toString(); }); }); }
        document.querySelectorAll('a, button, th[data-sort]').forEach(el => { el.addEventListener('mousedown', () => el.style.transform = 'scale(0.98)'); el.addEventListener('mouseup', () => el.style.transform = ''); el.addEventListener('mouseleave', () => el.style.transform = ''); });
    </script>
</body>
</html>