<?php
// config/seguridad.php

// ─── BLOQUEO DE ACCESO DIRECTO AL ARCHIVO ────────────────
if (basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    http_response_code(403);
    exit("Access Forbidden");
}

// ─── INICIAR SESIÓN SEGURA ───────────────────────────────
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_samesite' => 'Strict'
    ]);
}

// ─── SESSION FIXATION PROTECTION ─────────────────────────
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

// ─── DETECCIÓN DE IP PRIVADA VS PÚBLICA ──────────────────
function es_ip_privada($ip) {
    return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}
$ip_actual = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if ($ip_actual === 'unknown' || es_ip_privada($ip_actual)) {
    log_attack("Acceso desde IP privada o desconocida: $ip_actual");
    exit("Acceso no permitido.");
}

// ─── HEADERS DE SEGURIDAD AVANZADOS ─────────────────────
$csp = "default-src 'self'; "
     . "script-src 'self' https://cdn.jsdelivr.net https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; "
     . "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
     . "img-src 'self' https://images.unsplash.com https://randomuser.me https://avatars.githubusercontent.com data:; "
     . "font-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com data:; "
     . "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self';";

function aplicar_headers() {
    global $csp;
    header("X-Frame-Options: SAMEORIGIN");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: no-referrer");
    header("Permissions-Policy: geolocation=(), microphone=()");
    header("X-XSS-Protection: 1; mode=block");
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
    header("Content-Security-Policy: $csp");
    header("X-Permitted-Cross-Domain-Policies: none");
}
aplicar_headers();

// ─── BLOQUEO DE REQUESTS HEAD/OPTIONS ANÓMALOS ───────────
$metodo = $_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN';
if (in_array($metodo, ['HEAD','OPTIONS'])) {
    log_attack("Método HTTP bloqueado: $metodo");
    http_response_code(405);
    exit("Método no permitido.");
}

// ─── CSRF TOKEN ──────────────────────────────────────────
function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validar_csrf($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ─── HONEYPOT ANTI-BOT ──────────────────────────────────
function honeypot_check() {
    if (isset($_POST['hp_field']) && !empty(trim($_POST['hp_field']))) {
        log_attack('Honeypot activado');
        bloquear_ip($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        session_destroy();
        header('Location: login.php');
        exit();
    }
}

// ─── BLOQUEO DE IP ──────────────────────────────────────
function ip_bloqueada($ip) {
    $archivo = _DIR_ . '/../logs/ips_bloqueadas.txt';
    if (!file_exists($archivo)) return false;
    $bloqueadas = file($archivo, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return in_array($ip, $bloqueadas);
}

function bloquear_ip($ip) {
    $archivo = _DIR_ . '/../logs/ips_bloqueadas.txt';
    if (!is_dir(dirname($archivo))) {
        mkdir(dirname($archivo), 0755, true);
    }
    file_put_contents($archivo, $ip . "\n", FILE_APPEND | LOCK_EX);
}

// ─── BLOQUEO DE AGENTES SOSPECHOSOS ─────────────────────
function bloquear_agentes_sospechosos() {
    $sospechosos = ['sqlmap','curl','httpie','fuzz','nmap','dirbuster','nikto','postman','acunetix','wget'];
    $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');

    if (!$ua) {
        log_attack("User-Agent ausente");
        bloquear_ip($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        session_destroy();
        header('Location: login.php');
        exit();
    }

    foreach ($sospechosos as $bad) {
        if (strpos($ua, $bad) !== false) {
            log_attack("User-Agent sospechoso: $ua");
            bloquear_ip($_SERVER['REMOTE_ADDR'] ?? 'unknown');
            session_destroy();
            header('Location: login.php');
            exit();
        }
    }
}
bloquear_agentes_sospechosos();

// ─── RATE LIMITING AVANZADO ─────────────────────────────
function rate_limit($max = 20, $window = 60) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key = 'rate_' . md5($ip);
    $time = time();

    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 1, 'time' => $time];
    } else {
        $elapsed = $time - $_SESSION[$key]['time'];
        if ($elapsed < $window) {
            $_SESSION[$key]['count']++;
            if ($_SESSION[$key]['count'] > $max) {
                log_attack("Rate limit IP $ip");
                bloquear_ip($ip);
                session_destroy();
                header("Location: login.php");
                exit();
            }
        } else {
            $_SESSION[$key] = ['count' => 1, 'time' => $time];
        }
    }
}
rate_limit();

// ─── DETECCIÓN DE CRLF INJECTION BÁSICO ─────────────────
foreach ($_GET as $param => $value) {
    if (preg_match('/(%0A|%0D|\n|\r)/i', $value)) {
        log_attack("CRLF Injection detectada en GET param: $param");
        http_response_code(400);
        exit("Solicitud inválida.");
    }
}

// ─── REGISTRO DE ATAQUES ────────────────────────────────
function log_attack($motivo = 'Desconocido') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'N/A';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'N/A';
    $hora = date('Y-m-d H:i:s');
    $linea = "[$hora] IP: $ip - UA: $ua - Motivo: $motivo\n";
    $logFile = __DIR__ . '/../logs/ataques.log';
    if (!is_dir(dirname($logFile))) {
        mkdir(dirname($logFile), 0755, true);
    }
    file_put_contents($logFile, $linea, FILE_APPEND | LOCK_EX);
}

// ─── BLOQUEAR SI IP ESTÁ EN LISTA NEGRA ────────────────
if (ip_bloqueada($ip_actual)) {
    log_attack("Acceso bloqueado: IP $ip_actual");
    http_response_code(403);
    exit("Tu IP ha sido bloqueada por actividad sospechosa.");
}

// ─── EJECUTAR HONEYPOT ──────────────────────────────────
honeypot_check();

// ─── VALIDAR MÉTODO POST ────────────────────────────────
function metodo_post_seguro() {
    return $_SERVER['REQUEST_METHOD']==='POST';
}
