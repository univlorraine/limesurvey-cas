<?php
/**
 * AuthCAS diagnostic script (command line only)
 *
 * Checks the installation and configuration of the AuthCAS plugin of a LimeSurvey instance
 * and explains why the CAS login page is not displayed.
 *
 * Usage :
 *   sudo -u www-data php check-authcas.php /path/to/limesurvey [cas_login]
 *
 * Run it with the same user as the web server (www-data, apache, nginx...) so that file
 * permissions are the same. cas_login (optional) : check if this CAS user is allowed to log in.
 *
 * The script only reads the database, it never changes anything.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("This script must be run from the command line.\n");
}

$errors = 0;
$warnings = 0;

function ok($msg)
{
    echo "  [OK]    $msg\n";
}
function ko($msg)
{
    global $errors;
    $errors++;
    echo "  [ERROR] $msg\n";
}
function warn($msg)
{
    global $warnings;
    $warnings++;
    echo "  [WARN]  $msg\n";
}
function info($msg)
{
    echo "  [INFO]  $msg\n";
}
function section($title)
{
    echo "\n== $title ==\n";
}

if ($argc < 2) {
    fwrite(STDERR, "Usage: php {$argv[0]} /path/to/limesurvey [cas_login]\n");
    exit(2);
}
$lsPath = rtrim($argv[1], '/');
$casLogin = isset($argv[2]) ? $argv[2] : null;

/* ------------------------------------------------------------------ */
section('PHP');
/* ------------------------------------------------------------------ */
info('PHP ' . PHP_VERSION . ' (CLI, ' . (php_ini_loaded_file() ?: 'no php.ini') . ')');
info('The web server may use another PHP version / php.ini (php-fpm) : check it too.');
if (PHP_VERSION_ID >= 70100) {
    ok('PHP >= 7.1 (required by phpCAS 1.6)');
} else {
    ko('PHP >= 7.1 is required by phpCAS 1.6');
}
extension_loaded('curl') ? ok('curl extension loaded') : ko('curl extension missing (required by phpCAS)');
extension_loaded('dom') ? ok('dom extension loaded') : ko('dom extension missing (required by phpCAS)');
extension_loaded('pdo') ? ok('pdo extension loaded') : ko('pdo extension missing (required by this script)');
if (!extension_loaded('ldap')) {
    info('ldap extension not loaded (only needed for auto-creation from LDAP)');
}
$openBasedir = ini_get('open_basedir');
if ($openBasedir) {
    info("open_basedir = $openBasedir");
}

/* ------------------------------------------------------------------ */
section('Plugin files');
/* ------------------------------------------------------------------ */
$pluginDir = null;
foreach (array("$lsPath/plugins/AuthCAS", "$lsPath/upload/plugins/AuthCAS") as $dir) {
    if (is_file("$dir/AuthCAS.php")) {
        $pluginDir = $dir;
        break;
    }
}
if (!$pluginDir) {
    ko("AuthCAS.php not found in $lsPath/plugins/AuthCAS or $lsPath/upload/plugins/AuthCAS");
    exit(1);
}
ok("Plugin found in $pluginDir");
if (is_file("$lsPath/plugins/AuthCAS/AuthCAS.php") && is_file("$lsPath/upload/plugins/AuthCAS/AuthCAS.php")) {
    warn('AuthCAS is present both in plugins/ and upload/plugins/ : LimeSurvey may load the old one. Remove one of them.');
}
$source = file_get_contents("$pluginDir/AuthCAS.php");
if (strpos($source, 'serviceBaseUrl') !== false) {
    ok('AuthCAS.php is the new version (serviceBaseUrl setting present)');
} else {
    ko('AuthCAS.php is an old version (no serviceBaseUrl setting) : the file was not replaced');
}
if (preg_match('#<version>([^<]+)</version>#', (string) @file_get_contents("$pluginDir/config.xml"), $m)) {
    info("config.xml version : {$m[1]}");
}
if (is_file("$pluginDir/vendor/apereo/phpcas/source/CAS.php")) {
    $casSource = file_get_contents("$pluginDir/vendor/apereo/phpcas/source/CAS.php");
    preg_match("#define\('PHPCAS_VERSION', '([^']+)'\)#", $casSource, $m);
    ok('phpCAS ' . (isset($m[1]) ? $m[1] : '?') . ' found in vendor/apereo/phpcas');
} else {
    ko('vendor/apereo/phpcas is missing : copy the whole AuthCAS directory, vendor/ included');
}
if (is_dir("$pluginDir/vendor/jasig")) {
    warn('Old vendor/jasig directory still present (the new directory was copied over the old one). It is not used, but you should remove it.');
}
$autoload = "$pluginDir/vendor/composer/autoload_static.php";
if (is_file($autoload) && strpos(file_get_contents($autoload), 'apereo/phpcas') !== false) {
    ok('Composer autoloader points to apereo/phpcas');
} else {
    ko('Composer autoloader (vendor/composer) is outdated : copy the whole vendor/ directory');
}
if (!is_readable("$pluginDir/AuthCAS.php") || !is_readable("$pluginDir/vendor/autoload.php")) {
    ko('Plugin files are not readable by the current user (' . get_current_user() . ')');
}

/* ------------------------------------------------------------------ */
section('Database');
/* ------------------------------------------------------------------ */
$configFile = "$lsPath/application/config/config.php";
if (!is_readable($configFile)) {
    ko("Cannot read $configFile");
    exit(1);
}
if (!defined('BASEPATH')) {
    define('BASEPATH', $lsPath . '/');
}
$config = include $configFile;
if (!is_array($config) || empty($config['components']['db']['connectionString'])) {
    ko("No database configuration found in $configFile");
    exit(1);
}
$db = $config['components']['db'];
$prefix = isset($db['tablePrefix']) ? $db['tablePrefix'] : 'lime_';
try {
    $pdo = new PDO(
        $db['connectionString'],
        isset($db['username']) ? $db['username'] : null,
        isset($db['password']) ? $db['password'] : null,
        array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION)
    );
    ok('Connected to the database');
} catch (Exception $e) {
    ko('Database connection failed : ' . $e->getMessage());
    exit(1);
}

$plugin = null;
foreach ($pdo->query("SELECT * FROM {$prefix}plugins") as $row) {
    if ($row['name'] === 'AuthCAS') {
        $plugin = $row;
    }
}
if (!$plugin) {
    ko('AuthCAS is not registered in LimeSurvey : go to Configuration > Plugins and scan for plugins');
    exit(1);
}
if ((int) $plugin['active'] === 1) {
    ok("AuthCAS plugin is active (id {$plugin['id']})");
} else {
    ko('AuthCAS plugin is NOT active : activate it in Configuration > Plugins');
}

/* Plugin settings (values are JSON encoded) */
$settings = array();
$stmt = $pdo->prepare("SELECT * FROM {$prefix}plugin_settings WHERE plugin_id = :id");
$stmt->execute(array(':id' => $plugin['id']));
foreach ($stmt as $row) {
    if (!empty($row['model'])) {
        continue;
    }
    $settings[$row['key']] = json_decode($row['value'], true);
}
$get = function ($key, $default = null) use ($settings) {
    return (isset($settings[$key]) && $settings[$key] !== '') ? $settings[$key] : $default;
};

/* ------------------------------------------------------------------ */
section('Plugin settings');
/* ------------------------------------------------------------------ */
$casHost = $get('casAuthServer', 'localhost');
$casPort = (int) $get('casAuthPort', 8443);
$casUri = $get('casAuthUri', '/cas');
$casVersion = $get('casVersion', '2.0');
$serviceBaseUrl = trim((string) $get('serviceBaseUrl', ''));
$caCert = trim((string) $get('casCACert', ''));
info("casAuthServer = $casHost, casAuthPort = $casPort, casAuthUri = $casUri, casVersion = $casVersion");
info('autoCreate = ' . $get('autoCreate', '0') . ', autoGrantCasPermission = ' . $get('autoGrantCasPermission', '0'));

if (empty($casHost)) {
    ko('casAuthServer is empty : CAS is disabled');
}
if (preg_match('#^[a-z]+://#i', (string) $casHost)) {
    ko('casAuthServer must not contain the protocol (use "cas.example.org", not "https://cas.example.org")');
}
if ($serviceBaseUrl === '') {
    ko('serviceBaseUrl is NOT set : CAS is disabled and the local login form is displayed. '
        . 'Set it in the plugin settings (e.g. https://survey.example.org)');
} elseif (!preg_match('#^https?://[^/?\#]+#i', $serviceBaseUrl)) {
    ko("serviceBaseUrl \"$serviceBaseUrl\" is invalid : it must start with https:// (e.g. https://survey.example.org)");
} else {
    ok("serviceBaseUrl = $serviceBaseUrl");
    if (stripos($serviceBaseUrl, 'https://') !== 0) {
        warn('serviceBaseUrl does not use https');
    }
    if (preg_match('#^https?://[^/]+/.+#', $serviceBaseUrl)) {
        warn('serviceBaseUrl must only contain the scheme and host (and port), without path : e.g. https://survey.example.org');
    }
}
if ($caCert === '') {
    ko('casCACert is NOT set : CAS is disabled and the local login form is displayed. '
        . 'Set it in the plugin settings (e.g. /etc/ssl/certs/ca-certificates.crt)');
} elseif (!is_file($caCert)) {
    ko("casCACert : file $caCert does not exist" . ($openBasedir ? ' (or is outside open_basedir)' : ''));
} elseif (!is_readable($caCert)) {
    ko("casCACert : file $caCert is not readable by " . get_current_user());
} else {
    ok("casCACert = $caCert (readable)");
    if ($openBasedir) {
        warn('open_basedir is set in the CLI : make sure the web server open_basedir also allows ' . $caCert);
    }
}

/* ------------------------------------------------------------------ */
section('Connection to the CAS server');
/* ------------------------------------------------------------------ */
if ($casHost && extension_loaded('curl')) {
    $casUrl = 'https://' . $casHost . ($casPort == 443 ? '' : ':' . $casPort) . rtrim($casUri, '/') . '/login';
    info("GET $casUrl");
    $ch = curl_init($casUrl);
    curl_setopt_array($ch, array(
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ));
    if ($caCert !== '' && is_readable($caCert)) {
        curl_setopt($ch, CURLOPT_CAINFO, $caCert);
    }
    curl_exec($ch);
    $curlErr = curl_error($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($curlErr) {
        ko("Cannot reach the CAS server with certificate validation : $curlErr");
        if (stripos($curlErr, 'certificate') !== false || stripos($curlErr, 'SSL') !== false) {
            info('The CA file does not contain the authority that signed the CAS server certificate, '
                . 'or the certificate name does not match casAuthServer.');
        }
    } elseif ($httpCode >= 200 && $httpCode < 400) {
        ok("CAS server answered HTTP $httpCode with a valid certificate");
    } else {
        warn("CAS server answered HTTP $httpCode : check casAuthUri");
    }
}

/* ------------------------------------------------------------------ */
section('Permissions');
/* ------------------------------------------------------------------ */
$rows = $pdo->query("SELECT * FROM {$prefix}permissions WHERE entity = 'global' AND permission = 'auth_cas'")->fetchAll(PDO::FETCH_ASSOC);
$allowed = 0;
foreach ($rows as $row) {
    if ((int) $row['read_p'] === 1) {
        $allowed++;
    }
}
$totalUsers = (int) $pdo->query("SELECT COUNT(*) FROM {$prefix}users")->fetchColumn();
info("$allowed / $totalUsers users have the \"Use CAS authentication\" permission");
if ($allowed === 0 && !$get('autoGrantCasPermission')) {
    warn('No existing user can log in with CAS. Give them the global permission "Use CAS authentication" '
        . '(or enable autoGrantCasPermission).');
}

if ($casLogin !== null) {
    $login = $get('casUserIdToLowercase') ? strtolower($casLogin) : $casLogin;
    $stmt = $pdo->prepare("SELECT uid, users_name FROM {$prefix}users WHERE users_name = :name");
    $stmt->execute(array(':name' => $login));
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        if ((int) $get('autoCreate', 0) > 0) {
            ok("User \"$login\" does not exist : they will be created on first CAS login (autoCreate = " . $get('autoCreate') . ')');
        } else {
            ko("User \"$login\" does not exist and autoCreate is disabled : they cannot log in with CAS");
        }
    } else {
        $stmt = $pdo->prepare("SELECT permission, read_p FROM {$prefix}permissions WHERE entity = 'global' AND entity_id = 0 AND uid = :uid AND permission IN ('auth_cas', 'superadmin')");
        $stmt->execute(array(':uid' => $user['uid']));
        $perms = array();
        foreach ($stmt as $row) {
            $perms[$row['permission']] = (int) $row['read_p'];
        }
        $forced = isset($config['config']['forcedsuperadmin']) ? $config['config']['forcedsuperadmin'] : array(1);
        $isSuperAdmin = !empty($perms['superadmin']) || in_array((int) $user['uid'], array_map('intval', (array) $forced), true);
        info("User \"$login\" exists (uid {$user['uid']})" . ($isSuperAdmin ? ', superadmin' : ''));
        if (isset($perms['auth_cas'])) {
            $perms['auth_cas'] ? ok('auth_cas permission granted : CAS login allowed')
                : ko('auth_cas permission explicitly refused : CAS login denied');
        } elseif ($get('autoGrantCasPermission') && !$isSuperAdmin) {
            ok('No auth_cas permission yet : it will be granted on first CAS login (autoGrantCasPermission)');
        } else {
            ko('No auth_cas permission : CAS login denied. Give this user the global permission "Use CAS authentication"'
                . ($isSuperAdmin ? ' (superadmins always need it explicitly)' : ''));
        }
    }
}

/* ------------------------------------------------------------------ */
section('Result');
/* ------------------------------------------------------------------ */
if ($errors === 0) {
    echo "  No blocking problem found ($warnings warning(s)).\n";
    echo "  If the local login form is still displayed, clear the LimeSurvey cache (tmp/runtime) and restart php-fpm (opcache).\n";
    echo "  Also check the LimeSurvey logs for 'CAS authentication disabled'.\n";
} else {
    echo "  $errors error(s), $warnings warning(s) : fix the errors above.\n";
}
echo "  Local login is still available with : /index.php/admin/authentication/sa/login?noAuthCAS=true\n";
exit($errors ? 1 : 0);
