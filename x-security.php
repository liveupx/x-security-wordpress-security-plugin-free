<?php
/**
 * Plugin Name: X Security by Liveupx.com
 * Plugin URI: https://liveupx.com
 * Description: Complete WordPress security solution - Login protection, firewall, 2FA, file monitoring, database security and more.
 * Version: 1.0.0
 * Author: Liveupx.com
 * Author URI: https://liveupx.com
 * License: GPL v2 or later
 * Text Domain: x-security
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.7
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('XSEC_VERSION', '1.0.0');
define('XSEC_DB_VERSION', '1.0.0');
define('XSEC_PLUGIN_FILE', __FILE__);
define('XSEC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('XSEC_PLUGIN_URL', plugin_dir_url(__FILE__));
define('XSEC_PLUGIN_BASENAME', plugin_basename(__FILE__));

// Database table names
global $wpdb;
define('XSEC_TBL_LOGIN_LOCKOUT', $wpdb->prefix . 'xsec_login_lockouts');
define('XSEC_TBL_FAILED_LOGINS', $wpdb->prefix . 'xsec_failed_logins');
define('XSEC_TBL_ACTIVITY_LOG', $wpdb->prefix . 'xsec_activity_log');
define('XSEC_TBL_BLOCKED_IPS', $wpdb->prefix . 'xsec_blocked_ips');
define('XSEC_TBL_WHITELIST_IPS', $wpdb->prefix . 'xsec_whitelist_ips');

// Include required files
require_once XSEC_PLUGIN_DIR . 'classes/class-xsec-config.php';
require_once XSEC_PLUGIN_DIR . 'classes/class-xsec-installer.php';
require_once XSEC_PLUGIN_DIR . 'classes/class-xsec-helper.php';

// Register hooks
register_activation_hook(__FILE__, array('XSEC_Installer', 'activate'));
register_deactivation_hook(__FILE__, array('XSEC_Installer', 'deactivate'));

/**
 * Main Plugin Class
 */
class X_Security {
    
    private static $instance = null;
    public $config;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->config = XSEC_Config::get_instance();
        $this->load_dependencies();
        $this->init_hooks();
    }
    
    private function load_dependencies() {
        // Core classes
        require_once XSEC_PLUGIN_DIR . 'classes/class-xsec-login-security.php';
        require_once XSEC_PLUGIN_DIR . 'classes/class-xsec-firewall.php';
        require_once XSEC_PLUGIN_DIR . 'classes/class-xsec-user-security.php';
        
        // Admin only
        if (is_admin()) {
            require_once XSEC_PLUGIN_DIR . 'admin/class-xsec-admin.php';
            require_once XSEC_PLUGIN_DIR . 'admin/class-xsec-ajax.php';
        }
    }
    
    private function init_hooks() {
        add_action('init', array($this, 'init'));
        add_action('plugins_loaded', array($this, 'plugins_loaded'));
    }
    
    public function init() {
        // Initialize security modules
        XSEC_Login_Security::get_instance();
        XSEC_Firewall::get_instance();
        XSEC_User_Security::get_instance();
        
        // Admin
        if (is_admin()) {
            XSEC_Admin::get_instance();
            XSEC_Ajax::get_instance();
        }
    }
    
    public function plugins_loaded() {
        load_plugin_textdomain('x-security', false, dirname(XSEC_PLUGIN_BASENAME) . '/languages');
    }
}

// Initialize plugin
function xsec_init() {
    return X_Security::get_instance();
}
add_action('plugins_loaded', 'xsec_init', 1);

// Add settings link
add_filter('plugin_action_links_' . XSEC_PLUGIN_BASENAME, function($links) {
    $settings = '<a href="' . admin_url('admin.php?page=x-security') . '">' . __('Settings', 'x-security') . '</a>';
    array_unshift($links, $settings);
    return $links;
});
