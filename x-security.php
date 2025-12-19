<?php
/**
 * Plugin Name: X Security
 * Plugin URI: https://liveupx.com/x-security
 * Description: Complete WordPress security solution - Login protection, firewall, brute force protection, IP blocking, activity logging, and more. Developed by Liveupx.com
 * Version: 1.5.0
 * Author: Liveupx
 * Author URI: https://liveupx.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: x-security
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.9
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('XSEC_VERSION', '1.5.0');
define('XSEC_DB_VERSION', '1.0.0');
define('XSEC_PLUGIN_FILE', __FILE__);
define('XSEC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('XSEC_PLUGIN_URL', plugin_dir_url(__FILE__));
define('XSEC_PLUGIN_BASENAME', plugin_basename(__FILE__));

/**
 * Get database table name
 */
function xsec_get_table($table) {
    global $wpdb;
    return $wpdb->prefix . 'xsec_' . $table;
}

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
        // Translations are automatically loaded by WordPress.org for hosted plugins
    }
}

// Initialize plugin
function xsec_init() {
    return X_Security::get_instance();
}
add_action('plugins_loaded', 'xsec_init', 1);

// Add settings link
add_filter('plugin_action_links_' . XSEC_PLUGIN_BASENAME, function($links) {
    $settings_url = esc_url(admin_url('admin.php?page=x-security'));
    $settings = '<a href="' . $settings_url . '">' . esc_html__('Settings', 'x-security') . '</a>';
    array_unshift($links, $settings);
    return $links;
});
