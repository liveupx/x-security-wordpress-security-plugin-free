<?php
/**
 * Configuration Management Class
 */

if (!defined('ABSPATH')) {
    exit;
}

class XSEC_Config {
    
    private static $instance = null;
    private $settings = array();
    private $option_name = 'xsec_settings';
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->load_settings();
    }
    
    /**
     * Get default settings
     */
    public static function get_defaults() {
        return array(
            // Login Security
            'login_lockout_enabled' => 1,
            'max_login_attempts' => 3,
            'lockout_duration' => 60,
            'login_captcha_enabled' => 0,
            'login_honeypot_enabled' => 1,
            'hide_login_errors' => 1,
            
            // User Security
            'user_enum_protection' => 1,
            'strong_password_enabled' => 1,
            'min_password_length' => 10,
            'block_admin_username' => 1,
            'disable_file_editing' => 1,
            
            // Firewall
            'firewall_enabled' => 1,
            'block_bad_queries' => 1,
            'block_bad_bots' => 1,
            'remove_wp_version' => 1,
            'disable_xmlrpc' => 1,
            'disable_pingbacks' => 1,
            
            // Notifications
            'email_notifications' => 1,
            'notification_email' => '',
            
            // Misc
            'security_score' => 0,
        );
    }
    
    /**
     * Load settings from database
     */
    private function load_settings() {
        $saved = get_option($this->option_name, array());
        $this->settings = wp_parse_args($saved, self::get_defaults());
    }
    
    /**
     * Get a setting value
     */
    public function get($key, $default = null) {
        if (isset($this->settings[$key])) {
            return $this->settings[$key];
        }
        return $default !== null ? $default : (isset(self::get_defaults()[$key]) ? self::get_defaults()[$key] : null);
    }
    
    /**
     * Set a setting value
     */
    public function set($key, $value) {
        $this->settings[$key] = $value;
        return $this->save();
    }
    
    /**
     * Update multiple settings
     */
    public function update($settings) {
        $this->settings = wp_parse_args($settings, $this->settings);
        return $this->save();
    }
    
    /**
     * Save settings to database
     */
    public function save() {
        return update_option($this->option_name, $this->settings);
    }
    
    /**
     * Get all settings
     */
    public function get_all() {
        return $this->settings;
    }
    
    /**
     * Reset to defaults
     */
    public function reset() {
        $this->settings = self::get_defaults();
        return $this->save();
    }
}
