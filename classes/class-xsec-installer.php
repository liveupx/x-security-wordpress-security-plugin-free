<?php
/**
 * Plugin Installer - Handles activation, deactivation, database tables
 */

if (!defined('ABSPATH')) {
    exit;
}

class XSEC_Installer {
    
    /**
     * Plugin activation
     */
    public static function activate() {
        self::create_tables();
        self::set_default_options();
        
        // Flush rewrite rules
        flush_rewrite_rules();
        
        // Set activation flag
        update_option('xsec_activated', time());
    }
    
    /**
     * Plugin deactivation
     */
    public static function deactivate() {
        // Clear scheduled hooks
        wp_clear_scheduled_hook('xsec_daily_scan');
        wp_clear_scheduled_hook('xsec_cleanup');
        
        flush_rewrite_rules();
    }
    
    /**
     * Create database tables
     */
    public static function create_tables() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        
        // Login lockouts table
        $sql1 = "CREATE TABLE " . XSEC_TBL_LOGIN_LOCKOUT . " (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            username varchar(255) NOT NULL,
            lockout_time datetime NOT NULL,
            release_time datetime NOT NULL,
            reason varchar(255) DEFAULT '',
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY release_time (release_time)
        ) $charset_collate;";
        dbDelta($sql1);
        
        // Failed logins table
        $sql2 = "CREATE TABLE " . XSEC_TBL_FAILED_LOGINS . " (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            username varchar(255) NOT NULL,
            attempt_time datetime NOT NULL,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY attempt_time (attempt_time)
        ) $charset_collate;";
        dbDelta($sql2);
        
        // Activity log table
        $sql3 = "CREATE TABLE " . XSEC_TBL_ACTIVITY_LOG . " (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) DEFAULT 0,
            username varchar(255) DEFAULT '',
            ip_address varchar(100) NOT NULL,
            event_type varchar(100) NOT NULL,
            event_description text NOT NULL,
            event_data longtext,
            event_time datetime NOT NULL,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY event_time (event_time),
            KEY ip_address (ip_address)
        ) $charset_collate;";
        dbDelta($sql3);
        
        // Blocked IPs table
        $sql4 = "CREATE TABLE " . XSEC_TBL_BLOCKED_IPS . " (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            reason varchar(255) DEFAULT '',
            blocked_by varchar(100) DEFAULT 'manual',
            blocked_time datetime NOT NULL,
            expires datetime DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address),
            KEY blocked_time (blocked_time)
        ) $charset_collate;";
        dbDelta($sql4);
        
        // Whitelist IPs table
        $sql5 = "CREATE TABLE " . XSEC_TBL_WHITELIST_IPS . " (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            description varchar(255) DEFAULT '',
            added_time datetime NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address)
        ) $charset_collate;";
        dbDelta($sql5);
        
        // Save DB version
        update_option('xsec_db_version', XSEC_DB_VERSION);
    }
    
    /**
     * Set default options
     */
    public static function set_default_options() {
        $defaults = XSEC_Config::get_defaults();
        $defaults['notification_email'] = get_option('admin_email');
        
        if (!get_option('xsec_settings')) {
            add_option('xsec_settings', $defaults);
        }
    }
    
    /**
     * Check if tables exist
     */
    public static function tables_exist() {
        global $wpdb;
        $table = XSEC_TBL_ACTIVITY_LOG;
        return $wpdb->get_var("SHOW TABLES LIKE '$table'") === $table;
    }
}
