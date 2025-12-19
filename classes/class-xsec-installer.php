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
        
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        
        // Login lockouts table
        $table_name = $wpdb->prefix . 'xsec_login_lockouts';
        $sql = "CREATE TABLE $table_name (
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
        dbDelta($sql);
        
        // Failed logins table
        $table_name = $wpdb->prefix . 'xsec_failed_logins';
        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            username varchar(255) NOT NULL,
            attempt_time datetime NOT NULL,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY attempt_time (attempt_time)
        ) $charset_collate;";
        dbDelta($sql);
        
        // Activity log table
        $table_name = $wpdb->prefix . 'xsec_activity_log';
        $sql = "CREATE TABLE $table_name (
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
        dbDelta($sql);
        
        // Blocked IPs table
        $table_name = $wpdb->prefix . 'xsec_blocked_ips';
        $sql = "CREATE TABLE $table_name (
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
        dbDelta($sql);
        
        // Whitelist IPs table
        $table_name = $wpdb->prefix . 'xsec_whitelist_ips';
        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(100) NOT NULL,
            description varchar(255) DEFAULT '',
            added_time datetime NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address)
        ) $charset_collate;";
        dbDelta($sql);
        
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
     *
     * @return bool
     */
    public static function tables_exist() {
        global $wpdb;
        $table = $wpdb->prefix . 'xsec_activity_log';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table existence check during activation.
        return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
    }
}
