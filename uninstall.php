<?php
/**
 * Uninstall X Security
 * Removes all plugin data when uninstalled
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// Delete options
delete_option('xsec_settings');
delete_option('xsec_db_version');
delete_option('xsec_activated');

// Drop tables
$tables = array(
    $wpdb->prefix . 'xsec_login_lockouts',
    $wpdb->prefix . 'xsec_failed_logins',
    $wpdb->prefix . 'xsec_activity_log',
    $wpdb->prefix . 'xsec_blocked_ips',
    $wpdb->prefix . 'xsec_whitelist_ips',
);

foreach ($tables as $table) {
    $wpdb->query("DROP TABLE IF EXISTS $table");
}

// Remove .htaccess rules
$htaccess_file = ABSPATH . '.htaccess';
if (is_writable($htaccess_file)) {
    $content = file_get_contents($htaccess_file);
    $pattern = '/# BEGIN X Security.*?# END X Security\s*/s';
    $content = preg_replace($pattern, '', $content);
    file_put_contents($htaccess_file, $content);
}
