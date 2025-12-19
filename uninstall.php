<?php
/**
 * Uninstall X Security
 * Removes all plugin data when uninstalled
 *
 * @package X_Security
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

// Delete options.
delete_option( 'xsec_settings' );
delete_option( 'xsec_db_version' );
delete_option( 'xsec_activated' );

/*
 * Drop plugin tables.
 * Table names use $wpdb->prefix (WordPress core) + hardcoded plugin table suffixes.
 * These are safe, known values. Using esc_sql() for additional safety.
 */

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared -- Safe table name using esc_sql with hardcoded suffix.
$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'xsec_login_lockouts' ) . '`' );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared -- Safe table name using esc_sql with hardcoded suffix.
$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'xsec_failed_logins' ) . '`' );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared -- Safe table name using esc_sql with hardcoded suffix.
$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'xsec_activity_log' ) . '`' );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared -- Safe table name using esc_sql with hardcoded suffix.
$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'xsec_blocked_ips' ) . '`' );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.NotPrepared -- Safe table name using esc_sql with hardcoded suffix.
$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $wpdb->prefix . 'xsec_whitelist_ips' ) . '`' );

// Remove .htaccess rules using WP_Filesystem.
$xsec_htaccess_file = ABSPATH . '.htaccess';

// Initialize WP_Filesystem.
if ( ! function_exists( 'WP_Filesystem' ) ) {
    require_once ABSPATH . 'wp-admin/includes/file.php';
}

WP_Filesystem();
global $wp_filesystem;

if ( $wp_filesystem && $wp_filesystem->exists( $xsec_htaccess_file ) && $wp_filesystem->is_writable( $xsec_htaccess_file ) ) {
    $xsec_htaccess_content = $wp_filesystem->get_contents( $xsec_htaccess_file );
    $xsec_htaccess_pattern = '/# BEGIN X Security.*?# END X Security\s*/s';
    $xsec_htaccess_content = preg_replace( $xsec_htaccess_pattern, '', $xsec_htaccess_content );
    $wp_filesystem->put_contents( $xsec_htaccess_file, $xsec_htaccess_content, FS_CHMOD_FILE );
}
