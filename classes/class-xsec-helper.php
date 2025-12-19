<?php
/**
 * Helper Utility Functions
 *
 * @package X_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * XSEC_Helper class
 */
class XSEC_Helper {

    /**
     * Get client IP address
     *
     * @return string IP address
     */
    public static function get_ip() {
        $ip = '';

        // CloudFlare.
        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            // X-Forwarded-For (proxy/load balancer).
            $ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
            $ip  = trim( $ips[0] );
        } elseif ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            // X-Real-IP.
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
        } elseif ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
            // Client IP.
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) );
        } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            // Remote Address.
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }

        // Validate IP.
        if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return $ip;
        }

        return '0.0.0.0';
    }

    /**
     * Check if IP is whitelisted
     *
     * @param string|null $ip IP address.
     * @return bool
     */
    public static function is_whitelisted( $ip = null ) {
        global $wpdb;

        if ( null === $ip ) {
            $ip = self::get_ip();
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security plugin requires direct DB access for real-time IP checks.
        $count = $wpdb->get_var(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is safely constructed from $wpdb->prefix.
                "SELECT COUNT(*) FROM {$wpdb->prefix}xsec_whitelist_ips WHERE ip_address = %s",
                $ip
            )
        );

        return $count > 0;
    }

    /**
     * Check if IP is blocked
     *
     * @param string|null $ip IP address.
     * @return bool
     */
    public static function is_blocked( $ip = null ) {
        global $wpdb;

        if ( null === $ip ) {
            $ip = self::get_ip();
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security plugin requires direct DB access for real-time IP checks.
        $count = $wpdb->get_var(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is safely constructed from $wpdb->prefix.
                "SELECT COUNT(*) FROM {$wpdb->prefix}xsec_blocked_ips WHERE ip_address = %s AND (expires IS NULL OR expires > NOW())",
                $ip
            )
        );

        return $count > 0;
    }

    /**
     * Block an IP address
     *
     * @param string      $ip      IP address.
     * @param string      $reason  Reason for blocking.
     * @param string|null $expires Expiration datetime.
     * @return bool
     */
    public static function block_ip( $ip, $reason = '', $expires = null ) {
        global $wpdb;

        // Don't block whitelisted IPs.
        if ( self::is_whitelisted( $ip ) ) {
            return false;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security plugin requires direct DB access.
        $wpdb->replace(
            $wpdb->prefix . 'xsec_blocked_ips',
            array(
                'ip_address'   => $ip,
                'reason'       => $reason,
                'blocked_by'   => 'manual',
                'blocked_time' => current_time( 'mysql' ),
                'expires'      => $expires,
            ),
            array( '%s', '%s', '%s', '%s', '%s' )
        );

        self::log( 'ip_blocked', sprintf( 'IP %s blocked. Reason: %s', $ip, $reason ), 0, $ip );

        return true;
    }

    /**
     * Unblock an IP address
     *
     * @param string $ip IP address.
     * @return bool
     */
    public static function unblock_ip( $ip ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security plugin requires direct DB access.
        $wpdb->delete(
            $wpdb->prefix . 'xsec_blocked_ips',
            array( 'ip_address' => $ip ),
            array( '%s' )
        );

        self::log( 'ip_unblocked', sprintf( 'IP %s unblocked', $ip ) );

        return true;
    }

    /**
     * Whitelist an IP address
     *
     * @param string $ip          IP address.
     * @param string $description Description.
     * @return bool
     */
    public static function whitelist_ip( $ip, $description = '' ) {
        global $wpdb;

        // Remove from blocked list first.
        self::unblock_ip( $ip );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security plugin requires direct DB access.
        $wpdb->replace(
            $wpdb->prefix . 'xsec_whitelist_ips',
            array(
                'ip_address'  => $ip,
                'description' => $description,
                'added_time'  => current_time( 'mysql' ),
            ),
            array( '%s', '%s', '%s' )
        );

        self::log( 'ip_whitelisted', sprintf( 'IP %s whitelisted', $ip ) );

        return true;
    }

    /**
     * Remove IP from whitelist
     *
     * @param string $ip IP address.
     * @return bool
     */
    public static function remove_whitelist( $ip ) {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security plugin requires direct DB access.
        $wpdb->delete(
            $wpdb->prefix . 'xsec_whitelist_ips',
            array( 'ip_address' => $ip ),
            array( '%s' )
        );

        return true;
    }

    /**
     * Log an activity
     *
     * @param string      $event_type  Event type.
     * @param string      $description Event description.
     * @param int|null    $user_id     User ID.
     * @param string|null $ip          IP address.
     * @param mixed       $data        Additional data.
     * @return void
     */
    public static function log( $event_type, $description, $user_id = null, $ip = null, $data = null ) {
        global $wpdb;

        if ( null === $user_id ) {
            $user_id = get_current_user_id();
        }

        if ( null === $ip ) {
            $ip = self::get_ip();
        }

        $username = '';
        if ( $user_id > 0 ) {
            $user = get_userdata( $user_id );
            if ( $user ) {
                $username = $user->user_login;
            }
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Security plugin requires direct DB access for logging.
        $wpdb->insert(
            $wpdb->prefix . 'xsec_activity_log',
            array(
                'user_id'           => $user_id,
                'username'          => $username,
                'ip_address'        => $ip,
                'event_type'        => $event_type,
                'event_description' => $description,
                'event_data'        => $data ? wp_json_encode( $data ) : null,
                'event_time'        => current_time( 'mysql' ),
            ),
            array( '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
        );
    }

    /**
     * Calculate security score
     *
     * @return int Security score (0-100)
     */
    public static function get_security_score() {
        $config = XSEC_Config::get_instance();
        $score  = 0;
        $max    = 100;

        // Login security (25 points).
        if ( $config->get( 'login_lockout_enabled' ) ) {
            $score += 10;
        }
        if ( $config->get( 'login_honeypot_enabled' ) ) {
            $score += 5;
        }
        if ( $config->get( 'hide_login_errors' ) ) {
            $score += 5;
        }
        if ( $config->get( 'login_captcha_enabled' ) ) {
            $score += 5;
        }

        // User security (25 points).
        if ( $config->get( 'user_enum_protection' ) ) {
            $score += 5;
        }
        if ( $config->get( 'strong_password_enabled' ) ) {
            $score += 10;
        }
        if ( $config->get( 'block_admin_username' ) ) {
            $score += 5;
        }
        if ( $config->get( 'disable_file_editing' ) ) {
            $score += 5;
        }

        // Firewall (30 points).
        if ( $config->get( 'firewall_enabled' ) ) {
            $score += 10;
        }
        if ( $config->get( 'block_bad_queries' ) ) {
            $score += 5;
        }
        if ( $config->get( 'block_bad_bots' ) ) {
            $score += 5;
        }
        if ( $config->get( 'disable_xmlrpc' ) ) {
            $score += 5;
        }
        if ( $config->get( 'disable_pingbacks' ) ) {
            $score += 5;
        }

        // General (20 points).
        if ( $config->get( 'remove_wp_version' ) ) {
            $score += 10;
        }
        if ( $config->get( 'email_notifications' ) ) {
            $score += 10;
        }

        return min( $score, $max );
    }

    /**
     * Send email notification
     *
     * @param string $subject Email subject.
     * @param string $message Email message.
     * @return bool
     */
    public static function send_notification( $subject, $message ) {
        $config = XSEC_Config::get_instance();

        if ( ! $config->get( 'email_notifications' ) ) {
            return false;
        }

        $to = $config->get( 'notification_email' );
        if ( empty( $to ) ) {
            $to = get_option( 'admin_email' );
        }

        $site_name = get_bloginfo( 'name' );
        $subject   = '[' . $site_name . '] ' . $subject;

        $headers = array( 'Content-Type: text/html; charset=UTF-8' );

        return wp_mail( $to, $subject, $message, $headers );
    }

    /**
     * Clean old data
     *
     * @return void
     */
    public static function cleanup() {
        global $wpdb;

        // Delete old failed logins (older than 7 days).
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Cleanup routine with safe table name from $wpdb->prefix.
        $wpdb->query( "DELETE FROM {$wpdb->prefix}xsec_failed_logins WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 7 DAY)" );

        // Delete expired lockouts.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Cleanup routine with safe table name from $wpdb->prefix.
        $wpdb->query( "DELETE FROM {$wpdb->prefix}xsec_login_lockouts WHERE release_time < NOW()" );

        // Delete old activity logs (older than 30 days).
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Cleanup routine with safe table name from $wpdb->prefix.
        $wpdb->query( "DELETE FROM {$wpdb->prefix}xsec_activity_log WHERE event_time < DATE_SUB(NOW(), INTERVAL 30 DAY)" );

        // Delete expired blocked IPs.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Cleanup routine with safe table name from $wpdb->prefix.
        $wpdb->query( "DELETE FROM {$wpdb->prefix}xsec_blocked_ips WHERE expires IS NOT NULL AND expires < NOW()" );
    }
}
