<?php
/**
 * AJAX Handler - Processes all AJAX requests
 *
 * @package X_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * XSEC_Ajax class
 */
class XSEC_Ajax {

    /**
     * Singleton instance
     *
     * @var XSEC_Ajax|null
     */
    private static $instance = null;

    /**
     * Get singleton instance
     *
     * @return XSEC_Ajax
     */
    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct() {
        add_action( 'wp_ajax_xsec_action', array( $this, 'handle_ajax' ) );
    }

    /**
     * Handle AJAX requests
     *
     * @return void
     */
    public function handle_ajax() {
        // Verify nonce.
        if ( ! check_ajax_referer( 'xsec_ajax_nonce', 'nonce', false ) ) {
            wp_send_json_error( array( 'message' => __( 'Security check failed.', 'x-security' ) ) );
        }

        // Check permissions.
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'Permission denied.', 'x-security' ) ) );
        }

        // Nonce verified above, safe to access $_POST.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified by check_ajax_referer above.
        $action = isset( $_POST['security_action'] ) ? sanitize_text_field( wp_unslash( $_POST['security_action'] ) ) : '';

        switch ( $action ) {
            case 'run_scan':
                $this->run_scan();
                break;

            case 'clear_lockouts':
                $this->clear_lockouts();
                break;

            case 'clear_failed_logins':
                $this->clear_failed_logins();
                break;

            case 'clear_activity_log':
                $this->clear_activity_log();
                break;

            case 'cleanup':
                $this->cleanup();
                break;

            case 'block_ip':
                $this->block_ip();
                break;

            case 'unblock_ip':
                $this->unblock_ip();
                break;

            case 'whitelist_ip':
                $this->whitelist_ip();
                break;

            case 'remove_whitelist':
                $this->remove_whitelist();
                break;

            case 'write_htaccess':
                $this->write_htaccess();
                break;

            case 'remove_htaccess':
                $this->remove_htaccess();
                break;

            case 'save_settings':
                $this->save_settings();
                break;

            default:
                wp_send_json_error( array( 'message' => __( 'Invalid action.', 'x-security' ) ) );
        }
    }

    /**
     * Run security scan
     *
     * @return void
     */
    private function run_scan() {
        $results = array(
            'score'   => XSEC_Helper::get_security_score(),
            'issues'  => array(),
            'passed'  => array(),
        );

        $config = XSEC_Config::get_instance();

        // Check login security.
        if ( $config->get( 'login_lockout_enabled' ) ) {
            $results['passed'][] = __( 'Login lockout enabled', 'x-security' );
        } else {
            $results['issues'][] = __( 'Login lockout disabled', 'x-security' );
        }

        // Check firewall.
        if ( $config->get( 'firewall_enabled' ) ) {
            $results['passed'][] = __( 'Firewall enabled', 'x-security' );
        } else {
            $results['issues'][] = __( 'Firewall disabled', 'x-security' );
        }

        // Check version hiding.
        if ( $config->get( 'remove_wp_version' ) ) {
            $results['passed'][] = __( 'WordPress version hidden', 'x-security' );
        } else {
            $results['issues'][] = __( 'WordPress version exposed', 'x-security' );
        }

        // Check XML-RPC.
        if ( $config->get( 'disable_xmlrpc' ) ) {
            $results['passed'][] = __( 'XML-RPC disabled', 'x-security' );
        } else {
            $results['issues'][] = __( 'XML-RPC enabled (potential security risk)', 'x-security' );
        }

        // Check file editing.
        if ( $config->get( 'disable_file_editing' ) || defined( 'DISALLOW_FILE_EDIT' ) ) {
            $results['passed'][] = __( 'File editing disabled', 'x-security' );
        } else {
            $results['issues'][] = __( 'File editing enabled', 'x-security' );
        }

        XSEC_Helper::log( 'security_scan', 'Security scan completed' );

        wp_send_json_success( $results );
    }

    /**
     * Clear all lockouts
     *
     * @return void
     */
    private function clear_lockouts() {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Admin action to clear security data.
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}xsec_login_lockouts" );
        XSEC_Helper::log( 'lockouts_cleared', 'All login lockouts cleared' );
        wp_send_json_success( array( 'message' => __( 'All lockouts cleared.', 'x-security' ) ) );
    }

    /**
     * Clear failed logins
     *
     * @return void
     */
    private function clear_failed_logins() {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Admin action to clear security data.
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}xsec_failed_logins" );
        XSEC_Helper::log( 'failed_logins_cleared', 'Failed login records cleared' );
        wp_send_json_success( array( 'message' => __( 'Failed login records cleared.', 'x-security' ) ) );
    }

    /**
     * Clear activity log
     *
     * @return void
     */
    private function clear_activity_log() {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Admin action to clear security data.
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}xsec_activity_log" );
        wp_send_json_success( array( 'message' => __( 'Activity log cleared.', 'x-security' ) ) );
    }

    /**
     * Run cleanup
     *
     * @return void
     */
    private function cleanup() {
        XSEC_Helper::cleanup();
        wp_send_json_success( array( 'message' => __( 'Old data cleaned up.', 'x-security' ) ) );
    }

    /**
     * Block IP
     *
     * @return void
     */
    private function block_ip() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in handle_ajax() before calling this method.
        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in handle_ajax() before calling this method.
        $reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';

        if ( empty( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'x-security' ) ) );
        }

        // Don't block current user's IP.
        if ( $ip === XSEC_Helper::get_ip() ) {
            wp_send_json_error( array( 'message' => __( 'You cannot block your own IP address.', 'x-security' ) ) );
        }

        XSEC_Helper::block_ip( $ip, $reason );
        wp_send_json_success( array( 'message' => __( 'IP blocked successfully.', 'x-security' ) ) );
    }

    /**
     * Unblock IP
     *
     * @return void
     */
    private function unblock_ip() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in handle_ajax() before calling this method.
        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';

        if ( empty( $ip ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'x-security' ) ) );
        }

        XSEC_Helper::unblock_ip( $ip );
        wp_send_json_success( array( 'message' => __( 'IP unblocked.', 'x-security' ) ) );
    }

    /**
     * Whitelist IP
     *
     * @return void
     */
    private function whitelist_ip() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in handle_ajax() before calling this method.
        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in handle_ajax() before calling this method.
        $description = isset( $_POST['description'] ) ? sanitize_text_field( wp_unslash( $_POST['description'] ) ) : '';

        if ( empty( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'x-security' ) ) );
        }

        XSEC_Helper::whitelist_ip( $ip, $description );
        wp_send_json_success( array( 'message' => __( 'IP whitelisted.', 'x-security' ) ) );
    }

    /**
     * Remove from whitelist
     *
     * @return void
     */
    private function remove_whitelist() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in handle_ajax() before calling this method.
        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';

        if ( empty( $ip ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid IP address.', 'x-security' ) ) );
        }

        XSEC_Helper::remove_whitelist( $ip );
        wp_send_json_success( array( 'message' => __( 'IP removed from whitelist.', 'x-security' ) ) );
    }

    /**
     * Write .htaccess rules
     *
     * @return void
     */
    private function write_htaccess() {
        $result = XSEC_Firewall::write_htaccess_rules();

        if ( $result ) {
            XSEC_Helper::log( 'htaccess_updated', '.htaccess security rules added' );
            wp_send_json_success( array( 'message' => __( '.htaccess rules written successfully.', 'x-security' ) ) );
        } else {
            wp_send_json_error( array( 'message' => __( 'Failed to write .htaccess rules. Check file permissions.', 'x-security' ) ) );
        }
    }

    /**
     * Remove .htaccess rules
     *
     * @return void
     */
    private function remove_htaccess() {
        $result = XSEC_Firewall::remove_htaccess_rules();

        if ( $result ) {
            XSEC_Helper::log( 'htaccess_updated', '.htaccess security rules removed' );
            wp_send_json_success( array( 'message' => __( '.htaccess rules removed.', 'x-security' ) ) );
        } else {
            wp_send_json_error( array( 'message' => __( 'Failed to update .htaccess. Check file permissions.', 'x-security' ) ) );
        }
    }

    /**
     * Save settings
     *
     * @return void
     */
    private function save_settings() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in handle_ajax() before calling this method.
        if ( ! isset( $_POST['settings'] ) || ! is_array( $_POST['settings'] ) ) {
            wp_send_json_error( array( 'message' => __( 'No settings provided.', 'x-security' ) ) );
        }

        // Sanitize the entire settings array using map_deep with sanitize_text_field.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verified in handle_ajax(). Input is sanitized via map_deep with sanitize_text_field.
        $raw_settings = map_deep( wp_unslash( $_POST['settings'] ), 'sanitize_text_field' );

        // Further process and validate each setting.
        $settings = array();
        foreach ( $raw_settings as $key => $value ) {
            $clean_key = sanitize_key( $key );
            if ( is_numeric( $value ) ) {
                $settings[ $clean_key ] = intval( $value );
            } elseif ( is_string( $value ) ) {
                if ( 'notification_email' === $clean_key ) {
                    $settings[ $clean_key ] = sanitize_email( $value );
                } else {
                    $settings[ $clean_key ] = $value; // Already sanitized by map_deep.
                }
            } else {
                $settings[ $clean_key ] = $value ? 1 : 0;
            }
        }

        if ( empty( $settings ) ) {
            wp_send_json_error( array( 'message' => __( 'No valid settings provided.', 'x-security' ) ) );
        }

        $config  = XSEC_Config::get_instance();
        $current = $config->get_all();

        // Merge with current settings.
        $updated = array_merge( $current, $settings );
        update_option( 'xsec_settings', $updated );

        XSEC_Helper::log( 'settings_updated', 'Security settings updated' );

        wp_send_json_success( array( 'message' => __( 'Settings saved successfully.', 'x-security' ) ) );
    }
}
