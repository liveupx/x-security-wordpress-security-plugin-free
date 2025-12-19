<?php
/**
 * User Security - Enumeration protection, password strength, file editing
 *
 * @package X_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * XSEC_User_Security class
 */
class XSEC_User_Security {

    /**
     * Singleton instance
     *
     * @var XSEC_User_Security|null
     */
    private static $instance = null;

    /**
     * Config instance
     *
     * @var XSEC_Config
     */
    private $config;

    /**
     * Get singleton instance
     *
     * @return XSEC_User_Security
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
        $this->config = XSEC_Config::get_instance();
        $this->init_hooks();
    }

    /**
     * Initialize hooks
     *
     * @return void
     */
    private function init_hooks() {
        // User enumeration protection.
        if ( $this->config->get( 'user_enum_protection' ) ) {
            add_action( 'init', array( $this, 'block_user_enumeration' ) );
            add_filter( 'redirect_canonical', array( $this, 'block_author_scans' ), 10, 2 );
            add_filter( 'rest_endpoints', array( $this, 'disable_rest_user_endpoints' ) );
        }

        // Strong password enforcement.
        if ( $this->config->get( 'strong_password_enabled' ) ) {
            add_action( 'user_profile_update_errors', array( $this, 'validate_password_strength' ), 10, 3 );
            add_filter( 'registration_errors', array( $this, 'validate_registration_password' ), 10, 3 );
        }

        // Block 'admin' username.
        if ( $this->config->get( 'block_admin_username' ) ) {
            add_filter( 'illegal_user_logins', array( $this, 'block_admin_username' ) );
        }

        // Disable file editing.
        if ( $this->config->get( 'disable_file_editing' ) ) {
            $this->disable_file_editor();
        }

        // Log user activity.
        add_action( 'profile_update', array( $this, 'log_profile_update' ), 10, 2 );
        add_action( 'user_register', array( $this, 'log_user_registration' ) );
        add_action( 'delete_user', array( $this, 'log_user_deletion' ) );
    }

    /**
     * Block user enumeration via ?author=
     *
     * @return void
     */
    public function block_user_enumeration() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a security check to block enumeration, not form processing.
        if ( ! is_admin() && isset( $_REQUEST['author'] ) && is_numeric( $_REQUEST['author'] ) ) {
            XSEC_Helper::log( 'user_enumeration', 'User enumeration attempt blocked' );
            wp_safe_redirect( home_url() );
            exit;
        }
    }

    /**
     * Block author archive scans
     *
     * @param string $redirect Redirect URL.
     * @param string $request  Request URL.
     * @return string
     */
    public function block_author_scans( $redirect, $request ) {
        if ( preg_match( '/\?author=([0-9]*)/', $request ) ) {
            XSEC_Helper::log( 'user_enumeration', 'Author scan blocked' );
            return home_url();
        }
        return $redirect;
    }

    /**
     * Disable REST API user endpoints
     *
     * @param array $endpoints REST API endpoints.
     * @return array
     */
    public function disable_rest_user_endpoints( $endpoints ) {
        if ( ! current_user_can( 'list_users' ) ) {
            if ( isset( $endpoints['/wp/v2/users'] ) ) {
                unset( $endpoints['/wp/v2/users'] );
            }
            if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
                unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
            }
        }
        return $endpoints;
    }

    /**
     * Validate password strength on profile update
     *
     * @param WP_Error $errors Errors object.
     * @param bool     $update Whether updating existing user.
     * @param stdClass $user   User object.
     * @return WP_Error
     */
    public function validate_password_strength( $errors, $update, $user ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified by WordPress core in user profile update.
        if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified by WordPress core in user profile update.
            $password   = sanitize_text_field( wp_unslash( $_POST['pass1'] ) );
            $validation = $this->check_password_strength( $password );

            if ( is_wp_error( $validation ) ) {
                $errors->add( 'weak_password', $validation->get_error_message() );
            }
        }
        return $errors;
    }

    /**
     * Validate password on registration
     *
     * @param WP_Error $errors              Errors object.
     * @param string   $sanitized_user_login Sanitized username.
     * @param string   $user_email          User email.
     * @return WP_Error
     */
    public function validate_registration_password( $errors, $sanitized_user_login, $user_email ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified by WordPress core in registration.
        if ( isset( $_POST['user_pass'] ) && ! empty( $_POST['user_pass'] ) ) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce is verified by WordPress core in registration.
            $password   = sanitize_text_field( wp_unslash( $_POST['user_pass'] ) );
            $validation = $this->check_password_strength( $password );

            if ( is_wp_error( $validation ) ) {
                $errors->add( 'weak_password', $validation->get_error_message() );
            }
        }
        return $errors;
    }

    /**
     * Check password strength
     *
     * @param string $password Password to check.
     * @return true|WP_Error
     */
    private function check_password_strength( $password ) {
        $min_length = $this->config->get( 'min_password_length', 10 );

        // Check length.
        if ( strlen( $password ) < $min_length ) {
            return new WP_Error(
                'password_length',
                sprintf(
                    /* translators: %d: minimum required password length */
                    __( 'Password must be at least %d characters long.', 'x-security' ),
                    $min_length
                )
            );
        }

        // Check for uppercase.
        if ( ! preg_match( '/[A-Z]/', $password ) ) {
            return new WP_Error(
                'password_uppercase',
                __( 'Password must contain at least one uppercase letter.', 'x-security' )
            );
        }

        // Check for lowercase.
        if ( ! preg_match( '/[a-z]/', $password ) ) {
            return new WP_Error(
                'password_lowercase',
                __( 'Password must contain at least one lowercase letter.', 'x-security' )
            );
        }

        // Check for number.
        if ( ! preg_match( '/[0-9]/', $password ) ) {
            return new WP_Error(
                'password_number',
                __( 'Password must contain at least one number.', 'x-security' )
            );
        }

        // Check for special character.
        if ( ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
            return new WP_Error(
                'password_special',
                __( 'Password must contain at least one special character.', 'x-security' )
            );
        }

        return true;
    }

    /**
     * Block 'admin' username
     *
     * @param array $usernames Blocked usernames.
     * @return array
     */
    public function block_admin_username( $usernames ) {
        $usernames[] = 'admin';
        $usernames[] = 'administrator';
        $usernames[] = 'Admin';
        $usernames[] = 'ADMIN';
        return $usernames;
    }

    /**
     * Disable file editor
     *
     * @return void
     */
    private function disable_file_editor() {
        if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- This is a WordPress core constant used to disable file editing.
            define( 'DISALLOW_FILE_EDIT', true );
        }
    }

    /**
     * Log profile update
     *
     * @param int     $user_id       User ID.
     * @param WP_User $old_user_data Old user data.
     * @return void
     */
    public function log_profile_update( $user_id, $old_user_data ) {
        $user = get_userdata( $user_id );
        XSEC_Helper::log(
            'profile_update',
            sprintf( 'Profile updated for user: %s', $user->user_login ),
            $user_id
        );
    }

    /**
     * Log user registration
     *
     * @param int $user_id User ID.
     * @return void
     */
    public function log_user_registration( $user_id ) {
        $user = get_userdata( $user_id );
        XSEC_Helper::log(
            'user_registered',
            sprintf( 'New user registered: %s', $user->user_login ),
            $user_id
        );
    }

    /**
     * Log user deletion
     *
     * @param int $user_id User ID.
     * @return void
     */
    public function log_user_deletion( $user_id ) {
        $user = get_userdata( $user_id );
        if ( $user ) {
            XSEC_Helper::log(
                'user_deleted',
                sprintf( 'User deleted: %s', $user->user_login ),
                get_current_user_id()
            );
        }
    }
}
