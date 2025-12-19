<?php
/**
 * Firewall - Block bad requests, bots, and malicious activity
 *
 * @package X_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * XSEC_Firewall class
 */
class XSEC_Firewall {

    /**
     * Singleton instance
     *
     * @var XSEC_Firewall|null
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
     * @return XSEC_Firewall
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

        if ( $this->config->get( 'firewall_enabled' ) ) {
            $this->init_hooks();
        }
    }

    /**
     * Initialize hooks
     *
     * @return void
     */
    private function init_hooks() {
        // Run firewall checks early.
        add_action( 'init', array( $this, 'run_firewall' ), 1 );

        // Remove WP version.
        if ( $this->config->get( 'remove_wp_version' ) ) {
            remove_action( 'wp_head', 'wp_generator' );
            add_filter( 'the_generator', '__return_empty_string' );
            add_filter( 'style_loader_src', array( $this, 'remove_version_strings' ), 9999 );
            add_filter( 'script_loader_src', array( $this, 'remove_version_strings' ), 9999 );
        }

        // Disable XML-RPC.
        if ( $this->config->get( 'disable_xmlrpc' ) ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
            add_filter( 'wp_headers', array( $this, 'remove_xmlrpc_header' ) );
        }

        // Disable pingbacks.
        if ( $this->config->get( 'disable_pingbacks' ) ) {
            add_filter( 'xmlrpc_methods', array( $this, 'disable_pingback_methods' ) );
            add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
        }
    }

    /**
     * Main firewall check
     *
     * @return void
     */
    public function run_firewall() {
        // Skip for whitelisted IPs.
        if ( XSEC_Helper::is_whitelisted() ) {
            return;
        }

        // Skip for admin users.
        if ( is_admin() && current_user_can( 'manage_options' ) ) {
            return;
        }

        // Check if blocked.
        if ( XSEC_Helper::is_blocked() ) {
            $this->block_access( __( 'Your IP address has been blocked due to suspicious activity.', 'x-security' ) );
        }

        // Block bad queries.
        if ( $this->config->get( 'block_bad_queries' ) ) {
            $this->check_bad_queries();
        }

        // Block bad bots.
        if ( $this->config->get( 'block_bad_bots' ) ) {
            $this->check_bad_bots();
        }
    }

    /**
     * Check for malicious query strings
     *
     * @return void
     */
    private function check_bad_queries() {
        $request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        $query_string = isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '';

        $check_string = strtolower( $request_uri . $query_string );

        // Patterns to block.
        $bad_patterns = array(
            // SQL Injection.
            'union select',
            'union all select',
            'concat(',
            'group_concat(',
            'information_schema',
            'load_file(',
            'into outfile',
            'into dumpfile',
            'benchmark(',
            'sleep(',

            // XSS.
            '<script',
            '</script',
            'javascript:',
            'vbscript:',
            'onload=',
            'onerror=',
            'onclick=',
            'onmouseover=',

            // File Inclusion.
            '../',
            '..\\',
            '/etc/passwd',
            '/etc/shadow',
            'proc/self/environ',

            // Common exploits.
            'base64_decode(',
            'eval(',
            'shell_exec(',
            'passthru(',
            'wp-config.php',

            // Null bytes.
            '%00',
            '%2e%2e',
        );

        foreach ( $bad_patterns as $pattern ) {
            if ( stripos( $check_string, $pattern ) !== false ) {
                XSEC_Helper::log(
                    'firewall_blocked',
                    sprintf( 'Blocked malicious request: %s', $pattern ),
                    0,
                    XSEC_Helper::get_ip()
                );
                $this->block_access( __( 'Malicious request blocked.', 'x-security' ) );
            }
        }
    }

    /**
     * Check for bad bots/scanners
     *
     * @return void
     */
    private function check_bad_bots() {
        if ( ! isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            return;
        }

        $user_agent = strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) );

        $bad_bots = array(
            'sqlmap',
            'nikto',
            'nmap',
            'masscan',
            'acunetix',
            'nessus',
            'w3af',
            'openvas',
            'dirbuster',
            'gobuster',
            'wpscan',
            'nuclei',
            'havij',
            'zmeu',
            'morfeus',
            'wget',
            'curl',
            'libwww',
            'python-requests',
        );

        foreach ( $bad_bots as $bot ) {
            if ( stripos( $user_agent, $bot ) !== false ) {
                XSEC_Helper::log(
                    'bot_blocked',
                    sprintf( 'Blocked scanner/bot: %s', $bot ),
                    0,
                    XSEC_Helper::get_ip()
                );
                $this->block_access( __( 'Automated scanner detected and blocked.', 'x-security' ) );
            }
        }
    }

    /**
     * Remove version from scripts/styles
     *
     * @param string $src Source URL.
     * @return string
     */
    public function remove_version_strings( $src ) {
        if ( strpos( $src, 'ver=' ) ) {
            $src = remove_query_arg( 'ver', $src );
        }
        return $src;
    }

    /**
     * Remove X-Pingback header
     *
     * @param array $headers HTTP headers.
     * @return array
     */
    public function remove_pingback_header( $headers ) {
        unset( $headers['X-Pingback'] );
        return $headers;
    }

    /**
     * Remove XML-RPC header
     *
     * @param array $headers HTTP headers.
     * @return array
     */
    public function remove_xmlrpc_header( $headers ) {
        unset( $headers['X-Pingback'] );
        return $headers;
    }

    /**
     * Disable pingback methods
     *
     * @param array $methods XML-RPC methods.
     * @return array
     */
    public function disable_pingback_methods( $methods ) {
        unset( $methods['pingback.ping'] );
        unset( $methods['pingback.extensions.getPingbacks'] );
        return $methods;
    }

    /**
     * Block access and die
     *
     * @param string $message Block message.
     * @return void
     */
    private function block_access( $message ) {
        // Log before blocking.
        XSEC_Helper::log( 'access_blocked', $message, 0, XSEC_Helper::get_ip() );

        status_header( 403 );

        // Load blocked template if exists.
        $template = XSEC_PLUGIN_DIR . 'templates/blocked.php';
        if ( file_exists( $template ) ) {
            include $template;
        } else {
            wp_die(
                '<h1>' . esc_html__( 'Access Denied', 'x-security' ) . '</h1>' .
                '<p>' . esc_html( $message ) . '</p>' .
                '<p>' . esc_html__( 'If you believe this is an error, please contact the site administrator.', 'x-security' ) . '</p>',
                esc_html__( '403 Forbidden', 'x-security' ),
                array( 'response' => 403 )
            );
        }
        exit;
    }

    /**
     * Initialize WP_Filesystem
     *
     * @return WP_Filesystem_Base|false
     */
    private static function init_filesystem() {
        global $wp_filesystem;

        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        if ( ! WP_Filesystem() ) {
            return false;
        }

        return $wp_filesystem;
    }

    /**
     * Write .htaccess rules
     *
     * @return bool
     */
    public static function write_htaccess_rules() {
        $wp_filesystem = self::init_filesystem();
        if ( ! $wp_filesystem ) {
            return false;
        }

        $htaccess_file = ABSPATH . '.htaccess';

        if ( ! $wp_filesystem->exists( $htaccess_file ) || ! $wp_filesystem->is_writable( $htaccess_file ) ) {
            return false;
        }

        $rules   = self::get_htaccess_rules();
        $content = $wp_filesystem->get_contents( $htaccess_file );

        // Remove old rules first.
        $content = self::remove_htaccess_rules_from_content( $content );

        // Add new rules before WordPress block.
        $wp_marker = '# BEGIN WordPress';
        $pos       = strpos( $content, $wp_marker );

        if ( false !== $pos ) {
            $content = substr_replace( $content, $rules . "\n\n", $pos, 0 );
        } else {
            $content = $rules . "\n\n" . $content;
        }

        return $wp_filesystem->put_contents( $htaccess_file, $content, FS_CHMOD_FILE );
    }

    /**
     * Remove .htaccess rules
     *
     * @return bool
     */
    public static function remove_htaccess_rules() {
        $wp_filesystem = self::init_filesystem();
        if ( ! $wp_filesystem ) {
            return false;
        }

        $htaccess_file = ABSPATH . '.htaccess';

        if ( ! $wp_filesystem->exists( $htaccess_file ) || ! $wp_filesystem->is_writable( $htaccess_file ) ) {
            return false;
        }

        $content = $wp_filesystem->get_contents( $htaccess_file );
        $content = self::remove_htaccess_rules_from_content( $content );

        return $wp_filesystem->put_contents( $htaccess_file, $content, FS_CHMOD_FILE );
    }

    /**
     * Remove rules from content
     *
     * @param string $content File content.
     * @return string
     */
    private static function remove_htaccess_rules_from_content( $content ) {
        $pattern = '/# BEGIN X Security.*?# END X Security\s*/s';
        return preg_replace( $pattern, '', $content );
    }

    /**
     * Get htaccess rules
     *
     * @return string
     */
    private static function get_htaccess_rules() {
        $rules   = array();
        $rules[] = '# BEGIN X Security';
        $rules[] = '# Security rules by X Security plugin';
        $rules[] = '';

        // Disable server signature.
        $rules[] = 'ServerSignature Off';
        $rules[] = '';

        // Protect wp-config.php.
        $rules[] = '<Files wp-config.php>';
        $rules[] = '    Order Allow,Deny';
        $rules[] = '    Deny from all';
        $rules[] = '</Files>';
        $rules[] = '';

        // Protect .htaccess.
        $rules[] = '<Files .htaccess>';
        $rules[] = '    Order Allow,Deny';
        $rules[] = '    Deny from all';
        $rules[] = '</Files>';
        $rules[] = '';

        // Block XML-RPC.
        $rules[] = '<Files xmlrpc.php>';
        $rules[] = '    Order Allow,Deny';
        $rules[] = '    Deny from all';
        $rules[] = '</Files>';
        $rules[] = '';

        // Disable directory browsing.
        $rules[] = 'Options -Indexes';
        $rules[] = '';

        // Block common exploits.
        $rules[] = '<IfModule mod_rewrite.c>';
        $rules[] = '    RewriteEngine On';
        $rules[] = '    RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]';
        $rules[] = '    RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]';
        $rules[] = '    RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2})';
        $rules[] = '    RewriteRule .* - [F,L]';
        $rules[] = '</IfModule>';
        $rules[] = '';

        $rules[] = '# END X Security';

        return implode( "\n", $rules );
    }
}
