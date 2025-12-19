<?php
/**
 * AJAX Handler - Processes all AJAX requests
 */

if (!defined('ABSPATH')) {
    exit;
}

class XSEC_Ajax {
    
    private static $instance = null;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        add_action('wp_ajax_xsec_action', array($this, 'handle_ajax'));
    }
    
    /**
     * Handle AJAX requests
     */
    public function handle_ajax() {
        // Verify nonce
        if (!check_ajax_referer('xsec_ajax_nonce', 'nonce', false)) {
            wp_send_json_error(array('message' => __('Security check failed.', 'x-security')));
        }
        
        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Permission denied.', 'x-security')));
        }
        
        $action = isset($_POST['security_action']) ? sanitize_text_field(wp_unslash($_POST['security_action'])) : '';
        
        switch ($action) {
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
                
            default:
                wp_send_json_error(array('message' => __('Invalid action.', 'x-security')));
        }
    }
    
    /**
     * Run security scan
     */
    private function run_scan() {
        $config = XSEC_Config::get_instance();
        $results = array(
            'score' => XSEC_Helper::get_security_score(),
            'passed' => array(),
            'issues' => array(),
            'warnings' => array()
        );
        
        // Check login security
        if ($config->get('login_lockout_enabled')) {
            $results['passed'][] = array('title' => 'Login lockout is enabled');
        } else {
            $results['issues'][] = array('title' => 'Login lockout is disabled', 'description' => 'Enable login lockout to prevent brute force attacks');
        }
        
        // Check honeypot
        if ($config->get('login_honeypot_enabled')) {
            $results['passed'][] = array('title' => 'Login honeypot is active');
        } else {
            $results['warnings'][] = array('title' => 'Login honeypot is disabled');
        }
        
        // Check firewall
        if ($config->get('firewall_enabled')) {
            $results['passed'][] = array('title' => 'Firewall is enabled');
        } else {
            $results['issues'][] = array('title' => 'Firewall is disabled', 'description' => 'Enable the firewall to block malicious requests');
        }
        
        // Check XML-RPC
        if ($config->get('disable_xmlrpc')) {
            $results['passed'][] = array('title' => 'XML-RPC is disabled');
        } else {
            $results['warnings'][] = array('title' => 'XML-RPC is enabled', 'description' => 'Consider disabling XML-RPC if not used');
        }
        
        // Check user enumeration
        if ($config->get('user_enum_protection')) {
            $results['passed'][] = array('title' => 'User enumeration protection is active');
        } else {
            $results['issues'][] = array('title' => 'User enumeration protection is disabled');
        }
        
        // Check file editor
        if ($config->get('disable_file_editing') || defined('DISALLOW_FILE_EDIT')) {
            $results['passed'][] = array('title' => 'Theme/Plugin editor is disabled');
        } else {
            $results['issues'][] = array('title' => 'Theme/Plugin editor is enabled', 'description' => 'Disable the file editor for better security');
        }
        
        // Check WP version
        if ($config->get('remove_wp_version')) {
            $results['passed'][] = array('title' => 'WordPress version is hidden');
        } else {
            $results['warnings'][] = array('title' => 'WordPress version is visible');
        }
        
        // Check debug mode
        if (defined('WP_DEBUG') && WP_DEBUG) {
            $results['warnings'][] = array('title' => 'Debug mode is enabled', 'description' => 'Disable debug mode in production');
        } else {
            $results['passed'][] = array('title' => 'Debug mode is disabled');
        }
        
        // Check SSL
        if (is_ssl()) {
            $results['passed'][] = array('title' => 'SSL/HTTPS is active');
        } else {
            $results['issues'][] = array('title' => 'SSL/HTTPS is not active', 'description' => 'Enable HTTPS for secure connections');
        }
        
        XSEC_Helper::log('security_scan', 'Security scan completed. Score: ' . $results['score']);
        
        wp_send_json_success(array(
            'message' => __('Security scan completed!', 'x-security'),
            'results' => $results
        ));
    }
    
    /**
     * Clear all lockouts
     */
    private function clear_lockouts() {
        global $wpdb;
        $wpdb->query("TRUNCATE TABLE " . XSEC_TBL_LOGIN_LOCKOUT);
        XSEC_Helper::log('lockouts_cleared', 'All login lockouts cleared');
        wp_send_json_success(array('message' => __('All lockouts cleared.', 'x-security')));
    }
    
    /**
     * Clear failed logins
     */
    private function clear_failed_logins() {
        global $wpdb;
        $wpdb->query("TRUNCATE TABLE " . XSEC_TBL_FAILED_LOGINS);
        XSEC_Helper::log('failed_logins_cleared', 'Failed login records cleared');
        wp_send_json_success(array('message' => __('Failed login records cleared.', 'x-security')));
    }
    
    /**
     * Clear activity log
     */
    private function clear_activity_log() {
        global $wpdb;
        $wpdb->query("TRUNCATE TABLE " . XSEC_TBL_ACTIVITY_LOG);
        wp_send_json_success(array('message' => __('Activity log cleared.', 'x-security')));
    }
    
    /**
     * Run cleanup
     */
    private function cleanup() {
        XSEC_Helper::cleanup();
        wp_send_json_success(array('message' => __('Old data cleaned up.', 'x-security')));
    }
    
    /**
     * Block IP
     */
    private function block_ip() {
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        $reason = isset($_POST['reason']) ? sanitize_text_field(wp_unslash($_POST['reason'])) : '';
        
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(array('message' => __('Invalid IP address.', 'x-security')));
        }
        
        // Don't block current user's IP
        if ($ip === XSEC_Helper::get_ip()) {
            wp_send_json_error(array('message' => __('You cannot block your own IP address.', 'x-security')));
        }
        
        XSEC_Helper::block_ip($ip, $reason);
        wp_send_json_success(array('message' => __('IP blocked successfully.', 'x-security')));
    }
    
    /**
     * Unblock IP
     */
    private function unblock_ip() {
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        
        if (empty($ip)) {
            wp_send_json_error(array('message' => __('Invalid IP address.', 'x-security')));
        }
        
        XSEC_Helper::unblock_ip($ip);
        wp_send_json_success(array('message' => __('IP unblocked.', 'x-security')));
    }
    
    /**
     * Whitelist IP
     */
    private function whitelist_ip() {
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        $description = isset($_POST['description']) ? sanitize_text_field(wp_unslash($_POST['description'])) : '';
        
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error(array('message' => __('Invalid IP address.', 'x-security')));
        }
        
        XSEC_Helper::whitelist_ip($ip, $description);
        wp_send_json_success(array('message' => __('IP whitelisted.', 'x-security')));
    }
    
    /**
     * Remove from whitelist
     */
    private function remove_whitelist() {
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
        
        if (empty($ip)) {
            wp_send_json_error(array('message' => __('Invalid IP address.', 'x-security')));
        }
        
        XSEC_Helper::remove_whitelist($ip);
        wp_send_json_success(array('message' => __('IP removed from whitelist.', 'x-security')));
    }
    
    /**
     * Write .htaccess rules
     */
    private function write_htaccess() {
        if (XSEC_Firewall::write_htaccess_rules()) {
            XSEC_Helper::log('htaccess_enabled', '.htaccess security rules enabled');
            wp_send_json_success(array('message' => __('.htaccess protection enabled.', 'x-security')));
        } else {
            wp_send_json_error(array('message' => __('Failed to write .htaccess rules.', 'x-security')));
        }
    }
    
    /**
     * Remove .htaccess rules
     */
    private function remove_htaccess() {
        if (XSEC_Firewall::remove_htaccess_rules()) {
            XSEC_Helper::log('htaccess_disabled', '.htaccess security rules removed');
            wp_send_json_success(array('message' => __('.htaccess rules removed.', 'x-security')));
        } else {
            wp_send_json_error(array('message' => __('Failed to remove .htaccess rules.', 'x-security')));
        }
    }
}
