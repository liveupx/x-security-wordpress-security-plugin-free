<?php
/**
 * Login Security - Brute force protection, lockouts, honeypot
 */

if (!defined('ABSPATH')) {
    exit;
}

class XSEC_Login_Security {
    
    private static $instance = null;
    private $config;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->config = XSEC_Config::get_instance();
        $this->init_hooks();
    }
    
    private function init_hooks() {
        // Check if IP is locked before login
        add_action('wp_login', array($this, 'on_login_success'), 10, 2);
        add_filter('authenticate', array($this, 'check_lockout'), 30, 3);
        add_action('wp_login_failed', array($this, 'on_login_failed'), 10, 2);
        
        // Honeypot field
        if ($this->config->get('login_honeypot_enabled')) {
            add_action('login_form', array($this, 'add_honeypot_field'));
            add_filter('authenticate', array($this, 'check_honeypot'), 25, 3);
        }
        
        // Hide login errors
        if ($this->config->get('hide_login_errors')) {
            add_filter('login_errors', array($this, 'hide_login_errors'));
        }
        
        // Simple math captcha
        if ($this->config->get('login_captcha_enabled')) {
            add_action('login_form', array($this, 'add_captcha_field'));
            add_filter('authenticate', array($this, 'check_captcha'), 20, 3);
        }
    }
    
    /**
     * Check if user is locked out
     */
    public function check_lockout($user, $username, $password) {
        if (empty($username)) {
            return $user;
        }
        
        // Skip for whitelisted IPs
        if (XSEC_Helper::is_whitelisted()) {
            return $user;
        }
        
        $ip = XSEC_Helper::get_ip();
        
        // Check if IP is blocked
        if (XSEC_Helper::is_blocked($ip)) {
            return new WP_Error('xsec_blocked', 
                __('<strong>Access Denied</strong>: Your IP has been blocked due to suspicious activity.', 'x-security')
            );
        }
        
        // Check for active lockout
        if ($this->is_locked_out($ip, $username)) {
            $remaining = $this->get_lockout_remaining($ip, $username);
            return new WP_Error('xsec_lockout', 
                sprintf(
                    __('<strong>Account Locked</strong>: Too many failed login attempts. Please try again in %d minutes.', 'x-security'),
                    ceil($remaining / 60)
                )
            );
        }
        
        return $user;
    }
    
    /**
     * Handle failed login
     */
    public function on_login_failed($username, $error = null) {
        if (!$this->config->get('login_lockout_enabled')) {
            return;
        }
        
        // Skip for whitelisted IPs
        if (XSEC_Helper::is_whitelisted()) {
            return;
        }
        
        $ip = XSEC_Helper::get_ip();
        
        // Record failed attempt
        $this->record_failed_attempt($ip, $username);
        
        // Check if should lockout
        $attempts = $this->get_failed_attempts($ip, $username);
        $max_attempts = $this->config->get('max_login_attempts', 3);
        
        if ($attempts >= $max_attempts) {
            $this->create_lockout($ip, $username);
        }
        
        XSEC_Helper::log('login_failed', sprintf('Failed login attempt for user: %s', $username), 0, $ip);
    }
    
    /**
     * Handle successful login
     */
    public function on_login_success($username, $user) {
        $ip = XSEC_Helper::get_ip();
        
        // Clear failed attempts
        $this->clear_failed_attempts($ip, $username);
        
        XSEC_Helper::log('login_success', sprintf('Successful login for user: %s', $username), $user->ID, $ip);
    }
    
    /**
     * Record a failed login attempt
     */
    private function record_failed_attempt($ip, $username) {
        global $wpdb;
        
        $wpdb->insert(
            XSEC_TBL_FAILED_LOGINS,
            array(
                'ip_address' => $ip,
                'username' => $username,
                'attempt_time' => current_time('mysql'),
            ),
            array('%s', '%s', '%s')
        );
    }
    
    /**
     * Get failed attempts count
     */
    private function get_failed_attempts($ip, $username) {
        global $wpdb;
        
        // Count attempts in last hour
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM " . XSEC_TBL_FAILED_LOGINS . " 
            WHERE ip_address = %s 
            AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
            $ip
        ));
    }
    
    /**
     * Clear failed attempts
     */
    private function clear_failed_attempts($ip, $username) {
        global $wpdb;
        
        $wpdb->delete(
            XSEC_TBL_FAILED_LOGINS,
            array('ip_address' => $ip),
            array('%s')
        );
    }
    
    /**
     * Create a lockout
     */
    private function create_lockout($ip, $username) {
        global $wpdb;
        
        $duration = $this->config->get('lockout_duration', 60);
        
        $wpdb->insert(
            XSEC_TBL_LOGIN_LOCKOUT,
            array(
                'ip_address' => $ip,
                'username' => $username,
                'lockout_time' => current_time('mysql'),
                'release_time' => date('Y-m-d H:i:s', strtotime('+' . $duration . ' minutes')),
                'reason' => 'Too many failed login attempts',
            ),
            array('%s', '%s', '%s', '%s', '%s')
        );
        
        XSEC_Helper::log('lockout_created', 
            sprintf('Lockout created for IP: %s, User: %s', $ip, $username), 
            0, $ip
        );
        
        // Send notification
        XSEC_Helper::send_notification(
            __('Login Lockout Alert', 'x-security'),
            sprintf(
                __('A lockout has been triggered on your site.<br><br>IP Address: %s<br>Username: %s<br>Duration: %d minutes', 'x-security'),
                $ip, $username, $duration
            )
        );
    }
    
    /**
     * Check if IP/user is locked out
     */
    private function is_locked_out($ip, $username) {
        global $wpdb;
        
        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM " . XSEC_TBL_LOGIN_LOCKOUT . " 
            WHERE ip_address = %s AND release_time > NOW()",
            $ip
        ));
        
        return $count > 0;
    }
    
    /**
     * Get remaining lockout time in seconds
     */
    private function get_lockout_remaining($ip, $username) {
        global $wpdb;
        
        $release_time = $wpdb->get_var($wpdb->prepare(
            "SELECT release_time FROM " . XSEC_TBL_LOGIN_LOCKOUT . " 
            WHERE ip_address = %s AND release_time > NOW() 
            ORDER BY release_time DESC LIMIT 1",
            $ip
        ));
        
        if ($release_time) {
            return strtotime($release_time) - time();
        }
        
        return 0;
    }
    
    /**
     * Add honeypot field
     */
    public function add_honeypot_field() {
        ?>
        <p class="xsec-hp-field" style="position:absolute;left:-9999px;">
            <label for="xsec_hp_email"><?php esc_html_e('Leave this empty', 'x-security'); ?></label>
            <input type="text" name="xsec_hp_email" id="xsec_hp_email" value="" autocomplete="off" tabindex="-1">
        </p>
        <?php
    }
    
    /**
     * Check honeypot field
     */
    public function check_honeypot($user, $username, $password) {
        if (empty($username)) {
            return $user;
        }
        
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        if (!empty($_POST['xsec_hp_email'])) {
            XSEC_Helper::log('honeypot_triggered', 'Bot detected via honeypot field');
            return new WP_Error('xsec_honeypot', __('Bot detected. Access denied.', 'x-security'));
        }
        
        return $user;
    }
    
    /**
     * Hide specific login errors
     */
    public function hide_login_errors($error) {
        return __('<strong>Error</strong>: The username or password you entered is incorrect.', 'x-security');
    }
    
    /**
     * Add simple math captcha
     */
    public function add_captcha_field() {
        $num1 = wp_rand(1, 10);
        $num2 = wp_rand(1, 10);
        $answer = $num1 + $num2;
        
        // Store answer in transient
        $key = 'xsec_captcha_' . XSEC_Helper::get_ip();
        set_transient($key, $answer, 300);
        
        ?>
        <p>
            <label for="xsec_captcha"><?php printf(esc_html__('Security Check: %d + %d = ?', 'x-security'), $num1, $num2); ?></label>
            <input type="number" name="xsec_captcha" id="xsec_captcha" class="input" required>
        </p>
        <?php
    }
    
    /**
     * Check captcha answer
     */
    public function check_captcha($user, $username, $password) {
        if (empty($username)) {
            return $user;
        }
        
        $key = 'xsec_captcha_' . XSEC_Helper::get_ip();
        $expected = get_transient($key);
        
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $answer = isset($_POST['xsec_captcha']) ? intval($_POST['xsec_captcha']) : 0;
        
        if ($expected && $answer !== $expected) {
            return new WP_Error('xsec_captcha_failed', __('<strong>Error</strong>: Security check failed. Please try again.', 'x-security'));
        }
        
        delete_transient($key);
        
        return $user;
    }
}
