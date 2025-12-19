<?php
/**
 * Admin Menu and Pages
 */

if (!defined('ABSPATH')) {
    exit;
}

class XSEC_Admin {
    
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
        
        add_action('admin_menu', array($this, 'add_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
        add_action('admin_init', array($this, 'register_settings'));
    }
    
    /**
     * Add admin menu
     */
    public function add_menu() {
        add_menu_page(
            __('X Security', 'x-security'),
            __('X Security', 'x-security'),
            'manage_options',
            'x-security',
            array($this, 'render_dashboard'),
            'dashicons-shield-alt',
            80
        );
        
        add_submenu_page('x-security', __('Dashboard', 'x-security'), __('Dashboard', 'x-security'), 
            'manage_options', 'x-security', array($this, 'render_dashboard'));
        
        add_submenu_page('x-security', __('Settings', 'x-security'), __('Settings', 'x-security'), 
            'manage_options', 'x-security-settings', array($this, 'render_settings'));
        
        add_submenu_page('x-security', __('Login Security', 'x-security'), __('Login Security', 'x-security'), 
            'manage_options', 'x-security-login', array($this, 'render_login'));
        
        add_submenu_page('x-security', __('Firewall', 'x-security'), __('Firewall', 'x-security'), 
            'manage_options', 'x-security-firewall', array($this, 'render_firewall'));
        
        add_submenu_page('x-security', __('IP Manager', 'x-security'), __('IP Manager', 'x-security'), 
            'manage_options', 'x-security-ip', array($this, 'render_ip_manager'));
        
        add_submenu_page('x-security', __('Activity Log', 'x-security'), __('Activity Log', 'x-security'), 
            'manage_options', 'x-security-logs', array($this, 'render_logs'));
    }
    
    /**
     * Enqueue admin assets
     */
    public function enqueue_assets($hook) {
        if (strpos($hook, 'x-security') === false) {
            return;
        }
        
        wp_enqueue_style('xsec-admin', XSEC_PLUGIN_URL . 'assets/css/admin.css', array(), XSEC_VERSION);
        wp_enqueue_script('xsec-admin', XSEC_PLUGIN_URL . 'assets/js/admin.js', array('jquery'), XSEC_VERSION, true);
        
        wp_localize_script('xsec-admin', 'xsec', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('xsec_ajax_nonce'),
            'strings' => array(
                'confirm' => __('Are you sure?', 'x-security'),
                'loading' => __('Loading...', 'x-security'),
                'success' => __('Success!', 'x-security'),
                'error' => __('An error occurred.', 'x-security'),
            )
        ));
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('xsec_settings', 'xsec_settings', array($this, 'sanitize_settings'));
    }
    
    /**
     * Sanitize settings
     */
    public function sanitize_settings($input) {
        $defaults = XSEC_Config::get_defaults();
        $sanitized = array();
        
        // Checkboxes
        $checkboxes = array(
            'login_lockout_enabled', 'login_captcha_enabled', 'login_honeypot_enabled', 'hide_login_errors',
            'user_enum_protection', 'strong_password_enabled', 'block_admin_username', 'disable_file_editing',
            'firewall_enabled', 'block_bad_queries', 'block_bad_bots', 'remove_wp_version',
            'disable_xmlrpc', 'disable_pingbacks', 'email_notifications'
        );
        
        foreach ($checkboxes as $key) {
            $sanitized[$key] = isset($input[$key]) ? 1 : 0;
        }
        
        // Numbers
        $sanitized['max_login_attempts'] = isset($input['max_login_attempts']) ? absint($input['max_login_attempts']) : 3;
        $sanitized['lockout_duration'] = isset($input['lockout_duration']) ? absint($input['lockout_duration']) : 60;
        $sanitized['min_password_length'] = isset($input['min_password_length']) ? absint($input['min_password_length']) : 10;
        
        // Email
        $sanitized['notification_email'] = isset($input['notification_email']) ? sanitize_email($input['notification_email']) : '';
        
        return $sanitized;
    }
    
    /**
     * Render page header
     */
    private function render_header($title) {
        ?>
        <div class="wrap xsec-wrap">
            <div class="xsec-header">
                <div class="xsec-logo">
                    <span class="dashicons dashicons-shield-alt"></span>
                    <h1>X Security</h1>
                    <span class="xsec-version">v<?php echo esc_html(XSEC_VERSION); ?></span>
                </div>
                <div class="xsec-by">by <a href="https://liveupx.com" target="_blank">Liveupx.com</a></div>
            </div>
            
            <div class="xsec-promo">
                <span class="dashicons dashicons-megaphone"></span>
                <strong>Need WordPress Help?</strong> Hire our expert team for custom development, security audits, and more!
                <a href="https://liveupx.com/contact" target="_blank" class="button">Hire Us →</a>
            </div>
        <?php
    }
    
    /**
     * Render page footer
     */
    private function render_footer() {
        ?>
            <div class="xsec-footer">
                <p>
                    <strong>X Security</strong> by <a href="https://liveupx.com" target="_blank">Liveupx.com</a> | 
                    <a href="https://liveupx.com/docs" target="_blank">Documentation</a> | 
                    <a href="https://liveupx.com/support" target="_blank">Support</a>
                </p>
            </div>
        </div>
        <?php
    }
    
    /**
     * Dashboard page
     */
    public function render_dashboard() {
        global $wpdb;

        $score = XSEC_Helper::get_security_score();

        // Stats.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Dashboard stats require real-time data.
        $blocked_ips = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}xsec_blocked_ips" );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Dashboard stats require real-time data.
        $active_lockouts = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}xsec_login_lockouts WHERE release_time > NOW()" );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Dashboard stats require real-time data.
        $events_today = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}xsec_activity_log WHERE DATE(event_time) = CURDATE()" );

        // Recent activity.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Dashboard requires real-time activity data.
        $recent_activity = $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}xsec_activity_log ORDER BY event_time DESC LIMIT 10"
        );
        
        $this->render_header(__('Dashboard', 'x-security'));
        ?>
        
        <div class="xsec-dashboard">
            <!-- Score Card -->
            <div class="xsec-card xsec-score-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-chart-area"></span> Security Score</h2>
                </div>
                <div class="card-body">
                    <div class="score-circle <?php echo $score >= 70 ? 'good' : ($score >= 40 ? 'medium' : 'low'); ?>">
                        <span class="score-value"><?php echo esc_html($score); ?></span>
                        <span class="score-max">/100</span>
                    </div>
                    <p class="score-message">
                        <?php
                        if ($score >= 80) {
                            esc_html_e('Excellent! Your site is well protected.', 'x-security');
                        } elseif ($score >= 60) {
                            esc_html_e('Good protection. Enable more features for better security.', 'x-security');
                        } elseif ($score >= 40) {
                            esc_html_e('Moderate security. Consider enabling more features.', 'x-security');
                        } else {
                            esc_html_e('Low protection! Enable security features now.', 'x-security');
                        }
                        ?>
                    </p>
                    <button type="button" class="button button-primary xsec-action-btn" data-action="run_scan">
                        <span class="dashicons dashicons-search"></span> Run Security Scan
                    </button>
                </div>
            </div>
            
            <!-- Stats -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-chart-bar"></span> Quick Stats</h2>
                </div>
                <div class="card-body">
                    <div class="stats-grid">
                        <div class="stat-item">
                            <span class="stat-number"><?php echo esc_html($blocked_ips); ?></span>
                            <span class="stat-label">Blocked IPs</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number"><?php echo esc_html($active_lockouts); ?></span>
                            <span class="stat-label">Active Lockouts</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number"><?php echo esc_html($events_today); ?></span>
                            <span class="stat-label">Events Today</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Quick Actions -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-admin-tools"></span> Quick Actions</h2>
                </div>
                <div class="card-body">
                    <div class="quick-actions">
                        <button type="button" class="button xsec-action-btn" data-action="clear_lockouts">
                            <span class="dashicons dashicons-unlock"></span> Clear Lockouts
                        </button>
                        <button type="button" class="button xsec-action-btn" data-action="clear_failed_logins">
                            <span class="dashicons dashicons-dismiss"></span> Clear Failed Logins
                        </button>
                        <button type="button" class="button xsec-action-btn" data-action="cleanup">
                            <span class="dashicons dashicons-trash"></span> Cleanup Old Data
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- Recent Activity -->
            <div class="xsec-card xsec-card-wide">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-list-view"></span> Recent Activity</h2>
                </div>
                <div class="card-body">
                    <?php if ($recent_activity) : ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Event', 'x-security'); ?></th>
                                    <th><?php esc_html_e('Description', 'x-security'); ?></th>
                                    <th><?php esc_html_e('IP Address', 'x-security'); ?></th>
                                    <th><?php esc_html_e('Time', 'x-security'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($recent_activity as $event) : ?>
                                    <tr>
                                        <td><span class="event-badge event-<?php echo esc_attr($event->event_type); ?>"><?php echo esc_html($event->event_type); ?></span></td>
                                        <td><?php echo esc_html($event->event_description); ?></td>
                                        <td><code><?php echo esc_html($event->ip_address); ?></code></td>
                                        <td><?php echo esc_html(human_time_diff(strtotime($event->event_time), current_time('timestamp'))); ?> ago</td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else : ?>
                        <p class="no-data"><?php esc_html_e('No recent activity recorded.', 'x-security'); ?></p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Scan Results Modal -->
        <div id="xsec-modal" class="xsec-modal" style="display:none;">
            <div class="modal-content">
                <span class="modal-close">&times;</span>
                <h2 id="modal-title">Results</h2>
                <div id="modal-body"></div>
            </div>
        </div>
        
        <?php
        $this->render_footer();
    }
    
    /**
     * Settings page
     */
    public function render_settings() {
        $settings = $this->config->get_all();
        
        $this->render_header(__('Settings', 'x-security'));
        ?>
        
        <form method="post" action="options.php" class="xsec-form">
            <?php settings_fields('xsec_settings'); ?>
            
            <div class="xsec-settings-grid">
                <!-- Login Security -->
                <div class="xsec-card">
                    <div class="card-header">
                        <h2><span class="dashicons dashicons-lock"></span> Login Security</h2>
                    </div>
                    <div class="card-body">
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[login_lockout_enabled]" value="1" <?php checked($settings['login_lockout_enabled']); ?>>
                            <span class="slider"></span>
                            Enable Login Lockout
                        </label>
                        
                        <div class="form-row">
                            <label>
                                Max Login Attempts
                                <input type="number" name="xsec_settings[max_login_attempts]" value="<?php echo esc_attr($settings['max_login_attempts']); ?>" min="1" max="20" class="small-text">
                            </label>
                            <label>
                                Lockout Duration (minutes)
                                <input type="number" name="xsec_settings[lockout_duration]" value="<?php echo esc_attr($settings['lockout_duration']); ?>" min="1" class="small-text">
                            </label>
                        </div>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[login_captcha_enabled]" value="1" <?php checked($settings['login_captcha_enabled']); ?>>
                            <span class="slider"></span>
                            Enable Login CAPTCHA
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[login_honeypot_enabled]" value="1" <?php checked($settings['login_honeypot_enabled']); ?>>
                            <span class="slider"></span>
                            Enable Honeypot
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[hide_login_errors]" value="1" <?php checked($settings['hide_login_errors']); ?>>
                            <span class="slider"></span>
                            Hide Login Error Details
                        </label>
                    </div>
                </div>
                
                <!-- User Security -->
                <div class="xsec-card">
                    <div class="card-header">
                        <h2><span class="dashicons dashicons-admin-users"></span> User Security</h2>
                    </div>
                    <div class="card-body">
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[user_enum_protection]" value="1" <?php checked($settings['user_enum_protection']); ?>>
                            <span class="slider"></span>
                            Block User Enumeration
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[strong_password_enabled]" value="1" <?php checked($settings['strong_password_enabled']); ?>>
                            <span class="slider"></span>
                            Enforce Strong Passwords
                        </label>
                        
                        <label>
                            Min Password Length
                            <input type="number" name="xsec_settings[min_password_length]" value="<?php echo esc_attr($settings['min_password_length']); ?>" min="8" max="64" class="small-text">
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[block_admin_username]" value="1" <?php checked($settings['block_admin_username']); ?>>
                            <span class="slider"></span>
                            Block "admin" Username
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[disable_file_editing]" value="1" <?php checked($settings['disable_file_editing']); ?>>
                            <span class="slider"></span>
                            Disable Theme/Plugin Editor
                        </label>
                    </div>
                </div>
                
                <!-- Firewall -->
                <div class="xsec-card">
                    <div class="card-header">
                        <h2><span class="dashicons dashicons-shield"></span> Firewall</h2>
                    </div>
                    <div class="card-body">
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[firewall_enabled]" value="1" <?php checked($settings['firewall_enabled']); ?>>
                            <span class="slider"></span>
                            Enable Firewall
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[block_bad_queries]" value="1" <?php checked($settings['block_bad_queries']); ?>>
                            <span class="slider"></span>
                            Block Malicious Queries
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[block_bad_bots]" value="1" <?php checked($settings['block_bad_bots']); ?>>
                            <span class="slider"></span>
                            Block Bad Bots
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[remove_wp_version]" value="1" <?php checked($settings['remove_wp_version']); ?>>
                            <span class="slider"></span>
                            Remove WP Version
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[disable_xmlrpc]" value="1" <?php checked($settings['disable_xmlrpc']); ?>>
                            <span class="slider"></span>
                            Disable XML-RPC
                        </label>
                        
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[disable_pingbacks]" value="1" <?php checked($settings['disable_pingbacks']); ?>>
                            <span class="slider"></span>
                            Disable Pingbacks
                        </label>
                    </div>
                </div>
                
                <!-- Notifications -->
                <div class="xsec-card">
                    <div class="card-header">
                        <h2><span class="dashicons dashicons-email"></span> Notifications</h2>
                    </div>
                    <div class="card-body">
                        <label class="xsec-toggle">
                            <input type="checkbox" name="xsec_settings[email_notifications]" value="1" <?php checked($settings['email_notifications']); ?>>
                            <span class="slider"></span>
                            Enable Email Notifications
                        </label>
                        
                        <label>
                            Notification Email
                            <input type="email" name="xsec_settings[notification_email]" value="<?php echo esc_attr($settings['notification_email']); ?>" class="regular-text" placeholder="<?php echo esc_attr(get_option('admin_email')); ?>">
                        </label>
                    </div>
                </div>
            </div>
            
            <?php submit_button(__('Save Settings', 'x-security')); ?>
        </form>
        
        <?php
        $this->render_footer();
    }
    
    /**
     * Login Security page
     */
    public function render_login() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security page requires real-time lockout data.
        $lockouts = $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}xsec_login_lockouts ORDER BY lockout_time DESC LIMIT 50"
        );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security page requires real-time failed login data.
        $failed_logins = $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}xsec_failed_logins ORDER BY attempt_time DESC LIMIT 50"
        );
        
        $this->render_header(__('Login Security', 'x-security'));
        ?>
        
        <div class="xsec-grid">
            <!-- Lockouts -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-lock"></span> Login Lockouts</h2>
                    <button type="button" class="button xsec-action-btn" data-action="clear_lockouts">Clear All</button>
                </div>
                <div class="card-body">
                    <?php if ($lockouts) : ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Username</th>
                                    <th>Locked At</th>
                                    <th>Expires</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($lockouts as $lockout) : 
                                    $is_active = strtotime($lockout->release_time) > current_time('timestamp');
                                ?>
                                    <tr>
                                        <td><code><?php echo esc_html($lockout->ip_address); ?></code></td>
                                        <td><?php echo esc_html($lockout->username); ?></td>
                                        <td><?php echo esc_html(date_i18n('M j, Y g:i A', strtotime($lockout->lockout_time))); ?></td>
                                        <td><?php echo esc_html(date_i18n('M j, Y g:i A', strtotime($lockout->release_time))); ?></td>
                                        <td>
                                            <?php if ($is_active) : ?>
                                                <span class="status-badge active">Active</span>
                                            <?php else : ?>
                                                <span class="status-badge expired">Expired</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else : ?>
                        <p class="no-data"><?php esc_html_e('No lockouts recorded.', 'x-security'); ?></p>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Failed Logins -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-warning"></span> Failed Login Attempts</h2>
                    <button type="button" class="button xsec-action-btn" data-action="clear_failed_logins">Clear All</button>
                </div>
                <div class="card-body">
                    <?php if ($failed_logins) : ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Username</th>
                                    <th>Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($failed_logins as $attempt) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html($attempt->ip_address); ?></code></td>
                                        <td><?php echo esc_html($attempt->username); ?></td>
                                        <td><?php echo esc_html(human_time_diff(strtotime($attempt->attempt_time), current_time('timestamp'))); ?> ago</td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else : ?>
                        <p class="no-data"><?php esc_html_e('No failed login attempts recorded.', 'x-security'); ?></p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <?php
        $this->render_footer();
    }
    
    /**
     * Firewall page
     */
    public function render_firewall() {
        $settings = $this->config->get_all();
        $htaccess_file = ABSPATH . '.htaccess';

        // Initialize WP_Filesystem.
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();
        global $wp_filesystem;

        $htaccess_exists    = $wp_filesystem && $wp_filesystem->exists( $htaccess_file );
        $htaccess_writable  = $htaccess_exists && $wp_filesystem->is_writable( $htaccess_file );

        $rules_active = false;
        if ( $htaccess_exists && $wp_filesystem ) {
            $content      = $wp_filesystem->get_contents( $htaccess_file );
            $rules_active = strpos( $content, '# BEGIN X Security' ) !== false;
        }
        
        $this->render_header(__('Firewall', 'x-security'));
        ?>
        
        <div class="xsec-grid">
            <!-- Firewall Status -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-shield"></span> Firewall Status</h2>
                </div>
                <div class="card-body">
                    <div class="status-list">
                        <div class="status-item">
                            <span class="label">PHP Firewall:</span>
                            <span class="value <?php echo $settings['firewall_enabled'] ? 'on' : 'off'; ?>">
                                <?php echo $settings['firewall_enabled'] ? 'Enabled' : 'Disabled'; ?>
                            </span>
                        </div>
                        <div class="status-item">
                            <span class="label">Bad Query Blocking:</span>
                            <span class="value <?php echo $settings['block_bad_queries'] ? 'on' : 'off'; ?>">
                                <?php echo $settings['block_bad_queries'] ? 'Enabled' : 'Disabled'; ?>
                            </span>
                        </div>
                        <div class="status-item">
                            <span class="label">Bot Protection:</span>
                            <span class="value <?php echo $settings['block_bad_bots'] ? 'on' : 'off'; ?>">
                                <?php echo $settings['block_bad_bots'] ? 'Enabled' : 'Disabled'; ?>
                            </span>
                        </div>
                        <div class="status-item">
                            <span class="label">XML-RPC:</span>
                            <span class="value <?php echo $settings['disable_xmlrpc'] ? 'on' : 'off'; ?>">
                                <?php echo $settings['disable_xmlrpc'] ? 'Disabled' : 'Enabled'; ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- .htaccess Protection -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-admin-generic"></span> .htaccess Protection</h2>
                </div>
                <div class="card-body">
                    <div class="status-list">
                        <div class="status-item">
                            <span class="label">.htaccess File:</span>
                            <span class="value <?php echo $htaccess_exists ? 'on' : 'off'; ?>">
                                <?php echo $htaccess_exists ? 'Exists' : 'Not Found'; ?>
                            </span>
                        </div>
                        <div class="status-item">
                            <span class="label">Writable:</span>
                            <span class="value <?php echo $htaccess_writable ? 'on' : 'off'; ?>">
                                <?php echo $htaccess_writable ? 'Yes' : 'No'; ?>
                            </span>
                        </div>
                        <div class="status-item">
                            <span class="label">Security Rules:</span>
                            <span class="value <?php echo $rules_active ? 'on' : 'off'; ?>">
                                <?php echo $rules_active ? 'Active' : 'Not Active'; ?>
                            </span>
                        </div>
                    </div>
                    
                    <div class="button-row">
                        <?php if ($htaccess_writable) : ?>
                            <?php if ($rules_active) : ?>
                                <button type="button" class="button xsec-action-btn" data-action="remove_htaccess">
                                    <span class="dashicons dashicons-no"></span> Remove Rules
                                </button>
                            <?php else : ?>
                                <button type="button" class="button button-primary xsec-action-btn" data-action="write_htaccess">
                                    <span class="dashicons dashicons-yes"></span> Enable .htaccess Protection
                                </button>
                            <?php endif; ?>
                        <?php else : ?>
                            <p class="description"><?php esc_html_e('.htaccess file is not writable. Please check file permissions.', 'x-security'); ?></p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        
        <?php
        $this->render_footer();
    }
    
    /**
     * IP Manager page
     */
    public function render_ip_manager() {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- IP manager requires real-time blocked IP data.
        $blocked_ips = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}xsec_blocked_ips ORDER BY blocked_time DESC" );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- IP manager requires real-time whitelist data.
        $whitelisted_ips = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}xsec_whitelist_ips ORDER BY added_time DESC" );
        $current_ip      = XSEC_Helper::get_ip();
        
        $this->render_header(__('IP Manager', 'x-security'));
        ?>
        
        <div class="xsec-grid">
            <!-- Block IP Form -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-dismiss"></span> Block IP Address</h2>
                </div>
                <div class="card-body">
                    <p>Your current IP: <code><?php echo esc_html($current_ip); ?></code></p>
                    <form id="block-ip-form" class="xsec-inline-form">
                        <input type="text" name="ip" placeholder="IP Address" required>
                        <input type="text" name="reason" placeholder="Reason (optional)">
                        <button type="submit" class="button button-primary">Block IP</button>
                    </form>
                </div>
            </div>
            
            <!-- Whitelist IP Form -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-yes-alt"></span> Whitelist IP Address</h2>
                </div>
                <div class="card-body">
                    <form id="whitelist-ip-form" class="xsec-inline-form">
                        <input type="text" name="ip" placeholder="IP Address" required>
                        <input type="text" name="description" placeholder="Description (optional)">
                        <button type="submit" class="button button-primary">Whitelist IP</button>
                    </form>
                </div>
            </div>
            
            <!-- Blocked IPs -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-lock"></span> Blocked IPs</h2>
                </div>
                <div class="card-body">
                    <?php if ($blocked_ips) : ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Reason</th>
                                    <th>Blocked</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($blocked_ips as $ip) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html($ip->ip_address); ?></code></td>
                                        <td><?php echo esc_html($ip->reason ?: 'N/A'); ?></td>
                                        <td><?php echo esc_html(human_time_diff(strtotime($ip->blocked_time), current_time('timestamp'))); ?> ago</td>
                                        <td>
                                            <button type="button" class="button button-small xsec-action-btn" data-action="unblock_ip" data-ip="<?php echo esc_attr($ip->ip_address); ?>">Unblock</button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else : ?>
                        <p class="no-data"><?php esc_html_e('No blocked IPs.', 'x-security'); ?></p>
                    <?php endif; ?>
                </div>
            </div>
            
            <!-- Whitelisted IPs -->
            <div class="xsec-card">
                <div class="card-header">
                    <h2><span class="dashicons dashicons-yes"></span> Whitelisted IPs</h2>
                </div>
                <div class="card-body">
                    <?php if ($whitelisted_ips) : ?>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Description</th>
                                    <th>Added</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($whitelisted_ips as $ip) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html($ip->ip_address); ?></code></td>
                                        <td><?php echo esc_html($ip->description ?: 'N/A'); ?></td>
                                        <td><?php echo esc_html(human_time_diff(strtotime($ip->added_time), current_time('timestamp'))); ?> ago</td>
                                        <td>
                                            <button type="button" class="button button-small xsec-action-btn" data-action="remove_whitelist" data-ip="<?php echo esc_attr($ip->ip_address); ?>">Remove</button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else : ?>
                        <p class="no-data"><?php esc_html_e('No whitelisted IPs.', 'x-security'); ?></p>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <?php
        $this->render_footer();
    }
    
    /**
     * Activity Log page
     */
    public function render_logs() {
        global $wpdb;

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pagination uses page number only, nonce not needed for read-only display.
        $page     = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
        $per_page = 50;
        $offset   = ( $page - 1 ) * $per_page;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Security log requires real-time data.
        $total       = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}xsec_activity_log" );
        $total_pages = ceil( $total / $per_page );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Security log requires real-time data, table name is safe.
        $logs = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}xsec_activity_log ORDER BY event_time DESC LIMIT %d OFFSET %d",
                $per_page,
                $offset
            )
        );
        
        $this->render_header(__('Activity Log', 'x-security'));
        ?>
        
        <div class="xsec-card xsec-card-full">
            <div class="card-header">
                <h2><span class="dashicons dashicons-list-view"></span> Security Activity Log</h2>
                <button type="button" class="button xsec-action-btn" data-action="clear_activity_log">Clear Log</button>
            </div>
            <div class="card-body">
                <?php if ($logs) : ?>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th>Event</th>
                                <th>Description</th>
                                <th>User</th>
                                <th>IP Address</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs as $log) : ?>
                                <tr>
                                    <td><span class="event-badge event-<?php echo esc_attr($log->event_type); ?>"><?php echo esc_html($log->event_type); ?></span></td>
                                    <td><?php echo esc_html($log->event_description); ?></td>
                                    <td><?php echo esc_html($log->username ?: 'Guest'); ?></td>
                                    <td><code><?php echo esc_html($log->ip_address); ?></code></td>
                                    <td><?php echo esc_html(date_i18n('M j, Y g:i A', strtotime($log->event_time))); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    
                    <?php if ($total_pages > 1) : ?>
                        <div class="tablenav">
                            <div class="tablenav-pages">
                                <span class="displaying-num"><?php echo esc_html($total); ?> items</span>
                                <?php
                                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- paginate_links() returns safe HTML with escaped URLs.
                                echo paginate_links(array(
                                    'base' => add_query_arg('paged', '%#%'),
                                    'format' => '',
                                    'prev_text' => '&laquo;',
                                    'next_text' => '&raquo;',
                                    'total' => $total_pages,
                                    'current' => $page
                                ));
                                ?>
                            </div>
                        </div>
                    <?php endif; ?>
                <?php else : ?>
                    <p class="no-data"><?php esc_html_e('No activity recorded yet.', 'x-security'); ?></p>
                <?php endif; ?>
            </div>
        </div>
        
        <?php
        $this->render_footer();
    }
}
