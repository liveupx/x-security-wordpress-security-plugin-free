/**
 * X Security Admin JS
 */
(function($) {
    'use strict';

    var XSec = {
        
        init: function() {
            this.bindEvents();
        },
        
        bindEvents: function() {
            var self = this;
            
            // Action buttons
            $(document).on('click', '.xsec-action-btn', function(e) {
                e.preventDefault();
                var $btn = $(this);
                var action = $btn.data('action');
                
                if (action) {
                    self.doAction($btn, action);
                }
            });
            
            // Block IP form
            $('#block-ip-form').on('submit', function(e) {
                e.preventDefault();
                var $form = $(this);
                self.doAjax('block_ip', {
                    ip: $form.find('input[name="ip"]').val(),
                    reason: $form.find('input[name="reason"]').val()
                }, function() {
                    $form[0].reset();
                    location.reload();
                });
            });
            
            // Whitelist IP form
            $('#whitelist-ip-form').on('submit', function(e) {
                e.preventDefault();
                var $form = $(this);
                self.doAjax('whitelist_ip', {
                    ip: $form.find('input[name="ip"]').val(),
                    description: $form.find('input[name="description"]').val()
                }, function() {
                    $form[0].reset();
                    location.reload();
                });
            });
            
            // Modal close
            $(document).on('click', '.modal-close, .xsec-modal', function(e) {
                if (e.target === this) {
                    $('#xsec-modal').hide();
                }
            });
        },
        
        doAction: function($btn, action) {
            var self = this;
            var data = {};
            
            // Confirm dangerous actions
            if (['clear_lockouts', 'clear_failed_logins', 'clear_activity_log', 'remove_htaccess'].indexOf(action) !== -1) {
                if (!confirm(xsec.strings.confirm)) {
                    return;
                }
            }
            
            // Get IP for IP actions
            if (['unblock_ip', 'remove_whitelist'].indexOf(action) !== -1) {
                data.ip = $btn.data('ip');
            }
            
            self.doAjax(action, data, function(response) {
                // Handle scan results
                if (action === 'run_scan' && response.data.results) {
                    self.showScanResults(response.data.results);
                }
                
                // Reload for certain actions
                if (['clear_lockouts', 'clear_failed_logins', 'clear_activity_log', 'unblock_ip', 'remove_whitelist', 'write_htaccess', 'remove_htaccess'].indexOf(action) !== -1) {
                    setTimeout(function() {
                        location.reload();
                    }, 1000);
                }
            }, $btn);
        },
        
        doAjax: function(action, data, successCallback, $btn) {
            var self = this;
            var originalText = '';
            
            if ($btn) {
                originalText = $btn.html();
                $btn.prop('disabled', true).addClass('xsec-loading').html('<span class="dashicons dashicons-update"></span> ' + xsec.strings.loading);
            }
            
            $.ajax({
                url: xsec.ajax_url,
                type: 'POST',
                data: $.extend({
                    action: 'xsec_action',
                    security_action: action,
                    nonce: xsec.nonce
                }, data),
                success: function(response) {
                    if (response.success) {
                        self.showNotice('success', response.data.message);
                        if (successCallback) {
                            successCallback(response);
                        }
                    } else {
                        self.showNotice('error', response.data.message || xsec.strings.error);
                    }
                },
                error: function() {
                    self.showNotice('error', xsec.strings.error);
                },
                complete: function() {
                    if ($btn) {
                        $btn.prop('disabled', false).removeClass('xsec-loading').html(originalText);
                    }
                }
            });
        },
        
        showScanResults: function(results) {
            var html = '<div class="scan-results">';
            html += '<div style="text-align:center;margin-bottom:20px;"><strong style="font-size:24px;">Score: ' + results.score + '/100</strong></div>';
            
            if (results.passed.length > 0) {
                html += '<h3>✓ Passed (' + results.passed.length + ')</h3><div class="passed"><ul>';
                $.each(results.passed, function(i, item) {
                    html += '<li><span class="dashicons dashicons-yes-alt"></span> ' + item.title + '</li>';
                });
                html += '</ul></div>';
            }
            
            if (results.issues.length > 0) {
                html += '<h3>✗ Issues (' + results.issues.length + ')</h3><div class="issues"><ul>';
                $.each(results.issues, function(i, item) {
                    html += '<li><span class="dashicons dashicons-warning"></span> ' + item.title;
                    if (item.description) {
                        html += '<br><small>' + item.description + '</small>';
                    }
                    html += '</li>';
                });
                html += '</ul></div>';
            }
            
            if (results.warnings.length > 0) {
                html += '<h3>⚠ Warnings (' + results.warnings.length + ')</h3><div class="warnings"><ul>';
                $.each(results.warnings, function(i, item) {
                    html += '<li><span class="dashicons dashicons-info"></span> ' + item.title;
                    if (item.description) {
                        html += '<br><small>' + item.description + '</small>';
                    }
                    html += '</li>';
                });
                html += '</ul></div>';
            }
            
            html += '</div>';
            
            $('#modal-title').text('Security Scan Results');
            $('#modal-body').html(html);
            $('#xsec-modal').show();
        },
        
        showNotice: function(type, message) {
            var $notice = $('<div class="notice notice-' + type + ' is-dismissible"><p>' + message + '</p></div>');
            
            $('.xsec-wrap .notice').remove();
            $('.xsec-header').after($notice);
            
            setTimeout(function() {
                $notice.fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
        }
    };

    $(document).ready(function() {
        XSec.init();
    });

})(jQuery);
