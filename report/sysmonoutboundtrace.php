<?php
/**
 * Plugin Name: Sysmon Outbound HTTP Tracer (v2)
 * Description: Traces outbound HTTP requests (wp_remote_get/post, etc.)
 *              with full caller backtrace.  Two modes:
 *
 *   NORMAL  - logs only slow (>threshold) or failed calls, one line
 *             each, for sysmon to parse.  Safe to leave on always.
 *
 *   VERBOSE - logs EVERY outbound call with the full caller chain
 *             (like the manual debug the engineer ran during the
 *             outage).  For active incident diagnosis; produces a lot
 *             of output, so turn it off after.
 *
 * Version: 2.0
 * Author: sysmon
 *
 * INSTALL: copy to wp-content/mu-plugins/ on each site.
 *
 * MODE CONTROL (in wp-config.php or leave defaults):
 *   define('SYSMON_TRACE_VERBOSE', true);   // full backtrace, every call
 *   define('SYSMON_SLOW_THRESHOLD', 2.0);   // normal-mode slow cutoff
 *
 * Or toggle verbose live without editing config by touching a file:
 *   touch /var/log/sysmon-trace-verbose.flag     # enable
 *   rm    /var/log/sysmon-trace-verbose.flag     # disable
 * (checked per-request, so no restart needed.)
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('SYSMON_SLOW_THRESHOLD')) {
    define('SYSMON_SLOW_THRESHOLD', 2.0);
}
if (!defined('SYSMON_OUTBOUND_LOG')) {
    define('SYSMON_OUTBOUND_LOG', '/var/log/sysmon-outbound.log');
}
// Verbose (full-backtrace) log - separate file so it can be rotated /
// truncated independently of the machine-parsed one.
if (!defined('SYSMON_VERBOSE_LOG')) {
    define('SYSMON_VERBOSE_LOG', '/var/log/sysmon-outbound-verbose.log');
}
if (!defined('SYSMON_VERBOSE_FLAG')) {
    define('SYSMON_VERBOSE_FLAG', '/var/log/sysmon-trace-verbose.flag');
}

/**
 * Is verbose mode on?  True if the constant is set OR the flag file
 * exists.  The flag file lets you enable it live during an incident
 * without editing config or restarting PHP.
 */
function sysmon_verbose_on() {
    if (defined('SYSMON_TRACE_VERBOSE') && SYSMON_TRACE_VERBOSE) {
        return true;
    }
    static $flag = null;
    if ($flag === null) {
        $flag = @file_exists(SYSMON_VERBOSE_FLAG);
    }
    return $flag;
}

/**
 * pre_http_request fires BEFORE every outbound call.  In verbose mode
 * we log the full caller chain here - this is what captures a hanging
 * request AS it starts, exactly like the manual debug from the outage.
 *
 * We return the unchanged $preempt so the request proceeds normally.
 */
add_filter('pre_http_request', function ($preempt, $args, $url) {
    $GLOBALS['_sysmon_last_start'] = microtime(true);

    if (sysmon_verbose_on()) {
        sysmon_log_verbose($url, $args);
    }

    return $preempt; // don't interfere - let the request run
}, 10, 3);

/**
 * http_api_debug fires AFTER each call.  Normal mode logs slow/failed
 * calls here as a single parseable line.
 */
add_action('http_api_debug', function ($response, $context, $class, $args, $url) {
    $start = isset($GLOBALS['_sysmon_last_start'])
        ? $GLOBALS['_sysmon_last_start'] : null;
    if ($start === null) {
        return;
    }

    $elapsed = microtime(true) - $start;
    $is_error = is_wp_error($response);

    if ($elapsed < SYSMON_SLOW_THRESHOLD && !$is_error) {
        return; // fast success - no log in normal mode
    }

    $domain = parse_url(home_url(), PHP_URL_HOST) ?: 'unknown';
    $culprit = sysmon_find_culprit();
    $timeout = isset($args['timeout']) ? $args['timeout'] : '?';
    $status = $is_error
        ? 'ERROR:' . $response->get_error_message()
        : wp_remote_retrieve_response_code($response);
    $host = parse_url($url, PHP_URL_HOST) ?: '?';

    // ts|domain|elapsed|timeout|status|host|culprit|url
    $line = sprintf(
        "%s|%s|%.2f|%s|%s|%s|%s|%s\n",
        gmdate('Y-m-d H:i:s'), $domain, $elapsed, $timeout,
        $status, $host, $culprit, substr($url, 0, 200)
    );
    @file_put_contents(SYSMON_OUTBOUND_LOG, $line, FILE_APPEND | LOCK_EX);
}, 10, 5);

/**
 * Write a full, human-readable backtrace block - the same shape as the
 * manual debug that traced the outage to wp-rocket's Mixpanel producer.
 */
function sysmon_log_verbose($url, $args) {
    $domain = parse_url(home_url(), PHP_URL_HOST) ?: 'unknown';
    $timeout = isset($args['timeout']) ? $args['timeout'] : '?';
    $method = isset($args['method']) ? $args['method'] : 'GET';

    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 40);
    $frames = array();
    foreach ($trace as $frame) {
        if (empty($frame['file'])) {
            continue;
        }
        if (strpos($frame['file'], 'sysmon-outbound-tracer') !== false) {
            continue;
        }
        $line = isset($frame['line']) ? $frame['line'] : 0;
        $frames[] = sprintf('  %s:%d', $frame['file'], $line);
    }

    $block = sprintf(
        "[%s]\n==== HTTP REQUEST ====\nSite: %s\nURL: %s\nMethod: %s\nTimeout: %s\nCaller:\n%s\n\n",
        gmdate('d-M-Y H:i:s') . ' UTC',
        $domain, $url, $method, $timeout,
        implode("\n", $frames)
    );

    @file_put_contents(SYSMON_VERBOSE_LOG, $block, FILE_APPEND | LOCK_EX);
}

/**
 * Find the first plugin/theme/mu-plugin file in the backtrace - the
 * component responsible for the outbound call.
 */
function sysmon_find_culprit() {
    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 40);
    foreach ($trace as $frame) {
        if (empty($frame['file'])) {
            continue;
        }
        $file = $frame['file'];
        $line = isset($frame['line']) ? $frame['line'] : 0;

        if (strpos($file, 'sysmon-outbound-tracer') !== false) {
            continue;
        }
        if (preg_match('#/wp-content/plugins/([^/]+)/(.*)$#', $file, $m)) {
            return sprintf('plugin:%s %s:%d', $m[1], basename($m[2]), $line);
        }
        if (preg_match('#/wp-content/themes/([^/]+)/(.*)$#', $file, $m)) {
            return sprintf('theme:%s %s:%d', $m[1], basename($m[2]), $line);
        }
        if (preg_match('#/wp-content/mu-plugins/(.*)$#', $file, $m)) {
            return sprintf('mu-plugin:%s:%d', basename($m[1]), $line);
        }
    }
    return 'core/unknown';
}
