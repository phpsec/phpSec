<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/xqus/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Adds logging functionality.
 */
class phpsecLog {
  /**
   * Define how, and where to write logs.
   *
   * Examples:
   *
   * phpsecLog::$_logdir = 'filesystem:/var/www/phpSec/logs';
   *   Write log to a file in the /var/www/phpsec/logs directory.
   *
   * phpsecLog::$_logdir = 'syslog:'.LOG_USER;
   *   Write log til syslog.
   *   @see http://www.php.net/manual/en/function.openlog.php
   *   for available facilities.
   */
  public static $_logdir = null;
  /**
   * Write an entry to a log.
   *
   * @param string $type
   *   Specify the type of the logentry. This will be a part of the filname.
   *
   * @param string $msg
   *   The log message itself.
   *
   * @param string $level
   *   Error level (optional) can be one of:
   *    LOG_EMERG    system is unusable
   *    LOG_ALERT    action must be taken immediately
   *    LOG_CRIT     critical conditions
   *    LOG_ERR      error conditions
   *    LOG_WARNING  warning conditions
   *    LOG_NOTICE   normal, but significant, condition
   *    LOG_INFO     informational message
   *    LOG_DEBUG    debug-level message
   *   If none is specified LOG_WARNING is used.
   *
   * @return bool
   *   Returns true on success, false on failure.
   */
  public static function log($type, $msg, $level = LOG_WARNING) {
    /* I'm only using vsprintf() to make the code look good. */
    $line = vsprintf('[%s] [%s] [%s] %s %s %s - %s "%s"',
      array(
        date('c'),
        'Priority:'.$level,
        $_SERVER['REMOTE_ADDR'],
        $_SERVER['REQUEST_METHOD'],
        $_SERVER['SCRIPT_NAME'],
        $_SERVER['SERVER_PROTOCOL'],
        $msg,
        $_SERVER['HTTP_USER_AGENT']
      )
    );

    /* Check the log destination for : to ensure it's the correct format. */
    if(strpos(self::$_logdir, ':') === false) {
      phpsec::error('Invalid log destination: '.self::$_logdir);
      return false;
    }

    /* Check the log destination and call the appropriate method for storage. */
    $logDest = explode(':', self::$_logdir);
    switch($logDest[0]) {
      case 'filesystem':
        /* Save til a file in the filesystem. */
        $fileName = $logDest[1].'/log_'.$type;
        return self::fileWrite($fileName, $line);
      break;

      case 'syslog':
        /* Write log using syslog. */
        return self::syslogWrite($logDest[1], $line, $level);
      break;

      default:
        /* We don't know what type of storage this is. Return error. */
        phpsec::error('Invalid log destination type: '.$logDest[0]);
        return false;
      break;
    }
    return true;
  }

  /**
   * Write a log entry to a file.
   *
   * @param string $filename
   *   File to write to.
   *
   * @param string $line
   *   Message to write til $filename.
   *
   * @return bool
   */
  private static function fileWrite($fileName, $line) {
    /* Open the logfile and write the entry. */
    $fp = fopen($fileName, 'a');
    if($fp !== false) {
      if(flock($fp, LOCK_EX)) {
        fwrite($fp, $line."\n");
        flock($fp, LOCK_UN);
        fclose($fp);
        return true;
      } else {
        phpsec::error('Could not lock logfile');
      }
    }
    return false;
  }

  /**
   * Write a log entry to syslog.
   *
   * @param const $facility
   *   @see http://www.php.net/manual/en/function.openlog.php
   *
   * @param string $msg
   *   Message to write to syslog.
   *
   * @param const $level
   *   @see http://www.php.net/manual/en/function.syslog.php
   *
   * @return bool
   */
  private static function syslogWrite($facility, $msg, $level) {
    openlog('phpSec', LOG_ODELAY, $facility);
    syslog ($level, $msg);
    closelog();
    return true;
  }
}