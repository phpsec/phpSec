<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/xqus/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

class phpsecLog {
  /**
   * Define how, and where to write logs.
   *
   * Examples:
   *
   * filesystem:/var/www/phpsec/logs
   *   Write log to a file in the /var/www/phpsec/logs directory.
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
   *   Error level (optional). Should be either debug, notice, warn or error.
   *   If none is specified warn is used.
   */
  public static function log($type, $msg, $level = 'warn') {

    /* I'm only using vsprintf() to make the code look good. */
    $line = vsprintf('[%s] [%s] [%s] %s %s %s - %s "%s"',
      array(
        date('c'),
        $level,
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

      default:
        /* We don't know what type of storage this is. Return error. */
        phpsec::error('Invalid log destination type: '.$logDest[0]);
        return false;
      break;
    }
    return true;
  }

  private static function fileWrite($fileName, $line) {
    /* Open the logfile and write the entry. */
    $fp = fopen($fileName, 'a');
    if($fp !== false) {
      if(flock($fp, LOCK_EX)) {
        fwrite($fp, $line."\n");
        flock($fp, LOCK_UN);
        fclose($fp);
      } else {
        phpsec::error('Could not lock logfile');
      }
    }
    return true;
  }
}