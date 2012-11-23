<?php namespace phpSec\Http;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Implements HTTP Strict Transport Security (HSTS), RFC 6797
 */
class Hsts {

  public static $_maxAge            = 31536000;

  /**
   * Enables HSTS.
   */
  public static function enable() {
    if (self::detectHttps() === true) {
      header('Strict-Transport-Security: max-age='.self::$_maxAge);
    } else {
      header('Location: https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'], true, 301);
      /* Prevent further execution and output. */
      die();
    }
  }

  private static function detectHttps() {
    if(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') {
      return true;
    }
    return false;
  }
}