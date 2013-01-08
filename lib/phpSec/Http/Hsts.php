<?php namespace phpSec\Http;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012, 2013
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Implements HTTP Strict Transport Security (HSTS), RFC 6797
 * @package phpSec
 */
class Hsts {

  public $maxAge = 31536000;

  /**
   * Enables HSTS.
   */
  public static function enable() {
    if ($this->detectHttps() === true) {
      header('Strict-Transport-Security: max-age='.$this->maxAge);
    } else {
      header('Location: https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'], true, 301);
      /* Prevent further execution and output. */
      die();
    }
  }

  private function detectHttps() {
    if(isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') {
      return true;
    }
    return false;
  }
}