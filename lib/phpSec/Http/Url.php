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
 * Class to prevent URL manipulation.
 */
class Url {

  /**
   * Name of GET variable to pass security token trough.
   */
  public static $_getParam = 'pstkn';

  /**
   * Create a security token for a URL.
   *
   * @param string $url
   *   URL to create token for.
   *
   * @return string
   *   Return a URL with the security token included.
   */
  public static function create($url) {
    $part = parse_url($url);

    $appendQuery = false;

    if(isset($part['query'])) {
      $appendQuery = true;
    }

    $request = self::getRequest($url);
    $token = self::getToken($request);

    if($appendQuery === true) {
      return $url.'&'.self::$_getParam.'='.$token;
    } else {
      return $url.'?'.self::$_getParam.'='.$token;
    }
  }

  /**
   * Verify if a URL.
   *
   * @return boolean
   *   Return true if a security token was included in the request
   *   and the URL was not manipulated.
   */
  public static function verify() {
    if(!isset($_GET[self::$_getParam])) {
      return false;
    }

    $request = self::getRequest($_SERVER['REQUEST_URI']);
    if(self::gettoken($request) === $_GET[self::$_getParam]) {
      return true;
    }
    return false;
  }

  /**
   * Get the request from a string to create a security token from.
   *
   * @param string $url
   *   URL to get request striong from.
   *
   * @return string
   *   Request string.
   */
  private static function getRequest($url) {
    $part = parse_url($url);

    $apeendQuery = false;

    if(isset($part['query'])) {
      parse_str($part['query'], $query);
      if(isset($query[self::$_getParam])) {
        unset($query[self::$_getParam]);
      }
      if(sizeof($query) > 0) {
        $request = $part['path'].http_build_query($query);
        $apeendQuery = true;
      } else {
        $request = $part['path'];
      }
    } else {
      $request = $part['path'];
    }

    return $request;
  }

  /**
   * Get a security token from a request.
   *
   * @param string $request
   *   Request to create token from.
   *
   * @return string
   *   Returns a security token.
   */
  private static function getToken($request) {
    $hash = hash('sha256', $request.\phpSec\Common\Core::getUid());

    return substr($hash, 0, 4).substr($hash, 16, 4).substr($hash, 32, 4).substr($hash, 48, 4);

  }
}