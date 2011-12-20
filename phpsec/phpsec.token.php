<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Provides CSRF protection methods.
 */
class phpsecToken {
  /**
   * Generate and save a one-time-token for a form. Used to protect against
   * CSRF attacks.
   *
   * @param string $name
   *   Name of the form to generate a token for.
   *
   * @param integer $ttl
   *   How long the token should be valid in seconds.
   *
   * @return string
   *   The token to supply with the form data.
   */
  public static function set($name, $ttl = 3600) {
    $token = phpsecRand::str(32);
    /* Save the token to the cahce. */
    phpsecCache::cacheSet('token-'.$name, $token, $ttl);
    return $token;
  }

  /**
   * Validate a one-time-token generated with setToken();
   * This function should be called before accepting data from a user-submitted form.
   * @see phpsecToken::setToken();
   *
   * @param string $name
   *   Name of the form to validate the token for.
   *
   * @return boolean
   *   Returns true if the token is valid. Returns false otherwise.
   */
  public static function validate($name, $token) {
    if(strlen($token) == 0) {
      return false;
    }
    $cacheToken = phpsecCache::cacheGet('token-'.$name);
    /* Check if the provided token matches the token in the cache. */
    if($cacheToken == $token) {
      /* Remove the token from the cahche so it can't be reused. */
      phpsecCache::cacheRem('token-'.$name);
      return true;
    }
    return false;
  }
}