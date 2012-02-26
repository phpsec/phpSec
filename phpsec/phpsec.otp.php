<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Provides one time password functionality.
 */
class phpsecOtp {
  /**
   * Generate a one-time-password (OTP). The password is only valid for a given time,
   * and must be delivered to the user instantly. The password is also only valid
   * for the current session.
   *
   * @param string $action
   *   The action to generate a OTP for. This should be as specific as possible.
   *   Used to ensure that the OTP is used for the intended action.
   *
   * @param array $data
   *   Optional array of data that belongs to $action. Used to ensure that the action
   *   is performed with the same data as when the OTP was generated.
   *
   * @param integer $length
   *   OTP length.
   *
   * @param integer $ttl
   *   Time to live for the OTP. In seconds.
   *
   * @return string
   *   One time password that should be delivered to the user by for example email or SMS.
   *
   */
  public static function generate($action, $data = '', $length = 6, $ttl = 480) {
    $pw = phpsecRand::str($length);

    $otp['pw'] = phpsecHash::create($pw);

    if($data !== null) {
     $otp['data'] = phpsecHash::create(serialize($data));
    } else {
      $otp['data'] = $data;
    }

    phpsecCache::cacheSet('otp-'.$action, $otp, $ttl);

    return $pw;
  }

  /**
   * Validate a one-time-password.
   *
   * @param strgin $otp
   *   OTP supplied by user.
   *
   * @param string $action
   *   See phpsecOtp::generate().
   *
   * @param array $data
   *   See phpsecOtp::generate().
   *
   */
  public static function validate($otp, $action, $data = '') {
    $cache = phpsecCache::cacheGet('otp-'.$action);

    if($cache !== false) {
      if(!phpsecHash::check($otp, $cache['pw'])) {
        return false;
      } elseif(!phpsecHash::check(serialize($data), $cache['data'])) {
        return false;
      }
      phpsecCache::cacheRem('otp-'.$action);
      return true;
    }
    return false;
  }

}