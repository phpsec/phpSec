<?php namespace phpSec\Auth;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use phpSec\Common\Core;
use phpSec\Crypt\Hash;
use phpSec\Crypt\Rand;

/**
 * Provides one time password functionality.
 */
class Otp {
  public static $_charset = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

  /**
   * Generate a one-time-password (OTP). The password is only valid for a given time,
   * and must be delivered to the user instantly. The password is also only valid
   * for the current session.
   *
   * @param string $action
   *   The action to generate a OTP for. This should be as specific as possible.
   *   Used to ensure that the OTP is used for the intended action.
   *
   * @param string $uid
   *   User identifier. Default is a session identifier. Can be set to a username or user id
   *   if you want the OTP to be valid outside the session active when creating it.
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
  public static function generate($action, $uid = null, $data = null, $length = 6, $ttl = 480) {
    if($uid === null) {
	    $uid = Core::getUid();
	  }

	  $pw = Rand::str($length, self::$_charset);

    $otp['pw']   = Hash::create($pw);
    $otp['data'] = Hash::create(serialize($data));
    $otp['ttl']  = time() + $ttl;

    if(Core::$store->write('otp', self::storeId($uid, $action), $otp)) {
      return $pw;
    }
    return false;
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
   * @param string $uid
   *   See phpsecOtp::generate().
   *
   * @param array $data
   *   See phpsecOtp::generate().
   *
   */
  public static function validate($otp, $action, $uid = null, $data = null) {
    if($uid === null) {
	    $uid = Core::getUid();
	  }

    $store = Core::$store->read('otp', self::storeId($uid, $action));

    if($store !== false) {
      if($store['ttl'] < time()) {
        Core::$store->delete('otp', self::storeId($uid, $action));
        return false;
      }

      if(Hash::check($otp, $store['pw']) && Hash::check(serialize($data), $store['data'])) {
        Core::$store->delete('otp', self::storeId($uid, $action));
        return true;
      }
    }
    return false;
  }

  private static function storeId($uid, $action) {
    return hash('sha512', $uid.$action);
  }

}