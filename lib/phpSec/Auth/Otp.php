<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
namespace phpSec\Auth;

/**
 * Provides one time password functionality.
 * @package phpSec
 */
class Otp {
  public $_charset = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

  private $psl = null;

  public function __construct($psl) {
    $this->psl = $psl;
  }

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
  public function generate($action, $uid = null, $data = null, $length = 6, $ttl = 480) {
    $rand  = $this->psl['crypt/rand'];
    $hash  = $this->psl['crypt/hash'];
    $store = $this->psl['store'];

    if($uid === null) {
	    $uid = $this->psl->getUid();
	  }

	  $pw = $rand->str($length, $this->_charset);

    $otp['pw']   = $hash->create($pw);
    $otp['data'] = $hash->create(serialize($data));
    $otp['ttl']  = time() + $ttl;

    if($store->write('otp', $this->storeId($uid, $action), $otp)) {
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
  public function validate($otp, $action, $uid = null, $data = null) {
    $hash  = $this->psl['crypt/hash'];
    $store = $this->psl['store'];

    if($uid === null) {
	    $uid = $this->psl->getUid();
	  }

    $storeData = $store->read('otp', $this->storeId($uid, $action));

    if($storeData !== false) {
      if($storeData['ttl'] < time()) {
        $store->delete('otp', $this->storeId($uid, $action));
        return false;
      }

      if($hash->check($otp, $storeData['pw']) && $hash->check(serialize($data), $storeData['data'])) {
        $store->delete('otp', $this->storeId($uid, $action));
        return true;
      }
    }
    return false;
  }

  private function storeId($uid, $action) {
    return hash('sha512', $uid.$action);
  }

}