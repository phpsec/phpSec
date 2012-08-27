<?php namespace phpSec\Auth;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use \phpSec\Common\Core;
use \phpSec\Crypt\Rand;
use \phpSec\Crypt\Hash;
use \phpSec\Crypt\Crypto;
use \phpSec\String\Base32;


/**
 * Implements authentication using Google Authenticator.
 *
 * @see http://www.ietf.org/rfc/rfc4226.txt
 */
class Google {

  public static $_otpLen  = 6;
  public static $_deviate = 2;

  /**
   * Generate a new secret key.
   */
  public static function newKey() {
    return Rand::str(16, '234567QWERTYUIOPASDFGHJKLZXCVBNM');
  }

  /**
   * Verify a OTP token.
   *
   * @param string $otp
   *   OTP token to verify.
   *
   * @param string $secret
   *   User secret key.
   *
   * @return boolean
   *   Returns true if the OTP is valid.
   */
  public static function verify($otp, $secret) {
    $timeTick = self::getTimestamp();
    $storeId = self::getStoreId($secret);
    $store = Core::$store->read('google-auth', $storeId);

    for($tick = $timeTick - self::$_deviate ; $tick <= $timeTick + self::$_deviate; $tick++) {
      $tickOtp = self::getToken($secret, $tick);
      if($store !== false) {
        /**
         * This secret has been used before, so we have to make sure that:
         * 1. This token has not been used before.
         * 2. This token is not older than the last one.
         * 3. We keep the Sith from world domination.
         */
        if($otp === $store['lastOtp'] || $store['lastTick'] > $tick) {
          continue;
        }
      }

      if($tickOtp === $otp) {
        $store['lastTick'] = $tick;
        $store['lastOtp']  = $otp;
        Core::$store->write('google-auth', $storeId, $store);
        return true;
      }
    }
    return false;
  }

  /**
   * Generate a OTP from a secret and time.
   *
   * @param string $secret
   *
   * @param integer $timeTick
   *
   * @return string
   */
  private static function getToken($secret, $timeTick = null) {
    $secret = Base32::decode($secret);

    if($timeTick === null) {
      $timeTick = self::getTimestamp();
    }

    $timestamp = pack('N*', 0) . pack('N*', $timeTick);

    $hash = hash_hmac ('sha1', $timestamp, $secret, true);

    $offset = ord($hash[19]) & 0xf;

    $otp = (
        ((ord($hash[$offset+0]) & 0x7f) << 24 ) |
        ((ord($hash[$offset+1]) & 0xff) << 16 ) |
        ((ord($hash[$offset+2]) & 0xff) << 8 ) |
        (ord($hash[$offset+3]) & 0xff)
    ) % pow(10, self::$_otpLen);

    return str_pad($otp, self::$_otpLen, '0', STR_PAD_LEFT);
  }

  /**
   * Get current timestamp.
   *
   * @return integer
   */
  private static function getTimestamp() {
    return floor(time()/30);
  }

  /**
   * Get the URL used to add a secret $key to Google Authenticator.
   *
   * @param string $account
   *   Account name.
   *
   * @param string $key
   *   Secret key.
   *
   * @return array
   *   An array with URL's that can be used.
   */
  public static function getUrl($account, $key) {
    /*TODO: Add URL filter. */
    $url['url'] = 'otpauth://totp/'.$account.'?secret='.$key;
    $url['qr']  = 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/'.$account.'?secret='.$key;

    return $url;
  }

  /**
   * Get a store ID from a $secret
   *
   * @param string $secret
   *
   * @return string
   */
  private static function getStoreId($secret) {
    return base64_encode(Crypto::pbkdf2('google-auth', $secret, 500, 32));
  }

}