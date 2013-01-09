<?php namespace phpSec\Auth;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Implements authentication using Google Authenticator.
 *
 * @see http://www.ietf.org/rfc/rfc4226.txt
 * @package phpSec
 */
class Google {

  public $_otpLen  = 6;
  public $_deviate = 2;

  private $psl = null;

  public function __construct($psl) {
    $this->psl = $psl;
  }

  /**
   * Generate a new secret key.
   */
  public function newKey() {
    return $this->psl['crypt/rand']->str(16, '234567QWERTYUIOPASDFGHJKLZXCVBNM');
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
  public function verify($otp, $secret) {
    $timeTick = $this->getTimestamp();
    $storeId  = $this->getStoreId($secret);
    try {
      $store = $this->psl['store']->read('google-auth', $storeId);
      for($tick = $timeTick - $this->_deviate ; $tick <= $timeTick + $this->_deviate; $tick++) {
        $tickOtp = $this->getToken($secret, $tick);
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
          $this->psl['store']->write('google-auth', $storeId, $store);
          return true;
        }
      }
      return false;
    } catch (\phpSec\Exception $e) { /* Say what? */
      return false;
    }
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
  public function getToken($secret, $timeTick = null) {
    $base32 = new \phpSec\String\Base32();

    $secret = $base32->decode($secret);

    if($timeTick === null) {
      $timeTick = $this->getTimestamp();
    }

    $timestamp = pack('N*', 0) . pack('N*', $timeTick);

    $hash = hash_hmac ('sha1', $timestamp, $secret, true);

    $offset = ord($hash[19]) & 0xf;

    $otp = (
        ((ord($hash[$offset+0]) & 0x7f) << 24 ) |
        ((ord($hash[$offset+1]) & 0xff) << 16 ) |
        ((ord($hash[$offset+2]) & 0xff) << 8 ) |
        (ord($hash[$offset+3]) & 0xff)
    ) % pow(10, $this->_otpLen);

    return str_pad($otp, $this->_otpLen, '0', STR_PAD_LEFT);
  }

  /**
   * Get current timestamp.
   *
   * @return integer
   */
  private function getTimestamp() {
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
  public function getUrl($account, $key) {

    $url['url'] = Filter::t('otpauth://totp/&account?secret=&key',
                    array('&account' => $account, '&key' => $key)
                  );

    $url['qr']  = Filter::t('https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/&account?secret=&key',
                    array('&account' => $account, '&key' => $key)
                  );

    return $url;
  }

  /**
   * Get a store ID from a $secret
   *
   * @param string $secret
   *
   * @return string
   */
  private function getStoreId($secret) {
    $crypto = $this->psl['crypt/crypto'];

    return base64_encode($crypto->pbkdf2('google-auth', $secret, 500, 32));
  }

}