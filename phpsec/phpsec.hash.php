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
 * Implements password hashing using crypt() with PBKDF2 support.
 */
class phpsecHash {

  const PBKDF2 = '$pbkdf2$';
  const BCRYPT = '$2a$';
  const SHA256 = '$5$';
  const SHA512 = '$6$';

  /**
   * Default hashing method.
   */
  public static $_method = self::PBKDF2;

  /**
   * PBKDF2: Iteration count.
   */
  public static $_pbkdf2_c = 8192;

  /**
   * PBKDF2: Derived key length.
   */
  public static $_pbkdf2_dkLen = 128;

  /**
   * PBKDF2: Underlying hash method.
   */
  public static $_pbkdf2_prf = 'sha256';

  /**
   * Bcrypt: Work factor.
   */
  public static $_bcrypt_cost = 12;

  /**
   * SHA2: Number of rounds.
   */
  public static $_sha2_c = 6000;

  /**
   * Salt charsets.
   */
  public static $charsets = array(
    'itoa64' => './abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  );

  /**
   * Creates a salted hash from a string.
   *
   *   @param string $str
   *     String to hash.
   *
   *   @return string
   *     Returns hashed string, or false on error.
   */
  public static function create($str) {

    switch(self::$_method) {
      case self::BCRYPT:
        $saltRnd = phpsecRand::str(22, self::$charsets['itoa64']);
        $salt = sprintf('$2a$%s$%s', self::$_bcrypt_cost, $saltRnd);
        $hash = crypt($str, $salt);
      break;

      case self::PBKDF2:
        $salt = phpsecRand::bytes(64);
        $hash = phpsecCrypt::pbkdf2($str, $salt, self::$_pbkdf2_c, self::$_pbkdf2_dkLen, self::$_pbkdf2_prf);

        $hash = sprintf('$pbkdf2$c=%s&dk=%s&f=%s$%s$%s',
                       self::$_pbkdf2_c,
                       self::$_pbkdf2_dkLen,
                       self::$_pbkdf2_prf,
                       base64_encode($hash),
                       base64_encode($salt)
                       );
      break;

      case self::SHA256:
      case self::SHA512:
        $saltRnd = phpsecRand::str(16, self::$charsets['itoa64']);
        $salt = sprintf('%srounds=%s$%s', self::$_method, self::$_sha2_c, $saltRnd);
        $hash = crypt($str, $salt);
      break;
    }

    if(strlen($hash) > 13) {
      return $hash;
    }
    return false;
  }

  /**
   * Check a string against a hash.
   *
   * @param string $str
   *   String to check.
   *
   * @param string $hash
   *   The hash to check the string against.
   *
   * @return bool
   *   Returns true on match.
   */
  public static function check($str, $hash) {
    $regex_pattern = '/^\$[a-z, 1-6]{1,6}\$/i';
    preg_match($regex_pattern, $hash, $matches);
    list($method) = $matches;
    switch($method) {
      case self::PBKDF2:
        $param = array();
        list( , , $params, $hash, $salt) = explode('$', $hash);
        parse_str($params, $param);

        if(base64_decode($hash) === phpsecCrypt::pbkdf2($str, base64_decode($salt), $param['c'], $param['dk'], $param['f'])) {
          return true;
        }
        return false;
      break;

      default:
        if(crypt($str, $hash) === $hash) {
          return true;
        }
        return false;
      break;
    }
  }
}