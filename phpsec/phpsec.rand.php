<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/xqus/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Provides methods for generating random data.
 */
class phpsecRand {
  public static $_charset = 'abcdefghijklmnopqrstuvwxyz0123456789';

  /**
   * Generate random data.
   *
   * @param integer $len
   * @return binary
   */
  public static function bytes($len) {
    /* Code inspired by this blogpost by Enrico Zimuel
     * http://www.zimuel.it/blog/2011/01/strong-cryptography-in-php/ */
    $strong = false;
    if(function_exists('openssl_random_pseudo_bytes')) {
      $rnd = openssl_random_pseudo_bytes($len, $strong);
      if($strong === true) {
        return $rnd;
      }
    }
    /* Either we dont have the OpenSSL library or the data returned was not
     * considered secure. Fall back on this less secure code. */
    $rnd = '';
    for ($i=0;$i<$len;$i++) {
      $sha = hash('sha256', mt_rand());
      $char = mt_rand(0,30);
      $rnd .= chr(hexdec($sha[$char].$sha[$char+1]));
    }
    return (binary) $rnd;
  }

  /**
   * Generate a random integer.
   *
   * @param integer $min
   * @param integer $max
   * @return integer
   */
  public static function int($min, $max) {
    $delta = $max-$min;
    $bytes = ceil($delta/256);
    $rnd = self::bytes($bytes);
    $add = 0;
    for ($i = 0; $i < $bytes; $i++) {
      $add += ord($rnd[$i]);
    }
    $add = $add % ($delta + 1);
    return $min + $add;
  }

  /**
   * Generate a random string.
   *
   * @param integer $len
   * @return string
   */
  public static function str($len) {
    $str = '';
    for ($i = 0; $i < $len; $i++) {
      $pos = self::int(0,strlen(self::$_charset)-1);
      $str .= self::$_charset[$pos];
    }
    return $str;
  }

  /**
   * Return random hexadecimal data.
   *
   * @param integer $len
   * @return string
   */
  public static function hex($len) {
    return bin2hex(self::bytes($len));
  }
}

