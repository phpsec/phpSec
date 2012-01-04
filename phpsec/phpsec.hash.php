<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

class phpsecHash {

  const PBKDF2 = '$pbkdf2$';
  const BCRYPT = '$2a$';
  const SHA256 = '$5$';
  const SHA512 = '$6$';

  public static $_method       = self::SHA256;
  public static $_pbkdf2_c     = 8192;
  public static $_pbkdf2_dkLen = 128;
  public static $_pbkdf2_prf   = 'sha256';
  public static $_bcrypt_cost  = 12;
  public static $_sha2_c       = 6000;

  public static $charsets = array(
    'bcrypt' => './abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'sha2'   => './abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  );

  public static function make($str) {

    switch(self::$_method) {
      case self::BCRYPT:
        $saltRnd = phpsecRand::str(22, self::$charsets['bcrypt']);
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
        $saltRnd = phpsecRand::str(16, self::$charsets['sha2']);
        $salt = sprintf('%srounds=%s$%s', self::$_method, self::$_sha2_c, $saltRnd);
        $hash = crypt($str, $salt);
      break;
    }

    if(strlen($hash) > 13) {
      return $hash;
    }
    return false;
  }

  public static function check($str, $hash) {
    $regex_pattern = '/^\$[a-z, 1-6]{1,6}\$/i';
    preg_match($regex_pattern, $hash, $matches);
    list($method) = $matches;
    switch($method) {
      case self::PBKDF2:
        $param = array();
        $hashPart = explode('$', $hash);
        parse_str($hashPart[2], $param);

        $hash = base64_decode($hashPart[3]);
        $salt = base64_decode($hashPart[4]);

        if($hash === phpsecCrypt::pbkdf2($str, $salt, $param['c'], $param['dk'], $param['f'])) {
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