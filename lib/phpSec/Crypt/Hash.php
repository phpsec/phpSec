<?php namespace phpSec\Crypt;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use phpSec\Crypt\Rand;
use phpSec\Crypt\Crypto;


/**
 * Implements password hashing using crypt() with PBKDF2 support.
 */
class Hash {

  const PBKDF2 = '$pbkdf2$';
  const BCRYPT = '$2a$';
  const SHA256 = '$5$';
  const SHA512 = '$6$';
  const DRUPAL = '$S$';

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
   * Drupal: Hash length.
   */
  public static $_drupal_hashLen = 55;

  /**
   * Drupal: Iteration count (log 2).
   */
  public static $_drupal_count = 15;

  /**
   * Salt charsets.
   */
  public static $charsets = array(
    'itoa64' => './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
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
        $saltRnd = Rand::str(22, self::$charsets['itoa64']);
        $salt = sprintf('$2a$%s$%s', self::$_bcrypt_cost, $saltRnd);
        $hash = crypt($str, $salt);
      break;

      case self::PBKDF2:
        $salt = Rand::bytes(64);
        $hash = Crypto::pbkdf2($str, $salt, self::$_pbkdf2_c, self::$_pbkdf2_dkLen, self::$_pbkdf2_prf);

        $hash = sprintf('$pbkdf2$c=%s&dk=%s&f=%s$%s$%s',
                       self::$_pbkdf2_c,
                       self::$_pbkdf2_dkLen,
                       self::$_pbkdf2_prf,
                       base64_encode($hash),
                       base64_encode($salt)
                       );
      break;

      case self::DRUPAL;
        $setting  = '$S$';
        $setting .= self::$charsets['itoa64'][self::$_drupal_count];
        $setting .= self::_b64Encode(\phpSec\Crypt\Rand::bytes(6), 6);

        return substr(self::_phpassHash($str, $setting), 0, self::$_drupal_hashLen);
      break;

      case self::SHA256:
      case self::SHA512:
        $saltRnd = Rand::str(16, self::$charsets['itoa64']);
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
    $hashInfo = self::getInfo($hash);

    switch($hashInfo['algo']) {
      case self::PBKDF2:
        $param = array();
        list( , , $params, $hash, $salt) = explode('$', $hash);
        parse_str($params, $param);

        if(base64_decode($hash) === Crypto::pbkdf2($str, base64_decode($salt), $param['c'], $param['dk'], $param['f'])) {
          return true;
        }
        return false;
      break;

      case self::DRUPAL:
        $test = strpos(self::_phpassHash($str, $hash), $hash);
        if($test === false || $test !== 0) {
        	return false;
        }
        return true;
      break;

      case self::BCRYPT;
      case self::SHA256:
      case self::SHA512:
        if(crypt($str, $hash) === $hash) {
          return true;
        }
        return false;
      break;

      default:
        /* Not any of the supported formats. Try plain hash methods. */
      	$hashLen = strlen($hash);
      	switch($hashLen) {
      		case 32:
        	  $mode = 'md5';
      	  break;
      		case 40:
      		  $mode = 'sha1';
      	  break;
      		case 64:
            $mode = 'sha256';
          break;
      		case 128:
      		  $mode = 'sha512';
      		break;
      		default:
      		  return false;
      	}
      	return ($hash == hash($mode, $str));
      break;
    }
  }

  /**
   * Returns settings used to generate a hash.
   *
   * @param string $hash
   *   Hash to get settings for.
   *
   * @return array
   *   Returns an array with settings used to create $hash.
   */
  public static function getInfo($hash) {
    $regex_pattern = '/^\$[a-z, 1-6]{1,6}\$/i';
    preg_match($regex_pattern, $hash, $matches);

    if(sizeof($matches) > 0) {
      list($method) = $matches;
    } else {
      $method = null;
    }

    switch($method) {
      case self::SHA256:
      case self::SHA512:
      case self::PBKDF2:
        $param = array();
        list( , , $params) = explode('$', $hash);
        parse_str($params, $param);
        $info['options'] = $param;
      break;

      case self::BCRYPT;
        list( , , $cost) = explode('$', $hash);
        $info['options'] = array(
          'cost' => $cost,
        );
      break;
    }
    $info['algo'] = $method;
    return $info;
  }

  private static function _phpassHash($password, $setting, $method = 'sha512') {
  	/* First 12 characters are the settings. */
  	$setting = substr($setting, 0 , 12);
  	$salt    = substr($setting, 4, 8);
  	$count   = 1 << strpos(self::$charsets['itoa64'], $setting[3]);

  	$hash = hash($method, $salt . $password, TRUE);
  	do {
  		$hash = hash($method, $hash . $password, TRUE);
  	} while (--$count);

  	$len = strlen($hash);
  	$output = $setting . self::_b64Encode($hash, $len);
  	$expected = 12 + ceil((8 * $len) / 6);

  	return substr($output, 0, $expected);
  }

  private static function _b64Encode($input, $count) {
  	$itoa64 = self::$charsets['itoa64'];

  	$output = '';
  	$i = 0;
  	do {
    $value = ord($input[$i++]);
    $output .= $itoa64[$value & 0x3f];
    if ($i < $count) {
      $value |= ord($input[$i]) << 8;
    }
    $output .= $itoa64[($value >> 6) & 0x3f];
    if ($i++ >= $count) {
      break;
    }
    if ($i < $count) {
      $value |= ord($input[$i]) << 16;
    }
    $output .= $itoa64[($value >> 12) & 0x3f];
    if ($i++ >= $count) {
      break;
    }
    $output .= $itoa64[($value >> 18) & 0x3f];
  } while ($i < $count);

  return $output;
  }
}