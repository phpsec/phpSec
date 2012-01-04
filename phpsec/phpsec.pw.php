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
 *  Provides methods for hashing and salting of passwords. Note: This class is deprecated. Use phpsecHash instead.
 *  @see phpsecHash
 */
class phpsecPw {
  const phpsecPw_PBKDF2 = 'pbkdf2';
  const phpsecPw_BCRYPT = 'bcrypt';
  const phpsecPw_SHA256 = 'sha256';
  const phpsecPw_SHA512 = 'sha512';

  public static $_method       = self::phpsecPw_PBKDF2;

  /**
   * Iteration count that PBKDF2 will use.
   * 8192 is just a little slower than a work load of 11 when using bcrypt.
   * Oh, slow is good.
   */
  public static $_pbkdf2_c     = 8192;
  public static $_pbkdf2_dkLen = 256;
  public static $_pbkdf2_prf   = self::phpsecPw_SHA512;

  /**
   * Create a hashed version of a password, safe for storage in a database.
   * This function return a json encoded array that can be stored directly
   * into a database. The array has the following layout:
   * array(
   *   'hash'      => The hash created from the password and a salt.
   *   'salt'      => The salt that was used along with the password to create the hash.
   *   'algo'      => The hashing algorithm used.
   * )
   *
   * @param string $password
   *   The password to hash.
   *
   * @return string
   *   Returns a json encoded array containing the password hash, salt and
   *   some meta data.
   */
  public static function hash($password) {
    $salt     = phpsecRand::bytes(64);
    switch(self::$_method) {
      case self::phpsecPw_PBKDF2:
        $hash = phpsecCrypt::pbkdf2($password, $salt, self::$_pbkdf2_c, self::$_pbkdf2_dkLen, self::$_pbkdf2_prf);
        /* phpsecCrypt::pbkdf2() returns a binary string. So let's base64 encode it.*/
        $hash = base64_encode($hash);
        /* We append the iteration count, derived key length and PRF as we need this later. */
        $algo = 'pbkdf2:'.self::$_pbkdf2_c.':'.self::$_pbkdf2_dkLen.':'.self::$_pbkdf2_prf;
      break;
      default:
        $injected = self::inject($password, $salt);
        $hash     = hash(self::$_method, $injected);
        $algo     = self::$_method;
    }


    $return = array(
      'hash'      => $hash,
      'salt'      => base64_encode($salt),
      'algo'      => $algo,
    );
    return json_encode($return);
  }

  /**
   * Validate a user-supplied password against a stored password generated
   * using the phpsecPw::hash() method.
   *
   * @param string $password
   *   The password supplied by the user in the login form.
   *
   * @param string $dbPassword
   *   The json string fetched from the database, in the exact format
   *   as created by phpsecPw::hash().
   *
   * @return boolean
   *   True on password match, false otherwise.
   */
  public static function check($password, $dbPassword) {
    /**
     * Unserialize registered password array and validate it to ensure
     * we got a valid array.
     */
    $data = json_decode($dbPassword, true);

    $dataStructure = array(
      'hash'  => true,
      'salt'  => true,
      'algo'  => true,
    );

    /* Check structure of array. */
    if($data !== null && phpsec::arrayCheck($data, $dataStructure)) {

      /* Try to Base64 decode the salt.  base64_decode() will return false
       * if the string passed is not Base64 encoded. This way we can separate
       * binary salts from the old type of salts. */
      $decodedSalt = base64_decode($data['salt'], true);
      if($decodedSalt !== false) {
        /* The salt was Base64 encoded. Use the decoded version. */
        $data['salt'] = $decodedSalt;
      }

      /**
       * We do a switch on the 6 first characters on the used hashing method.
       * This way we are able to catch when pbkdf2 is used, since this has
       * it's iteration count, derived key length and PRF attached to it:
       * "pbkdf2:iteration count:derived key length:PRF"
       */
      switch(substr($data['algo'], 0, 6)) {
        case self::phpsecPw_PBKDF2:
          /* As described above, we need to seperate out the iteration count
           * and derived key length. */
          list($method, $iterationCount, $dkLen, $prf) = explode(':', $data['algo']);
          /* Just to make sure anything fishy isn't going on. */
          if(!is_numeric($iterationCount) || !is_numeric($dkLen)) {
            return false;
          }

          /* Create a new derived key, with the iteration count and derived key length
           * that were used when generating the original dk. */
          $dk = phpsecCrypt::pbkdf2($password, $data['salt'], $iterationCount, $dkLen, $prf);

          /* Check the new dk against the old base64 encoded dk. */
          if($dk === base64_decode($data['hash'])) {
            return true;
          }
        break;

        default:
          /* If not pbkdf2, we assume normal hash. */
          $pwInjected = self::inject($password, $data['salt']);
          /* Create a hash and see if it matches. */
          if(hash($data['algo'], $pwInjected) == $data['hash']) {
            return true;
          }
      }
    } else {
      /* Invalid array supplied. */
      phpsec::error('Invalid data supplied. Expected serialized array as returned by pwHash()');
    }
    return false;
  }

  /**
   * Inject a salt into a password to create the string to be hashed.
   * What we really do is to create an hash from the password, and retrieve
   * the first character from this hash. This is then converted to its decimal value.
   * We now have a number between 0 and 15. We use this to calculate where to place the salt.
   * We take the length of the password and dividing it by 16, and then we multiply this by the
   * number we got from the hash.
   *
   * @param string $password
   *   Plain-text password.
   *
   * @param string $salt
   *   Well, the salt to inject into the password.
   *
   * @return string
   *   Returns the salted password, ready to be hashed.
   *
   */
  private static function inject($password, $salt) {
    $hex = hexdec(substr(hash(phpsec::HASH_TYPE, $password), 0, 1));
    $len = strlen($password);
    $pos = floor($hex*($len/16));

    return substr($password, 0, $pos).$salt.substr($password, $pos);
  }
}