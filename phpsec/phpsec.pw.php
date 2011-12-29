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
 *  Provides methods for hashing and salting of passwords.
 */
class phpsecPw {
  /**
   * Create a hashed version of a password, safe for storage in a database.
   * This function return a json encoded array that can be stored directly
   * into a database. The array has the following layout:
   * array(
   *   'hash'      => The hash created from the password and a salt.
   *   'salt'      => The salt that was used along with the password to create the hash.
   *   'algo'      => The hashing algorythm used.
   * )
   * The following injection methods exists:
   * before: The salt is placed diectly in front of the password, without using any
   * seperation characters.
   * after: The salt is placed directly after the password without any seperation
   * characters.
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
    $injected = self::inject($password, $salt);
    $hash     = hash(phpsec::HASH_TYPE, $injected);

    $return = array(
      'hash'      => $hash,
      'salt'      => base64_encode($salt),
      'algo'      => phpsec::HASH_TYPE,
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
   *   as created by pwHash().
   *
   * @return boolean
   *   True on password match, false otherwise.
   */
  public static function check($password, $dbPassword) {
    /**
     * Unserialize registerd password array and validate it to ensure
     * we got a valid array.
     */
    $data = json_decode($dbPassword, true);

    $dataStructure = array(
      'hash'  => true,
      'salt'  => true,
      'algo'  => true,
    );

    if($data !== null && phpsec::arrayCheck($data, $dataStructure)) {
      /**
       * Ok, we are pretty sure that this is a good array. Now inject the salt
       * into the user supplied password, to see if it matches the registerd
       * data from $dbPassword.
       */

      /* Try to Base64 decode the salt.  base64_decode() will return false
       * if the string passed is not Base64 encoded. This way we can separate
       * binary salts from the old type of salts. */
      $decodedSalt = base64_decode($data['salt'], true);
      if($decodedSalt !== false) {
        /* The salt was Base64 encoded. Use the decoded version. */
        $data['salt'] = $decodedSalt;
      }

      $pwInjected = self::inject($password, $data['salt']);
      /* Create a hash and see if it matches. */
      if(hash($data['algo'], $pwInjected) == $data['hash']) {
        return true;
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