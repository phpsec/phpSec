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
 * Provides methods for encrypting data.
 */
class phpsecCrypt {
  const ALGO      = MCRYPT_BLOWFISH;
  const ALGO_MODE = MCRYPT_MODE_CBC;
  const HASH_TYPE = 'sha256';

  /**
   * Encrypt data returning a JSON encoded array safe for storage in a database
   * or file. The array has the following structure before it is encoded:
   * array(
   *   'cdata' => 'Encrypted data, Base 64 encoded',
   *   'iv'    => 'Base64 encoded IV',
   *   'algo'  => 'Algorythm used',
   *   'mode'  => 'Mode used',
   *   'hash'  => 'A SHA256 hash of the data'
   * )
   *
   * @param mixed $data
   *   Data to encrypt.
   *
   * @return string
   *   Serialized array containing the encrypted data along with some meta data.
   */
  public static function encrypt($data, $key) {
    $td = mcrypt_module_open(self::ALGO, '', self::ALGO_MODE, '');

    /* Create IV. */
    $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);

    /* Get keysize length. */
    $ks = mcrypt_enc_get_key_size($td);

    /* Get key. */
    $key = self::getKey($key, $ks);

    /* Init mcrypt. */
    mcrypt_generic_init($td, $key, $iv);

    /* Prepeare the array with data. */
    $serializedData = serialize($data);

    $encrypted['cdata'] = base64_encode(mcrypt_generic($td, $serializedData));
    $encrypted['hash']  = hash(self::HASH_TYPE, $serializedData);
    $encrypted['algo']  = self::ALGO;
    $encrypted['mode']  = self::ALGO_MODE;
    $encrypted['iv']    = base64_encode($iv);

    return json_encode($encrypted);
  }

  /**
   * Decrypt a data encrypted by encrypt().
   *
   * @param string $data
   *   JSON string containing the encrypted data and meta information in the
   *   excact format as returned by encrypt().
   *
   * @return mixed
   *   Decrypted data in it's original form.
   */
  public static function decrypt($data, $key) {

    /* Decode the JSON string */
    $data = json_decode($data, true);
    if($data === NULL || sizeof($data) !== 5) {
      self::error('Invalid data passed to decrypt()');
      return false;
    }
    /* Everything looks good so far. Let's continue.*/
    $td = mcrypt_module_open($data['algo'], '', $data['mode'], '');

    /* Get keysize length. */
    $ks = mcrypt_enc_get_key_size($td);

    /* Get key. */
    $key = self::getKey($key, $ks);

    /* Init mcrypt. */
    mcrypt_generic_init($td, $key, base64_decode($data['iv']));

    $decrypted = rtrim(mdecrypt_generic($td, base64_decode($data['cdata'])));
    if(hash(self::HASH_TYPE, $decrypted) == $data['hash']) {
      return unserialize($decrypted);
    } else {
      return false;
    }
  }

  /**
   * Get a key from a secret.
   *
   * @param string $secret
   *   The secret to generate a key from.
   *
   * @param integer $ks
   *   The key size.
   *
   * @return string
   */
  private static function getKey($secret, $ks) {
    return substr(hash(self::HASH_TYPE, $secret), 0, $ks);
  }
}
