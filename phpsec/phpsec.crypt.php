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
  public static $_algo = 'rijndael-256';
  public static $_mode = 'ctr';

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
    if(strlen($key) < 4) {
      phpsec::error('Key is to short. Expected 4 characters or more');
      return false;
    }

    $td = mcrypt_module_open(self::$_algo, '', self::$_mode, '');

    /* Create IV. */
    $iv = phpsecRand::bytes(mcrypt_enc_get_iv_size($td));

    /* Get keysize length. */
    $ks = mcrypt_enc_get_key_size($td);

    /* Get key. */
    $key = self::getKey($key, $ks);

    /* Init mcrypt. */
    mcrypt_generic_init($td, $key, $iv);

    /* Prepeare the array with data. */
    $serializedData = serialize($data);

    $encrypted['algo']  = self::$_algo;
    $encrypted['mode']  = self::$_mode;
    $encrypted['iv']    = base64_encode($iv);
    $encrypted['cdata'] = base64_encode(mcrypt_generic($td, $serializedData));
    $encrypted['hash']  = hash(self::HASH_TYPE, $serializedData);

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
      phpsec::error('Invalid data passed to decrypt()');
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

    /* Close up. */
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);

    if(hash(self::HASH_TYPE, $decrypted) == $data['hash']) {
      return unserialize($decrypted);
    } else {
      return false;
    }
  }

  /**
   * Get a key from a secret.
   * What we do is create two different hashes from the secret, combine them
   * and pick out the number of characters we need.
   * We use the raw binary output of the hash function for maximum
   * bit strength (we have 255 chars to choose from, instead of 16).
   *
   * @param string $secret
   *   The secret to generate a key from.
   *
   * @param integer $ks
   *   The key size.
   *
   * @return binary
   *   Key created from secret.
   */
  private static function getKey($secret, $ks) {
    /* Split the secret into two parts. */
    $secretSplit = floor(strlen($secret)/2);
    $secret1 = substr($secret, 0, $secretSplit);
    $secret2 = substr($secret, $secretSplit);

    /* Hash the two parts seperatly and return the result in raw format. */
    $key1 = hash('sha256', $secret1, true);
    $key2 = hash('sha256', $secret2, true);

    /* Return the part of the key we need. */
    return substr($key2.$key1, 0, $ks);
  }

  /**
   * Implement PBKDF2 as described in RFC 2898.
   *
   * @param string $p
   *   Password.
   *
   * @param string $s
   *   Salt.
   *
   * @param integer $c
   *   Iteration count.
   *
   * @param integer $dkLen
   *   Derived key length.
   *
   * @param string $a
   *   A hash algorithm.
   */
  public static function pbkdf2($p, $s, $c, $dkLen, $a = 'sha256') {
    $hLen = strlen(hash($a, null, true)); /* Hash length. */
    $l    = ceil($dkLen / $hLen); /* Length in blocks of derived key. */
    $dk   = ''; /* Derived key. */

    /* Step 1. Check dkLen. */
    if($dkLen > (2^32-1)*$hLen) {
      phpsec::error('derived key too long');
      return false;
    }

    for ($block = 1; $block<=$l; $block ++) {
      /* Initial hash for this block. */
      $ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);
      /* Do block iterations. */
      for ($i = 1; $i<$c; $i ++) {
        /* XOR iteration. */
        $ib ^= ($b = hash_hmac($a, $b, $p, true));
      }
      /* Append iterated block. */
      $dk .= $ib;
    }
    /* Returned derived key. */
    return substr($dk, 0, $dkLen);
  }
}
