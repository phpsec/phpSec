<?php
/**
      phpSec - A PHP security library
      Web:     https://github.com/xqus/phpSec

      Copyright (c) 2011 Audun Larsen <larsen@xqus.com>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
 */

/**
 * Provides methods for encrypting data.
 */
class phpsecCrypt {
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
    $td = mcrypt_module_open(MCRYPT_BLOWFISH, '', 'cbc', '');

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
    $encrypted['hash']  = hash('sha256', $serializedData);
    $encrypted['algo']  = MCRYPT_BLOWFISH; /* TODO: You know what to do here. */
    $encrypted['mode']  = 'cbc';
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
    if(hash('sha256', $decrypted) == $data['hash']) {
      return unserialize($decrypted);
    } else {
      return false;
    }
  }

  function getKey($key, $ks) {
    return substr(hash(PHPSEC_HASHTYPE, $key), 0, $ks);
  }
}
/* Initialize the crypto, set the keys and other stuff we need. */
