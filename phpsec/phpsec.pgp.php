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
 * Class to act as an interface to GPG.
 */
class phpsecPgp {
  public static $_gpgPath = '/usr/bin/gpg';

  /* Directory where we will store the keys. */
  public static $_keyDir  = null;

  /* Private key we want to use. */
  public static $privKey  = null;

  /* Passphrase for the private key we want to use. */
  public static $keyPass  = null;

  /**
   * Generate a pair of keys.
   *
   * @param string $name
   *   Name of the owner of the key.
   *
   * @param string $email
   *   E-mail to the owner of the key.
   *
   * @param string $comment
   *   Key comment.
   *
   * @param string $passphrase
   *   Passphrase to protect the privarte key with.
   *
   * @return string
   *   Key ID.
   */
  public static function genKeys($name, $email, $comment, $passphrase) {

  }

  /**
   * Sign a public key with a private key.
   *
   * @param string $key
   *   Name of public key to sign.
   *
   * @return bool
   *   True on success, false on error.
   */
  public static function signKey($key) {

  }

  /**
   * Sign data.
   *
   * @param string $data
   *   Data to sign.
   *
   * @return string
   *   Signature.
   */
  public static function sign($data) {

  }

  /**
   * Encrypt data.
   *
   * @param string $data
   *   Data to encrypt.
   *
   * @return string
   *   Encrypted data.
   */
  public static function encrypt($data) {

  }

  /**
   * Decrypt data.
   *
   * @param string $data
   *   Data to decrypt.
   *
   * @return string
   *   Decrypted data.
   */
  public static function decrypt($data) {

  }

}