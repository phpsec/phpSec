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
    $descriptorspec = array(
      0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
      1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
      2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
    );

    $process = proc_open(self::prep('batch --gen-key'), $descriptorspec, $pipes);
    if (is_resource($process)) {

      /* Setup the key data. */
      $str = "Key-Type: DSA\n" .
             "Key-Length: 1024\n" .
             "Subkey-Type: ELG-E\n" .
             "Subkey-Length: 1024\n" .
             "Name-Real: ".$name."\n" .
             "Name-Comment: ".$comment."\n" .
             "Name-Email: ".$email."\n" .
             "Expire-Date: 0\n" .
             "Passphrase: ".$passphrase."\n" .
             "%commit";

      /* Write to STDIN. */
      fwrite($pipes[0], $str);

      /* Close it up, Scotty! */
      fclose($pipes[0]);
      fclose($pipes[1]);

      /* Return true if all is good. */
      if(proc_close($process) == 0) {
        return true;
      }
    }
    return false;
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

  public static function verify($sig, $data) {

  }

  /**
   * Encrypt data.
   *
   * @param string $to
   *   Name of public key to the reciever.
   *
   * @param string $data
   *   Data to encrypt.
   *
   * @return string
   *   Encrypted data.
   */
  public static function encrypt($to, $data) {

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

  /**
   * Create a GPG command ready to pass to shell_exec()
   */
  private static function prep($action, $options = array()) {
    $str = self::$_gpgPath;
    $str .= ' --homedir '.self::$_keyDir;

    $str .= ' --'.$action;
    echo $str;
    return $str;
  }

}