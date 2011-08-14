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
 * Implements a session handler to save session data encrypted.
 */
class phpsecSession {
  private static $_savePath;
  private static $_name;
  private static $_keyCookie;
  private static $_secret;

  /**
   * Open a session.
   *
   * @param string $path
   * @param string $name
   * @return bool
   */
  public static function open($path, $name) {
    /* Set some variables we need later. */
    self::$_savePath  = $path;
    self::$_name      = $name;
    self::$_keyCookie = $name.'_secret';

    /* Set session ID if we don't have one. */
    if(!isset($_COOKIE[$name])) {
      session_id(phpsecRand::str(256));
    }

    /* If we don't have a encryption key, create one. */
    if(!isset($_COOKIE[self::$_keyCookie])) {
      /* Create a 128 bit secret used for encryption of session. */
      self::$_secret = phpsecRand::bytes(128);
      $cookieParam = session_get_cookie_params();
      setcookie(
        self::$_keyCookie,
        base64_encode(self::$_secret),
        $cookieParam['lifetime'],
        $cookieParam['path'],
        $cookieParam['domain'],
        $cookieParam['secure'],
        $cookieParam['httponly']
      );
    } else {
      self::$_secret = base64_decode($_COOKIE[self::$_keyCookie]);
    }

    return true;
  }

  /**
   * Close a session.
   *
   * @return bool
   */
  public static function close() {
    return true;
  }

  /**
   * Read and decrypt a session.
   *
   * @param string $id
   * @return bool
   */
  public static function read($id) {
    echo "Read!";
    $file = self::fileName($id);
    if(file_exists($file)) {
      $data = file_get_contents($file);
      return phpsecCrypt::decrypt($data, self::$_secret);
    }
    return false;
  }

  /**
   * Encrypt and save a session.
   *
   * @param string $id
   * @param string $data
   * @return bool
   */
  public static function write($id, $data) {
    $file = self::fileName($id);
    $encrypted = phpsecCrypt::encrypt($data, self::$_secret);
    $fp = @fopen($file, 'w');
    if($fp) {
      $success = fwrite($fp, $encrypted);
      fclose($fp);
      return $success;
    }
    return false;
  }
  /**
   * Destroy/remove a session.
   *
   * @param string $id
   * @return bool
   */
  public static function destroy($id) {
    $file = self::fileName($id);
    setcookie(
      self::$_keyCookie,
      '',
      time()-10
    );
    return(@unlink($file));
  }
  /**
   * Do garbage collection.
   *
   * @param integer $ttl
   * @return bool
   */
  public static function gc($ttl) {
    $fileNames = glob(self::$_savePath.'/'.self::$_name.'_*');
    foreach($fileNames as $fileName) {
      if(filemtime($fileName) + $ttl < time()) {
        @unlink($fileName);
      }
    }
    return true;
  }

  /**
   * Get the filname for a session ID.
   *
   * @param string $id
   * @return string
   */
  private static function fileName($id) {
    return self::$_savePath.'/'.self::$_name."_".$id;
  }
}
