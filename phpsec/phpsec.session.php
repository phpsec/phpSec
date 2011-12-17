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
 * Implements a session handler to save session data encrypted.
 */
class phpsecSession {
  private static $_savePath;
  private static $_name;
  private static $_keyCookie;
  private static $_secret;
  private static $_currID;
  private static $_newID;

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

    /* Set current and new ID. */
    if(isset($_COOKIE[$name])) {
      self::$_currID = $_COOKIE[$name];
    } else {
      self::$_currID = null;
    }
    self::$_newID  = phpsecRand::str(128);

    /* Set cookie with new session ID. */
    $cookieParam = session_get_cookie_params();
    setcookie(
      $name,
      self::$_newID,
      $cookieParam['lifetime'],
      $cookieParam['path'],
      $cookieParam['domain'],
      $cookieParam['secure'],
      $cookieParam['httponly']
    );

    /* If we don't have a encryption key, create one. */
    if(!isset($_COOKIE[self::$_keyCookie])) {
      /* Create a secret used for encryption of session. */
      self::setSecret();
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
   * @return mixed
   */
  public static function read($id) {
    /* If no cookie is set, just dropi it! */
    if(!isset($_COOKIE[self::$_name])) {
      return false;
    }

    /* Read from store and decrypt. */
    $sessData = phpsec::$store->read('session', $_COOKIE[self::$_name]);
    if($sessData !== false ) {
      $return = phpsecCrypt::decrypt($sessData, self::$_secret);
    } else {
      $return = false;
    }
    return $return;
  }

  /**
   * Encrypt and save a session.
   *
   * @param string $id
   * @param string $data
   * @return bool
   */
  public static function write($id, $data) {
    /* Encrypt session. */
    $encrypted = phpsecCrypt::encrypt($data, self::$_secret);

    /* Destroy old session. */
    self::destroy(self::$_currID);

    /* Write new session, with new ID. */
    return phpsec::$store->write('session', self::$_newID, $encrypted);

  }
  /**
   * Destroy/remove a session.
   *
   * @param string $id
   * @return bool
   */
  public static function destroy($id) {
    return phpsec::$store->delete('session', $id);
  }
  /**
   * Do garbage collection.
   *
   * @param integer $ttl
   * @return bool
   */
  public static function gc($ttl) {
    $Ids = phpsec::$store->listIds('session');
    foreach($Ids as $Id) {
      $data = phpsec::$store->meta('session', $Id);
      if($data->time + $ttl < time()) {
        phpsec::$store->delete('session', $Id);
      }
    }
    return true;
  }

  /**
   * Set the cookie with the secret.
   *
   * @return true
   */
  private static function setSecret() {
    self::$_secret = phpsecRand::bytes(32);
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
    return true;
  }
}
