<?php namespace phpSec\Common;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use \phpSec\Crypt\Crypto;
use \phpSec\Common\Core;
use \phpSec\Crypt\Rand;

/**
 * Implements a session handler to save session data encrypted.
 */
class Session {
  private static $_sessIdRegen;
  private static $_savePath;
  private static $_name;
  private static $_keyCookie;
  private static $_secret;
  private static $_currID;
  private static $_newID;

  public static $_cryptAlgo = 'rijndael-256';
  public static $_cryptMode = 'cfb';

  /**
   * Constant: Hash method to use.
   */
  const HASH_TYPE = 'sha256';

  /**
   * Init the phpSec session handler.
   */
  public static function init($_sessIdRegen) {
  	self::$_sessIdRegen = $_sessIdRegen;

  	ini_set('session.save_handler', 'user');
    session_set_save_handler(
      '\phpSec\Common\Session::open',
      '\phpSec\Common\Session::close',
      '\phpSec\Common\Session::read',
      '\phpSec\Common\Session::write',
      '\phpSec\Common\Session::destroy',
      '\phpSec\Common\Session::gc'
    );

    /* Since we set a session cookie on our session handler, disable the built-in cookies. */
    ini_set('session.use_cookies', 0);

    /* Start a new session. */
    session_start();

    /* Check the fingerprint to see if it matches, if not clear session data. */
    $fingerprint = hash(self::HASH_TYPE, 'phpSec-fingerprint'.$_SERVER['HTTP_USER_AGENT']);
    if(!isset($_SESSION['phpSec-fingerprint'])) {
      $_SESSION['phpSec-fingerprint'] = $fingerprint;
    }
    if($fingerprint != $_SESSION['phpSec-fingerprint']) {
      $_SESSION = array();
    }

    Core::getUid();
  }


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
    if(self::$_sessIdRegen === true || self::$_currID === null) {
    	self::$_newID = Rand::str(128, 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.!*#=%');
    } else {
    	self::$_newID = self::$_currID;
    }

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
    try {
      $sessData = Core::$store->read('session', $_COOKIE[self::$_name]);

      if($sessData !== false ) {
        $return = Crypto::decrypt($sessData, self::$_secret);
      } else {
        $return = false;
      }
      return $return;
    }  catch (\phpSec\Exception $e) {
      return false;
    }
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
    try {
      Crypto::$_algo = self::$_cryptAlgo;
      Crypto::$_mode = self::$_cryptMode;
      $encrypted = Crypto::encrypt($data, self::$_secret);

      /* Destroy old session. */
      if(self::$_newID != self::$_currID) {
      	self::destroy(self::$_currID);
      }

      /* Write new session, with new ID. */
      return Core::$store->write('session', self::$_newID, $encrypted);
    } catch (\phpSec\Exception $e) {
      return false;
    }
  }
  /**
   * Destroy/remove a session.
   *
   * @param string $id
   * @return bool
   */
  public static function destroy($id) {
    return Core::$store->delete('session', $id);
  }
  /**
   * Do garbage collection.
   *
   * @param integer $ttl
   * @return bool
   */
  public static function gc($ttl) {
    $Ids = Core::$store->listIds('session');
    foreach($Ids as $Id) {
      $data = Core::$store->meta('session', $Id);
      if($data->time + $ttl < time()) {
        Core::$store->delete('session', $Id);
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
    self::$_secret = Rand::bytes(32);
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
