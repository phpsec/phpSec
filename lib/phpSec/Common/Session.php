<?php namespace phpSec\Common;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

class Session implements \SessionHandlerInterface {

  private $psl = null;
  private $sessIdRegen;
  private $savePath;
  private $name;
  private $keyCookie;
  private $secret;
  private $currID;
  private $newID;

  public $cryptAlgo = 'rijndael-256';
  public $cryptMode = 'cfb';

  public function __construct($psl) {
    $this->psl = $psl;
    ini_set('session.save_handler', 'user');
    session_set_save_handler($this);

    /* Since we set a session cookie on our session handler, disable the built-in cookies. */
    ini_set('session.use_cookies', 0);

    /* Start a new session. */
    session_start();

    $psl->getUid();
  }

  public function close() {
    return true;
  }

  public function destroy($id) {
    $store  = $this->psl['store'];
    return $store->delete('session', $id);

  }

  public function gc($ttl) {
    $store  = $this->psl['store'];

    $Ids = $store->listIds('session');
    foreach($Ids as $Id) {
      $data = $store->meta('session', $Id);
      if($data->time + $ttl < time()) {
        $store->delete('session', $Id);
      }
    }
    return true;
  }

  public function open($path, $name) {
    $rand = $this->psl['crypt/rand'];

    /* Set some variables we need later. */
    $this->savePath  = $path;
    $this->name      = $name;
    $this->keyCookie = $name.'_secret';

    /* Set current and new ID. */
    if(isset($_COOKIE[$name])) {
      $this->currID = $_COOKIE[$name];
    } else {
      $this->currID = null;
    }
    if($this->sessIdRegen === true || $this->currID === null) {
      $this->newID = $rand->str(128, 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.!*#=%');
    } else {
      $this->newID = $this->currID;
    }

    /* Set cookie with new session ID. */
    $cookieParam = session_get_cookie_params();
    setcookie(
        $name,
        $this->newID,
        $cookieParam['lifetime'],
        $cookieParam['path'],
        $cookieParam['domain'],
        $cookieParam['secure'],
        $cookieParam['httponly']
    );

    /* If we don't have a encryption key, create one. */
    if(!isset($_COOKIE[$this->keyCookie])) {
      /* Create a secret used for encryption of session. */
      $this->setSecret();
    } else {
      $this->secret = base64_decode($_COOKIE[$this->keyCookie]);
    }
    return true;
  }

  public function read($id) {
    $crypto = $this->psl['crypt/crypto'];
    $store  = $this->psl['store'];

    /* If no cookie is set, just drop it! */
    if(!isset($_COOKIE[$this->name])) {
      return false;
    }

    /* Read from store and decrypt. */
    try {
      $sessData = $store->read('session', $_COOKIE[$this->name]);

      if($sessData !== false ) {
        $return = $crypto->decrypt($sessData, $this->secret);
      } else {
        $return = false;
      }
      return $return;
    }  catch (\phpSec\Exception $e) {
      return false;
    }
  }

  public function write($id , $data) {
    $crypto = $this->psl['crypt/crypto'];
    $store  = $this->psl['store'];

    /* Encrypt session. */
    try {
      $crypto->_algo = $this->cryptAlgo;
      $crypto->_mode = $this->cryptMode;
      $encrypted = $crypto->encrypt($data, $this->secret);

      /* Destroy old session. */
      if($this->newID != $this->currID) {
        $this->destroy($this->currID);
      }

      /* Write new session, with new ID. */
      return $store->write('session', $this->newID, $encrypted);
    } catch (\phpSec\Exception $e) {
      return false;
    }
  }

  public function setSecret() {
    $rand = $this->psl['crypt/rand'];

    $this->secret = $rand->bytes(32);
    $cookieParam = session_get_cookie_params();
    setcookie(
        $this->keyCookie,
        base64_encode($this->secret),
        $cookieParam['lifetime'],
        $cookieParam['path'],
        $cookieParam['domain'],
        $cookieParam['secure'],
        $cookieParam['httponly']
    );
    return true;
  }
}