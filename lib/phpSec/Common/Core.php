<?php namespace phpSec\Common;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

use \phpSec\Store;
use \phpSec\Crypt\Rand;

/**
 * phpSec core functionality.
 */
class Core {
  /**
   * Constant: Version number. Isn't really
   * used for something... yet.
   */
  const VERSION = '0.4.0';

  /**
   * Storage object.
   */
  public static $store = null;

  /**
   * User identifier.
   */
  public static $uid = null;

  /**
   * Provides the library a simple way of reporting errors to the developer using PHPs error
   * handler.
   *
   * @see http://php.net/manual/en/errorfunc.constants.php
   *
   * @param string $msg
   *   String containing the error message
   *
   * @param constant $level
   *   Error level (optional).
   *   If none is specified E_USER_WARNING is used.
   */
  public static function error($msg, $level = E_USER_WARNING) {
    $trace = debug_backtrace();
    trigger_error($msg.'. (Called from <strong>'.$trace[0]['file'].' line '.$trace[0]['line'].'</strong>)', $level);
  }

  /**
   * Check structure of an array.
   * This method checks the structure of an array (only the first layer of it) against
   * a defined set of rules.
   *
   * @param array $array
   *   Array to check.
   *
   * @param array $structure
   *   Expected array structure. Defined for example like this:
   *   array(
   *     'string' => array(
   *       'callback' => 'strlen',
   *       'params'   => array('%val'),
   *       'match'    => 3,
   *     ),
   *     'not allowed' = false, // Only makes sense with $strict = false
   *     'needed'      = true,
   *   ),
   *
   * @param bool $strict
   *   If strict is set to false we will allow keys that's not defined in the structure.
   */
  public static function arrayCheck($array, $structure, $strict = true) {
    $success = true;
    /* First compare the size of the two arrays. Return error if strict is enabled. */
    if(sizeof($array) != sizeof($structure) && $strict === true) {
      self::error('Array does not match defined structure');
      return false;
    }

    /* Loop trough all the defined keys defined in the structure. */
    foreach($structure as $key => $callbackArray) {
      if(isset($array[$key])) {
        /* The key exists in the array we are checking. */

        if(is_array($callbackArray) && isset($callbackArray['callback'])) {
          /* We have a callback. */

          /* Replace %val with the acutal value of the key. */
          $callbackArray['params'] = str_replace('%val', $array[$key], $callbackArray['params']);

          if(call_user_func_array($callbackArray['callback'], $callbackArray['params']) !== $callbackArray['match']) {
            /* Call the *duh* callback. If this returns false throw error, or an axe. */
            self::error('Array does not match defined structure. The '.$key.' key did not pass the '.$callbackArray['callback'].' callback');
            $success = false;
          }
        } elseif($callbackArray === false) {
          /* We don't have a callback, but we have found a disallowed key. */
          self::error('Array does not match defined structure. '.$key.' is not allowed');
          $success = false;
        }
      } else {
        /* The key don't exist in the array we are checking. */

        if($callbackArray !== false) {
          /* As long as this is not a disallowed key, sound the general alarm. */
          self::error('Array does not match defined structure. '.$key.' not defined');
          $success = false;
        }
      }
    }
    return $success;
  }

  /**
   * Returns a unique identifier in the format spsecified in
   * OpenID Authentication 2.0 protocol.
   * For example: 2005-05-15T17:11:51ZUNIQUE
   * This function is used to generate all unique tokens used by
   * phpSec.
   * @see http://openid.net/specs/openid-authentication-2_0.html
   *
   * @param integer $length
   *   The total length of the uid. Must be above 25.
   */
  public static function genUid($length = 50) {
    if($length < 25) {
      self::error('Length must be longer than 25');
      return false;
    }
    $timeStamp = gmdate('Y-m-d\TH:i:se');
    $randLength = $length-strlen($timeStamp);
    return $timeStamp.Rand::str($randLength);
  }

  public function getUid() {
  	/* Create a random token for each visitor and store it the users session.
       This is for example used to identify owners of cache data. */
    if(!isset($_SESSION['phpSec-uid'])) {
      $_SESSION['phpSec-uid'] = self::genUid();
    }

    return $_SESSION['phpSec-uid'];
  }

  public static function setStore($dsn) {

  	/* Open store. */
    list($storeType, $storeDest) = explode(':', $dsn, 2);
    switch($storeType) {
      case 'filesystem':
        self::$store = new Store\File($storeDest);
      break;
      case 'mysql':
        self::$store = new Store\Pdo($storeDest);
      break;
      default:
      self::error('Store type('.$storeType.') invalid', E_USER_ERROR);
    }
  }
}