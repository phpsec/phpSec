<?php namespace phpSec;
/**
 phpSec - A PHP security library

 @author    Audun Larsen <larsen@xqus.com>
 @copyright Copyright (c) Audun Larsen, 2012, 2013
 @link      https://github.com/phpsec/phpSec
 @license   http://opensource.org/licenses/mit-license.php The MIT License
 @package   phpSec
 */

/**
 * phpSec core class.
 * Includes Core phpSec methods, and act as an Pimple DI container.
 *
 * @author    Audun Larsen <larsen@xqus.com>
 * @package   phpSec
 */
class Core extends \Pimple {

  /**
   * phpSec version consant.
   */
  const VERSION = '0.6.1';

  /**
   * Constructor.
   * Set up the default objects for phpSec.
   */
  public function __construct() {

    /* Store object. Must be defined by the developer. */
    $this['store']  = null;

    /* Cache object. Shared object that handles the cache. */
    $this['cache'] = $this->share(function($psl) {
      return new Common\Cache($psl);
    });

    /* Session object. Shared object that handles sessions. */
    $this['session'] = $this->share(function($psl) {
      return new Common\Session($psl);
    });

    /**
     * Core phpSec objects.
     */
    $this['auth/authy'] = function() {
      return new Auth\Authy();
    };

    $this['auth/mnemonic'] = function($psl) {
      return new Auth\Mnemonic($psl);
    };

    $this['auth/google'] = function($psl) {
      return new Auth\Google($psl);
    };

    $this['auth/otp'] = function($psl) {
      return new Auth\Otp($psl);
    };

    $this['auth/yubikey'] = function($psl) {
      return new Auth\Yubikey($psl);
    };

    $this['common/exec'] = function($psl) {
      return new Common\Exec();
    };

    $this['common/token'] = function($psl) {
      return new Common\Token($psl);
    };

    $this['crypt/crypto'] = function($psl) {
      return new Crypt\Crypto($psl);
    };

    $this['crypt/hash'] = function($psl) {
      return new Crypt\Hash($psl);
    };

    $this['crypt/rand'] = function($psl) {
      return new Crypt\Rand();
    };

    $this['http/hsts'] = function($psl) {
      return new Http\Hsts();
    };

    $this['http/url'] = function($psl) {
      return new Http\Url($psl);
    };

    $this['http/xfo'] = function($psl) {
      return new Http\Xfo();
    };

    $this['string/base32'] = function($psl) {
      return new String\Base32($psl);
    };

    $this['string/compare'] = function($psl) {
      return new String\Compare();
    };

    $this['text/filter'] = function($psl) {
      return new Http\Hsts($psl);
    };


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
   *
   * @return bool
   *   Returns true on match, and false on mismatch.
   */
  public static function arrayCheck($array, $structure, $strict = true) {
    $success = true;
    /* First compare the size of the two arrays. Return error if strict is enabled. */
    if(sizeof($array) != sizeof($structure) && $strict === true) {
      //self::error('Array does not match defined structure');
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
            //self::error('Array does not match defined structure. The '.$key.' key did not pass the '.$callbackArray['callback'].' callback');
            $success = false;
          }
        } elseif($callbackArray === false) {
          /* We don't have a callback, but we have found a disallowed key. */
          //self::error('Array does not match defined structure. '.$key.' is not allowed');
          $success = false;
        }
      } else {
        /* The key don't exist in the array we are checking. */

        if($callbackArray !== false) {
          /* As long as this is not a disallowed key, sound the general alarm. */
          //self::error('Array does not match defined structure. '.$key.' not defined');
          $success = false;
        }
      }
    }
    return $success;
  }

  /**
   * Returns a unique identifier.
   *
   * @return string
   *   Returns a unique identifier.
   */
  public function genUid() {
    $rand = $this['crypt/rand'];

    $hex = bin2hex($rand->Bytes(32));
    $str = substr($hex,0,16) . '-' . substr($hex,16,8) . '-' . substr($hex,24,8) . '-' . substr($hex,32,8) . '-' . substr($hex,40,24);
    return $str;
  }

  /**
   * Get/set the current phpSec UID.
   *
   * The phpSec UID is required for some sub classes of phpSec, for
   * example Cache.
   *
   * @return string
   *   Return the current phpSec UID.
   */
  public function getUid() {
    /* Create a random token for each visitor and store it the users session.
     This is for example used to identify owners of cache data. */
    if(!isset($_SESSION['phpSec-uid'])) {
      $_SESSION['phpSec-uid'] = $this->genUid();
    }
    return $_SESSION['phpSec-uid'];
  }

}
