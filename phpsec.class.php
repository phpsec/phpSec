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
 * phpSec basic functionality.
 */
class phpsec {
  public static $_charset    = 'utf-8';
  public static $_storeName  = null;
  public static $_sessenable = true;
  public static $uid         = null; // User identifier.
  public static $store       = null;

  /* Constants. */
  const HASH_TYPE      = 'sha256';
  const VERSION        = '0.1-dev';
  /**
   * Autoload function to load required files when needed.
   */
  public static function load($class) {
    $basePath = dirname(__FILE__);
    $classes = array(
      'phpsecCache'           => 'phpsec.cache.php',
      'phpsecSession'         => 'phpsec.session.php',
      'phpsecRand'            => 'phpsec.rand.php',
      'phpsecCrypt'           => 'phpsec.crypt.php',
      'phpsecYubikey'         => 'phpsec.yubikey.php',
      'phpsecOtp'             => 'phpsec.otp.php',
      'phpsecStore'           => 'phpsec.store.php',
      'phpsecToken'           => 'phpsec.token.php',
      'phpsecPw'              => 'phpsec.pw.php',
      'phpsecStoreFilesystem' => 'phpsec.store.filesystem.php',
    );

    if(isset($classes[$class])) {
      require_once $basePath.'/phpsec/'.$classes[$class];
    }
  }

  /**
   * Initialize the library.
   */
  public static function init() {
    /* First of all, register the autoloading function.
     * If we have one set from somewhere else, keep it. */
     $autoLoadFunctions   = spl_autoload_functions();
     $autoLoadFunctions[] = 'phpsec::load';
     foreach($autoLoadFunctions as $autoLoadFunction) {
       spl_autoload_register($autoLoadFunction);
     }

    /* Open store. */
    list($storeType, $storeDest) = explode(':', self::$_storeName);
    switch($storeType) {
      case 'filesystem':
        self::$store = new phpsecStoreFilesystem($storeDest);
      break;
      default:
      self::error('Store type('.$storeType.') invalid', E_USER_ERROR);
    }

    /* Set the charset of the multibyte functions in PHP. */
    mb_internal_encoding(self::$_charset);
    mb_regex_encoding(self::$_charset);

    /* Register the custom session handler if enabled. */
    if(self::$_sessenable === true) {
      ini_set('session.save_handler', 'user');
      session_set_save_handler(
        'phpsecSession::open',
        'phpsecSession::close',
        'phpsecSession::read',
        'phpsecSession::write',
        'phpsecSession::destroy',
        'phpsecSession::gc'
      );

      /* Since we set a session cookie on our session handler, disable the build in cookies. */
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
    }


    /* Create a random token for each visitor and store it the users session.
       This is for example used to identify owners of cache data. */
    if(!isset($_SESSION['phpSec-uid'])) {
      self::$uid = self::genUid();
      $_SESSION['phpSec-uid'] = self::$uid;
    } else {
      self::$uid = $_SESSION['phpSec-uid'];
    }
  }

  /**
   * XSS filter. Returns a string that is safe to use on the page.
   *
   * There are three types of variables:
   * %variables: stip mode of phpsec::f() is used.
   * !variables: escapeAll mode of phpsec::f() is used.
   * @variables: escape mode of phpsec::f() is used.
   * &variables: url mode of phpsec::f() is used.
   *
   * @see phpsec::f()
   * @see http://phpsec.xqus.com/node/2424
   * @see http://www.faqs.org/rfcs/rfc3986
   *
   * @param string $str
   *   A string containing the 'glue' used to compose the filtered parts
   *   from the $args array.
   *
   * @param mixed $args
   *   An associative array containing data to filter.
   *   The array keys should be preceeded with %, ! or @ defining what filter
   *   to apply.
   */
  public static function t($str, $args) {
    /* Loop trough the args and apply the filters. */
    while(list($name, $data) = each($args)) {
      $safeData = false;
      $filterType = mb_substr($name, 0, 1);
      switch($filterType) {
        case '%':
          /* %variables: HTML is stripped from the string
             before it is in inserted. */
          $safeData = self::f($data, 'strip');
          break;
        case '!':
          /* !variables: HTML and special characters is escaped from the string
             before it is in inserted. */
          $safeData = self::f($data, 'escapeAll');
          break;
        case '@':
          /* @variables: Only HTML is escaped from the string. Special characters
             is kept as is. */
          $safeData = self::f($data, 'escape');
          break;
        case '&':
          /* Encode a string according to RFC 3986 for use in a URL. */
          $safeData = self::f($data, 'url');
          break;
        default:
          self::error('Unknown variable type', E_USER_NOTICE);
          break;
      }
      if($safeData !== false) {
        $str = str_replace($name, $safeData, $str);
      }
    }
    return $str;
  }

  /**
   * XSS filter. Returns a string that is safe to use on the page.
   *
   * There are three modes:
   * strip: HTML is stripped from the string
   * before it is inserted.
   * escapeAll: HTML and special characters is escaped from the string
   * before it is inserted.
   * escape: Only HTML is escaped from the string. Special characters
   * is kept as is.
   * url: Encode a string according to RFC 3986 for use in a URL.
   *
   * @see http://phpsec.xqus.com/node/2424
   * @see http://www.faqs.org/rfcs/rfc3986
   *
   * @param string $str
   *   String to filter
   *
   * @param string $mode
   *   String defining what filter to apply.
   */
  public static function f($str, $mode = 'escape') {
    switch($mode) {
      case 'strip':
        /* HTML is stripped from the string
           before it is in inserted. */
        return strip_tags($str);
      case 'escapeAll':
        /* HTML and special characters is escaped from the string
           before it is in inserted. */
        return htmlentities($str, ENT_QUOTES, self::$_charset);
      case 'escape':
        /* Only HTML is escaped from the string. Special characters
           is kept as is. */
        return htmlspecialchars($str, ENT_NOQUOTES, self::$_charset);
      case 'url':
        /* Encode a string according to RFC 3986 for use in a URL. */
        return rawurlencode($str);
      default:
        self::error('Unknown variable type', E_USER_NOTICE);
    }
  }

  /**
   * Provides the library a simple way of reporting errors to the developer using PHPs error
   * handler.
   *
   * @param string $msg
   *   String containing the error message
   *
   * @param constant $level
   *   Error level (optional).
   *   If none is specified PHPSEC_E_WARN is used.
   */
  public static function error($msg, $level = E_USER_WARNING) {
    $callee = next(debug_backtrace());
    trigger_error($msg.'. (Called from <strong>'.$callee['file'].' line '.$callee['line'].'</strong>)', $level);
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
    return $timeStamp.phpsecRand::str($randLength);
  }
}
