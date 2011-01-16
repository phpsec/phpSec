<?php
/* $Id: phpsec.class.php,v 1.17 2011/01/16 11:09:09 xqus Exp $

      phpSec - A PHP security library
      Web:     phpsec.sf.net

      Copyright 2011 Audun Larsen. All rights reserved.
      larsen@xqus.com

   Redistribution and use, with or without modification,
   are permitted provided that the following condition is met:

   * Redistribution and use of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

   THIS SOFTWARE IS PROVIDED BY ``AS IS''
   IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY TYPE OF
   DAMAGE ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE.


 */

/**
 * Define whether to use the more secure phpSec session handler.
 * Set to true to use the phpSec handler, or false to use the
 * native php session handler.
 */
define('PHPSEC_SESSIONS', true);

/**
 * Defines the charset that phpSec uses. This should be that same
 * as you use for your application in general.
 */
define('PHPSEC_CHARSET', 'UTF-8');

/**
 * Define directory to the phpSec log directory.
 * Should not be accessible from web
 */
define('PHPSEC_LOGDIR', './logs');

/**
 * Define directory to the phpSec data directory.
 * Should not be accessible from web.
 */
define('PHPSEC_DATADIR', '/var/www/phpSec/data');

/**
 * Define directory to the phpSec public data directory.
 * This must be accessible from the web.
 */
define('PHPSEC_PUBLICDATADIR', '/var/www/phpSec/data');

/**
 * Define defult hashing method.
 */
define('PHPSEC_HASHTYPE', 'sha256');

/**
 * Define default salt injection method.
 */
define('PHPSEC_SALTINJECTION', 'before');

/**
 * Define phpSec session name.
 */
define('PHPSEC_SESSNAME', 'phpSecSess');

/**
 * Define cookie name for the krypto key.
 */
define('PHPSEC_CIKCOOKIE', 'phpSecCik');

define('PHPSEC_E_ERROR',  E_USER_ERROR);
define('PHPSEC_E_WARN',   E_USER_WARNING);
define('PHPSEC_E_NOTICE', E_USER_NOTICE);

class phpsec {
  public  static $uid = null; // User identifier. To identify a session.
  private static $cik = null; // Session crypto key. Used for encryption of session data.

  /**
   * Initialize the library.
   */
  public static function init() {
    // Check write permissions to directories
    if(!is_writeable(PHPSEC_LOGDIR)) {
      self::error('Log directory('.PHPSEC_LOGDIR.') not writeable');
    }
    if(!is_writeable(PHPSEC_DATADIR)) {
      self::error('Data directory('.PHPSEC_DATADIR.') not writeable');
    }

    // If the phpSec session handler is enabled, start it.
    if(PHPSEC_SESSIONS === true) {
      self::sessionStart();
    }
    // Start session if not already started earlier.
    if(session_id() == '') {
       session_start();
     }

    // Set the charset of the multibyte functions in PHP.
    mb_internal_encoding(PHPSEC_CHARSET);
    mb_regex_encoding(PHPSEC_CHARSET);

     // Create a random token for each visitor and store it the users session.
     // This is for example used to identify owners of cache data.
     if(!isset($_SESSION['phpSec-uid'])) {
       self::$uid = self::genUid();
       $_SESSION['phpSec-uid'] = self::$uid;
     } else {
       self::$uid = $_SESSION['phpSec-uid'];
     }
     // Initialize the crypto, set the keys and other stuff we need.
     self::cryptoInit();
  }

  /**
   * XSS filter. Returns a string that is safe to use on the page.
   * A string with variables is supplied to the function along with an
   * associative array defining tha values of the variables.
   * There are three types of variables:
   * %variables: HTML is stripped from the string
   * before it is inserted.
   * !variables: HTML and special characters is escaped from the string
   * before it is inserted.
   * @variables: Only HTML is escaped from the string. Special characters
   * is kept as is.
   *
   * @see https://sourceforge.net/apps/mediawiki/phpsec/index.php?title=Documentation#2.1_Using_the_XSS_filter
   *
   * @param str
   *   Base string. The string itself is not filtered in any way, but
   *   used to compose the filtered parts from the args array.
   *
   * @param args
   *   An associative array containing data to be filtered by the XSS filter.
   *   The array keys should be preceeded with %, ! or @ defining what filter
   *   to apply.
   */
  public static function f($str, $args = array()) {
    //First, loop trough the args and apply the filters.
    while(list($name, $data) = each($args)) {
      $safeData = false;
      $filterType = mb_substr($name, 0, 1);
      switch($filterType) {
        case '%':
          // %variables: HTML is stripped from the string
          // before it is in inserted.
          $safeData = strip_tags($data);
          break;
        case '!':
          // !variables: HTML and special characters is escaped from the string
          // before it is in inserted.
          $safeData = htmlentities($data, ENT_QUOTES, PHPSEC_CHARSET);
          break;
        case '@':
          // @variables: Only HTML is escaped from the string. Special characters
          // is kept as is.
          $safeData = htmlspecialchars($data, ENT_NOQUOTES, PHPSEC_CHARSET);
          break;
        default:
          self::error('Unknown variable type', PHPSEC_E_NOTICE);
          break;
      }
      if($safeData !== false) {
        $str = str_replace($name, $safeData, $str);
      }
    }
    return $str;
  }

  /**
   * Provides the library a simple way of reporting errors to the developer using PHPs error
   * handler.
   *
   * @param string
   *   String containing the error message
   *
   * @param constant
   *   Error level (optional). Could be PHPSEC_E_ERROR, PHPSEC_E_WARN, PHPSEC_E_NOTICE.
   *   If none is specified PHPSEC_E_WARN is used.
   */
  private static function error($msg, $level = PHPSEC_E_WARN) {
    $callee = next(debug_backtrace());
    trigger_error($msg.'. (Called from <strong>'.$callee['file'].' line '.$callee['line'].'</strong>)', $level);
    //TODO: Write error to file.
  }

  /**
   * Write an entry to a log.
   *
   * @param type
   *   Specify the type of the logentry. This will be a part of the filname.
   *
   * @param msg
   *   The log message itself.
   *
   * @param level
   *   Error level (optional). Should be either debug, notice, warn or error.
   *   If none is specified warn is used.
   */
  public static function log($type, $msg, $level = 'warn') {
    $fileName = PHPSEC_LOGDIR.'/log_'.$type;
    //TODO: Add some more information when writing log entry.
    $line = date('c').' - '.$level.' - '.$msg;

    $fp = fopen($fileName, 'a');
    if($fp !== false) {
      if(flock($fp, LOCK_EX)) {
        fwrite($fp, $line."\n");
        flock($fp, LOCK_UN);
        fclose($fp);
      } else {
        self::error('Could not lock logfile');
      }
    }
  }

  /**
   * Save data to the cache.
   *
   * @param name
   *   String containing the name of the data to save.
   *
   * @param data
   *   Data to save. Can be any dataform.
   *
   * @param ttl
   *   Time to live in seconds.
   */
  private static function cacheSet($name, $data, $ttl = 3600) {
    $fileName =  PHPSEC_DATADIR.'/'.self::cacheFilename($name);
    $saveData['data'] = $data;
    $saveData['ttl']  = time() + $ttl;
    $data = serialize($saveData);
    $fp = fopen($fileName, 'w');
    if($fp !== false) {
      if(flock($fp, LOCK_EX)) {
        fwrite($fp, $data);
        flock($fp, LOCK_UN);
        fclose($fp);
      } else {
        self::error('Could not lock logfile');
      }
    }
  }

  /**
   * Get data from the cache.
   *
   * @param name
   *   String containing the name of the data to get.
   *
   * @return mixed
   *   Returns data in it's original form, or false if no data stored.
   */
  private static function cacheGet($name) {
    $fileName =  PHPSEC_DATADIR.'/'.self::cacheFilename($name);
    if(file_exists($fileName)) {
      $data = unserialize(file_get_contents($fileName));
      if($data['ttl'] > time()) {
        return $data['data'];
      }

    }
    return false;
  }

  /**
   * Remove data from the cache.
   *
   * @param name
   *   String containing the name of the data to remove.
   *
   * @return boolean
   *   True on success, false otherwise.
   */
  private static function cacheRem($name) {
    $fileName =  PHPSEC_DATADIR.'/'.self::cacheFilename($name);
    if(unlink($fileName)) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * Do garbage collection on cached data.
   */
  private static function cacheGc() {
    //TODO: Create garbage collection
  }

  private static function cacheFilename($name) {
    return 'cache_'.$name.'_'.hash(PHPSEC_HASHTYPE, self::$uid);
  }

  /**
   * Returns a unique identifier in the format spsecified in
   * OpenID Authentication 2.0 protocol.
   * For example: 2005-05-15T17:11:51ZUNIQUE
   * This function is used to generate all unique tokens used by
   * phpSec.
   * @see http://openid.net/specs/openid-authentication-2_0.html
   *
   * @param length
   *   The total length of the uid. Must be between 25 and 80 characters.
   */
  public static function genUid($length = 50) {
    if($length < 25 || $length > 80) {
      self::error('Length should be between 25 and 80');
      return false;
    }
    $timeStamp = gmdate('Y-m-d\TH:i:s\Z');
    $randLength = $length-strlen($timeStamp);
    return $timeStamp.substr(hash(PHPSEC_HASHTYPE, uniqid(null, true)), 0, $randLength);
  }

  /**
   * Generate and save a one-time-token for a form. Used to protect against
   * CSRF attacks.
   *
   * @param name
   *   Name of the form to generate a token for.
   *
   * @param ttl
   *   How long the token should be valid in seconds.
   *
   * @return string
   *   The token to supply with the form data.
   */
  public static function getToken($name, $ttl = 3600) {
    $token = self::genUid();
    // Save the token to the cahce.
    self::cacheSet('token-'.$name, $token, $ttl);
    return $token;
  }

  /**
   * Validate a one-time-token generated with setToken();
   * This function should be called before accepting data from a user-submitted form.
   * @see setToken();
   *
   * @param name
   *   Name of the form to validate the token for.
   *
   * @return boolean
   *   Returns true if the token is valid. Returns false otherwise.
   */
  public static function validToken($name, $token) {
    $cacheToken = self::cacheGet('token-'.$name);
    // Check if the provided token matches the token in the cache.
    if($cacheToken == $token) {
      // Remove the token from the cahche so it can't be reused.
      self::cacheRem('token-'.$name);
      return true;
    }
    return false;
  }

  /**
   * Create a hashed version of a password, safe for storage in a database.
   * This function return a serialized array that can be stored directly
   * in a database. The array has the following layout:
   * array(
   *   'hash'      => The hash created from the password and a salt.
   *   'salt'      => The salt that was used along with the password to create the hash.
   *   'algo'      => The hashing algorythm used.
   *   'injection' => How the salt was injected into the password.
   * )
   * The following injection methods exists:
   * before: The salt is placed diectly in front of the password, without using any
   * seperation characters.
   * after: The salt is placed directly after the password without any seperation
   * characters.
   *
   * @param password
   *   The password to hash.
   *
   * @return string
   *   Returns a serialized array containing the password hash, salt and
   *   some meta data.
   */
  public static function pwHash($password) {
    $salt     = self::genUid();
    $injected = self::pwInject($password, $salt, PHPSEC_SALTINJECTION);
    $hash     = hash(PHPSEC_HASHTYPE, $injected);

    $return = array(
      'hash'      => $hash,
      'salt'      => $salt,
      'algo'      => PHPSEC_HASHTYPE,
      'injection' => PHPSEC_SALTINJECTION,
    );
    return serialize($return);
  }

  /**
   * Validate a user-supplied  password against a stored password saved
   * using the pwHash() method.
   *
   * @param password
   *   The password supplied by the user in the login form.
   *
   * @param dbPassword
   *   The serialized array fetched from the database, in the exact format
   *   as created by pwHash().
   *
   * @return boolean
   *   True on password match, false otherwise.
   */
  public static function pwCheck($password, $dbPassword) {
    /**
     * Unserialize registerd password array and validate it to ensure
     * we got a valid array.
     */
    $data = unserialize($dbPassword);
    if(isset($data['injection']) && sizeof($data) == 4) {
      /**
       * Ok, e are pretty sure this is good stuff. Now inject the salt
       * into the user supplied password, to see if it matches the registerd
       * data from $dbPassword.
       */
      $pwInjected = self::pwInject($password, $data['salt'], $data['injection']);
      // Create a hash and see if it matches.
      if(hash($data['algo'], $pwInjected) == $data['hash']) {
        return true;
      }
    } else {
      // Invalid array supplied.
      self::error('Invalid data supplied. Expected serialized array as returned by pwHash()');
    }
    return false;
  }

  /**
   * Inject a salt into a password to create the string to be hashed.
   *
   * @param password
   *   Plain-text password.
   *
   * @param salt
   *   Well, the salt to inject into the password.
   *
   * @param injection
   *   The method used to inject the salt. @see pwHash().
   *
   * @return string
   *   Returns the salted password, ready to be hashed.
   *
   */
  private static function pwInject($password, $salt, $injection) {
    switch($injection) {
      case 'before':
        $injected = $salt.$password;
        break;
      case 'after':
        $injected = $password.$salt;
        break;
      default:
        self::error('Invalid salt injection method');
        return false;
    }
    return $injected;
  }

  /**
   * Create a captcha iamge and return filename.
   *
   * @return mixed
   *   Returns the filename to the image containing the captcha or false on failure.
   */
  public static function captcha() {
    /**
     * First, make sure we have GD.
     */
    if(!function_exists('imagecreatetruecolor')) {
      self::error('GD is required to create captchas');
      return false;
    }

    self::captchaImgCreate('filename');
  }

  /**
   * Create the captcha image, and save it as $filename.
   *
   * @param string $filename
   *   Filename to save the captcha as.
   */
  private static function captchaImgCreate($filename) {
    $width  = 120;
    $height = 30;

    $img = imagecreatetruecolor($width, $height);

    // Allocate some colors.
    $bg[]  = imagecolorallocate($img, 212, 219, 234);
    $bg[]  = imagecolorallocate($img, 212, 219, 234);
    $bg[]  = imagecolorallocate($img, 212, 219, 234);
    $bg[]  = imagecolorallocate($img, 212, 219, 234);
    $bg[]  = imagecolorallocate($img, 212, 219, 234);
    $bg[]  = imagecolorallocate($img, 162, 176, 205);
    $bg[]  = imagecolorallocate($img, 162, 176, 205);
    $bg[]  = imagecolorallocate($img, 179, 191, 217);
    $bg[]  = imagecolorallocate($img, 179, 191, 217);
    $bg[]  = imagecolorallocate($img, 255, 184, 47);
    $border = imagecolorallocate($img, 0, 0, 0);
    $line   = imagecolorallocate($img, 255, 0, 0);

    // Add border.
    imagerectangle ($img,0 ,0, $width-1, $height-1, $border);

    /**
     * Add some background noice to the image. Loops trough the image and
     * randomly set background colors.
     */
    $numColors = sizeof($bg);
    for($y = 1; $y < $height-1; $y++) {
      for($x = 1; $x < $width-1; $x++) {
        imagesetpixel($img, $x, $y, $bg[rand(0, $numColors-1)]);
      }
    }

    // Add a line to the image just for the heck of it.
    imageline($img, 10, rand(5, $height-5), $width-10, rand(5, $height-5), $line);

    // Add the text to the image. You need to be a genius to come up with code like this.
    $str = self::captchaWord(6);
    for($i = 0; $i < strlen($str); $i++) {
      $char = strtoupper(substr($str, $i, 1));
      imagestring($img, 5, 20+$i*14, rand(5,10), $char, $border);
    }
    // Set the magic word in the cache.
    self::cacheSet('captcha', $str);

    // Save the image.
    imagepng($img, PHPSEC_PUBLICDATADIR.'/'.$filename.'.png');
    imagedestroy($img);
  }

  /**
   * Generate a random word to use in the captcha.
   *
   * @param int $len
   *   Length of the word.
   */
  private static function captchaWord($len = 5) {
    return substr(hash(PHPSEC_HASHTYPE, self::genUid()), 0, $len);
  }

  /**
   * Initialize a phpSec enforced session.
   */
  private static function sessionStart() {
    if(session_id() != '') {
      self::error('Session already started. Can\'t use phpSec sessions', PHPSEC_E_WARN);
    } else {
      // TODO: Create own session handler and add encryption support.
      // Set the session.save.path to our datadir.
      session_save_path(PHPSEC_DATADIR);
      // Rename the session to avoid clusterfu*ks.
      session_name(PHPSEC_SESSNAME);
      // Initialize the session.
      session_start();
      // Regenerate the session ID and remove the old session to avaoid session hijacking.
      session_regenerate_id(true);
    }
  }
  /**
   * Initialize the crypto library.
   * Check to see if our PHP installation meets the requirements.
   * Create a crypto key to use for this session.
   */
  private static function cryptoInit() {
    //TODO: Do some checks to see if our PHP installation supports the algos.
    /**
     * If we don't already have a crypto key we need to create one and save it in
     * a cookie so e can use it trough the session. Note that this key should only
     * be used for session data and not database storage. For that we need a permanent
     * key that don't change.
     */
    if(!isset($_COOKIE[PHPSEC_CIKCOOKIE])) {
      self::$cik = self::genUid(80);
      // TODO: Path, domain and secure only should be defined by user.
      setcookie(PHPSEC_CIKCOOKIE, self::$cik, 0, null, null, false);
    } else {
      self::$cik = $_COOKIE[PHPSEC_CIKCOOKIE];
    }
  }
} phpsec::init();
// Since this is a staticly called library, we need to initialize it ourself as no
// contruct funtion is called for us.