<?php
/**
      phpSec - A PHP security library
      Web:     https://github.com/xqus/phpSec

      Copyright (c) 2011 Audun Larsen <larsen@xqus.com>

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
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

/**
 * Garbage collection probablility. Setting it to 1 makes it run every time,
 * 0.5 every second time and setting it to 0 disabled garbage collection.
 */
define('PHPSEC_GCPROB', 0.2);

/**
 * Define secret to use as a shared crypto key.
 * WARNING: Changing this breaks all before encrypted data.
 */
define('PHPSEC_SECRET', 'twxwcMNlp3xchzlHmuXzHJHE96DPiatAxrcw3sxu');

define('PHPSEC_E_ERROR',  E_USER_ERROR);
define('PHPSEC_E_WARN',   E_USER_WARNING);
define('PHPSEC_E_NOTICE', E_USER_NOTICE);

class phpsec {
  public  static $uid          = null; // User identifier. To identify a session.
  private static $cryptSessKey = null; // Session crypto key. Used for session data.
  private static $cryptAppKey  = null; // App crypto key. Used for long time storage.
  private static $cryptDescr   = null; // Crypto descriptor.

  /**
   * Initialize the library.
   */
  public static function init() {
    /* Check write permissions to directories */
    if(!is_writeable(PHPSEC_LOGDIR)) {
      self::error('Log directory('.PHPSEC_LOGDIR.') not writeable');
    }
    if(!is_writeable(PHPSEC_DATADIR)) {
      self::error('Data directory('.PHPSEC_DATADIR.') not writeable');
    }

    /* If the phpSec session handler is enabled, start it. */
    if(PHPSEC_SESSIONS === true) {
      self::sessionStart();
    }
    /* Start session if not already started earlier. */
    if(session_id() == '') {
       session_start();
     }

    /* Set the charset of the multibyte functions in PHP. */
    mb_internal_encoding(PHPSEC_CHARSET);
    mb_regex_encoding(PHPSEC_CHARSET);

    /* Do cache garbage collection. */
    self::cacheGc();

    /* Create a random token for each visitor and store it the users session.
       This is for example used to identify owners of cache data. */
    if(!isset($_SESSION['phpSec-uid'])) {
      self::$uid = self::genUid();
      $_SESSION['phpSec-uid'] = self::$uid;
    } else {
      self::$uid = $_SESSION['phpSec-uid'];
    }
    /* Initialize the crypto, set the keys and other stuff we need. */
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
    /* First, loop trough the args and apply the filters. */
    while(list($name, $data) = each($args)) {
      $safeData = false;
      $filterType = mb_substr($name, 0, 1);
      switch($filterType) {
        case '%':
          /* %variables: HTML is stripped from the string
             before it is in inserted. */
          $safeData = strip_tags($data);
          break;
        case '!':
          /* !variables: HTML and special characters is escaped from the string
             before it is in inserted. */
          $safeData = htmlentities($data, ENT_QUOTES, PHPSEC_CHARSET);
          break;
        case '@':
          /* @variables: Only HTML is escaped from the string. Special characters
             is kept as is. */
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
    /* TODO: Write error to file. */
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
    /* TODO: Add some more information when writing log entry. */
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
    $probMax = 1 / PHPSEC_GCPROB;
    $do = rand(1, $probMax);
    if($do > 1) {
      /* Skipping GC this time. */
      return false;
    }
    if ($handle = opendir(PHPSEC_DATADIR)) {
      while (false !== ($file = readdir($handle))) {
        if ($file != "." && $file != "..") {
          if(substr($file, 0 ,6) == 'cache_') {
            $fileName = PHPSEC_DATADIR.'/'.$file;
            $data = unserialize(file_get_contents($fileName));
            if($data['ttl'] < time()) {
              unlink($fileName);
            }
          }
        }
      }
      closedir($handle);
    }
    return true;
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
    /* Save the token to the cahce. */
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
    /* Check if the provided token matches the token in the cache. */
    if($cacheToken == $token) {
      /* Remove the token from the cahche so it can't be reused. */
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
      /* Create a hash and see if it matches. */
      if(hash($data['algo'], $pwInjected) == $data['hash']) {
        return true;
      }
    } else {
      /* Invalid array supplied. */
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
    /* First, make sure we have GD. */
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

    /* Add border. */
    imagerectangle ($img,0 ,0, $width-1, $height-1, $border);

    /* Add some background noice to the image. Loops trough the image and
     * randomly set background colors. */
    $numColors = sizeof($bg);
    for($y = 1; $y < $height-1; $y++) {
      for($x = 1; $x < $width-1; $x++) {
        imagesetpixel($img, $x, $y, $bg[rand(0, $numColors-1)]);
      }
    }

    /* Add a line to the image just for the heck of it. */
    imageline($img, 10, rand(5, $height-5), $width-10, rand(5, $height-5), $line);

    /* Add the text to the image. You need to be a genius to come up with code like this. */
    $str = self::captchaWord(6);
    for($i = 0; $i < strlen($str); $i++) {
      $char = strtoupper(substr($str, $i, 1));
      imagestring($img, 5, 20+$i*14, rand(5,10), $char, $border);
    }
    /* Set the magic word in the cache. */
    self::cacheSet('captcha', $str);

    /* Save the image in the public data dir. */
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
      /* TODO: Create own session handler and add encryption support.
       * Set the session.save.path to our datadir. */
      session_save_path(PHPSEC_DATADIR);
      /* Rename the session to avoid clusterfu*ks. */
      session_name(PHPSEC_SESSNAME);
      /* Initialize the session. */
      session_start();
      /* Regenerate the session ID and remove the old session to avaoid session hijacking. */
      session_regenerate_id(true);
    }
  }
  /**
   * Initialize the crypto library.
   * Check to see if our PHP installation meets the requirements.
   * Create a crypto key to use for this session.
   */
  private static function cryptoInit() {
    /* TODO: Do some checks to see if our PHP installation supports the algos. */

    self::$cryptDescr = mcrypt_module_open(MCRYPT_BLOWFISH, '', 'cbc', '');

    /* Get keysize length. */
    $ks = mcrypt_enc_get_key_size(self::$cryptDescr);

    /* Get the application key from our secret. */
    self::$cryptAppKey = substr(hash(PHPSEC_HASHTYPE, PHPSEC_SECRET), 0, $ks);

    /* If we don't already have a session crypto key we need to create one and save it in
     * a cookie so e can use it trough the session. Note that this key should only
     * be used for session data and not database storage. For that we need a permanent
     * key that don't change. */
    if(!isset($_COOKIE[PHPSEC_CIKCOOKIE])) {
      self::$cryptSessKey = substr(hash(PHPSEC_HASHTYPE, self::genUid(80)), 0, $ks);
      /* TODO: Path, domain and secure only should be defined by user. */
      setcookie(PHPSEC_CIKCOOKIE, self::$cryptSessKey, 0, null, null, false);
    } else {
      self::$cryptSessKey = $_COOKIE[PHPSEC_CIKCOOKIE];
    }
  }

  /**
   * Encrypt data returning a JSON encoded array safe for storage in a database
   * or file. The array has the following structure before it is encoded:
   * array(
   *   'cdata' => 'Encrypted data, Base 64 encoded',
   *   'iv'    => 'Base64 encoded IV',
   *   'algo'  => 'Algorythm used',
   *   'mode'  => 'Mode used',
   *   'hash'  => 'A SHA256 hash of the data'
   * )
   *
   * @param mixed $data
   *   Data to encrypt.
   *
   * @return string
   *   Serialized array containing the encrypted data along with some meta data.
   */
  public static function encrypt($data, $keyType = 'longtime') {
    /* Create IV. */
    $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size(self::$cryptDescr), MCRYPT_RAND);

    /* Select key and pass on to mcrypt.
     * TODO: Move this to cryptoInit() or mabye a new method?*/
    switch($keyType) {
      case 'longtime':
        $key = self::$cryptAppKey;
        break;
      case 'onetime':
        $key = self::$cryptSessKey;
        break;
    }
    mcrypt_generic_init(self::$cryptDescr, $key, $iv);

    /* Prepeare the array with data. */
    $serializedData = serialize($data);

    $encrypted['cdata'] = base64_encode(mcrypt_generic(self::$cryptDescr, $serializedData));
    $encrypted['hash']  = hash('sha256', $serializedData);
    $encrypted['algo']  = MCRYPT_BLOWFISH; /* TODO: You know what to do here. */
    $encrypted['mode']  = 'cbc';
    $encrypted['iv']    = base64_encode($iv);

    return json_encode($encrypted);
  }

  /**
   * Decrypt a data encrypted by encrypt().
   *
   * @param string $data
   *   JSON string containing the encrypted data and meta information in the
   *   excact format as returned by encrypt().
   *
   * @return mixed
   *   Decrypted data in it's original form.
   */
  public static function decrypt($data, $keyType = 'longtime') {
    /* First select the key to use. */
    switch($keyType) {
      case 'longtime':
        $key = self::$cryptAppKey;
        break;
      case 'onetime':
        $key = self::$cryptSessKey;
        break;
    }

    /* Decode the JSON string */
    $data = json_decode($data, true);
    if($data === NULL || sizeof($data) !== 5) {
      self::error('Invalid data passed to decrypt()');
      return false;
    }

    /* Everything looks good so far. Let's continue.*/
    $td = mcrypt_module_open($data['algo'], '', $data['mode'], '');

    mcrypt_generic_init($td, $key, base64_decode($data['iv']));
    $decrypted = rtrim(mdecrypt_generic($td, base64_decode($data['cdata'])));
    if(hash('sha256', $decrypted) == $data['hash']) {
      return unserialize($decrypted);
    } else {
      return false;
    }
  }

  public static function randBytes($length) {
    /* Code inspired by this blogpost by Enrico Zimuel
     * http://www.zimuel.it/blog/2011/01/strong-cryptography-in-php/ */
    $strong = false;
    if(function_exists('openssl_random_pseudo_bytes')) {
      $rnd = openssl_random_pseudo_bytes($length, $strong);
      if($strong === true) {
        return $rnd;
      }
    }
    /* Either we dont have the OpenSSL library or the data returned was not
     * considered secure. Fall back on this less secure code. */
    for ($i=0;$i<$length;$i++) {
      $sha= hash('sha256', mt_rand());
      $char= mt_rand(0,30);
      $rnd.= chr(hexdec($sha[$char].$sha[$char+1]));
    }
    return $rnd;
  }

  public static function randInt() {

  }

  public static function randStr() {

  }

  public static function randhex() {

  }
} phpsec::init();
/* Since this is a staticly called library, we need to initialize it ourself as no
 * contruct funtion is called for us. */
