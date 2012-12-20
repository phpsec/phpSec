<?php namespace phpSec\Auth;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
 */
use phpSec\Common\Core;

/**
 * Implements Authy authentication. It's like magic, except it's math.
 *
 * @package phpSec
 */
class Authy {

  /**
   * Authy API key.
   */
  public static $_apiKey  = null;

  /**
   * Connect to sandbox?
   */
  public static $_sandbox = false;

  /**
   * Server timeout. In seconds.
   */
  public static $_serverTimeout = 3;

  /**
   * Last error returned by Authy API.
   */
  public static $lastError = null;

  /**
   * Server URLs.
   */
  private static $_servers = array(
    'production' => 'https://api.authy.com',
    'sandbox'    => 'http://sandbox-api.authy.com',
  );

  /**
   * Add a new Authy user and get the Authy ID.
   *
   * @param string $email
   *   User email.
   *
   * @param string $cellphone
   *   User cellphone.
   *
   * @param string $countrycode
   *   User countrycode. Defaults to 1 (USA).
   *
   * @return mixed
   *   Returns the users Authy ID on success or false on errors.
   *   @see \phpSec\Auth\Authy::$lastError.
   */
  public static function userNew($email, $cellphone, $countrycode = 1) {

    $data = array(
      'user[email]'        => $email,
      'user[cellphone]'    => $cellphone,
      'user[country_code]' => $countrycode,
    );

    $result = self::apiCall('new', $data);

    if($result === false) {
    	self::$lastError = 'AUTHY_SERVER_ERROR';
    	return false;
    }

    if(isset($result->errors)) {
      if(isset($result->errors->api_key)) {
        self::$lastError = 'AUTHY_SERVER_INVALID_API_KEY';
      } else {
        self::$lastError = 'AUTHY_SERVER_INVALID_DATA';
      }
      return false;
    }

    if(isset($result->user->id)) {
    	return $result->user->id;
    }
    self::$lastError = 'AUTHY_SERVER_SAYS_NO';
    return false;
  }

  /**
   * Verify a Authy OTP.
   *
   * @param int $authyId
   *   User Authy ID. @see \phpSec\Auth\Authy::userNew().
   *
   * @param int $token
   *   User supplied OPT/token.
   *
   * @return boolean
   *   Return true if a valid Authy token is supplied, false on any errors.
   *   @see \phpSec\Auth\Authy::$lastError.
   */
  public static function verify($authyId, $token) {
    $data = array(
      'token'    => $token,
      'authy_id' => $authyId,
    );


    $result = self::apiCall('verify', $data);

    if($result === false) {
    	self::$lastError = 'AUTHY_SERVER_ERROR';
    	return false;
    }

    if(isset($result->errors)) {
    	if(isset($result->errors->token))   {
    		self::$lastError = 'AUTHY_SERVER_BAD_OTP';
    	} elseif(isset($result->errors->api_key)) {
        self::$lastError = 'AUTHY_SERVER_INVALID_API_KEY';
      } else {
    		self::$lastError = 'AUTHY_SERVER_INVALID_DATA';
    	}
    	return false;
    }

    if(isset($result->token) && $result->token == 'is valid') {
    	return true;
    }

    return false;
  }

  /**
   * Performs a call to the Authy API.
   *
   * @param string $action
   *   Action to perform: should be 'new' or 'verify'
   *
   * @param array $data
   *   Data to perform the action with.
   *
   * @throws \phpSec\Exception\IOException If the Auty API server is unreachable.
   *
   * @return object
   *   Decoded JSON results from Authy server.
   */
  private static function apiCall($action, $data) {
    switch(self::$_sandbox) {
      case true:
     	  $url = self::$_servers['sandbox'];
     	  break;
     	default:
     	  $url = self::$_servers['production'];
    }

    switch($action) {
    	case 'new':
        $url = $url.'/protected/json/users/new?api_key='.self::$_apiKey;
        $postData = http_build_query($data);
        $opts = array(
          'http' => array(
          'method'  => 'POST',
          'timeout' => self::$_serverTimeout,
          'header'  => "Content-Type: application/x-www-form-urlencoded\r\n" .
                       "Content-Length: ".strlen($postData) ."\r\n".
                       "User-Agent: phpSec (http://phpseclib.com)\r\n",
          'content' => $postData,
          'ignore_errors' => true,
        ));

    	  break;
    	case 'verify':
        $url = $url.'/protected/json/verify/'.$data['token'].'/'.$data['authy_id'].'?api_key='.self::$_apiKey;

        $opts = array(
          'http' => array(
          'method'  => 'GET',
          'timeout' => self::$_serverTimeout,
          'header'  => "User-Agent: phpSec (http://phpseclib.com)",
          'ignore_errors' => true,
        ));

    	  break;
    }


    $context = stream_context_create($opts);
    $result  = @file_get_contents($url, false, $context);

    if($result === false) {
    	return false;
    }

    return json_decode($result);
   }
}