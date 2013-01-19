<?php namespace phpSec\Auth;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use phpSec\Crypt\Rand;

/**
 * Implements validation of Yubikey against Yubico servers.
 * @package phpSec
 */
class Yubikey {
  /**
   * Yubico client Id.
   * @see https://upgrade.yubico.com/getapikey/
   */
  public $clientId = null;

  /**
   * Yubico client shared secret.
   * @see https://upgrade.yubico.com/getapikey/
   */
  public $clientSecret = null;

  /**
   * Number of servers to try before giving up.
   */
  public $_numServers = 3;

  /**
   * Timeout in seconds for each server.
   */
  public $_serverTimeout = 3;

  /**
   * Last error produced by phpsecYubikey::verify().
   * @see https://phpseclib.com/manual/09-Yubikey-Authentication.md
   */
  public $lastError = null;

  /**
   * Yubico authentication servers.
   */
  private $_servers = array(
    'http://api.yubico.com/wsapi/2.0/verify',
    'http://api2.yubico.com/wsapi/2.0/verify',
    'http://api3.yubico.com/wsapi/2.0/verify',
    'http://api4.yubico.com/wsapi/2.0/verify',
    'http://api5.yubico.com/wsapi/2.0/verify',
  );

  /**
   * phpSec core Pimple container.
   */
  private $psl = null;

  /**
   * Constructor.
   *
   * @param \phpSec\Core $psl
   *   phpSec core Pimple container.
   */
  public function __construct(\phpSec\Core $psl) {
    $this->psl = $psl;
  }

  /**
   * Verify Yubikey one time password against the Yubico servers.
   *
   * @param string $otp
   *   One time password to verify.
   *
   * @return boolean
   *   True on valid OTP, false on invalid. If this method returns false
   *   $lastError will contain details.
   *
   * @see https://phpseclib.com/manual/09-Yubikey-Authentication.md
   */
  public function verify($otp) {
    $rand = $this->psl['crypt/rand'];

    if($this->clientId === null || $this->clientSecret === null) {
      $this->$lastError = 'YUBIKEY_CLIENT_DATA_NEEDED';
      return false;
    }

    if(!self::validOtp($otp)) {
      $this->lastError = 'YUBIKEY_INVALID_OTP';
      return false;
    }
    /* Setup the data needed to make the request. */
    $data['otp']       = $otp;
    $data['id']        = $this->clientId;
    $data['nonce']     = $rand->str(20);
    $data['timestamp'] = 1;
    $data['h']         = $this->sign($data);

    /* Do the request. */
    $response = $this->getResponse($data);
    if($response === false) {
      $this->lastError = 'YUBIKEY_SERVER_ERROR';
      return false;
    }

    /* Check status of response. If not OK return false. */
    if($response['status'] != 'OK') {
      switch($response['status']) {
        case 'REPLAYED_OTP':
          $this->lastError = 'YUBIKEY_SERVER_REPLAYED_OTP';
          break;
        case 'REPLAYED_REQUEST':
          $this->lastError = 'YUBIKEY_SERVER_REPLAYED_REQUEST';
          break;
        case 'BAD_OTP':
          $this->lastError = 'YUBIKEY_SERVER_BAD_OTP';
          break;
        case 'NO_SUCH_CLIENT':
          $this->lastError = 'YUBIKEY_SERVER_NO_SUCH_CLIENT';
          break;
        case 'BAD_SIGNATURE':
          $this->lastError = 'YUBIKEY_SERVER_BAD_SIGNATURE';
          break;
        default:
          $this->lastError = 'YUBIKEY_SERVER_SAYS_NO';
          break;
      }
      return false;
    }

    /* If tokens don't match return false. */
    if($response['otp'] != $otp) {
      $this->$lastError = 'YUBIKEY_NO_MATCH';
      return false;
    }

    /* Sign the request to see if it matches signature from server. */
    $signature = $this->sign($response);
    if($signature !== $response['h']) {
      $this->lastError = 'YUBIKEY_BAD_SERVER_SIGNATURE';
      return false;
    }
    return true;
  }

  /**
   * Sign data using shared secret.
   *
   * @param array $data
   *   Data to sign.
   *
   * @return string
   *   Base64 encoded HMAC hash.
   */
  public function sign($data) {
    /* Remove signature from server. */
    unset($data['h']);

    /* Sort keys alphabetically. */
    ksort($data);

    /* Build query string to sign. */
    $n = count($data);
    $query = '';
    $i = 0;
    while(list($key, $val) = each($data)) {
      $i++;
      $query .= $key.'='.$val;
      if($i < $n) {
        $query.= '&';
      }
    }

    /* Sign. */
    $sign = hash_hmac('sha1', utf8_encode($query), base64_decode($this->clientSecret), true);
    return base64_encode($sign);
  }

  /**
   * Make a request to the Yubico servers and get the response.
   *
   * @param array $data
   *   Array containing the key/values for the request.
   *
   * @return array
   *   Array containing key/values from the response.
   */
  private function getResponse($data) {
    /* Convert the array with data to a request string. */
    $query = http_build_query($data);

    /* Set up array with options for the context used by file_get_contents(). */
    $opts = array(
      'http'=>array(
        'method'  => 'GET',
        'timeout' => $this->_serverTimeout,
        'header'  => "Accept-language: en\r\n" .
                     "User-Agent: phpSec (http://phpseclib.com)\r\n"
      )
    );

    /* Create context. Allowing us to specify User-Agent. */
    $context = stream_context_create($opts);

    /* Try to get response from Yubico server. */
    $attempts = 0;
    $response = false;
    while($response === false && $attempts < $this->_numServers) {
      /* select a Yubico API server. */
      $server = array_rand($this->_servers);
      $response = @file_get_contents($this->_servers[$server].'?'.$query, null, $context);
      $attempts++;
    }

    if($response === false) {
      /* Could not make request. */
      return false;
    }

    /* Parse response and create an array with the data. */
    $lines = explode("\r\n", $response);
     foreach($lines as $line) {
       if(trim($line) != '') {
         list($key, $val) = explode("=", $line, 2);
         $rdata[$key] = trim($val);
       }
    }

    /* All done. */
    return $rdata;
  }

  /**
   * Validate a string as a one-time-password.
   * A valid OTP should consist of 32-48 printable characters.
   *
   * @param string $otp
   *   String to Validate
   *
   * @return boolean
   *   True if the OTP is valid, false on error.
   */
  public function validOtp($otp) {
    $length  = strlen($otp);

    /* Check length. */
    if($length > 48 || $length < 32) {
      return false;
    }

    /* Check for printable charcters (no whitespace). */
    return ctype_graph($otp);
  }

  /**
   * Get the identity of a Yubikey OTP.
   * The identity part is the same for every OTP, and it is the initial 2-16 modhex characters of the OTP.
   * Since the rest of the OTP is always 32 characters, the method to extract the identity is to remove
   * 32 characters from the end and then use the remaining string, which should be 2-16 characters,
   * as the YubiKey identity.
   *
   * @param string $otp
   *   The one time password to get the identity from.
   *
   * @return string
   *   Returns the Yubikey identity, or false on failure.
   */
  public function getYubikeyId($otp) {
    if(!$this->validOtp($otp)) {
      return false;
    }

    $idLen = strlen($otp) - 32;
    return substr($otp, 0, $idLen);
  }
}