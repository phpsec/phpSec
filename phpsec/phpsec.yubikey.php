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

class phpsecYubikey {
  public static $_clientId     = null;
  public static $_clientSecret = null;
  public static $lastError    = null;

  /**
   * Verify Yubikey one time password against the Yubico servers.
   *
   * @param string $otp
   *   One time password to verify.
   *
   * @return boolean
   */
  public static function verify($otp) {
    if(self::$_clientId === null || self::$_clientSecret === null) {
      self::$lastError = 'YUBIKEY_CLIENT_DATA_NEEDED';
      return false;
    }

    if(!self::validOtp($otp)) {
      self::$lastError = 'YUBIKEY_INVALID_OTP';
      return false;
    }
    /* Setup the data needed to make the request. */
    $data['otp']       = $otp;
    $data['id']        = self::$_clientId;
    $data['nonce']     = phpsecRand::str(20);
    $data['timestamp'] = 1;

    /* Do the request. */
    $response = self::getResponse($data);
    if($response === false) {
      self::$lastError = 'YUBIKEY_SERVER_ERROR';
      return false;
    }

    /* If tokens don't match return false. */
    if($response['otp'] != $otp) {
      self::$lastError = 'YUBIKEY_NO_MATCH';
      return false;
    }

    /* Check status of response. If not OK return false.*/
    if($response['status'] != 'OK') {
      self::$lastError = 'YUBIKEY_COMPUTER_SAYS_NO'; //TODO: Fix this. Use status from server.
      return false;
    }

    /* Sign the request to see if it matches signature from server. */
    $signature = self::sign($response);
    if($signature !== $response['h']) {
      self::$lastError = 'YUBIKEY_BAD_SERVER_SIGNATURE';
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
  private static function sign($data) {
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
    $sign = hash_hmac('sha1', utf8_encode($query), base64_decode(self::$_clientSecret), true);
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
  private static function getResponse($data) {
    /* Convert the array with data to a request string. */
    $query = http_build_query($data);

    /* Set up array with options for the context used by file_get_contents(). */
    $opts = array(
      'http'=>array(
        'method'=>"GET",
        'header'=>"Accept-language: en\r\n" .
                  "User-Agent: phpSec (http://phpsec.xqus.com)\r\n"
      )
    );

    /* Create context. Allowing us to specify User-Agent. */
    $context = stream_context_create($opts);

    /* Get response from Yubico server. */
    $response = @file_get_contents('http://api.yubico.com/wsapi/2.0/verify?'.$query, null, $context);
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
   *
   * @param string $otp
   *   String to Validate
   *
   * @return boolean
   */
  private static function validOtp($otp) {
    if(strlen($otp) != 44) {
      return false;
    }

    return true;
  }

  /**
   * Get the Yubico ID from a OTP.
   *
   * @param string $otp
   *   The one time password to get the ID from.
   *
   * @return string
   *   Returns the Yubikey ID, or FALSE on failure.
   */
  public static function getYubikeyId($otp) {
    if(!self::calidOtp($otp)) {
      return false;
    }
    return substr($otp, 0, 12);
  }
}