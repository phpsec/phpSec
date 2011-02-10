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

  public static function verify($otp) {
    if(self::$_clientId === null || self::$_clientSecret === null) {
      return false;
    }

    /* Setup the data needed to make the request. */
    $data['otp']       = $otp;
    $data['id']        = self::$_clientId;
    $data['nonce']     = phpsecRand::str(20);
    $data['timestamp'] = 1;

    /* Do the request. */
    $response = self::getResponse($data);

    /* Check status of response. If not OK return false.*/
    if($response['status'] != 'OK') {
      return false;
    }

    /* Sign the request to see if it matches signature from server. */
    $signature = self::sign($response);
    if($signature !== $response['h']) {
      return false;
    }
    return true;
  }

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

  private static function getResponse($data) {
    /* Convert the array with data to a request string. */
    $query = http_build_query($data);

    $response = file_get_contents('http://api.yubico.com/wsapi/2.0/verify?'.$query);

    $lines = explode("\r\n", $response);
     foreach($lines as $line) {
       if(trim($line) != '') {
         list($key, $val) = explode("=", $line, 2);
         $rdata[$key] = trim($val);
       }
    }
    return $rdata;
  }
}