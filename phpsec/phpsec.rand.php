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
 * Provides methods for generating random data.
 */

class phpsecRand {
  public static $_charset = 'abcdefghijklmnopqrstuvwxyz0123456789';

  public static function bytes($length) {
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
    $rnd = '';
    for ($i=0;$i<$length;$i++) {
      $sha = hash('sha256', mt_rand());
      $char = mt_rand(0,30);
      $rnd .= chr(hexdec($sha[$char].$sha[$char+1]));
    }
    return $rnd;
  }

  public static function int($min, $max) {
    $delta = $max-$min;
    $bytes = ceil($delta/256);
    $rnd = self::bytes($bytes);
    $add = 0;
    for ($i = 0; $i < $bytes; $i++) {
      $add += ord($rnd[$i]);
    }
    $add = $add % ($delta + 1);
    return $min + $add;
  }

  public static function str($len) {
    $str = '';
    for ($i = 0; $i < $len; $i++) {
      $pos = self::int(0,strlen(self::$_charset)-1);
      $str .= self::$_charset[$pos];
    }
    return $str;
  }

  public static function hex($len) {
    return bin2hex(self::bytes($len));
  }
}

