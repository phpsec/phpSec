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
 * Implements a session handler to save session data encrypted.
 */
class phpsecSession {
  private static $_savePath;
  private static $_name;
  private static $_keyCookie;
  private static $_secret;

  /**
   * Open session.
   */
  public static function open($path, $name) {
    /* Set some variables we need later */
    self::$_savePath  = $path;
    self::$_name      = $name;
    self::$_keyCookie = $name.'_secret';

    /* If we don't have a  encryption key, create one. */
    if(!isset($_COOKIE[self::$_keyCookie])) {
      self::$_secret = phpsec::genUid(); /* TODO: Use phpsecRand instead. */
      $cookieParam = session_get_cookie_params();
      setcookie(
        self::$_keyCookie,
        self::$_secret,
        $cookieParam['lifetime'],
        $cookieParam['path'],
        $cookieParam['domain'],
        $cookieParam['secure'],
        $cookieParam['httponly']
      );
    } else {
      self::$_secret = $_COOKIE[self::$_keyCookie];
    }
  }

  public static function close() {
    return true;
  }

  public static function read($id) {
    $file = self::fileName($id);
    if(file_exists($file)) {
      $data = file_get_contents($file);
      return phpsecCrypt::decrypt($data, self::$_secret);
    }
    return false;
  }

  public static function write($id, $data) {
    $file = self::fileName($id);
    $encrypted = phpsecCrypt::encrypt($data, self::$_secret);
    $fp = @fopen($file, 'w');
    if($fp) {
      $success = fwrite($fp, $encrypted);
      fclose($fp);
      return $success;
    }
    return false;
  }

  public static function destroy($id) {
    $file = self::fileName($id);
    setcookie(
      self::$_keyCookie,
      '',
      time()-10
    );
    return(@unlink($file));
  }

  public static function gc($ttl) {
    $fileNames = glob(self::$_savePath.'/'.self::$_name.'_*');
    foreach($fileNames as $fileName) {
      if(filemtime($fileName) + $ttl < time()) {
        @unlink($fileName);
      }
    }
    return true;
  }

  private static function fileName($id) {
    return self::$_savePath.'/'.self::$_name."_".$id;
  }
}
