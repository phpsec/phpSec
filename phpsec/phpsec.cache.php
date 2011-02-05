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
 * Provides as simple cahce engine.
 */
class phpsecCache {
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
  public static function cacheSet($name, $data, $ttl = 3600) {
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
  public static function cacheGet($name) {
    /* Do cache garbage collection. */
    self::cacheGc();

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
  public static function cacheRem($name) {
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
    return 'cache_'.$name.'_'.hash(PHPSEC_HASHTYPE, phpsec::$uid);
  }
}
