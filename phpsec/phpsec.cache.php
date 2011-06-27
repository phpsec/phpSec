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
 * Provides as simple cahce engine.
 */
class phpsecCache {
  public static $_datadir = null;

  const GC_PROB   = 0.2;
  const HASH_TYPE = 'sha256';

  /**
   * Save data to the cache.
   *
   * @param string $name
   *   String containing the name of the data to save.
   *
   * @param mixed $data
   *   Data to save. Can be any dataform.
   *
   * @param integer $ttl
   *   Time to live in seconds.
   */
  public static function cacheSet($name, $data, $ttl = 3600) {
    $fileName =  self::$_datadir.'/'.self::cacheFilename($name);
    $saveData['data'] = serialize($data);
    $saveData['ttl']  = time() + $ttl;
    $saveData['hash'] = hash(self::HASH_TYPE, $saveData['data']);

    $data = json_encode($saveData);
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
   * @param string $name
   *   String containing the name of the data to get.
   *
   * @return mixed
   *   Returns data in it's original form, or false if no data stored.
   */
  public static function cacheGet($name) {
    /* Do cache garbage collection. */
    self::cacheGc();

    $fileName =  self::$_datadir.'/'.self::cacheFilename($name);
    if(file_exists($fileName)) {
      $data = json_decode(file_get_contents($fileName), true);
      if($data['ttl'] > time()) {
        if(hash(self::HASH_TYPE, $data['data']) == $data['hash']) {
          return unserialize($data['data']);
        }
      }

    }
    return false;
  }

  /**
   * Remove data from the cache.
   *
   * @param string $name
   *   String containing the name of the data to remove.
   *
   * @return boolean
   *   True on success, false otherwise.
   */
  public static function cacheRem($name) {
    $fileName =  self::$_datadir.'/'.self::cacheFilename($name);
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
    $probMax = 1 / self::GC_PROB;
    $do = rand(1, $probMax);
    if($do > 1) {
      /* Skipping GC this time. */
      return false;
    }
    if ($handle = opendir(self::$_datadir)) {
      while (false !== ($file = readdir($handle))) {
        if ($file != "." && $file != "..") {
          if(substr($file, 0 ,6) == 'cache_') {
            $fileName = self::$_datadir.'/'.$file;
            $data = json_decode(file_get_contents($fileName), true);
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
    return 'cache_'.$name.'_'.hash(self::HASH_TYPE, phpsec::$uid);
  }
}
