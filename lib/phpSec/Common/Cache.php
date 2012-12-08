<?php namespace phpSec\Common;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use \phpSec\Common\Core;


/**
 * Provides us with a simple cahce engine.
 * Only intended for use by phpSec, but feel free to use
 * it if you want.
 */
class Cache {
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
    $saveData['data'] = serialize($data);
    $saveData['ttl']  = time() + $ttl;

    try {
      Core::$store->write('cache', self::cacheId($name), $saveData);
    } catch (\phpSec\Exception $e) {
      return false;
    }
    return true;
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

    try {
      $data = Core::$store->read('cache', self::cacheId($name));
    } catch (\phpSec\Exception $e) {
      return false;
    }
    if($data ==! false) {
      if($data['ttl'] > time()) {
        return unserialize($data['data']);
      }
      Core::$store->delete('cache', self::cacheId($name));
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
    return Core::$store->delete('cache', self::cacheId($name));
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
    $cahceIds = Core::$store->listIds('cache');
    foreach($cahceIds as $cahceId) {
      try {
        $data = Core::$store->read('cache', $cahceId);
      } catch (\phpSec\Exception $e) {
        /* Skip this. */
        continue;
      }

      if($data['ttl'] < time()) {
        Core::$store->delete('cache', $cahceId);
      }
    }
    return true;
  }

  /**
   * Get cache ID.
   *
   * @param string $name
   *   Name to get ID from.
   */
  private static function cacheId($name) {
    return $name.'_'.hash(self::HASH_TYPE, Core::getUid());
  }
}
