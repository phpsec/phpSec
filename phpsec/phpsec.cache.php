<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Provides us with simple cahce engine.
 * Only intended for use by phpSec, but feel free to use
 * it if you want.
 */
class phpsecCache {

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

    return phpsec::$store->write('cache', self::cacheId($name), $saveData);

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

    $data = phpsec::$store->read('cache', self::cacheId($name));
    if($data ==! false) {
      if($data['ttl'] > time()) {
        return unserialize($data['data']);
      } else {
        phpsec::$store->delete('cache', self::cacheId($name));
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
    return phpsec::$store->delete('cache', self::cacheId($name));
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
    $cahceIds = phpsec::$store->listIds('cache');
    foreach($cahceIds as $cahceId) {
      $data = phpsec::$store->read('cache', $cahceId);
      if($data['ttl'] < time()) {
        phpsec::$store->delete('cache', $cahceId);
      }
    }
    return true;
  }

  private static function cacheId($name) {
    return $name.'_'.hash(self::HASH_TYPE, phpsec::$uid);
  }
}
