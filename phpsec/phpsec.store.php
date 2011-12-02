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
 * Abstract class describing the phpSec storage interface class.
 */
abstract class phpsecStore {

  /**
   * Open/prepeare the storage.
   *
   * @param string $target
   *   Storage location.
   *
   * @return bool
   *   Returns true on success and false on error.
   */
  abstract public function __construct($loc);

  /**
   * Read object from storage.
   *
   * @param string $type
   *   Type of data (session, cache, etc.).
   *
   * @param string $id
   *   Unique identifier.
   *
   * @return mixed
   *   Returns data.
   */
  abstract public function read($type, $id);

  /**
   * Write object to storeage.
   *
   * @param string $type
   *   Type of data (session, cache, etc.).
   *
   * @param string $id
   *   Unique identifier.
   *
   * @param mixed $data
   *   Data to write.
   *
   * @return bool
   *   Returns true on success, false on error.
   */
  abstract public function write($type, $id, $data);

  /**
   * Delete object from storeage.
   *
   * @param string $type
   *   Type of data (session, cache, etc.).
   *
   * @param string $id
   *   Unique identifier.
   *
   * @return bool
   *   Returns true on success, false on error.
   */
  abstract public function delete($type, $id);

  /**
   * List existing object IDs for a store type.
   *
   * @param string $type
   *   Type of data (session, cache, etc.).
   *
   * @return array
   */
  abstract public function listIds($type);

  /**
   * Read metadata for object in store.
   *
   * @param string $type
   *   Type of data (session, cache, etc.).
   *
   * @param string $id
   *   Unique identifier.
   *
   * @return obj
   *   Return object with metadata.
   */
  abstract public function meta($type, $id);

}