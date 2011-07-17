<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011
  @link      https://github.com/xqus/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

abstract class phpsecStorage {
  const GC_PROB   = 0.2;
  const HASH_TYPE = 'sha256';

  function __construct() {

  }

  abstract public static function set();
  abstract public static function get();
  abstract public static function rem();


  private static function gc() {

  }
}