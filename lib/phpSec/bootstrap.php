<?php namespace phpSec;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
use \phpSec\Common\SplClassLoader;

require_once __DIR__ . '/Common/SplClassLoader.php';

$classLoader = new SplClassLoader(__NAMESPACE__, dirname(__DIR__));
$classLoader->register();