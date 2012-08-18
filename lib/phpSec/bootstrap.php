<?php namespace phpSec;
/**
  phpSec - A PHP security library

  @author    Anthony Ferrara <ircmaxell@ircmaxell.com>
  @copyright Copyright (c) Anthony Ferrara, 2011
  @link      https://github.com/ircmaxell/PHP-CryptLib
  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/bsd-license.php New BSD License
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */


/**
 * The simple autoloader for the phpSec library.
 *
 * Originally from the PHP-CryptLib project
 * @link https://github.com/ircmaxell/PHP-CryptLib/
 *
 * @param string $class
 *   The class name to load
 *
 * @return void
 */
spl_autoload_register(function ($class) {
  if(substr($class, 0, strlen(__NAMESPACE__)) != __NAMESPACE__) {
    //Only autoload libraries from this package
    return;
  }
  $path = substr(str_replace('\\', '/', $class), 6);
  $path = __DIR__ . $path . '.php';
  if(file_exists($path)) {
    require_once $path;
  }
});