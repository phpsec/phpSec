<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
namespace phpSec\String;

/**
 * Base 32 decoding of string.
 * @package phpSec
 */
class Compare {

  /**
   * A timing safe equals comparison.
   *
   * To prevent leaking length information, it is important
   * that user input is always used as the second parameter.
   * Based on code by Anthony Ferrara.
   * @see http://blog.ircmaxell.com/2012/12/seven-ways-to-screw-up-bcrypt.html
   *
   * @param string $safe
   *   The internal (safe) value to be checked
   *
   * @param string $user
   *   The user submitted (unsafe) value
   *
   * @return boolean
   *   True if the two strings are identical.
   */
  function timingSafe($safe, $user) {
    /* Prevent issues if string length is 0. */
    $safe .= chr(0);
    $user .= chr(0);

    $safeLen = strlen($safe);
    $userLen = strlen($user);

    /* Set the result to the difference between the lengths. */
    $result = $safeLen - $userLen;

    for ($i = 0; $i < $userLen; $i++) {
      $result |= (ord($safe[$i % $safeLen]) ^ ord($user[$i]));
    }

    // They are only identical strings if $result is exactly 0...
    return $result === 0;
  }
}