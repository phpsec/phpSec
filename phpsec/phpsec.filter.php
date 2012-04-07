<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2011, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Provides methods for XSS filtering.
 */
class phpsecFilter {

  /**
   * XSS text filter. Returns a string that is safe to use on the page.
   *
   * There are three types of variables:
   * %variables: stip mode of phpsec::f() is used.
   * !variables: escapeAll mode of phpsec::f() is used.
   * @variables: escape mode of phpsec::f() is used.
   * &variables: url mode of phpsec::f() is used.
   *
   * @see phpsec::f()
   * @see https://phpseclib.com/manual/filter
   * @see http://www.faqs.org/rfcs/rfc3986
   *
   * @param string $str
   *   A string containing the 'glue' used to compose the filtered parts
   *   from the $args array.
   *
   * @param mixed $args
   *   An associative array containing data to filter.
   *   The array keys should be preceeded with %, ! or @ defining what filter
   *   to apply.
   */
  public static function t($str, $args) {
    /* Loop trough the args and apply the filters. */
    while(list($name, $data) = each($args)) {
      $safeData = false;
      $filterType = mb_substr($name, 0, 1);
      switch($filterType) {
        case '%':
          /* %variables: HTML tags are stripped of from the string
             before it is in inserted. */
          $safeData = self::f($data, 'strip');
          break;
        case '!':
          /* !variables: HTML and special characters are escaped from the string
             before it is used. */
          $safeData = self::f($data, 'escapeAll');
          break;
        case '@':
          /* @variables: Only HTML is escaped from the string. Special characters
             is kept as it is. */
          $safeData = self::f($data, 'escape');
          break;
        case '&':
          /* Encode a string according to RFC 3986 for use in a URL. */
          $safeData = self::f($data, 'url');
          break;
        default:
          phpsec::error('Unknown variable type', E_USER_NOTICE);
          break;
      }
      if($safeData !== false) {
        $str = str_replace($name, $safeData, $str);
      }
    }
    return $str;
  }

  /**
   * XSS filter. Returns a string that is safe to use on the page.
   *
   * There are three modes:
   * strip: HTML is stripped from the string
   * before it is inserted.
   * escapeAll: HTML and special characters is escaped from the string
   * before it is inserted.
   * escape: Only HTML is escaped from the string. Special characters
   * is kept as is.
   * url: Encode a string according to RFC 3986 for use in a URL.
   *
   * @see https://phpseclib.com/manual/filter
   * @see http://www.faqs.org/rfcs/rfc3986
   *
   * @param string $str
   *   String to filter
   *
   * @param string $mode
   *   String defining what filter to apply.
   */
  public static function f($str, $mode = 'escape') {
    switch($mode) {
      case 'strip':
        /* HTML tags are stripped from the string
           before it is used. */
        return strip_tags($str);
      case 'escapeAll':
        /* HTML and special characters are escaped from the string
           before it is used. */
        return htmlentities($str, ENT_QUOTES, phpSec::$_charset);
      case 'escape':
        /* Only HTML tags are escaped from the string. Special characters
           is kept as is. */
        return htmlspecialchars($str, ENT_NOQUOTES, phpSec::$_charset);
      case 'url':
        /* Encode a string according to RFC 3986 for use in a URL. */
        return rawurlencode($str);
      default:
        phpsec::error('Unknown variable type', E_USER_NOTICE);
    }
  }
}