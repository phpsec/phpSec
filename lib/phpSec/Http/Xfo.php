<?php namespace phpSec\Http;
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2013
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */

/**
 * Implements HTTP X-Frame-Options (XFO)
 * @see https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-00
 * @package phpSec
 */
class Xfo {
  const DENY       = 'DENY';
  const SAMEORIGIN = 'SAMEORIGIN';
  const ALLOWFROM  = 'ALLOW-FROM';

  public $allowFrom = array();

  public function enable($policy = self::SAMEORIGIN) {
    $header = 'X-FRAME-OPTIONS: '. $policy;

    if($policy === self::ALLOWFROM) {
      $header .= ' '.join(', ', $this->allowFrom);
    }

    header($header);
  }
}