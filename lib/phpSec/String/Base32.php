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
class Base32 {

  private $decodeTable = array(
    'A' => 0,
    'B' => 1,
		'C' => 2,
    'D' => 3,
		'E' => 4,
    'F' => 5,
		'G' => 6,
    'H' => 7,
		'I' => 8,
    'J' => 9,
		'K' => 10,
    'L' => 11,
		'M' => 12,
    'N' => 13,
		'O' => 14,
    'P' => 15,
		'Q' => 16,
    'R' => 17,
		'S' => 18,
    'T' => 19,
		'U' => 20,
    'V' => 21,
		'W' => 22,
    'X' => 23,
		'Y' => 24,
    'Z' => 25,
		'2' => 26,
    '3' => 27,
		'4' => 28,
    '5' => 29,
		'6' => 30,
    '7' => 31,
	);

/**
 * Decode a Base32 encoded string.
 *
 * @param string $str
 *   Base 32 encoded string.
 *
 * @return string
 */
public function decode($str) {

		$str = strtoupper($str);

		$l = strlen($str);
		$n = 0;
		$b = 0;

		$decoded = null;

		for ($i = 0; $i < $l; $i++) {
			$n = $n << 5;
			$n = $n + $this->decodeTable[$str[$i]];
			$b = $b + 5;

			if ($b >= 8) {
				$b = $b - 8;
				$decoded .= chr(($n & (0xFF << $b)) >> $b);
			}
		}

		return $decoded;
	}

}