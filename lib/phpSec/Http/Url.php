<?php
/**
  phpSec - A PHP security library

  @author    Audun Larsen <larsen@xqus.com>
  @copyright Copyright (c) Audun Larsen, 2012
  @link      https://github.com/phpsec/phpSec
  @license   http://opensource.org/licenses/mit-license.php The MIT License
  @package   phpSec
 */
namespace phpSec\Http;

/**
 * Class to prevent URL manipulation.
 * @package phpSec
 */
class Url {

  /**
   * Name of GET variable to pass security token trough.
   */
  public $getParam = 'pstkn';

  private $psl = null;

  public function __construct($psl) {
    $this->psl = $psl;
  }

  /**
   * Create a security token for a URL.
   *
   * @param string $url
   *   URL to create token for.
   *
   * @return string
   *   Return a URL with the security token included.
   */
  public function create($url) {
    $part = parse_url($url);

    $appendQuery = false;

    if(isset($part['query'])) {
      $appendQuery = true;
    }

    $request = $this->getRequest($url);
    $token = $this->getToken($request);

    if($appendQuery === true) {
      return $url.'&'.$this->getParam.'='.$token;
    } else {
      return $url.'?'.$this->getParam.'='.$token;
    }
  }

  /**
   * Verify if a URL.
   *
   * @return boolean
   *   Return true if a security token was included in the request
   *   and the URL was not manipulated.
   */
  public function verify($url = null) {
    if($url === null) {
      $url = $_SERVER['REQUEST_URI'];
    }

    $part = parse_url($url);

    if(isset($part['query'])) {
      parse_str($part['query'], $query);
    }

    if(!isset($query[$this->getParam])) {
      return false;
    }

    $request = $this->getRequest($url);
    if($this->gettoken($request) === $query[$this->getParam]) {
      return true;
    }
    return false;
  }

  /**
   * Get the request from a string to create a security token from.
   *
   * @param string $url
   *   URL to get request striong from.
   *
   * @return string
   *   Request string.
   */
  private function getRequest($url) {
    $part = parse_url($url);

    if(isset($part['query'])) {
      parse_str($part['query'], $query);
      if(isset($query[$this->getParam])) {
        unset($query[$this->getParam]);
      }
      if(sizeof($query) > 0) {
        $request = $part['path'].http_build_query($query);
      } else {
        $request = $part['path'];
      }
    } else {
      $request = $part['path'];
    }

    return $request;
  }

  /**
   * Get a security token from a request.
   *
   * @param string $request
   *   Request to create token from.
   *
   * @return string
   *   Returns a security token.
   */
  private function getToken($request) {
    $hash = hash('sha256', $request.$this->psl->getUid());

    return substr($hash, 0, 4).substr($hash, 16, 4).substr($hash, 32, 4).substr($hash, 48, 4);

  }
}