<?php
/**
 phpSec - A PHP security library

 @author    Audun Larsen <larsen@xqus.com>
 @copyright Copyright (c) Audun Larsen, 2012
 @link      https://github.com/phpsec/phpSec
 @license   http://opensource.org/licenses/mit-license.php The MIT License
 @package   phpSec
 */
namespace phpSec;


class Core extends Pimple {

  const VERSION = '0.6.0-dev';

  public function __construct() {

    $this['logger'] = null;
    $this['store']  = null;

    $this['auth/google'] = $this->share(function($psl) {
      return new Auth\Google($psl);
    });

    $this['auth/authy'] = $this->share(function($psl) {
      return new Auth\Authy($psl);
    });

    $this['crypt/rand'] = $this->share(function($psl) {
      return new Crypt\Rand();
    });


  }


}
