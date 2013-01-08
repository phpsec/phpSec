<?php
class GoogleTest extends PHPUnit_Framework_TestCase {


  public function testKeyGen() {
    $psl = new \phpSec\Core();

    $psl['store'] = $psl->share(function($psl) {
      return new \phpSec\Store\File(sys_get_temp_dir(), $psl);
    });

    $google = $psl['auth/google'];

    $key = $google->newKey();
    $this->assertEquals(16, strlen($key));
  }

  public function testKeyValid() {
    $psl = new \phpSec\Core();

    $psl['store'] = $psl->share(function($psl) {
      return new \phpSec\Store\File(sys_get_temp_dir(), $psl);
    });

    $google = $psl['auth/google'];

    $key = $google->newKey();
    $token = $google->getToken($key);

    $this->assertTrue($google->verify($token, $key));
    $this->assertFalse($google->verify($token, $key));
  }
}