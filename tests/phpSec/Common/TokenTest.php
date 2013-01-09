<?php
class TokenTest extends PHPUnit_Framework_TestCase {


  public function testToken() {
    $psl = new \phpSec\Core();

    $psl['store'] = $psl->share(function($psl) {
      return new \phpSec\Store\File(sys_get_temp_dir(), $psl);
    });


    $token = $psl['common/token'];

    $csrf = $token->set('test');

    $this->assertTrue(strlen($csrf) == 32);

    $this->assertTrue($token->validate('test', $csrf));
    $this->assertFalse($token->validate('test', $csrf));

  }
}