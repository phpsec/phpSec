<?php
class RandTest extends PHPUnit_Framework_TestCase {

  public function testRandString() {
    $psl = new \phpSec\Core();
    $rnd = $psl['crypt/rand'];

    $len = 10;
    $this->assertEquals($len, strlen($rnd->str($len)));
  }
}