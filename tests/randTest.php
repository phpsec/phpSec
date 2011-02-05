<?php
require_once 'phpsec.class.php';
require_once 'phpsec/phpsec.rand.php';

class RandTest extends PHPUnit_Framework_TestCase {
  public function setUp(){
  }
  public function tearDown(){
  }
  public function testRandBytes()  {
    $rnd = phpsecRand::bytes(10);
    $this->assertTrue(strlen((binary) $rnd) == 10);
  }

  public function testRandInt() {
    $int = rand(1, 10);
    $this->assertGreaterThan(0, $int);
    $this->assertLessThan(11, $int);

    $int = rand(1, 1);
    $this->assertEquals(1, $int);

    $int = rand(34, 34);
    $this->assertEquals(34, $int);

    $int = rand(37864786, 398798798798);
    $this->assertGreaterThan(37864785, $int);
    $this->assertLessThan(398798798799, $int);
  }
}