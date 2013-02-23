<?php
class CompareTest extends PHPUnit_Framework_TestCase {


  public function testTimingsafe() {
    $psl = new \phpSec\Core();

    $compare = $psl['string/compare'];


    $this->assertTrue($compare->timingSafe('abcd', 'abcd'));
    $this->assertTrue($compare->timingSafe('', ''));
    $this->assertTrue($compare->timingSafe(null, null));

    $this->assertFalse($compare->timingSafe(null, 'abcd'));
    $this->assertFalse($compare->timingSafe('abcd', null));
    $this->assertFalse($compare->timingSafe('abcd', ''));
    $this->assertFalse($compare->timingSafe('', 'abcd'));
    $this->assertFalse($compare->timingSafe('abcd', 'abcc'));
  }
}