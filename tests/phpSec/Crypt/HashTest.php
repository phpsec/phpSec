<?php
class HashTest extends PHPUnit_Framework_TestCase {

  public function testHash() {
    $psl = new \phpSec\Core();

    $hash = $psl['crypt/hash'];
    $str = 'some string';
    $pwHash = $hash->create($str);

    $this->assertTrue($hash->check($str, $pwHash));

  }
}