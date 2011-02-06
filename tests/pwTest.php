<?php
require_once 'phpsec.class.php';

class PasswordHashingTest extends PHPUnit_Framework_TestCase {
  static private $hash;
  public function testValidJsonStringReturned()  {
    self::$hash = phpsec::pwHash('123abc');
    $this->assertTrue(self::$hash !== null);
  }

  public function testDecodingOfJsonString() {
    $data = json_decode(self::$hash, true);
    $this->assertArrayHasKey('hash', $data);
    $this->assertArrayHasKey('salt', $data);
    $this->assertArrayHasKey('algo', $data);
    $this->assertArrayHasKey('injection', $data);
  }

  public function testPwCheck() {
    $this->assertTrue(phpsec::pwCheck('123abc', self::$hash));
    $this->assertFalse(phpsec::pwCheck('invalidpw', self::$hash));
  }
}