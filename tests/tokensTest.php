<?php
require_once 'phpsec.class.php';
require_once 'phpsec/phpsec.cache.php';
require_once 'phpsec/phpsec.crypt.php';
require_once 'phpsec/phpsec.session.php';

phpsec::$_datadir = './tests';
phpsec::$_logdir = './tests';
phpsec::init();

class XsrfTest extends PHPUnit_Framework_TestCase {
  private static $token;
  public function setUp(){
  }
  public function tearDown(){
  }

  public function testGetToken()  {
    self::$token = phpsec::getToken('test');
    $this->assertTrue(is_string(self::$token));
    $this->assertTrue(strlen(self::$token)>20);
  }
  public function testValidToken() {
    $this->assertTrue(phpsec::validToken('test', self::$token));
  }
  public function testTokenIsRemoved()  {
    $this->assertFalse(phpsec::validToken('test', self::$token));
  }
}