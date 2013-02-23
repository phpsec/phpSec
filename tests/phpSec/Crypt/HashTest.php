<?php
class HashTest extends PHPUnit_Framework_TestCase {

  /**
   * Test the creation of the default hash (PBKDF2)
   */
  public function testDefaultHash() {
    $psl = new \phpSec\Core();

    $hash = $psl['crypt/hash'];
    $str = 'some string';
    $pwHash = $hash->create($str);

    $this->assertTrue($hash->check($str, $pwHash));
    $this->assertFalse($hash->check($str.'f00', $pwHash));
  }

  public function testPbkdf2Hash()
  {
    $psl = new \phpSec\Core();

    $hash = $psl['crypt/hash'];
    $hash->method = \phpSec\Crypt\Hash::PBKDF2;
    $str = 'some string';
    $pwHash = $hash->create($str);

    $this->assertTrue($hash->check($str, $pwHash));
    $this->assertFalse($hash->check($str.'f00', $pwHash));
  }

  public function testDrupalHash()
  {
    $psl = new \phpSec\Core();

    $hash = $psl['crypt/hash'];
    $hash->method = \phpSec\Crypt\Hash::DRUPAL;
    $str = 'some string';
    $pwHash = $hash->create($str);

    $this->assertTrue($hash->check($str, $pwHash));
    $this->assertFalse($hash->check($str.'f00', $pwHash));
  }

  public function testSha256Hash()
  {
    $psl = new \phpSec\Core();

    $hash = $psl['crypt/hash'];
    $hash->method = \phpSec\Crypt\Hash::SHA256;
    $str = 'some string';
    $pwHash = $hash->create($str);

    $this->assertTrue($hash->check($str, $pwHash));
    $this->assertFalse($hash->check($str.'f00', $pwHash));
  }

  public function testSha512Hash()
  {
    $psl = new \phpSec\Core();

    $hash = $psl['crypt/hash'];
    $hash->method = \phpSec\Crypt\Hash::SHA512;
    $str = 'some string';
    $pwHash = $hash->create($str);

    $this->assertTrue($hash->check($str, $pwHash));
    $this->assertFalse($hash->check($str.'f00', $pwHash));
  }
}