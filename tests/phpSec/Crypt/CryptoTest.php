<?php
class CryptoTest extends PHPUnit_Framework_TestCase {

  public function testCrypto() {
    $psl = new \phpSec\Core();
    $crypto = $psl['crypt/crypto'];

    $str = 'foobaz';
    $key = '123abc12123abc12';

    $encrypted = $crypto->encrypt($str, $key);

    $decrypted = $crypto->decrypt($encrypted, $key);

    $this->assertEquals($decrypted, $str);

  }
}