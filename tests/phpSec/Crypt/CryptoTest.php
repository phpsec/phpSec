<?php
class CryptoTest extends PHPUnit_Framework_TestCase {

  public function testCrypto() {
    $psl = new \phpSec\Core();
    $crypto = $psl['crypt/crypto'];

    $str = 'foobaz';
    $key = '123abc12123abc12';
    $badkey = '123abcR77123abc12';


    $encrypted = $crypto->encrypt($str, $key);

    $decrypted = $crypto->decrypt($encrypted, $key);

    $this->assertEquals($decrypted, $str);
    try {
        $ret = $crypto->decrypt($encrypted, $badkey);
    }catch(Exception $e){
       $this->assertEquals("Message authentication code invalid",$e->getMessage());
    }

  }
}
